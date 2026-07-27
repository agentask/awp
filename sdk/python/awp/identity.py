"""AWP core §0.1 signing primitive and core §1.1 domain index — a Python
counterpart to internal/identity (Go), byte-identical for the same logical
content: canonicalization here is JCS/RFC 8785 via the `rfc8785` package,
the same library agents/python/pyawp already validated against Go's
gowebpki/jcs.

Field presence matters as much as field value. Go's encoding/json emits
every struct field that isn't tagged `omitempty`, even at its zero value
(empty string, or `null` for a nil pointer/slice) — omission only happens
for `omitempty`-tagged fields that are empty/zero. JCS then canonicalizes
whatever JSON resulted, so presence changes signed bytes. Every `to_dict`
below reproduces Go's exact field set: a plain value for a non-omitempty
field (never skipped), `None` for a non-omitempty pointer field that's
unset (encodes as JSON `null`), and the key entirely absent for an
omitempty field with no value.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import b64url


def now_rfc3339_milli() -> str:
    """core §0's timestamp format: RFC 3339 UTC, millisecond precision,
    literal "Z" suffix — matches Go's
    time.Now().UTC().Format("2006-01-02T15:04:05.000Z") exactly. Deliberately
    not datetime.isoformat(), whose fractional-digit count and "Z"-vs-offset
    behavior differ."""
    t = time.time()
    ms = int((t - int(t)) * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{ms:03d}Z"


@dataclass
class Sig:
    kid: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"kid": self.kid, "value": self.value}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Sig":
        return Sig(kid=d["kid"], value=d["value"])


def canonical_bytes(obj_without_sig: dict[str, Any]) -> bytes:
    """core §0.1: JCS (RFC 8785) over the object with `sig` removed. Go's
    pipeline round-trips through a map (re-marshaling with sorted keys)
    before JCS — but JCS itself re-sorts everything by UTF-16 code unit
    regardless of input order, so that intermediate step changes nothing
    observable. Passing the dict straight to rfc8785 produces the same
    bytes as Go's jcs.Transform for identical content."""
    stripped = {k: v for k, v in obj_without_sig.items() if k != "sig"}
    return rfc8785.dumps(stripped)


def sign(obj_without_sig: dict[str, Any], priv: Ed25519PrivateKey, kid: str) -> Sig:
    canon = canonical_bytes(obj_without_sig)
    sig_bytes = priv.sign(canon)
    return Sig(kid=kid, value=b64url.encode(sig_bytes))


class BadSignatureError(Exception):
    pass


def verify_sig(obj_without_sig: dict[str, Any], sig: Sig | None, pub: Ed25519PublicKey) -> None:
    if sig is None:
        raise BadSignatureError("nil signature")
    canon = canonical_bytes(obj_without_sig)
    try:
        pub.verify(b64url.decode(sig.value), canon)
    except InvalidSignature as e:
        raise BadSignatureError("signature verification failed") from e


def domain_of(principal: str) -> str:
    """Strips the "#entity" fragment from a principal name, per core §0."""
    return principal.split("#", 1)[0]


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_b64url(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return b64url.encode(raw)


@dataclass
class Key:
    kid: str
    alg: str
    pub: str  # base64url-raw-32-bytes, unpadded
    created: str
    expires: str | None = None
    revoked: bool = False
    prev_sig: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kid": self.kid,
            "alg": self.alg,
            "pub": self.pub,
            "created": self.created,
            "expires": self.expires,
            "revoked": self.revoked,
            "prev_sig": self.prev_sig,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Key":
        return Key(
            kid=d["kid"], alg=d["alg"], pub=d["pub"], created=d["created"],
            expires=d.get("expires"), revoked=bool(d.get("revoked", False)),
            prev_sig=d.get("prev_sig"),
        )

    def public_key(self) -> Ed25519PublicKey:
        raw = b64url.decode(self.pub)
        if len(raw) != 32:
            raise ValueError(f"identity: key {self.kid!r} pub has {len(raw)} bytes, want 32")
        return Ed25519PublicKey.from_public_bytes(raw)


def new_key(pub: Ed25519PublicKey, kid: str, created: str | None = None) -> Key:
    return Key(kid=kid, alg="ed25519", pub=public_key_b64url(pub), created=created or now_rfc3339_milli())


@dataclass
class Entity:
    name: str
    kind: str
    manifest: str
    manifest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "kind": self.kind,
            "manifest": self.manifest, "manifest_sha256": self.manifest_sha256,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Entity":
        return Entity(name=d["name"], kind=d["kind"], manifest=d["manifest"],
                       manifest_sha256=d["manifest_sha256"])


@dataclass
class Transport:
    proto: str
    endpoint: str

    def to_dict(self) -> dict[str, Any]:
        return {"proto": self.proto, "endpoint": self.endpoint}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Transport":
        return Transport(proto=d["proto"], endpoint=d["endpoint"])


@dataclass
class Wake:
    """awp-push-v0.1.md §2: an OPTIONAL, unauthenticated liveness hint a
    sender may POST to (empty body) after a failed delivery attempt to
    this domain's inbox. Never carries envelope content."""
    endpoint: str

    def to_dict(self) -> dict[str, Any]:
        return {"endpoint": self.endpoint}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Wake":
        return Wake(endpoint=d["endpoint"])


@dataclass
class Index:
    domain: str
    updated: str
    # None means "wire value is JSON null" (a nil Go slice); a real but
    # empty list means "wire value is []" (a non-nil, zero-length Go
    # slice). Collapsing both into one Python representation would produce
    # different canonical bytes than a real Go-produced index and break
    # signature verification — see this module's doc comment.
    keys: list[Key] | None = None
    entities: list[Entity] | None = None
    inbox: str = ""
    awp: str = "0.1"
    peers: list[str] | None = None
    crawl: bool | None = None
    transports: list[Transport] | None = None
    # capabilities is awp-capabilities-v0.1.md §1: OPTIONAL domain-level
    # protocol-extension advertisement (e.g. "awp-streaming-v0.1"), in the
    # same spirit as transports. Absence means "no declared optional
    # capabilities," exactly like absent transports means HTTPS-only.
    capabilities: list[str] | None = None
    # wake is awp-push-v0.1.md §2: an OPTIONAL wake-notification hint,
    # distinct in scope from capabilities/transports — this is a liveness
    # nudge, never a way to carry envelope bytes.
    wake: Wake | None = None
    sig: Sig | None = None

    def to_dict(self, *, with_sig: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "awp": self.awp,
            "domain": self.domain,
            "updated": self.updated,
            "keys": [k.to_dict() for k in self.keys] if self.keys is not None else None,
            "entities": [e.to_dict() for e in self.entities] if self.entities is not None else None,
            "inbox": self.inbox,
        }
        if self.peers:
            d["peers"] = list(self.peers)
        if self.crawl is not None:
            d["crawl"] = self.crawl
        if self.transports:
            d["transports"] = [t.to_dict() for t in self.transports]
        if self.capabilities:
            d["capabilities"] = list(self.capabilities)
        if self.wake is not None:
            d["wake"] = self.wake.to_dict()
        if with_sig and self.sig is not None:
            d["sig"] = self.sig.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Index":
        keys_raw = d.get("keys")
        entities_raw = d.get("entities")
        return Index(
            awp=d.get("awp", "0.1"), domain=d["domain"], updated=d["updated"],
            keys=[Key.from_dict(k) for k in keys_raw] if keys_raw is not None else None,
            entities=[Entity.from_dict(e) for e in entities_raw] if entities_raw is not None else None,
            inbox=d.get("inbox", ""),
            peers=d.get("peers"), crawl=d.get("crawl"),
            transports=[Transport.from_dict(t) for t in d["transports"]] if d.get("transports") else None,
            capabilities=list(d["capabilities"]) if d.get("capabilities") else None,
            wake=Wake.from_dict(d["wake"]) if d.get("wake") else None,
            sig=Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def sign(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self.sig = sign(self.to_dict(with_sig=False), priv, kid)

    def verify_self_sig(self) -> None:
        """core §1.1: the index's own sig, verified against one of its own
        `keys` named by `sig.kid` — the self-referential TOFU trust
        anchor: an index proves its own signing key is legitimate by
        listing that same key in its own keys[], trusted wholesale on
        first fetch. No external CA involved."""
        if self.sig is None:
            raise BadSignatureError("index has no sig")
        for k in self.keys or []:
            if k.kid == self.sig.kid:
                verify_sig(self.to_dict(with_sig=False), self.sig, k.public_key())
                return
        raise BadSignatureError(f"index sig kid {self.sig.kid!r} not found in keys")


class BrokenRotationError(Exception):
    def __init__(self, index: int, reason: str) -> None:
        self.index = index
        self.reason = reason
        super().__init__(f"identity: rotation chain broken at link {index}: {reason}")


def verify_rotation_chain(chain: list[Key]) -> None:
    """core §1.1 rule 2: chain[0] is the trust anchor (taken on faith, e.g.
    via TOFU); for every i>0, chain[i].prev_sig MUST be the Ed25519
    signature of chain[i].pub's RAW BYTES (not JSON, not base64 — the one
    exception to this codebase's "always JCS then sign" convention) by
    chain[i-1]'s key."""
    if not chain:
        raise ValueError("identity: empty rotation chain")
    for i in range(1, len(chain)):
        prev, cur = chain[i - 1], chain[i]
        try:
            prev_pub = prev.public_key()
            cur_pub_key = cur.public_key()
        except ValueError as e:
            raise BrokenRotationError(i, str(e)) from e
        if cur.prev_sig is None:
            raise BrokenRotationError(i, "missing prev_sig")
        try:
            sig_bytes = b64url.decode(cur.prev_sig)
        except Exception as e:
            raise BrokenRotationError(i, f"prev_sig not valid base64url: {e}") from e
        cur_pub_raw = cur_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        try:
            prev_pub.verify(sig_bytes, cur_pub_raw)
        except InvalidSignature as e:
            raise BrokenRotationError(i, "prev_sig does not verify against previous key") from e
