"""AWP core §0.1 signing primitive and §1.1 domain index — a Python
counterpart to internal/identity (Go), precise enough to interoperate with
it: canonicalization and signatures here are byte-identical to the Go
reference implementation's for the same logical content, verified in
scripts/crosscheck_go.py.

Field presence matters as much as field values. Go's encoding/json emits
every struct field that isn't tagged `omitempty`, even when it's the zero
value (an empty string, or `null` for a nil pointer) — it's the *absence*
of a value, not its emptiness, that a `omitempty` tag controls. JCS then
canonicalizes whatever JSON resulted. So each `to_dict` below reproduces
Go's field set exactly: a plain value for a non-omitempty field (never
skipped), `None` for a non-omitempty pointer field that's unset (encodes
as JSON `null`), and the key entirely absent for an omitempty field with
no value.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import b64url

RFC3339_MILLI = "%Y-%m-%dT%H:%M:%S.{ms}Z"


def now_rfc3339_milli() -> str:
    """core §0's timestamp format: RFC 3339 UTC, millisecond precision."""
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
    """core §0.1: JCS (RFC 8785) over the object with `sig` removed.

    Go's pipeline also round-trips through a map (which re-marshals with
    sorted keys) before JCS — but JCS itself re-sorts everything by UTF-16
    code unit regardless of input order, so that intermediate step changes
    nothing observable. Passing our dict straight to rfc8785 produces the
    same bytes, verified directly against Go's jcs.Transform output for
    identical content in scripts/crosscheck_go.py.
    """
    stripped = {k: v for k, v in obj_without_sig.items() if k != "sig"}
    return rfc8785.dumps(stripped)


def sign(obj_without_sig: dict[str, Any], priv: Ed25519PrivateKey, kid: str) -> Sig:
    canon = canonical_bytes(obj_without_sig)
    sig_bytes = priv.sign(canon)
    return Sig(kid=kid, value=b64url.encode(sig_bytes))


class BadSignatureError(Exception):
    pass


def verify_sig(obj_without_sig: dict[str, Any], sig: Sig, pub: Ed25519PublicKey) -> None:
    canon = canonical_bytes(obj_without_sig)
    try:
        pub.verify(b64url.decode(sig.value), canon)
    except InvalidSignature as e:
        raise BadSignatureError("signature verification failed") from e


@dataclass
class Key:
    kid: str
    alg: str
    pub: str
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
        return Ed25519PublicKey.from_public_bytes(raw)


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
class Index:
    domain: str
    updated: str
    # None here means "wire value is JSON null" — Go's `keys`/`entities`
    # have no `omitempty`, so the key is always PRESENT, but a nil Go
    # slice still marshals to `null`, not `[]` (that only happens for an
    # explicitly-initialized-but-empty slice). This distinction changes
    # the canonicalized bytes, so it changes whether a signature verifies
    # — collapsing null and [] into the same Python value (as an earlier
    # version of this dataclass did, always defaulting to []) breaks
    # verification of a real Go-produced index whose `entities` happened
    # to be null. See scripts/crosscheck_go.py, which caught exactly this.
    keys: list[Key] | None = None
    entities: list[Entity] | None = None
    inbox: str = ""
    awp: str = "0.1"
    peers: list[str] | None = None
    crawl: bool | None = None
    transports: list[Transport] | None = None
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
        # omitempty in Go: only present when non-empty/non-nil.
        if self.peers:
            d["peers"] = list(self.peers)
        if self.crawl is not None:
            d["crawl"] = self.crawl
        if self.transports:
            d["transports"] = [t.to_dict() for t in self.transports]
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
            sig=Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def sign(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self.sig = sign(self.to_dict(with_sig=False), priv, kid)

    def verify_self_sig(self) -> None:
        """core §1.1: the index's own sig, verified against one of its own
        `keys` named by `sig.kid` — the TOFU trust anchor."""
        if self.sig is None:
            raise BadSignatureError("index has no sig")
        for k in self.keys or []:
            if k.kid == self.sig.kid:
                verify_sig(self.to_dict(with_sig=False), self.sig, k.public_key())
                return
        raise BadSignatureError(f"index sig kid {self.sig.kid!r} not found in keys")


def domain_of(principal: str) -> str:
    return principal.split("#", 1)[0]


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_b64url(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return b64url.encode(raw)


def new_key(pub: Ed25519PublicKey, kid: str, created: str | None = None) -> Key:
    return Key(kid=kid, alg="ed25519", pub=public_key_b64url(pub), created=created or now_rfc3339_milli())
