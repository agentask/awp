"""AWP core §2.1 envelope: types, JCS canon, sign/verify, and ULID id
generation — a Python counterpart to internal/envelope (Go)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ulid import ULID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import identity
from .delegation import Link

MAX_SIZE = 256 * 1024  # core §2.1 serialized-envelope cap

MIN_TTL = 60
MAX_TTL = 604800


def new_id() -> str:
    """core §0: lowercase Crockford base32 ULID — matches Go's
    strings.ToLower(ulid.Make().String())."""
    return str(ULID()).lower()


class TTLOutOfBoundsError(Exception):
    pass


class TooLargeError(Exception):
    pass


@dataclass
class Envelope:
    id: str
    kind: str
    from_: str
    to: str
    thread: str
    ts: str
    ttl: int
    body: Any
    in_reply_to: str | None = None
    session: str | None = None
    delegation: list[Link] | None = None
    awp: str = "0.1"
    sig: identity.Sig | None = None

    def validate_ttl(self) -> None:
        if not (MIN_TTL <= self.ttl <= MAX_TTL):
            raise TTLOutOfBoundsError(f"envelope: ttl {self.ttl} out of bounds [{MIN_TTL}, {MAX_TTL}]")

    def to_dict(self, *, with_sig: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "awp": self.awp,
            "id": self.id,
            "kind": self.kind,
            "from": self.from_,
            "to": self.to,
            "thread": self.thread,
            "in_reply_to": self.in_reply_to,
            "ts": self.ts,
            "ttl": self.ttl,
            "session": self.session,
            "delegation": [l.to_dict() for l in self.delegation] if self.delegation is not None else None,
            "body": self.body,
        }
        if with_sig and self.sig is not None:
            d["sig"] = self.sig.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Envelope":
        delegation_raw = d.get("delegation")
        return Envelope(
            awp=d.get("awp", "0.1"), id=d["id"], kind=d["kind"],
            from_=d["from"], to=d["to"], thread=d["thread"],
            in_reply_to=d.get("in_reply_to"), ts=d["ts"], ttl=d["ttl"],
            session=d.get("session"),
            delegation=[Link.from_dict(l) for l in delegation_raw] if delegation_raw is not None else None,
            body=d.get("body"),
            sig=identity.Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def validate_size(self) -> None:
        import json

        raw = json.dumps(self.to_dict()).encode("utf-8")
        if len(raw) > MAX_SIZE:
            raise TooLargeError("envelope: exceeds 256 KiB size limit")

    def sign(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self.sig = identity.sign(self.to_dict(with_sig=False), priv, kid)

    def verify(self, pub: Ed25519PublicKey) -> None:
        if self.sig is None:
            raise identity.BadSignatureError(f"envelope {self.id!r} has no sig")
        identity.verify_sig(self.to_dict(with_sig=False), self.sig, pub)
