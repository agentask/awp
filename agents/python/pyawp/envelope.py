"""AWP core §2.1 envelope — the async unit of communication, and a
Python counterpart to internal/envelope (Go). See identity.py's module
doc for why field presence (not just value) has to match Go exactly.

Deliberately out of scope, matching pyawp's overall scope note: `session`
and `delegation` are always emitted as `null` (this repo's own
`sdk/go.SendEnvelope` does the same — it never sets either field either,
since sync sessions and delegation chains are separate features neither
implementation's async send path exercises here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ulid import ULID

from . import identity


def new_id() -> str:
    """core §0: lowercase Crockford base32 ULID — matches Go's
    strings.ToLower(ulid.Make().String())."""
    return str(ULID()).lower()


MIN_TTL = 60
MAX_TTL = 604800


class TTLOutOfBoundsError(Exception):
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
    awp: str = "0.1"
    sig: identity.Sig | None = None

    def validate_ttl(self) -> None:
        if not (MIN_TTL <= self.ttl <= MAX_TTL):
            raise TTLOutOfBoundsError(f"ttl {self.ttl} out of bounds [{MIN_TTL}, {MAX_TTL}]")

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
            "session": None,
            "delegation": None,
            "body": self.body,
        }
        if with_sig and self.sig is not None:
            d["sig"] = self.sig.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Envelope":
        return Envelope(
            awp=d.get("awp", "0.1"), id=d["id"], kind=d["kind"],
            from_=d["from"], to=d["to"], thread=d["thread"],
            in_reply_to=d.get("in_reply_to"), ts=d["ts"], ttl=d["ttl"],
            body=d.get("body"),
            sig=identity.Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def sign(self, priv, kid: str) -> None:
        self.sig = identity.sign(self.to_dict(with_sig=False), priv, kid)

    def verify(self, pub) -> None:
        if self.sig is None:
            raise identity.BadSignatureError(f"envelope {self.id!r} has no sig")
        identity.verify_sig(self.to_dict(with_sig=False), self.sig, pub)
