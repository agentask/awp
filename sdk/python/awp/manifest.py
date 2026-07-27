"""AWP core §1.2 entity manifest: types, signing, and sha256 content
pinning against a domain index's entities[].manifest_sha256 — a Python
counterpart to internal/manifest (Go)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import identity


@dataclass
class IOSchema:
    input: Any = None
    output: Any = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.input is not None:
            d["input"] = self.input
        if self.output is not None:
            d["output"] = self.output
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "IOSchema":
        return IOSchema(input=d.get("input"), output=d.get("output"))


@dataclass
class Portable:
    url: str
    sha256: str
    runtime: str
    interface: str
    capabilities: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url, "sha256": self.sha256, "runtime": self.runtime,
            "interface": self.interface, "capabilities": list(self.capabilities),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Portable":
        return Portable(
            url=d["url"], sha256=d["sha256"], runtime=d["runtime"],
            interface=d["interface"], capabilities=list(d.get("capabilities") or []),
        )


@dataclass
class Hosted:
    endpoint: str

    def to_dict(self) -> dict[str, Any]:
        return {"endpoint": self.endpoint}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Hosted":
        return Hosted(endpoint=d["endpoint"])


@dataclass
class Distribution:
    hosted: Hosted | None = None
    portable: Portable | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.hosted is not None:
            d["hosted"] = self.hosted.to_dict()
        if self.portable is not None:
            d["portable"] = self.portable.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Distribution":
        return Distribution(
            hosted=Hosted.from_dict(d["hosted"]) if d.get("hosted") else None,
            portable=Portable.from_dict(d["portable"]) if d.get("portable") else None,
        )


@dataclass
class Auth:
    sig: str = "required"
    scopes: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"sig": self.sig}
        if self.scopes:
            d["scopes"] = list(self.scopes)
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Auth":
        return Auth(sig=d.get("sig", "required"), scopes=d.get("scopes"))


@dataclass
class Manifest:
    name: str
    kind: str
    version: str
    updated: str
    description: str
    io: IOSchema
    distribution: Distribution
    state: str
    auth: Auth
    awp: str = "0.1"
    pricing: Any = None
    inbox: str | None = None
    sig: identity.Sig | None = None

    def to_dict(self, *, with_sig: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "awp": self.awp,
            "name": self.name,
            "kind": self.kind,
            "version": self.version,
            "updated": self.updated,
            "description": self.description,
            "io": self.io.to_dict(),
            "distribution": self.distribution.to_dict(),
            "state": self.state,
            "auth": self.auth.to_dict(),
            "pricing": self.pricing,
            "inbox": self.inbox,
        }
        if with_sig and self.sig is not None:
            d["sig"] = self.sig.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Manifest":
        return Manifest(
            awp=d.get("awp", "0.1"), name=d["name"], kind=d["kind"], version=d["version"],
            updated=d["updated"], description=d.get("description", ""),
            io=IOSchema.from_dict(d.get("io") or {}),
            distribution=Distribution.from_dict(d.get("distribution") or {}),
            state=d.get("state", ""),
            auth=Auth.from_dict(d.get("auth") or {}),
            pricing=d.get("pricing"),
            inbox=d.get("inbox"),
            sig=identity.Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def sign(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self.sig = identity.sign(self.to_dict(with_sig=False), priv, kid)

    def verify(self, pub: Ed25519PublicKey) -> None:
        if self.sig is None:
            raise identity.BadSignatureError(f"manifest {self.name!r} has no sig")
        identity.verify_sig(self.to_dict(with_sig=False), self.sig, pub)


class PinMismatchError(Exception):
    def __init__(self, want: str, got: str) -> None:
        self.want = want
        self.got = got
        super().__init__(
            f"manifest: sha256 pin mismatch: index pins {want!r}, fetched document hashes to {got!r}"
        )


def verify_pinned_sha256(raw: bytes, want_hex: str) -> None:
    """MUST be checked on the raw fetched bytes, before JSON parsing or
    the manifest's own signature verification (core §1.2): a swapped
    manifest fails the pin, not the signature check."""
    got = hashlib.sha256(raw).hexdigest()
    if got != want_hex:
        raise PinMismatchError(want_hex, got)
