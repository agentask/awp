"""AWP core §2.5 delegation chain: Link type, signing, and full chain
verification — a Python counterpart to internal/delegation (Go).

Gotcha: a Link's `expires` is RFC3339 WITHOUT fractional seconds (bare
`time.RFC3339` on the Go side), unlike Envelope/Index timestamps, which are
always millisecond-precision. Format delegation-link `expires` accordingly
to keep canonical bytes identical to a Go peer's.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import identity

MAX_CHAIN_LENGTH = 8

RULE_CHAIN_TOO_LONG = "chain_too_long"
RULE_ROOT_SCOPE_UNBOUNDED = "root_scope_unbounded"
RULE_BAD_SIGNATURE = "signature"
RULE_EXPIRED = "expiry"
RULE_CONTINUITY = "continuity"
RULE_FINAL_DELEGATE = "final_delegate"
RULE_SCOPE_INTERSECTION = "scope_intersection"


def now_rfc3339() -> str:
    """Delegation-link `expires` format: RFC3339 UTC, NO fractional
    seconds — matches Go's bare time.RFC3339 parse/format used by
    delegation.go, distinct from envelope/index's millisecond form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(s: str) -> datetime:
    # Accept a trailing "Z" and, defensively, a fractional-second form
    # (Go's time.Parse(time.RFC3339, ...) also accepts fractional seconds
    # on parse even though it never emits them) or a numeric UTC offset.
    s2 = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s2)


@dataclass
class Scope:
    to: str | None = None
    kinds: list[str] | None = None
    body_types: list[str] | None = None

    def is_entirely_unscoped_to(self) -> bool:
        return self.to is None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.to is not None:
            d["to"] = self.to
        if self.kinds:
            d["kinds"] = list(self.kinds)
        if self.body_types:
            d["body_types"] = list(self.body_types)
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Scope":
        return Scope(to=d.get("to"), kinds=d.get("kinds"), body_types=d.get("body_types"))


@dataclass
class Link:
    delegator: str
    delegate: str
    scope: Scope
    expires: str
    nonce: str
    sig: identity.Sig | None = None

    def to_dict(self, *, with_sig: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "delegator": self.delegator,
            "delegate": self.delegate,
            "scope": self.scope.to_dict(),
            "expires": self.expires,
            "nonce": self.nonce,
        }
        if with_sig and self.sig is not None:
            d["sig"] = self.sig.to_dict()
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Link":
        return Link(
            delegator=d["delegator"], delegate=d["delegate"],
            scope=Scope.from_dict(d.get("scope") or {}),
            expires=d["expires"], nonce=d["nonce"],
            sig=identity.Sig.from_dict(d["sig"]) if d.get("sig") else None,
        )

    def sign(self, priv: Ed25519PrivateKey, kid: str) -> None:
        self.sig = identity.sign(self.to_dict(with_sig=False), priv, kid)

    def verify(self, pub: Ed25519PublicKey) -> None:
        identity.verify_sig(self.to_dict(with_sig=False), self.sig, pub)


class RuleViolation(Exception):
    def __init__(self, rule: str, link_index: int, detail: str) -> None:
        self.rule = rule
        self.link_index = link_index
        self.detail = detail
        if link_index < 0:
            msg = f"delegation: rule {rule!r} violated: {detail}"
        else:
            msg = f"delegation: rule {rule!r} violated at link {link_index}: {detail}"
        super().__init__(msg)


KeyResolver = Callable[[str, str], Ed25519PublicKey]


@dataclass
class VerifyInput:
    chain: list[Link]
    from_: str
    to: str
    kind: str
    body_type: str
    now: float  # unix seconds
    resolve_key: KeyResolver


def _decode_ulid_time(nonce: str) -> float:
    from ulid import ULID

    u = ULID.from_str(nonce.upper())
    return u.timestamp  # unix seconds, float


def _root_scope_bound(root: Link) -> None:
    if not root.scope.is_entirely_unscoped_to():
        return
    try:
        nonce_ts = _decode_ulid_time(root.nonce)
    except Exception as e:
        raise RuleViolation(
            RULE_ROOT_SCOPE_UNBOUNDED, 0,
            "root link has no `to` scope and nonce is not a valid ULID: " + str(e),
        ) from e
    try:
        expires_dt = parse_rfc3339(root.expires)
    except Exception as e:
        raise RuleViolation(
            RULE_ROOT_SCOPE_UNBOUNDED, 0,
            "root link has no `to` scope and expires is not valid RFC3339: " + str(e),
        ) from e
    expires_ts = expires_dt.timestamp()
    if expires_ts - nonce_ts > 24 * 3600:
        raise RuleViolation(
            RULE_ROOT_SCOPE_UNBOUNDED, 0,
            "root link has no `to` scope and expires > 24h after issuance",
        )


def _verify_link_signature(resolve: KeyResolver, link: Link, index: int) -> None:
    if link.sig is None:
        raise RuleViolation(RULE_BAD_SIGNATURE, index, "missing sig")
    try:
        pub = resolve(identity.domain_of(link.delegator), link.sig.kid)
    except Exception as e:
        raise RuleViolation(RULE_BAD_SIGNATURE, index, "resolve delegator key: " + str(e)) from e
    try:
        identity.verify_sig(link.to_dict(with_sig=False), link.sig, pub)
    except Exception as e:
        raise RuleViolation(RULE_BAD_SIGNATURE, index, str(e)) from e


def _verify_link_unexpired(link: Link, now: float, index: int) -> None:
    try:
        expires_dt = parse_rfc3339(link.expires)
    except Exception as e:
        raise RuleViolation(RULE_EXPIRED, index, "expires is not valid RFC3339: " + str(e)) from e
    if now > expires_dt.timestamp():
        raise RuleViolation(RULE_EXPIRED, index, "link expired")


def _verify_scope_intersection(chain: list[Link], to: str, kind: str, body_type: str) -> None:
    for i, link in enumerate(chain):
        if link.scope.to is not None and link.scope.to != to:
            raise RuleViolation(
                RULE_SCOPE_INTERSECTION, i,
                f"scope.to {link.scope.to!r} excludes envelope to {to!r}",
            )
        if link.scope.kinds and kind not in link.scope.kinds:
            raise RuleViolation(
                RULE_SCOPE_INTERSECTION, i,
                f"scope.kinds {link.scope.kinds!r} excludes envelope kind {kind!r}",
            )
        if link.scope.body_types and body_type not in link.scope.body_types:
            raise RuleViolation(
                RULE_SCOPE_INTERSECTION, i,
                f"scope.body_types {link.scope.body_types!r} excludes envelope body type {body_type!r}",
            )


def verify(inp: VerifyInput) -> None:
    """Runs every core §2.5 validity rule against the chain, short-
    circuiting on the first violation and identifying it specifically. An
    empty chain is not itself a violation — it means no delegation is
    being asserted; callers only invoke this when the envelope/call claims
    delegated authority."""
    if not inp.chain:
        return
    if len(inp.chain) > MAX_CHAIN_LENGTH:
        raise RuleViolation(
            RULE_CHAIN_TOO_LONG, -1,
            f"chain has {len(inp.chain)} links, max {MAX_CHAIN_LENGTH}",
        )

    _root_scope_bound(inp.chain[0])

    for i, link in enumerate(inp.chain):
        _verify_link_signature(inp.resolve_key, link, i)
        _verify_link_unexpired(link, inp.now, i)
        if i > 0 and inp.chain[i - 1].delegate != link.delegator:
            raise RuleViolation(
                RULE_CONTINUITY, i,
                f"link {i - 1} delegate {inp.chain[i - 1].delegate!r} != link {i} delegator {link.delegator!r}",
            )

    last = inp.chain[-1]
    if last.delegate != inp.from_:
        raise RuleViolation(
            RULE_FINAL_DELEGATE, len(inp.chain) - 1,
            f"final delegate {last.delegate!r} != envelope from {inp.from_!r}",
        )

    _verify_scope_intersection(inp.chain, inp.to, inp.kind, inp.body_type)
