from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from awp import delegation, envelope, identity


def _default_expires() -> str:
    return delegation.format_rfc3339(datetime.now(timezone.utc) + timedelta(hours=1))


def make_signed_link(priv, kid, *, delegator, delegate, scope=None, expires=None, nonce=None) -> delegation.Link:
    link = delegation.Link(
        delegator=delegator, delegate=delegate, scope=scope or delegation.Scope(),
        expires=expires or _default_expires(), nonce=nonce or envelope.new_id(),
    )
    link.sign(priv, kid)
    return link


def resolver_for(*pairs):
    keys = {(domain, kid): pub for domain, kid, pub in pairs}

    def resolve(domain: str, kid: str):
        return keys[(domain, kid)]

    return resolve


def test_empty_chain_is_not_a_violation() -> None:
    delegation.verify(delegation.VerifyInput(
        chain=[], from_="a.local", to="b.local", kind="message", body_type="",
        now=time.time(), resolve_key=resolver_for(),
    ))


def test_chain_too_long() -> None:
    priv, pub = identity.generate_keypair()
    to = "provider.local#tool"
    chain = []
    delegator = "root.local"
    for i in range(9):
        delegate = f"link{i}.local"
        chain.append(make_signed_link(
            priv, "k1", delegator=delegator, delegate=delegate,
            scope=delegation.Scope(to=to),
        ))
        delegator = delegate
    resolve = resolver_for(*[(identity.domain_of(l.delegator), "k1", pub) for l in chain])
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=chain, from_=delegator, to=to, kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_CHAIN_TOO_LONG


def test_root_scope_unbounded_rejects_long_lived_unscoped_root() -> None:
    priv, pub = identity.generate_keypair()
    nonce = envelope.new_id()
    far_future = datetime.now(timezone.utc) + timedelta(days=2)
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(), expires=delegation.format_rfc3339(far_future), nonce=nonce,
    )
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="x.local", kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_ROOT_SCOPE_UNBOUNDED


def test_root_scope_unbounded_accepts_short_lived_unscoped_root() -> None:
    priv, pub = identity.generate_keypair()
    nonce = envelope.new_id()
    soon = datetime.now(timezone.utc) + timedelta(hours=1)
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(), expires=delegation.format_rfc3339(soon), nonce=nonce,
    )
    resolve = resolver_for(("root.local", "k1", pub))
    delegation.verify(delegation.VerifyInput(
        chain=[link], from_="agent.local", to="x.local", kind="message", body_type="",
        now=time.time(), resolve_key=resolve,
    ))


def test_root_scope_bound_not_required_when_scoped_to() -> None:
    priv, pub = identity.generate_keypair()
    far_future = datetime.now(timezone.utc) + timedelta(days=30)
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(to="x.local"), expires=delegation.format_rfc3339(far_future),
    )
    resolve = resolver_for(("root.local", "k1", pub))
    delegation.verify(delegation.VerifyInput(
        chain=[link], from_="agent.local", to="x.local", kind="message", body_type="",
        now=time.time(), resolve_key=resolve,
    ))


def test_bad_signature_rejected() -> None:
    priv, pub = identity.generate_keypair()
    _, other_pub = identity.generate_keypair()
    link = make_signed_link(priv, "k1", delegator="root.local", delegate="agent.local", scope=delegation.Scope(to="x.local"))
    resolve = resolver_for(("root.local", "k1", other_pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="x.local", kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_BAD_SIGNATURE


def test_expired_link_rejected() -> None:
    priv, pub = identity.generate_keypair()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(to="x.local"), expires=delegation.format_rfc3339(past),
    )
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="x.local", kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_EXPIRED


def test_continuity_violation() -> None:
    priv, pub = identity.generate_keypair()
    to = "x.local"
    link0 = make_signed_link(priv, "k1", delegator="root.local", delegate="middle.local", scope=delegation.Scope(to=to))
    link1 = make_signed_link(priv, "k1", delegator="someone-else.local", delegate="final.local", scope=delegation.Scope(to=to))
    resolve = resolver_for(("root.local", "k1", pub), ("someone-else.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link0, link1], from_="final.local", to=to, kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_CONTINUITY
    assert exc.value.link_index == 1


def test_final_delegate_violation() -> None:
    priv, pub = identity.generate_keypair()
    to = "x.local"
    link = make_signed_link(priv, "k1", delegator="root.local", delegate="agent.local", scope=delegation.Scope(to=to))
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="someone-else.local", to=to, kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_FINAL_DELEGATE


def test_scope_intersection_to_violation() -> None:
    priv, pub = identity.generate_keypair()
    link = make_signed_link(priv, "k1", delegator="root.local", delegate="agent.local", scope=delegation.Scope(to="x.local"))
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="y.local", kind="message", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_SCOPE_INTERSECTION


def test_scope_intersection_kinds_violation() -> None:
    priv, pub = identity.generate_keypair()
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(to="x.local", kinds=["message"]),
    )
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="x.local", kind="reply", body_type="",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_SCOPE_INTERSECTION


def test_scope_intersection_body_types_violation() -> None:
    priv, pub = identity.generate_keypair()
    link = make_signed_link(
        priv, "k1", delegator="root.local", delegate="agent.local",
        scope=delegation.Scope(to="x.local", body_types=["text"]),
    )
    resolve = resolver_for(("root.local", "k1", pub))
    with pytest.raises(delegation.RuleViolation) as exc:
        delegation.verify(delegation.VerifyInput(
            chain=[link], from_="agent.local", to="x.local", kind="message", body_type="json",
            now=time.time(), resolve_key=resolve,
        ))
    assert exc.value.rule == delegation.RULE_SCOPE_INTERSECTION


def test_valid_two_link_chain_passes() -> None:
    priv_root, pub_root = identity.generate_keypair()
    priv_relay, pub_relay = identity.generate_keypair()
    to = "provider.local#tool"

    link0 = make_signed_link(priv_root, "k1", delegator="user-root.local", delegate="assistant.local#relay", scope=delegation.Scope(to=to))
    link1 = make_signed_link(priv_relay, "rk1", delegator="assistant.local#relay", delegate="assistant.local", scope=delegation.Scope())

    resolve = resolver_for(
        ("user-root.local", "k1", pub_root),
        (identity.domain_of("assistant.local#relay"), "rk1", pub_relay),
    )
    delegation.verify(delegation.VerifyInput(
        chain=[link0, link1], from_="assistant.local", to=to, kind="message", body_type="",
        now=time.time(), resolve_key=resolve,
    ))


def test_expires_has_no_fractional_seconds() -> None:
    """Gotcha from the porting spec: delegation Link.expires MUST be
    formatted without fractional seconds, unlike envelope/index
    timestamps -- confirms format_rfc3339/now_rfc3339 comply."""
    s = delegation.now_rfc3339()
    assert s.endswith("Z")
    assert "." not in s
