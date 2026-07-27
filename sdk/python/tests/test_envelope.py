from __future__ import annotations

import json

import pytest

from awp import envelope, identity


def make_envelope(**overrides) -> envelope.Envelope:
    defaults = dict(
        id=envelope.new_id(), kind="message", from_="a.local", to="b.local#agent",
        thread=envelope.new_id(), ts=identity.now_rfc3339_milli(), ttl=3600, body={"text": "hi"},
    )
    defaults.update(overrides)
    return envelope.Envelope(**defaults)


def test_sign_verify_round_trip() -> None:
    priv, pub = identity.generate_keypair()
    e = make_envelope()
    e.sign(priv, "k1")
    e.verify(pub)


def test_always_present_null_fields() -> None:
    """core §2.1: in_reply_to/session/delegation are always-present JSON
    keys, null when unset -- never omitted."""
    e = make_envelope()
    d = e.to_dict(with_sig=False)
    assert "in_reply_to" in d and d["in_reply_to"] is None
    assert "session" in d and d["session"] is None
    assert "delegation" in d and d["delegation"] is None


def test_ttl_bounds() -> None:
    e = make_envelope(ttl=59)
    with pytest.raises(envelope.TTLOutOfBoundsError):
        e.validate_ttl()
    e2 = make_envelope(ttl=604801)
    with pytest.raises(envelope.TTLOutOfBoundsError):
        e2.validate_ttl()
    e3 = make_envelope(ttl=60)
    e3.validate_ttl()
    e4 = make_envelope(ttl=604800)
    e4.validate_ttl()


def test_size_validation() -> None:
    e = make_envelope(body={"x": "a" * (300 * 1024)})
    priv, _ = identity.generate_keypair()
    e.sign(priv, "k1")
    with pytest.raises(envelope.TooLargeError):
        e.validate_size()


def test_id_and_thread_are_lowercase_ulids() -> None:
    e = make_envelope()
    assert e.id == e.id.lower()
    assert len(e.id) == 26
    assert e.thread == e.thread.lower()


def test_verify_fails_without_sig() -> None:
    _, pub = identity.generate_keypair()
    e = make_envelope()
    with pytest.raises(identity.BadSignatureError):
        e.verify(pub)


def test_json_round_trip_preserves_signature() -> None:
    priv, pub = identity.generate_keypair()
    e = make_envelope()
    e.sign(priv, "k1")
    raw = json.dumps(e.to_dict())
    e2 = envelope.Envelope.from_dict(json.loads(raw))
    e2.verify(pub)


def test_signature_covers_from_field_tamper() -> None:
    priv, pub = identity.generate_keypair()
    e = make_envelope()
    e.sign(priv, "k1")
    e.from_ = "attacker.local"
    with pytest.raises(identity.BadSignatureError):
        e.verify(pub)
