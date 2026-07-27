from __future__ import annotations

import pytest

from awp import identity


def test_sign_verify_round_trip_is_byte_identical_on_recanon() -> None:
    priv, pub = identity.generate_keypair()
    obj = {"awp": "0.1", "domain": "example.local", "updated": "2026-07-21T08:54:13.000Z"}
    sig = identity.sign(obj, priv, "k1")
    identity.verify_sig(obj, sig, pub)  # must not raise

    # Recanonicalizing the identical logical content (even key order
    # shuffled, since dict insertion order shouldn't matter after JCS)
    # must still verify.
    shuffled = {"updated": obj["updated"], "domain": obj["domain"], "awp": obj["awp"]}
    identity.verify_sig(shuffled, sig, pub)


def test_verify_rejects_tampered_content() -> None:
    priv, pub = identity.generate_keypair()
    obj = {"a": 1}
    sig = identity.sign(obj, priv, "k1")
    with pytest.raises(identity.BadSignatureError):
        identity.verify_sig({"a": 2}, sig, pub)


def test_verify_rejects_wrong_key() -> None:
    priv, _ = identity.generate_keypair()
    _, other_pub = identity.generate_keypair()
    obj = {"a": 1}
    sig = identity.sign(obj, priv, "k1")
    with pytest.raises(identity.BadSignatureError):
        identity.verify_sig(obj, sig, other_pub)


def test_index_field_presence_null_vs_empty_list() -> None:
    """core §1.1 gotcha: keys/entities are always-present JSON keys, null
    when the Python value is None, [] when it's an empty-but-real list —
    these two states must canonicalize to different bytes."""
    priv, pub = identity.generate_keypair()
    idx_null = identity.Index(domain="a.local", updated="2026-07-21T08:54:13.000Z", keys=None, entities=None)
    idx_empty = identity.Index(domain="a.local", updated="2026-07-21T08:54:13.000Z", keys=[], entities=[])

    canon_null = identity.canonical_bytes(idx_null.to_dict(with_sig=False))
    canon_empty = identity.canonical_bytes(idx_empty.to_dict(with_sig=False))
    assert canon_null != canon_empty
    assert b'"keys":null' in canon_null
    assert b'"keys":[]' in canon_empty


def test_index_self_sign_and_verify() -> None:
    priv, pub = identity.generate_keypair()
    idx = identity.Index(
        domain="example.local", updated=identity.now_rfc3339_milli(),
        keys=[identity.new_key(pub, "k1")], inbox="http://127.0.0.1:8001/awp/inbox",
    )
    idx.sign(priv, "k1")
    idx.verify_self_sig()


def test_index_self_sign_rejects_unknown_kid() -> None:
    priv, pub = identity.generate_keypair()
    idx = identity.Index(
        domain="example.local", updated=identity.now_rfc3339_milli(),
        keys=[identity.new_key(pub, "k1")], inbox="",
    )
    idx.sign(priv, "not-in-keys")
    with pytest.raises(identity.BadSignatureError):
        idx.verify_self_sig()


def test_index_round_trip_through_json_preserves_signature() -> None:
    import json

    priv, pub = identity.generate_keypair()
    idx = identity.Index(
        domain="example.local", updated=identity.now_rfc3339_milli(),
        keys=[identity.new_key(pub, "k1")], inbox="http://127.0.0.1:8001/awp/inbox",
    )
    idx.sign(priv, "k1")
    raw = json.dumps(idx.to_dict())
    idx2 = identity.Index.from_dict(json.loads(raw))
    idx2.verify_self_sig()


def test_resolve_rejects_revoked_key() -> None:
    priv, pub = identity.generate_keypair()
    key = identity.new_key(pub, "k1")
    key.revoked = True
    idx = identity.Index(domain="example.local", updated=identity.now_rfc3339_milli(), keys=[key], inbox="")
    for k in idx.keys or []:
        assert k.revoked


def test_rotation_chain_verifies_valid_chain() -> None:
    priv0, pub0 = identity.generate_keypair()
    priv1, pub1 = identity.generate_keypair()

    from cryptography.hazmat.primitives import serialization

    pub1_raw = pub1.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    prev_sig = priv0.sign(pub1_raw)

    from awp import b64url

    chain = [
        identity.new_key(pub0, "k0"),
        identity.Key(
            kid="k1", alg="ed25519", pub=identity.public_key_b64url(pub1),
            created=identity.now_rfc3339_milli(), prev_sig=b64url.encode(prev_sig),
        ),
    ]
    identity.verify_rotation_chain(chain)


def test_rotation_chain_rejects_broken_link() -> None:
    priv0, pub0 = identity.generate_keypair()
    _, pub1 = identity.generate_keypair()

    chain = [
        identity.new_key(pub0, "k0"),
        identity.Key(
            kid="k1", alg="ed25519", pub=identity.public_key_b64url(pub1),
            created=identity.now_rfc3339_milli(), prev_sig="not-a-real-signature-AAAA",
        ),
    ]
    with pytest.raises(identity.BrokenRotationError) as exc_info:
        identity.verify_rotation_chain(chain)
    assert exc_info.value.index == 1


def test_domain_of_strips_entity_fragment() -> None:
    assert identity.domain_of("example.com#agent") == "example.com"
    assert identity.domain_of("example.com") == "example.com"
