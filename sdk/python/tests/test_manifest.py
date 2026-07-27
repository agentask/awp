from __future__ import annotations

import json

import pytest

from awp import identity, manifest


def make_manifest(**overrides) -> manifest.Manifest:
    defaults = dict(
        name="tool.local#doubler", kind="tool", version="1.0.0",
        updated=identity.now_rfc3339_milli(), description="doubles a number",
        io=manifest.IOSchema(), distribution=manifest.Distribution(hosted=manifest.Hosted(endpoint="https://tool.local/awp/tools/doubler")),
        state="stateless", auth=manifest.Auth(sig="required"),
    )
    defaults.update(overrides)
    return manifest.Manifest(**defaults)


def test_sign_verify_round_trip() -> None:
    priv, pub = identity.generate_keypair()
    m = make_manifest()
    m.sign(priv, "k1")
    m.verify(pub)


def test_pricing_and_inbox_always_present_null() -> None:
    m = make_manifest()
    d = m.to_dict(with_sig=False)
    assert "pricing" in d and d["pricing"] is None
    assert "inbox" in d and d["inbox"] is None


def test_pin_check_before_parse() -> None:
    priv, pub = identity.generate_keypair()
    m = make_manifest()
    m.sign(priv, "k1")
    raw = json.dumps(m.to_dict()).encode("utf-8")

    import hashlib

    correct_hash = hashlib.sha256(raw).hexdigest()
    manifest.verify_pinned_sha256(raw, correct_hash)

    with pytest.raises(manifest.PinMismatchError):
        manifest.verify_pinned_sha256(raw, "0" * 64)


def test_swapped_manifest_fails_pin_not_signature() -> None:
    """A swapped manifest must fail the pin check, not the signature
    check (core §1.2) -- verify_pinned_sha256 must be callable, and
    reject, on raw bytes alone, before any JSON parsing happens."""
    priv, pub = identity.generate_keypair()
    real = make_manifest()
    real.sign(priv, "k1")
    real_raw = json.dumps(real.to_dict()).encode("utf-8")

    import hashlib

    pinned_hash = hashlib.sha256(real_raw).hexdigest()

    swapped = make_manifest(name="tool.local#evil")
    swapped.sign(priv, "k1")
    swapped_raw = json.dumps(swapped.to_dict()).encode("utf-8")

    with pytest.raises(manifest.PinMismatchError):
        manifest.verify_pinned_sha256(swapped_raw, pinned_hash)


def test_json_round_trip_preserves_signature() -> None:
    priv, pub = identity.generate_keypair()
    m = make_manifest()
    m.sign(priv, "k1")
    raw = json.dumps(m.to_dict())
    m2 = manifest.Manifest.from_dict(json.loads(raw))
    m2.verify(pub)
