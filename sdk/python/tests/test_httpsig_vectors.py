"""Every httpsig conformance vector in testdata/awp-sig/*.json, ground-
truthed against the real Go implementation at generation time — see
awp-porting-spec.md §3.8. Verify-side assertions use the fixture's own
already-signed values, never our own signer's output, so a verify bug
can't be masked by a matching sign bug.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from awp import b64url, httpsig

from .conftest import load_vector


class StaticKeyResolver:
    def __init__(self, keys: dict[tuple[str, str], Ed25519PublicKey]) -> None:
        self.keys = keys
        self.refresh_calls: list[str] = []

    def resolve(self, domain: str, kid: str) -> Ed25519PublicKey:
        try:
            return self.keys[(domain, kid)]
        except KeyError as e:
            raise KeyError(f"no key for {domain}/{kid}") from e

    def refresh(self, domain: str) -> None:
        self.refresh_calls.append(domain)


REQUEST_SUCCESS_VECTORS = [
    "bodyless-get",
    "post-with-body",
    "post-with-session",
    "post-with-delegation-2link",
]

REQUEST_FAILURE_VECTORS = [
    "failure-step1-missing-signature-input",
    "failure-step1-unknown-label",
    "failure-step1-forbidden-param",
    "failure-step1-missing-component",
    "failure-step2-created-outside-window",
    "failure-step3-digest-mismatch",
    "failure-step4-unknown-key",
    "failure-step5-bad-signature",
    "failure-step6-delegation-invalid",
    "failure-step7-session-invalid",
]

RESPONSE_SUCCESS_VECTORS = ["response-signed"]
RESPONSE_FAILURE_VECTORS = ["response-tampered-signature"]


def _verify_at_unix(vec: dict) -> float:
    dt = datetime.fromisoformat(vec["verify_at"].replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc).timestamp()


def _build_deps_for_request(vec: dict) -> httpsig.VerifyDeps:
    keys: dict[tuple[str, str], Ed25519PublicKey] = {}
    if vec.get("public_key_b64url"):
        pub = Ed25519PublicKey.from_public_bytes(b64url.decode(vec["public_key_b64url"]))
        keys[(vec["domain"], vec["kid"])] = pub
    for tk in vec.get("trusted_keys", []):
        pub = Ed25519PublicKey.from_public_bytes(b64url.decode(tk["pub_b64url"]))
        keys[(tk["domain"], tk["kid"])] = pub

    resolver = StaticKeyResolver(keys)

    verify_session = None
    if vec["name"] == "post-with-session":
        verify_session = lambda token, caller: None
    elif vec["name"] == "failure-step7-session-invalid":
        def verify_session(token: str, caller: str) -> None:
            raise ValueError("session rejected by provider")

    return httpsig.VerifyDeps(
        resolve_key=resolver,
        target=vec.get("delegation_target", ""),
        verify_session=verify_session,
    )


def _headers_from_vector(vec: dict) -> dict[str, str]:
    headers = dict(vec.get("extra_headers", {}))
    headers["Signature-Input"] = vec["signature_input"]
    headers["Signature"] = vec["signature"]
    if vec.get("content_digest"):
        headers["Content-Digest"] = vec["content_digest"]
    return headers


def _body_bytes(vec: dict) -> bytes:
    if vec.get("body_b64url") is None:
        return b""
    return b64url.decode(vec["body_b64url"])


@pytest.mark.parametrize("name", REQUEST_SUCCESS_VECTORS)
def test_request_vector_verifies(name: str) -> None:
    vec = load_vector(name)
    headers = _headers_from_vector(vec)
    body = _body_bytes(vec)
    deps = _build_deps_for_request(vec)

    result = httpsig.verify_request(
        method=vec["method"], url=vec["target_uri"], headers=headers, body=body,
        now=_verify_at_unix(vec), deps=deps,
    )
    assert result.err is None, f"{name}: expected success, got {result.err}"
    assert result.status == 0
    assert result.caller_principal == vec["domain"]


@pytest.mark.parametrize("name", REQUEST_FAILURE_VECTORS)
def test_request_vector_rejects(name: str) -> None:
    vec = load_vector(name)
    headers = _headers_from_vector(vec)
    body = _body_bytes(vec)
    deps = _build_deps_for_request(vec)

    result = httpsig.verify_request(
        method=vec["method"], url=vec["target_uri"], headers=headers, body=body,
        now=_verify_at_unix(vec), deps=deps,
    )
    assert result.err is not None, f"{name}: expected failure"
    assert result.err.code == vec["expect"]["code"], f"{name}: code mismatch"
    assert result.status == vec["expect"]["status"], f"{name}: status mismatch"


@pytest.mark.parametrize("name", RESPONSE_SUCCESS_VECTORS)
def test_response_vector_verifies(name: str) -> None:
    vec = load_vector(name)
    headers = {"Signature-Input": vec["signature_input"], "Signature": vec["signature"]}
    if vec.get("content_digest"):
        headers["Content-Digest"] = vec["content_digest"]
    body = _body_bytes(vec)

    pub = Ed25519PublicKey.from_public_bytes(b64url.decode(vec["public_key_b64url"]))
    resolver = StaticKeyResolver({(vec["domain"], vec["kid"]): pub})

    result = httpsig.verify_response(
        status=vec["status"], headers=headers, body=body,
        now=_verify_at_unix(vec), resolve_key=resolver,
    )
    assert result.err is None, f"{name}: expected success, got {result.err}"
    assert result.signed is True
    assert result.provider_principal == vec["domain"]


@pytest.mark.parametrize("name", RESPONSE_FAILURE_VECTORS)
def test_response_vector_rejects(name: str) -> None:
    vec = load_vector(name)
    headers = {"Signature-Input": vec["signature_input"], "Signature": vec["signature"]}
    if vec.get("content_digest"):
        headers["Content-Digest"] = vec["content_digest"]
    body = _body_bytes(vec)

    pub = Ed25519PublicKey.from_public_bytes(b64url.decode(vec["public_key_b64url"]))
    resolver = StaticKeyResolver({(vec["domain"], vec["kid"]): pub})

    result = httpsig.verify_response(
        status=vec["status"], headers=headers, body=body,
        now=_verify_at_unix(vec), resolve_key=resolver,
    )
    assert result.err is not None, f"{name}: expected failure"
    assert result.err.code == vec["expect"]["code"], f"{name}: code mismatch"


def test_response_absent_signature_is_success_not_failure() -> None:
    """awp-sig §3: a response with no Signature-Input at all is fine
    (SHOULD, not MUST) -- Signed=False, err=None. Distinct from a
    present-but-invalid signature, which must always be an error."""
    resolver = StaticKeyResolver({})
    result = httpsig.verify_response(
        status=200, headers={}, body=b"", now=1753088043, resolve_key=resolver,
    )
    assert result.err is None
    assert result.signed is False


@pytest.mark.parametrize("name", REQUEST_SUCCESS_VECTORS)
def test_sign_request_reproduces_vector_bytes(name: str) -> None:
    """For every success vector, re-sign with our own Sign and confirm we
    produce byte-identical Signature-Input/Signature/Content-Digest,
    proving our signer (not just our verifier) is byte-compatible with
    Go's."""
    vec = load_vector(name)
    priv = Ed25519PrivateKey.from_private_bytes(b64url.decode(vec["private_key_seed_b64url"]))
    body = _body_bytes(vec)
    headers = dict(vec.get("extra_headers", {}))

    signed_headers = httpsig.sign_request(
        method=vec["method"], url=vec["target_uri"], headers=headers, body=body,
        priv=priv, key_id=f"{vec['domain']}/{vec['kid']}", now=vec["created"],
    )

    assert signed_headers["Signature-Input"] == vec["signature_input"]
    assert signed_headers["Signature"] == vec["signature"]
    if vec.get("content_digest"):
        assert signed_headers["Content-Digest"] == vec["content_digest"]


@pytest.mark.parametrize("name", RESPONSE_SUCCESS_VECTORS)
def test_sign_response_reproduces_vector_bytes(name: str) -> None:
    vec = load_vector(name)
    priv = Ed25519PrivateKey.from_private_bytes(b64url.decode(vec["private_key_seed_b64url"]))
    body = _body_bytes(vec)

    signed_headers = httpsig.sign_response(
        status=vec["status"], headers={}, body=body,
        priv=priv, key_id=f"{vec['domain']}/{vec['kid']}", now=vec["created"],
    )

    assert signed_headers["Signature-Input"] == vec["signature_input"]
    assert signed_headers["Signature"] == vec["signature"]
    if vec.get("content_digest"):
        assert signed_headers["Content-Digest"] == vec["content_digest"]


@pytest.mark.parametrize("name", REQUEST_SUCCESS_VECTORS + REQUEST_FAILURE_VECTORS)
def test_signature_base_matches_vector_when_present(name: str) -> None:
    """Independent of the final signature, the vector's own
    signature_base string (when derivable from non-tampered inputs) lets
    us catch a base-construction bug before touching crypto at all."""
    vec = load_vector(name)
    if "signature_base" not in vec:
        pytest.skip("no signature_base in this vector")
    if name in (
        "failure-step3-digest-mismatch",
        "failure-step5-bad-signature",
        "failure-step1-missing-component",
    ):
        pytest.skip("vector's signature_base is a reference/pre-tamper value, not derivable from the actual signature_input")

    headers = dict(vec.get("extra_headers", {}))
    if vec.get("content_digest"):
        headers["Content-Digest"] = vec["content_digest"]

    try:
        parsed = httpsig.parse_signature_input(vec["signature_input"])
    except Exception:
        pytest.skip("vector's signature_input is deliberately malformed")
        return

    base = httpsig._signature_base(
        parsed.params.components,
        lambda c: httpsig._request_component_value(vec["method"], vec["target_uri"], headers, c),
        parsed.raw_value,
    )
    assert base == vec["signature_base"]
