"""awp-sig-v0.1.md's sync signing profile: a minimal, hand-rolled RFC 9421
subset. This subset IS the spec — anything outside it MUST be rejected, no
negotiation, no algorithm agility — so this module is deliberately narrow
rather than a general-purpose HTTP-message-signatures library. Python
counterpart to internal/httpsig (Go).
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import apperr, b64url, delegation

LABEL = "awp"

DERIVED_METHOD = "@method"
DERIVED_TARGET_URI = "@target-uri"
DERIVED_STATUS = "@status"
COMPONENT_DIGEST = "content-digest"

CREATED_WINDOW_SECONDS = 300


class MalformedSignatureInputError(Exception):
    pass


class ForbiddenParamError(Exception):
    pass


class DigestMismatchError(Exception):
    pass


def compute_content_digest(body: bytes) -> str:
    """RFC 9530 sha-256 Content-Digest header value:
    "sha-256=:<STANDARD, PADDED base64 of the raw digest bytes>:" — this is
    standard base64 with padding (base64.StdEncoding on the Go side), NOT
    base64url/unpadded like signatures and pubkeys. Do not conflate the two
    codecs used in this module."""
    digest = hashlib.sha256(body).digest()
    return "sha-256=:" + base64.b64encode(digest).decode("ascii") + ":"


def verify_content_digest(header: str, body: bytes) -> None:
    want = compute_content_digest(body)
    if header != want:
        raise DigestMismatchError(f"httpsig: content-digest mismatch: got {header!r}, want {want!r}")


def covered_components(has_body: bool, header_names: list[str]) -> list[str]:
    """awp-sig §1.1: @method, @target-uri, content-digest (iff has_body),
    then every AWP-* header currently present, lowercased, alphabetical."""
    components = [DERIVED_METHOD, DERIVED_TARGET_URI]
    if has_body:
        components.append(COMPONENT_DIGEST)
    awp_headers = sorted({name.lower() for name in header_names if name.lower().startswith("awp-")})
    components.extend(awp_headers)
    return components


@dataclass
class Params:
    components: list[str]
    created: int
    keyid: str
    alg: str

    def serialize_value(self) -> str:
        """Renders the params WITHOUT the "awp=" label — exactly what RFC
        9421 §2.5's "@signature-params" line wants."""
        comp_list = " ".join(f'"{c}"' for c in self.components)
        return f'({comp_list});created={self.created};keyid="{self.keyid}";alg="{self.alg}"'

    def header_value(self) -> str:
        return f"{LABEL}={self.serialize_value()}"


def _signature_base(
    components: list[str],
    value_fn: Callable[[str], str | None],
    raw_params_value: str,
) -> str:
    lines = []
    for c in components:
        v = value_fn(c)
        if v is None:
            raise MalformedSignatureInputError(f"httpsig: missing value for covered component {c!r}")
        lines.append(f'"{c}": {v}\n')
    lines.append(f'"@signature-params": {raw_params_value}')
    return "".join(lines)


class Request(Protocol):
    method: str
    url: str
    headers: dict[str, str]  # case-sensitive storage; lookups done case-insensitively by helpers


def _header_get(headers: dict[str, str], name: str) -> str | None:
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return None


def _request_component_value(method: str, url: str, headers: dict[str, str], component: str) -> str | None:
    if component == DERIVED_METHOD:
        return method
    if component == DERIVED_TARGET_URI:
        return url
    return _header_get(headers, component)


def _response_component_value(status: int, headers: dict[str, str], component: str) -> str | None:
    if component == DERIVED_STATUS:
        return str(status)
    return _header_get(headers, component)


def sign_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    priv: Ed25519PrivateKey,
    key_id: str,
    now: float | None = None,
) -> dict[str, str]:
    """Signs a request per awp-sig §1: computes Content-Digest if body is
    non-empty, determines the covered-component list from whatever
    AWP-* headers are ALREADY present in `headers`, and returns the
    Signature-Input/Signature (and, if applicable, Content-Digest) headers
    to merge into the caller's request. Any AWP-Session/AWP-Delegation
    headers the caller wants covered MUST already be present in `headers`
    when this is called — covered components are read from what's there,
    not supplied separately."""
    now = time.time() if now is None else now
    has_body = len(body) > 0
    out_headers = dict(headers)
    if has_body:
        out_headers["Content-Digest"] = compute_content_digest(body)

    components = covered_components(has_body, list(out_headers.keys()))
    params = Params(components=components, created=int(now), keyid=key_id, alg="ed25519")

    base = _signature_base(
        components,
        lambda c: _request_component_value(method, url, out_headers, c),
        params.serialize_value(),
    )
    sig = priv.sign(base.encode("utf-8"))
    out_headers["Signature-Input"] = params.header_value()
    out_headers["Signature"] = f"{LABEL}=:{b64url.encode(sig)}:"
    return out_headers


def sign_response(
    *,
    status: int,
    headers: dict[str, str],
    body: bytes,
    priv: Ed25519PrivateKey,
    key_id: str,
    now: float | None = None,
) -> dict[str, str]:
    """Signs a response per awp-sig §3: @status, content-digest iff body
    non-empty, keyid from the provider's own domain."""
    now = time.time() if now is None else now
    has_body = len(body) > 0
    out_headers = dict(headers)
    if has_body:
        out_headers["Content-Digest"] = compute_content_digest(body)

    components = [DERIVED_STATUS]
    if has_body:
        components.append(COMPONENT_DIGEST)
    params = Params(components=components, created=int(now), keyid=key_id, alg="ed25519")

    base = _signature_base(
        components,
        lambda c: _response_component_value(status, out_headers, c),
        params.serialize_value(),
    )
    sig = priv.sign(base.encode("utf-8"))
    out_headers["Signature-Input"] = params.header_value()
    out_headers["Signature"] = f"{LABEL}=:{b64url.encode(sig)}:"
    return out_headers


@dataclass
class ParsedSignatureInput:
    params: Params
    raw_value: str  # exact substring after "awp=" — MUST be reused verbatim on verify


_LABEL_RE = re.compile(r"^awp=(\(.*)$")
_COMP_LIST_RE = re.compile(
    r'^\((?P<components>(?:"[^"]*"(?: "[^"]*")*)?)\)(?P<params>(?:;[a-zA-Z]+=(?:"[^"]*"|-?[0-9]+))*)$'
)


def parse_signature_input(header: str) -> ParsedSignatureInput:
    """Parses a Signature-Input header, accepting only the exact awp-sig
    §1 grammar: label "awp", REQUIRED created/keyid/alg, no other params.
    Anything else — unknown label, missing/extra component, forbidden
    param, or unparseable bytes — is rejected."""
    m = _LABEL_RE.match(header)
    if not m:
        raise MalformedSignatureInputError("httpsig: unknown label or bad syntax")
    raw_value = m.group(1)

    cm = _COMP_LIST_RE.match(raw_value)
    if not cm:
        raise MalformedSignatureInputError("httpsig: bad component-list or param syntax")
    components_part = cm.group("components")
    params_part = cm.group("params")

    components: list[str] = []
    if components_part:
        for tok in components_part.split(" "):
            components.append(tok.strip('"'))

    created: int | None = None
    keyid: str | None = None
    alg: str | None = None
    seen: set[str] = set()
    for kv in params_part.split(";"):
        if kv == "":
            continue
        if "=" not in kv:
            raise MalformedSignatureInputError(f"httpsig: bad param {kv!r}")
        key, val = kv.split("=", 1)
        seen.add(key)
        if key == "created":
            try:
                created = int(val)
            except ValueError as e:
                raise MalformedSignatureInputError(f"httpsig: bad created value: {e}") from e
        elif key == "keyid":
            keyid = val.strip('"')
        elif key == "alg":
            alg = val.strip('"')
        elif key in ("expires", "nonce", "tag"):
            raise ForbiddenParamError(f"httpsig: forbidden signature parameter present: {key!r}")
        else:
            raise MalformedSignatureInputError(f"httpsig: unknown param {key!r}")

    if not ({"created", "keyid", "alg"} <= seen):
        raise MalformedSignatureInputError("httpsig: missing a required param (created/keyid/alg)")

    params = Params(components=components, created=created or 0, keyid=keyid or "", alg=alg or "")
    return ParsedSignatureInput(params=params, raw_value=raw_value)


_SIGNATURE_RE = re.compile(r"^awp=:([A-Za-z0-9_-]+):$")


def parse_signature(header: str) -> str:
    m = _SIGNATURE_RE.match(header)
    if not m:
        raise MalformedSignatureInputError("httpsig: bad Signature header syntax")
    return m.group(1)


class KeyResolver(Protocol):
    def resolve(self, domain: str, kid: str) -> Ed25519PublicKey: ...
    def refresh(self, domain: str) -> None: ...


SessionVerifier = Callable[[str, str], None]


@dataclass
class VerifyDeps:
    resolve_key: KeyResolver
    target: str = ""
    verify_session: SessionVerifier | None = None


@dataclass
class VerifyResult:
    status: int
    err: apperr.Error | None
    caller_principal: str = ""
    delegation: list[delegation.Link] | None = None
    has_session: bool = False


def _reject(status: int, code: str, detail: str) -> VerifyResult:
    return VerifyResult(status=status, err=apperr.Error(code=code, detail=detail, retryable=False))


def verify_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    now: float,
    deps: VerifyDeps,
) -> VerifyResult:
    """Runs the awp-sig §2 algorithm. `url` MUST already be absolute
    (scheme+host+path+query) — reconstruct it from your server framework's
    request object before calling this if the framework strips
    scheme/host, matching Go's AbsolutizeServerRequestURL gotcha."""
    sig_input_header = _header_get(headers, "Signature-Input")
    if not sig_input_header:
        return _reject(400, apperr.CODE_MALFORMED, "missing Signature-Input")
    try:
        parsed = parse_signature_input(sig_input_header)
    except Exception as e:
        return _reject(400, apperr.CODE_MALFORMED, str(e))
    if parsed.params.alg != "ed25519":
        return _reject(400, apperr.CODE_MALFORMED, 'alg must be "ed25519"')

    has_body = len(body) > 0
    want_components = covered_components(has_body, list(headers.keys()))
    if parsed.params.components != want_components:
        return _reject(400, apperr.CODE_MALFORMED, "covered components do not match this request")

    sig_header = _header_get(headers, "Signature")
    if not sig_header:
        return _reject(400, apperr.CODE_MALFORMED, "missing Signature")
    try:
        sig_b64 = parse_signature(sig_header)
    except Exception as e:
        return _reject(400, apperr.CODE_MALFORMED, str(e))
    try:
        sig_bytes = b64url.decode(sig_b64)
    except Exception:
        return _reject(400, apperr.CODE_MALFORMED, "bad Signature encoding")

    created_at = parsed.params.created
    if abs(now - created_at) > CREATED_WINDOW_SECONDS:
        return _reject(401, apperr.CODE_UNAUTHORIZED, "created outside the ±300s window")

    if has_body:
        digest_header = _header_get(headers, "Content-Digest")
        if not digest_header:
            return _reject(400, apperr.CODE_MALFORMED, "missing Content-Digest for a request with a body")
        try:
            verify_content_digest(digest_header, body)
        except Exception as e:
            return _reject(400, apperr.CODE_MALFORMED, str(e))

    if "/" not in parsed.params.keyid:
        return _reject(400, apperr.CODE_MALFORMED, "keyid must be {domain}/{kid}")
    domain, kid = parsed.params.keyid.split("/", 1)
    try:
        pub = deps.resolve_key.resolve(domain, kid)
    except Exception:
        try:
            deps.resolve_key.refresh(domain)
        except Exception:
            pass
        try:
            pub = deps.resolve_key.resolve(domain, kid)
        except Exception as e:
            return _reject(401, apperr.CODE_UNAUTHORIZED, f"unknown or revoked key: {e}")

    try:
        base = _signature_base(
            parsed.params.components,
            lambda c: _request_component_value(method, url, headers, c),
            parsed.raw_value,
        )
    except Exception as e:
        return _reject(400, apperr.CODE_MALFORMED, str(e))

    try:
        pub.verify(sig_bytes, base.encode("utf-8"))
    except InvalidSignature:
        return _reject(401, apperr.CODE_UNAUTHORIZED, "signature verification failed")

    caller_principal = domain
    result = VerifyResult(status=0, err=None, caller_principal=caller_principal)

    delegation_header = _header_get(headers, "AWP-Delegation")
    if delegation_header:
        try:
            chain = _decode_delegation_chain(delegation_header)
        except Exception as e:
            return _reject(403, apperr.CODE_UNAUTHORIZED_DELEGATION, str(e))
        verify_in = delegation.VerifyInput(
            chain=chain, from_=caller_principal, to=deps.target,
            kind="", body_type="", now=now, resolve_key=deps.resolve_key.resolve,
        )
        try:
            delegation.verify(verify_in)
        except Exception as e:
            return _reject(403, apperr.CODE_UNAUTHORIZED_DELEGATION, str(e))
        result.delegation = chain

    session_header = _header_get(headers, "AWP-Session")
    if session_header:
        if deps.verify_session is None:
            return _reject(401, apperr.CODE_UNAUTHORIZED, "this endpoint does not accept sessions")
        try:
            deps.verify_session(session_header, caller_principal)
        except Exception as e:
            return _reject(401, apperr.CODE_UNAUTHORIZED, f"session invalid: {e}")
        result.has_session = True

    return result


def _decode_delegation_chain(header: str) -> list[delegation.Link]:
    import json

    try:
        raw = b64url.decode(header)
    except Exception as e:
        raise ValueError("bad AWP-Delegation encoding") from e
    try:
        chain_raw = json.loads(raw)
    except Exception as e:
        raise ValueError("bad AWP-Delegation JSON") from e
    return [delegation.Link.from_dict(d) for d in chain_raw]


def encode_delegation_header(chain: list[delegation.Link]) -> str:
    """base64url (no padding) of the JSON array of delegation.Link — the
    raw bytes placed in the AWP-Delegation header. The header value bytes
    at signing time and verification time must be identical strings, so
    callers must set this header BEFORE calling sign_request."""
    import json

    chain_json = json.dumps([l.to_dict() for l in chain], separators=(",", ":")).encode("utf-8")
    return b64url.encode(chain_json)


@dataclass
class VerifyResponseResult:
    err: apperr.Error | None
    provider_principal: str = ""
    signed: bool = False


def _reject_response(code: str, detail: str) -> VerifyResponseResult:
    return VerifyResponseResult(err=apperr.Error(code=code, detail=detail, retryable=False))


def verify_response(
    *,
    status: int,
    headers: dict[str, str],
    body: bytes,
    now: float,
    resolve_key: KeyResolver,
) -> VerifyResponseResult:
    """Checks a provider's response signature per awp-sig §3.

    Absent Signature-Input is fine (SHOULD, not MUST) -> Signed=False,
    err=None. A PRESENT-BUT-INVALID signature is always an error, never
    silently downgraded to "unsigned" — this asymmetry is easy to get
    backwards if request-verification logic is reused wholesale; request
    signatures are effectively mandatory (Signature-Input required),
    response signatures are optional by design.
    """
    sig_input_header = _header_get(headers, "Signature-Input")
    if not sig_input_header:
        return VerifyResponseResult(err=None, signed=False)

    try:
        parsed = parse_signature_input(sig_input_header)
    except Exception as e:
        return _reject_response(apperr.CODE_MALFORMED, str(e))
    if parsed.params.alg != "ed25519":
        return _reject_response(apperr.CODE_MALFORMED, 'alg must be "ed25519"')

    has_body = len(body) > 0
    want_components = [DERIVED_STATUS]
    if has_body:
        want_components.append(COMPONENT_DIGEST)
    if parsed.params.components != want_components:
        return _reject_response(apperr.CODE_MALFORMED, "covered components do not match this response")

    sig_header = _header_get(headers, "Signature")
    if not sig_header:
        return _reject_response(apperr.CODE_MALFORMED, "missing Signature")
    try:
        sig_b64 = parse_signature(sig_header)
    except Exception as e:
        return _reject_response(apperr.CODE_MALFORMED, str(e))
    try:
        sig_bytes = b64url.decode(sig_b64)
    except Exception:
        return _reject_response(apperr.CODE_MALFORMED, "bad Signature encoding")

    created_at = parsed.params.created
    if abs(now - created_at) > CREATED_WINDOW_SECONDS:
        return _reject_response(apperr.CODE_UNAUTHORIZED, "created outside the ±300s window")

    if has_body:
        digest_header = _header_get(headers, "Content-Digest")
        if not digest_header:
            return _reject_response(apperr.CODE_MALFORMED, "missing Content-Digest for a response with a body")
        try:
            verify_content_digest(digest_header, body)
        except Exception as e:
            return _reject_response(apperr.CODE_MALFORMED, str(e))

    if "/" not in parsed.params.keyid:
        return _reject_response(apperr.CODE_MALFORMED, "keyid must be {domain}/{kid}")
    domain, kid = parsed.params.keyid.split("/", 1)
    try:
        pub = resolve_key.resolve(domain, kid)
    except Exception:
        try:
            resolve_key.refresh(domain)
        except Exception:
            pass
        try:
            pub = resolve_key.resolve(domain, kid)
        except Exception as e:
            return _reject_response(apperr.CODE_UNAUTHORIZED, f"unknown or revoked key: {e}")

    try:
        base = _signature_base(
            parsed.params.components,
            lambda c: _response_component_value(status, headers, c),
            parsed.raw_value,
        )
    except Exception as e:
        return _reject_response(apperr.CODE_MALFORMED, str(e))

    try:
        pub.verify(sig_bytes, base.encode("utf-8"))
    except InvalidSignature:
        return _reject_response(apperr.CODE_UNAUTHORIZED, "signature verification failed")

    return VerifyResponseResult(err=None, provider_principal=domain, signed=True)
