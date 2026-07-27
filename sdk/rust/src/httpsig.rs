//! The awp-sig-v0.1.md sync signing profile: a minimal, hand-rolled RFC
//! 9421 subset. Per the Go reference implementation's own doc comment:
//! "This subset IS the spec: anything outside it MUST be rejected" — no
//! negotiation, no algorithm agility, so this module is deliberately
//! narrow rather than a general-purpose HTTP-message-signatures library.
//!
//! `SignableRequest`/`SignableResponse` are transport-agnostic views over
//! headers so this module works uniformly against `reqwest::Request`,
//! a server framework's request type, or a synthetic vector loaded from
//! `testdata/awp-sig/*.json` — mirroring the Go package's own
//! `*http.Request`/`*http.Response` parameter choice, minus the coupling
//! to `net/http` specifically.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::apperr::{self, Error as AppError};
use crate::b64;
use crate::delegation::{self, Link};

const DERIVED_METHOD: &str = "@method";
const DERIVED_TARGET_URI: &str = "@target-uri";
const DERIVED_STATUS: &str = "@status";
const COMPONENT_DIGEST: &str = "content-digest";

/// The fixed replay window (awp-sig §2 step 2 / §4: "created + fixed 300s
/// window is one fewer knob to misconfigure").
pub const CREATED_WINDOW: Duration = Duration::from_secs(300);

/// The only signature label this subset recognizes (awp-sig §1: "Exactly
/// one signature per message, label `awp`").
pub const LABEL: &str = "awp";

/// A minimal case-insensitive header bag, ordered by insertion for
/// deterministic iteration in tests, queried case-insensitively like
/// `http.Header.Get` on the Go side.
#[derive(Debug, Clone, Default)]
pub struct Headers(BTreeMap<String, String>);

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.0.insert(name.to_ascii_lowercase(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(|s| s.as_str())
    }
}

/// A transport-agnostic view of a signable/verifiable HTTP request.
#[derive(Debug, Clone)]
pub struct SignableRequest {
    pub method: String,
    pub target_uri: String,
    pub headers: Headers,
}

/// A transport-agnostic view of a signable/verifiable HTTP response.
#[derive(Debug, Clone)]
pub struct SignableResponse {
    pub status: u16,
    pub headers: Headers,
}

/// Returns the exact, ordered covered-component list for a request
/// (awp-sig §1.1): @method, @target-uri, content-digest (iff has_body),
/// then every AWP-* header present, lowercase, alphabetical.
pub fn covered_components(has_body: bool, headers: &Headers) -> Vec<String> {
    let mut components = vec![DERIVED_METHOD.to_string(), DERIVED_TARGET_URI.to_string()];
    if has_body {
        components.push(COMPONENT_DIGEST.to_string());
    }
    let mut awp_headers: Vec<String> = headers
        .names()
        .filter(|n| n.starts_with("awp-"))
        .map(|n| n.to_string())
        .collect();
    awp_headers.sort();
    components.extend(awp_headers);
    components
}

/// The parsed signature parameters (awp-sig §1.2): created, keyid, alg,
/// plus the ordered list of covered component identifiers.
#[derive(Debug, Clone)]
pub struct Params {
    pub components: Vec<String>,
    pub created: i64,
    pub key_id: String,
    pub alg: String,
}

impl Params {
    /// Renders the params WITHOUT the "awp=" label — exactly the value RFC
    /// 9421 §2.5 wants for the signature base's "@signature-params" line.
    pub fn serialize_value(&self) -> String {
        let mut s = String::from("(");
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push('"');
            s.push_str(c);
            s.push('"');
        }
        s.push(')');
        s.push_str(&format!(
            ";created={};keyid=\"{}\";alg=\"{}\"",
            self.created, self.key_id, self.alg
        ));
        s
    }

    /// Renders the full Signature-Input header value.
    pub fn header_value(&self) -> String {
        format!("{}={}", LABEL, self.serialize_value())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("httpsig: malformed Signature-Input: {0}")]
    Malformed(String),
    #[error("httpsig: forbidden signature parameter present: {0}")]
    ForbiddenParam(String),
}

/// Holds both the structured Params and the exact raw value substring
/// (everything after "awp="), which MUST be reused verbatim when
/// reconstructing the signature base for verification — re-serializing
/// would silently accept a signature over bytes the signer never actually
/// signed if their serialization style (whitespace, param order) differed
/// from ours.
#[derive(Debug, Clone)]
pub struct ParsedSignatureInput {
    pub params: Params,
    pub raw_value: String,
}

/// Parses a Signature-Input header value, accepting only the exact
/// awp-sig §1 grammar: label "awp", REQUIRED created/keyid/alg, and no
/// other params.
pub fn parse_signature_input(header: &str) -> Result<ParsedSignatureInput, ParseError> {
    let raw_value = header
        .strip_prefix("awp=")
        .filter(|rest| rest.starts_with('('))
        .ok_or_else(|| ParseError::Malformed("unknown label or bad syntax".to_string()))?
        .to_string();

    let close = raw_value
        .find(')')
        .ok_or_else(|| ParseError::Malformed("bad component-list syntax".to_string()))?;
    let components_part = &raw_value[1..close];
    let params_part = &raw_value[close + 1..];

    let mut components = Vec::new();
    if !components_part.is_empty() {
        for tok in components_part.split(' ') {
            if !(tok.starts_with('"') && tok.ends_with('"') && tok.len() >= 2) {
                return Err(ParseError::Malformed(
                    "bad component-list syntax".to_string(),
                ));
            }
            components.push(tok[1..tok.len() - 1].to_string());
        }
    }

    let mut created: Option<i64> = None;
    let mut key_id: Option<String> = None;
    let mut alg: Option<String> = None;

    for kv in params_part.split(';') {
        if kv.is_empty() {
            continue;
        }
        let (key, val) = kv
            .split_once('=')
            .ok_or_else(|| ParseError::Malformed(format!("bad param {kv:?}")))?;
        match key {
            "created" => {
                created =
                    Some(val.parse().map_err(|_| {
                        ParseError::Malformed(format!("bad created value: {val:?}"))
                    })?);
            }
            "keyid" => {
                key_id = Some(unquote(val)?);
            }
            "alg" => {
                alg = Some(unquote(val)?);
            }
            "expires" | "nonce" | "tag" => {
                return Err(ParseError::ForbiddenParam(key.to_string()));
            }
            other => {
                return Err(ParseError::Malformed(format!("unknown param {other:?}")));
            }
        }
    }

    let (Some(created), Some(key_id), Some(alg)) = (created, key_id, alg) else {
        return Err(ParseError::Malformed(
            "missing a required param (created/keyid/alg)".to_string(),
        ));
    };

    Ok(ParsedSignatureInput {
        params: Params {
            components,
            created,
            key_id,
            alg,
        },
        raw_value,
    })
}

fn unquote(s: &str) -> Result<String, ParseError> {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        Ok(s[1..s.len() - 1].to_string())
    } else {
        Err(ParseError::Malformed(format!(
            "expected quoted value, got {s:?}"
        )))
    }
}

/// Extracts the raw signature bytes-as-base64url from a Signature header
/// value of the form `awp=:BASE64URL:`.
pub fn parse_signature(header: &str) -> Result<String, ParseError> {
    let rest = header
        .strip_prefix("awp=:")
        .ok_or_else(|| ParseError::Malformed("bad Signature header syntax".to_string()))?;
    let inner = rest
        .strip_suffix(':')
        .ok_or_else(|| ParseError::Malformed("bad Signature header syntax".to_string()))?;
    if inner.is_empty()
        || !inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ParseError::Malformed(
            "bad Signature header syntax".to_string(),
        ));
    }
    Ok(inner.to_string())
}

/// RFC 9530 sha-256 Content-Digest header value for body:
/// "sha-256=:<standard-base64 digest>:".
pub fn compute_content_digest(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(body);
    format!("sha-256=:{}:", b64::std_encode(&sum))
}

#[derive(Debug, thiserror::Error)]
#[error("httpsig: content-digest mismatch: got {got:?}, want {want:?}")]
pub struct DigestMismatch {
    pub got: String,
    pub want: String,
}

/// Checks header against body, sha-256 only (awp-sig §1.3: "RFC 9530,
/// sha-256 only").
pub fn verify_content_digest(header: &str, body: &[u8]) -> Result<(), DigestMismatch> {
    let want = compute_content_digest(body);
    if header != want {
        return Err(DigestMismatch {
            got: header.to_string(),
            want,
        });
    }
    Ok(())
}

fn request_component_value(req: &SignableRequest, component: &str) -> Option<String> {
    match component {
        DERIVED_METHOD => Some(req.method.clone()),
        DERIVED_TARGET_URI => Some(req.target_uri.clone()),
        other => req
            .headers
            .get(other)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
    }
}

fn response_component_value(resp: &SignableResponse, component: &str) -> Option<String> {
    match component {
        DERIVED_STATUS => Some(resp.status.to_string()),
        other => resp
            .headers
            .get(other)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("httpsig: missing value for covered component {0:?}")]
pub struct MissingComponent(pub String);

/// Builds the RFC 9421 §2.5 signature base: one line per covered component
/// ("name": value\n), terminated by the "@signature-params" line WITHOUT a
/// trailing newline.
fn signature_base(
    components: &[String],
    value: impl Fn(&str) -> Option<String>,
    raw_params_value: &str,
) -> Result<String, MissingComponent> {
    let mut sb = String::new();
    for c in components {
        let v = value(c).ok_or_else(|| MissingComponent(c.clone()))?;
        sb.push_str(&format!("\"{}\": {}\n", c, v));
    }
    sb.push_str(&format!(
        "\"{}\": {}",
        "@signature-params", raw_params_value
    ));
    Ok(sb)
}

pub fn request_signature_base(
    req: &SignableRequest,
    params: &Params,
) -> Result<String, MissingComponent> {
    signature_base(
        &params.components,
        |c| request_component_value(req, c),
        &params.serialize_value(),
    )
}

pub fn response_signature_base(
    resp: &SignableResponse,
    params: &Params,
) -> Result<String, MissingComponent> {
    signature_base(
        &params.components,
        |c| response_component_value(resp, c),
        &params.serialize_value(),
    )
}

/// Signs req per awp-sig §1: computes Content-Digest if body is
/// non-empty, determines the exact covered-component list (awp-sig §1.1),
/// and sets Signature-Input and Signature. Any AWP-* headers the caller
/// wants covered (AWP-Session, AWP-Delegation) MUST already be set on
/// req.headers before calling sign — covered components are read from
/// whatever's present, not supplied separately.
pub fn sign(
    req: &mut SignableRequest,
    body: &[u8],
    signing_key: &SigningKey,
    key_id: &str,
    now: SystemTime,
) -> Result<(), MissingComponent> {
    let has_body = !body.is_empty();
    if has_body {
        req.headers
            .set("content-digest", compute_content_digest(body));
    }
    let components = covered_components(has_body, &req.headers);
    let params = Params {
        components,
        created: unix_secs(now),
        key_id: key_id.to_string(),
        alg: "ed25519".to_string(),
    };
    let base = request_signature_base(req, &params)?;
    let sig: Signature = signing_key.sign(base.as_bytes());
    req.headers.set("signature-input", params.header_value());
    req.headers.set(
        "signature",
        format!("{}=:{}:", LABEL, b64::url_encode(&sig.to_bytes())),
    );
    Ok(())
}

/// Signs resp per awp-sig §3: covered components @status and
/// content-digest (iff body non-empty), keyid from the provider's own
/// domain.
pub fn sign_response(
    resp: &mut SignableResponse,
    body: &[u8],
    signing_key: &SigningKey,
    key_id: &str,
    now: SystemTime,
) -> Result<(), MissingComponent> {
    let has_body = !body.is_empty();
    if has_body {
        resp.headers
            .set("content-digest", compute_content_digest(body));
    }
    let mut components = vec![DERIVED_STATUS.to_string()];
    if has_body {
        components.push(COMPONENT_DIGEST.to_string());
    }
    let params = Params {
        components,
        created: unix_secs(now),
        key_id: key_id.to_string(),
        alg: "ed25519".to_string(),
    };
    let base = response_signature_base(resp, &params)?;
    let sig: Signature = signing_key.sign(base.as_bytes());
    resp.headers.set("signature-input", params.header_value());
    resp.headers.set(
        "signature",
        format!("{}=:{}:", LABEL, b64::url_encode(&sig.to_bytes())),
    );
    Ok(())
}

fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Resolves (domain, kid) to a public key, with a refresh primitive for
/// the core §0.1 rotation-race retry.
pub trait KeyResolver {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String>;
    fn refresh(&self, domain: &str) -> Result<(), String>;
}

/// Checks an AWP-Session token against the caller principal derived from
/// the request's signing key (core §1.3).
pub trait SessionVerifier {
    fn verify(&self, token: &str, caller_principal: &str) -> Result<(), String>;
}

/// Bundles what `verify` needs beyond the request/body themselves.
pub struct Deps<'a> {
    pub resolve_key: &'a dyn KeyResolver,
    /// This endpoint's own principal (the tool/entity being called) —
    /// checked against a delegation chain's scope.to, exactly as an
    /// envelope's `to` field would be (core §2.5).
    pub target: &'a str,
    /// Called when AWP-Session is present. `None` on an endpoint that
    /// receives an AWP-Session header is itself a verification failure.
    pub verify_session: Option<&'a dyn SessionVerifier>,
}

/// verify's outcome: status/err mirror the Go daemon's GateResult shape
/// (status 0 / err None means success).
#[derive(Debug, Default)]
pub struct VerifyResult {
    pub status: u16,
    pub err: Option<AppError>,
    pub caller_principal: String,
    pub delegation: Option<Vec<Link>>,
    pub has_session: bool,
}

fn reject(status: u16, code: &str, detail: impl Into<String>) -> VerifyResult {
    VerifyResult {
        status,
        err: Some(AppError {
            code: code.to_string(),
            detail: detail.into(),
            retryable: false,
        }),
        ..Default::default()
    }
}

/// Runs the awp-sig §2 algorithm against req, given the exact bytes of its
/// body (already read by the caller — this module never touches a
/// request stream itself). Each of the 7 steps short-circuits with the
/// specific status/code the spec assigns it.
pub fn verify(req: &SignableRequest, body: &[u8], now: SystemTime, deps: &Deps) -> VerifyResult {
    // Step 1: parse Signature-Input; validate components and params.
    let Some(sig_input_header) = req.headers.get("signature-input") else {
        return reject(400, apperr::CODE_MALFORMED, "missing Signature-Input");
    };
    let parsed = match parse_signature_input(sig_input_header) {
        Ok(p) => p,
        Err(e) => return reject(400, apperr::CODE_MALFORMED, e.to_string()),
    };
    if parsed.params.alg != "ed25519" {
        return reject(400, apperr::CODE_MALFORMED, "alg must be \"ed25519\"");
    }
    let has_body = !body.is_empty();
    let want_components = covered_components(has_body, &req.headers);
    if parsed.params.components != want_components {
        return reject(
            400,
            apperr::CODE_MALFORMED,
            "covered components do not match this request",
        );
    }

    let Some(sig_header) = req.headers.get("signature") else {
        return reject(400, apperr::CODE_MALFORMED, "missing Signature");
    };
    let sig_b64 = match parse_signature(sig_header) {
        Ok(s) => s,
        Err(e) => return reject(400, apperr::CODE_MALFORMED, e.to_string()),
    };
    let sig_bytes = match b64::url_decode(&sig_b64) {
        Ok(b) => b,
        Err(_) => return reject(400, apperr::CODE_MALFORMED, "bad Signature encoding"),
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return reject(400, apperr::CODE_MALFORMED, "bad Signature encoding"),
    };
    let signature = Signature::from_bytes(&sig_arr);

    // Step 2: created within +-300s.
    let created_at = UNIX_EPOCH + signed_duration(parsed.params.created);
    let d = signed_diff(now, created_at);
    if d > CREATED_WINDOW.as_secs_f64() || d < -(CREATED_WINDOW.as_secs_f64()) {
        return reject(
            401,
            apperr::CODE_UNAUTHORIZED,
            "created outside the +-300s window",
        );
    }

    // Step 3: digest before signature — never verify a signature over a
    // digest that hasn't itself been checked.
    if has_body {
        let Some(digest_header) = req.headers.get("content-digest") else {
            return reject(
                400,
                apperr::CODE_MALFORMED,
                "missing Content-Digest for a request with a body",
            );
        };
        if let Err(e) = verify_content_digest(digest_header, body) {
            return reject(400, apperr::CODE_MALFORMED, e.to_string());
        }
    }

    // Step 4: resolve keyid, one refresh on failure (core §0.1 rotation
    // race), then hard-fail.
    let Some((domain, kid)) = parsed.params.key_id.split_once('/') else {
        return reject(400, apperr::CODE_MALFORMED, "keyid must be {domain}/{kid}");
    };
    let pub_key = match deps.resolve_key.resolve(domain, kid) {
        Ok(p) => p,
        Err(_) => {
            let _ = deps.resolve_key.refresh(domain);
            match deps.resolve_key.resolve(domain, kid) {
                Ok(p) => p,
                Err(e) => {
                    return reject(
                        401,
                        apperr::CODE_UNAUTHORIZED,
                        format!("unknown or revoked key: {e}"),
                    )
                }
            }
        }
    };

    // Step 5: reconstruct the signature base from the RECEIVED params
    // value (not a re-serialization) and verify.
    let base = match signature_base(
        &parsed.params.components,
        |c| request_component_value(req, c),
        &parsed.raw_value,
    ) {
        Ok(b) => b,
        Err(e) => return reject(400, apperr::CODE_MALFORMED, e.to_string()),
    };
    if pub_key.verify(base.as_bytes(), &signature).is_err() {
        return reject(
            401,
            apperr::CODE_UNAUTHORIZED,
            "signature verification failed",
        );
    }

    let caller_principal = domain.to_string();
    let mut result = VerifyResult {
        caller_principal: caller_principal.clone(),
        ..Default::default()
    };

    // Step 6: delegation, if present.
    if let Some(del_header) = req.headers.get("awp-delegation") {
        let chain = match decode_delegation_chain(del_header) {
            Ok(c) => c,
            Err(e) => return reject(403, apperr::CODE_UNAUTHORIZED_DELEGATION, e),
        };
        let resolver_adapter = KeyResolverAdapter(deps.resolve_key);
        let verify_in = delegation::VerifyInput {
            chain: &chain,
            from: &caller_principal,
            to: deps.target,
            kind: "",
            body_type: "",
            now,
            resolve_key: &resolver_adapter,
        };
        if let Err(e) = delegation::verify(&verify_in) {
            return reject(403, apperr::CODE_UNAUTHORIZED_DELEGATION, e.to_string());
        }
        result.delegation = Some(chain);
    }

    // Step 7: session, if present.
    if let Some(sess_header) = req.headers.get("awp-session") {
        match deps.verify_session {
            None => {
                return reject(
                    401,
                    apperr::CODE_UNAUTHORIZED,
                    "this endpoint does not accept sessions",
                )
            }
            Some(verifier) => {
                if let Err(e) = verifier.verify(sess_header, &caller_principal) {
                    return reject(
                        401,
                        apperr::CODE_UNAUTHORIZED,
                        format!("session invalid: {e}"),
                    );
                }
            }
        }
        result.has_session = true;
    }

    result
}

struct KeyResolverAdapter<'a>(&'a dyn KeyResolver);

impl delegation::KeyResolver for KeyResolverAdapter<'_> {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        self.0.resolve(domain, kid)
    }
}

fn decode_delegation_chain(header: &str) -> Result<Vec<Link>, String> {
    let raw = b64::url_decode(header).map_err(|_| "bad AWP-Delegation encoding".to_string())?;
    serde_json::from_slice(&raw).map_err(|_| "bad AWP-Delegation JSON".to_string())
}

/// `verify_response`'s outcome. `err` is `None` on success OR when the
/// response carried no signature at all (response signing is awp-sig §3
/// SHOULD, not MUST — absence is not itself a failure). A
/// present-but-invalid signature MUST be treated as an error — easy to get
/// backwards if request-verification logic is reused wholesale, since
/// request signatures are effectively mandatory in practice.
#[derive(Debug, Default)]
pub struct VerifyResponseResult {
    pub err: Option<AppError>,
    pub provider_principal: String,
    pub signed: bool,
}

fn reject_response(code: &str, detail: impl Into<String>) -> VerifyResponseResult {
    VerifyResponseResult {
        err: Some(AppError {
            code: code.to_string(),
            detail: detail.into(),
            retryable: false,
        }),
        ..Default::default()
    }
}

/// Checks a provider's response signature per awp-sig §3.
pub fn verify_response(
    resp: &SignableResponse,
    body: &[u8],
    now: SystemTime,
    resolve_key: &dyn KeyResolver,
) -> VerifyResponseResult {
    let Some(sig_input_header) = resp.headers.get("signature-input") else {
        return VerifyResponseResult::default();
    };
    let parsed = match parse_signature_input(sig_input_header) {
        Ok(p) => p,
        Err(e) => return reject_response(apperr::CODE_MALFORMED, e.to_string()),
    };
    if parsed.params.alg != "ed25519" {
        return reject_response(apperr::CODE_MALFORMED, "alg must be \"ed25519\"");
    }
    let has_body = !body.is_empty();
    let mut want_components = vec![DERIVED_STATUS.to_string()];
    if has_body {
        want_components.push(COMPONENT_DIGEST.to_string());
    }
    if parsed.params.components != want_components {
        return reject_response(
            apperr::CODE_MALFORMED,
            "covered components do not match this response",
        );
    }

    let Some(sig_header) = resp.headers.get("signature") else {
        return reject_response(apperr::CODE_MALFORMED, "missing Signature");
    };
    let sig_b64 = match parse_signature(sig_header) {
        Ok(s) => s,
        Err(e) => return reject_response(apperr::CODE_MALFORMED, e.to_string()),
    };
    let sig_bytes = match b64::url_decode(&sig_b64) {
        Ok(b) => b,
        Err(_) => return reject_response(apperr::CODE_MALFORMED, "bad Signature encoding"),
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return reject_response(apperr::CODE_MALFORMED, "bad Signature encoding"),
    };
    let signature = Signature::from_bytes(&sig_arr);

    let created_at = UNIX_EPOCH + signed_duration(parsed.params.created);
    let d = signed_diff(now, created_at);
    if d > CREATED_WINDOW.as_secs_f64() || d < -(CREATED_WINDOW.as_secs_f64()) {
        return reject_response(
            apperr::CODE_UNAUTHORIZED,
            "created outside the +-300s window",
        );
    }

    if has_body {
        let Some(digest_header) = resp.headers.get("content-digest") else {
            return reject_response(
                apperr::CODE_MALFORMED,
                "missing Content-Digest for a response with a body",
            );
        };
        if let Err(e) = verify_content_digest(digest_header, body) {
            return reject_response(apperr::CODE_MALFORMED, e.to_string());
        }
    }

    let Some((domain, kid)) = parsed.params.key_id.split_once('/') else {
        return reject_response(apperr::CODE_MALFORMED, "keyid must be {domain}/{kid}");
    };
    let pub_key = match resolve_key.resolve(domain, kid) {
        Ok(p) => p,
        Err(_) => {
            let _ = resolve_key.refresh(domain);
            match resolve_key.resolve(domain, kid) {
                Ok(p) => p,
                Err(e) => {
                    return reject_response(
                        apperr::CODE_UNAUTHORIZED,
                        format!("unknown or revoked key: {e}"),
                    )
                }
            }
        }
    };

    let base = match signature_base(
        &parsed.params.components,
        |c| response_component_value(resp, c),
        &parsed.raw_value,
    ) {
        Ok(b) => b,
        Err(e) => return reject_response(apperr::CODE_MALFORMED, e.to_string()),
    };
    if pub_key.verify(base.as_bytes(), &signature).is_err() {
        return reject_response(apperr::CODE_UNAUTHORIZED, "signature verification failed");
    }

    VerifyResponseResult {
        provider_principal: domain.to_string(),
        signed: true,
        err: None,
    }
}

fn signed_duration(secs: i64) -> Duration {
    Duration::from_secs(secs.unsigned_abs())
}

/// now - created_at, in fractional seconds, allowing a negative result
/// (created_at may be in the future from now's perspective, or vice
/// versa) — Go's `time.Duration` subtraction is signed; std's
/// `SystemTime::duration_since` is not, so this reimplements the signed
/// comparison directly on unix-second integers instead of SystemTime
/// deltas.
fn signed_diff(now: SystemTime, created_at: SystemTime) -> f64 {
    match now.duration_since(created_at) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}
