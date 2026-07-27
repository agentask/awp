//! Loads every `testdata/awp-sig/*.json` conformance vector and drives
//! this crate's `httpsig::sign`/`verify`/`verify_response` against it.
//! These vectors are self-checked against the real Go `httpsig.Verify`
//! at generation time (`testdata/awp-sig/generate.go`), so they are ground
//! truth, not just "probably right" — see `CLAUDE.md` Phase 5.

use awp::delegation::KeyResolver as DelegationKeyResolver;
use awp::httpsig::{
    self, Headers, KeyResolver as HttpsigKeyResolver, SessionVerifier, SignableRequest,
    SignableResponse,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct TrustedKey {
    domain: String,
    kid: String,
    pub_b64url: String,
}

#[derive(Debug, Deserialize)]
struct Expect {
    status: i64,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(default)]
    description: String,
    domain: String,
    kid: String,
    private_key_seed_b64url: String,
    #[serde(default)]
    public_key_b64url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    target_uri: Option<String>,
    #[serde(default)]
    body_b64url: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    extra_headers: HashMap<String, String>,
    created: i64,
    verify_at: String,
    signature_input: String,
    signature: String,
    #[serde(default)]
    content_digest: Option<String>,
    signature_base: String,
    #[serde(default)]
    trusted_keys: Vec<TrustedKey>,
    #[serde(default)]
    delegation_target: Option<String>,
    expect: Expect,
    #[allow(dead_code)]
    #[serde(default)]
    note: Option<String>,
}

fn testdata_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/awp-sig")
}

fn load_vector(name: &str) -> Vector {
    let path = testdata_dir().join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn signing_key_from_seed(seed_b64url: &str) -> SigningKey {
    let seed = URL_SAFE_NO_PAD.decode(seed_b64url).expect("decode seed");
    let arr: [u8; 32] = seed.as_slice().try_into().expect("seed must be 32 bytes");
    SigningKey::from_bytes(&arr)
}

fn pubkey_from_b64(pub_b64url: &str) -> VerifyingKey {
    let raw = URL_SAFE_NO_PAD.decode(pub_b64url).expect("decode pubkey");
    let arr: [u8; 32] = raw.as_slice().try_into().expect("pubkey must be 32 bytes");
    VerifyingKey::from_bytes(&arr).expect("valid pubkey")
}

fn parse_verify_at(s: &str) -> SystemTime {
    awp::rfc3339::parse(s).unwrap_or_else(|e| panic!("parse verify_at {s:?}: {e}"))
}

/// A resolver backed by the vector's own (domain, kid) -> pubkey plus any
/// `trusted_keys` entries (e.g. a delegation root's key that the request's
/// own signer key does not cover).
struct VectorResolver {
    keys: HashMap<(String, String), VerifyingKey>,
}

impl VectorResolver {
    fn from_vector(v: &Vector) -> Self {
        let mut keys = HashMap::new();
        if !v.public_key_b64url.is_empty() {
            keys.insert(
                (v.domain.clone(), v.kid.clone()),
                pubkey_from_b64(&v.public_key_b64url),
            );
        }
        for tk in &v.trusted_keys {
            keys.insert(
                (tk.domain.clone(), tk.kid.clone()),
                pubkey_from_b64(&tk.pub_b64url),
            );
        }
        Self { keys }
    }
}

impl HttpsigKeyResolver for VectorResolver {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        self.keys
            .get(&(domain.to_string(), kid.to_string()))
            .copied()
            .ok_or_else(|| format!("no key for {domain}/{kid}"))
    }

    fn refresh(&self, _domain: &str) -> Result<(), String> {
        Ok(())
    }
}

impl DelegationKeyResolver for VectorResolver {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        HttpsigKeyResolver::resolve(self, domain, kid)
    }
}

struct AcceptAnySession;
impl SessionVerifier for AcceptAnySession {
    fn verify(&self, _token: &str, _caller_principal: &str) -> Result<(), String> {
        Ok(())
    }
}

struct RejectAllSessions;
impl SessionVerifier for RejectAllSessions {
    fn verify(&self, _token: &str, _caller_principal: &str) -> Result<(), String> {
        Err("session rejected by this fixture's provider".to_string())
    }
}

fn build_request(v: &Vector) -> SignableRequest {
    let mut headers = Headers::new();
    for (k, val) in &v.extra_headers {
        headers.set(k, val.clone());
    }
    if let Some(cd) = &v.content_digest {
        headers.set("content-digest", cd.clone());
    }
    headers.set("signature-input", v.signature_input.clone());
    headers.set("signature", v.signature.clone());
    SignableRequest {
        method: v.method.clone().unwrap_or_default(),
        target_uri: v.target_uri.clone().unwrap_or_default(),
        headers,
    }
}

fn decode_body(v: &Vector) -> Vec<u8> {
    match &v.body_b64url {
        Some(b) => URL_SAFE_NO_PAD.decode(b).expect("decode body"),
        None => Vec::new(),
    }
}

fn run_request_vector(name: &str, session_verifier: Option<&dyn SessionVerifier>) {
    let v = load_vector(name);
    let body = decode_body(&v);
    let req = build_request(&v);
    let resolver = VectorResolver::from_vector(&v);
    let now = parse_verify_at(&v.verify_at);

    let target = v.delegation_target.clone().unwrap_or_default();
    let deps = httpsig::Deps {
        resolve_key: &resolver,
        target: &target,
        verify_session: session_verifier,
    };
    let result = httpsig::verify(&req, &body, now, &deps);

    if v.expect.status == 0 {
        assert!(
            result.err.is_none(),
            "vector {:?} ({}) expected success, got {:?}",
            v.name,
            v.description,
            result.err
        );
    } else {
        let err = result.err.unwrap_or_else(|| {
            panic!(
                "vector {:?} expected failure status {}, got success",
                v.name, v.expect.status
            )
        });
        assert_eq!(
            result.status, v.expect.status as u16,
            "vector {:?}: wrong status",
            v.name
        );
        if let Some(code) = &v.expect.code {
            assert_eq!(&err.code, code, "vector {:?}: wrong code", v.name);
        }
    }
}

#[test]
fn bodyless_get() {
    run_request_vector("bodyless-get.json", None);
}

#[test]
fn post_with_body() {
    run_request_vector("post-with-body.json", None);
}

#[test]
fn post_with_session() {
    run_request_vector("post-with-session.json", Some(&AcceptAnySession));
}

#[test]
fn post_with_delegation_2link() {
    run_request_vector("post-with-delegation-2link.json", None);
}

#[test]
fn failure_step1_missing_signature_input() {
    run_request_vector("failure-step1-missing-signature-input.json", None);
}

#[test]
fn failure_step1_unknown_label() {
    run_request_vector("failure-step1-unknown-label.json", None);
}

#[test]
fn failure_step1_forbidden_param() {
    run_request_vector("failure-step1-forbidden-param.json", None);
}

#[test]
fn failure_step1_missing_component() {
    run_request_vector("failure-step1-missing-component.json", None);
}

#[test]
fn failure_step2_created_outside_window() {
    run_request_vector("failure-step2-created-outside-window.json", None);
}

#[test]
fn failure_step3_digest_mismatch() {
    run_request_vector("failure-step3-digest-mismatch.json", None);
}

#[test]
fn failure_step4_unknown_key() {
    run_request_vector("failure-step4-unknown-key.json", None);
}

#[test]
fn failure_step5_bad_signature() {
    run_request_vector("failure-step5-bad-signature.json", None);
}

#[test]
fn failure_step6_delegation_invalid() {
    run_request_vector("failure-step6-delegation-invalid.json", None);
}

#[test]
fn failure_step7_session_invalid() {
    run_request_vector(
        "failure-step7-session-invalid.json",
        Some(&RejectAllSessions),
    );
}

fn build_response(v: &Vector) -> SignableResponse {
    let mut headers = Headers::new();
    if let Some(cd) = &v.content_digest {
        headers.set("content-digest", cd.clone());
    }
    headers.set("signature-input", v.signature_input.clone());
    headers.set("signature", v.signature.clone());
    SignableResponse {
        status: v.status.unwrap_or(200),
        headers,
    }
}

fn run_response_vector(name: &str, expect_signed_ok: bool) {
    let v = load_vector(name);
    let body = decode_body(&v);
    let resp = build_response(&v);
    let resolver = VectorResolver::from_vector(&v);
    let now = parse_verify_at(&v.verify_at);

    let result = httpsig::verify_response(&resp, &body, now, &resolver);
    if v.expect.status == 0 {
        assert!(
            result.err.is_none(),
            "vector {:?} expected success, got {:?}",
            v.name,
            result.err
        );
        assert_eq!(
            result.signed, expect_signed_ok,
            "vector {:?}: signed flag",
            v.name
        );
    } else {
        let err = result
            .err
            .unwrap_or_else(|| panic!("vector {:?} expected failure, got success", v.name));
        if let Some(code) = &v.expect.code {
            assert_eq!(&err.code, code, "vector {:?}: wrong code", v.name);
        }
    }
}

#[test]
fn response_signed() {
    run_response_vector("response-signed.json", true);
}

#[test]
fn response_tampered_signature() {
    run_response_vector("response-tampered-signature.json", false);
}

/// For every success vector, re-sign with this crate's own `sign` and
/// confirm byte-identical `Signature-Input`/`Signature`/`Content-Digest`
/// against the fixture — proving the sign side independently of whatever
/// the verify-side assertions above already covered (those deliberately
/// use the fixture's own pre-signed bytes, not our signer's output, so a
/// verify bug can't be masked by a matching sign bug — this test is the
/// other half: a sign bug caught even if verify happened to still accept
/// it).
#[test]
fn resign_matches_fixture_bytes() {
    for name in [
        "bodyless-get.json",
        "post-with-body.json",
        "post-with-session.json",
        "post-with-delegation-2link.json",
    ] {
        let v = load_vector(name);
        let body = decode_body(&v);
        let signing_key = signing_key_from_seed(&v.private_key_seed_b64url);
        let mut req = SignableRequest {
            method: v.method.clone().unwrap_or_default(),
            target_uri: v.target_uri.clone().unwrap_or_default(),
            headers: Headers::new(),
        };
        for (k, val) in &v.extra_headers {
            req.headers.set(k, val.clone());
        }
        let created_at = UNIX_EPOCH + Duration::from_secs(v.created as u64);
        let key_id = format!("{}/{}", v.domain, v.kid);
        httpsig::sign(&mut req, &body, &signing_key, &key_id, created_at)
            .unwrap_or_else(|e| panic!("sign {name}: {e}"));

        assert_eq!(
            req.headers.get("signature-input"),
            Some(v.signature_input.as_str()),
            "{name}: Signature-Input mismatch"
        );
        assert_eq!(
            req.headers.get("signature"),
            Some(v.signature.as_str()),
            "{name}: Signature mismatch"
        );
        if let Some(cd) = &v.content_digest {
            assert_eq!(
                req.headers.get("content-digest"),
                Some(cd.as_str()),
                "{name}: Content-Digest mismatch"
            );
        }
    }
}

#[test]
fn response_signing_matches_fixture_bytes() {
    let v = load_vector("response-signed.json");
    let body = decode_body(&v);
    let signing_key = signing_key_from_seed(&v.private_key_seed_b64url);
    let mut resp = SignableResponse {
        status: v.status.unwrap_or(200),
        headers: Headers::new(),
    };
    let created_at = UNIX_EPOCH + Duration::from_secs(v.created as u64);
    let key_id = format!("{}/{}", v.domain, v.kid);
    httpsig::sign_response(&mut resp, &body, &signing_key, &key_id, created_at).unwrap();

    assert_eq!(
        resp.headers.get("signature-input"),
        Some(v.signature_input.as_str())
    );
    assert_eq!(resp.headers.get("signature"), Some(v.signature.as_str()));
    assert_eq!(
        resp.headers.get("content-digest"),
        v.content_digest.as_deref()
    );
}

/// The exact signature-base string is documented per vector independent
/// of the final ed25519 bytes — comparing against it isolates a
/// base-construction bug from a crypto bug.
#[test]
fn signature_base_matches_fixture() {
    for name in [
        "post-with-body.json",
        "post-with-delegation-2link.json",
        "bodyless-get.json",
    ] {
        let v = load_vector(name);
        let body = decode_body(&v);
        let req = build_request(&v);
        let parsed = httpsig::parse_signature_input(&v.signature_input)
            .unwrap_or_else(|e| panic!("{name}: parse signature_input: {e}"));
        let _ = &body;
        let base = httpsig::request_signature_base(&req, &parsed.params)
            .unwrap_or_else(|e| panic!("{name}: build base: {e}"));
        assert_eq!(base, v.signature_base, "{name}: signature_base mismatch");
    }
}
