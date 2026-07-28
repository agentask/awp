//! The AWP core §0.1 signing primitive (JCS-then-ed25519), and the domain
//! index / key types of core §1.1.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::b64;
use crate::jcs;

/// The {kid, value} signature envelope used by every signed object (index,
/// manifest, envelope, delegation link) per core §0.1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sig {
    pub kid: String,
    pub value: String,
}

/// Strips the "#entity" fragment from a principal name, per core §0.
pub fn domain_of(principal: &str) -> String {
    principal.split('#').next().unwrap_or(principal).to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity: nil signature")]
    NilSignature,
    #[error("identity: signature verification failed")]
    BadSignature,
    #[error("identity: decode sig value: {0}")]
    DecodeSig(#[from] base64::DecodeError),
    #[error("identity: bad public key: {0}")]
    BadPublicKey(String),
    #[error("identity: serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Serializes `v` to a serde_json::Value, removes the top-level "sig"
/// member if present, and applies JCS to produce the exact bytes that are
/// signed/verified per core §0.1. `v` must serialize to a JSON object.
pub fn canonical_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, IdentityError> {
    let mut value = serde_json::to_value(v)?;
    if let Value::Object(map) = &mut value {
        map.remove("sig");
    }
    Ok(jcs::canonicalize(&value).into_bytes())
}

/// Produces the Sig for v under `signing_key`, keyed by kid. v's own "sig"
/// field (if present) is ignored/stripped before signing.
pub fn sign<T: Serialize>(
    v: &T,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<Sig, IdentityError> {
    let canon = canonical_bytes(v)?;
    let sig: Signature = signing_key.sign(&canon);
    Ok(Sig {
        kid: kid.to_string(),
        value: b64::url_encode(&sig.to_bytes()),
    })
}

/// Recomputes v's canonical bytes (with "sig" stripped, regardless of what
/// v currently carries) and checks sig against pub.
pub fn verify_sig<T: Serialize>(
    v: &T,
    sig: Option<&Sig>,
    pub_key: &VerifyingKey,
) -> Result<(), IdentityError> {
    let sig = sig.ok_or(IdentityError::NilSignature)?;
    let canon = canonical_bytes(v)?;
    let sig_bytes = b64::url_decode(&sig.value)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    pub_key
        .verify(&canon, &signature)
        .map_err(|_| IdentityError::BadSignature)
}

/// RFC3339 UTC, millisecond precision, literal "Z" suffix — Go's
/// `time.Now().UTC().Format("2006-01-02T15:04:05.000Z")`. Deliberately not
/// delegated to any general-purpose RFC3339 formatter: fractional-second
/// digit counts and trailing-Z behavior vary across libraries/defaults, and
/// this exact byte shape feeds directly into JCS-then-sign, so any drift
/// changes signed bytes.
pub fn now_rfc3339_milli() -> String {
    system_time_rfc3339_milli(SystemTime::now())
}

pub fn system_time_rfc3339_milli(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, millis
    )
}

/// Civil (Gregorian) calendar breakdown of a unix timestamp, UTC. Hand-
/// rolled (Howard Hinnant's well-known `civil_from_days` algorithm) to
/// avoid pulling a full chrono dependency for one formatting need.
pub(crate) fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let h = (secs_of_day / 3600) as u32;
    let mi = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/// One entry of a domain index's keys[] array (core §1.1). `expires` and
/// `prev_sig` are always-present JSON keys (never omitted; `null` when
/// unset) — matching Go's `*string` fields with no `omitempty` tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub kid: String,
    pub alg: String,
    #[serde(rename = "pub")]
    pub pub_: String, // base64url-raw-32-bytes, unpadded
    pub created: String,
    pub expires: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    pub prev_sig: Option<String>,
}

impl Key {
    /// Decodes the key's base64url raw public key bytes.
    pub fn pub_key(&self) -> Result<VerifyingKey, IdentityError> {
        let raw = b64::url_decode(&self.pub_)?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            IdentityError::BadPublicKey(format!(
                "key {:?} pub has {} bytes, want 32",
                self.kid,
                raw.len()
            ))
        })?;
        VerifyingKey::from_bytes(&arr).map_err(|e| IdentityError::BadPublicKey(e.to_string()))
    }
}

/// One entry of a domain index's entities[] array (core §1.1). No optional
/// fields — all plain strings, always present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub name: String,
    pub kind: String,
    pub manifest: String,
    pub manifest_sha256: String,
}

/// One entry of a domain index's transports[] array (core §1.1, awp-quic
/// §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transport {
    pub proto: String,
    pub endpoint: String,
}

/// awp-push-v0.1.md §2: an OPTIONAL, unauthenticated liveness hint a
/// sender may POST to (empty body) after a failed delivery attempt to
/// this domain's inbox. Never carries envelope content and is not a
/// transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wake {
    pub endpoint: String,
}

/// The signed root document served at /.well-known/awp.json (core §1.1).
///
/// `keys`/`entities` are always-present JSON keys — `null` when the Go
/// struct's slice is nil, `[]`/`[...]` when it is a real (possibly empty)
/// slice. This distinction changes signed bytes, so it's modeled as
/// `Option<Vec<T>>` rather than defaulting to an empty vec, mirroring the
/// fix `pyawp/identity.py` already had to make for the same field class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub awp: String,
    pub domain: String,
    pub updated: String,
    pub keys: Option<Vec<Key>>,
    pub entities: Option<Vec<Entity>>,
    #[serde(default)]
    pub inbox: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crawl: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Transport>>,
    /// awp-capabilities-v0.1.md §1: OPTIONAL domain-level protocol-
    /// extension advertisement (e.g. "awp-streaming-v0.1"), in the same
    /// spirit as `transports`. Absence means "no declared optional
    /// capabilities," exactly like absent `transports` means HTTPS-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// awp-push-v0.1.md §2: an OPTIONAL wake-notification hint, distinct
    /// in scope from `capabilities`/`transports` — this is a liveness
    /// nudge, never a way to carry envelope bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wake: Option<Wake>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

impl Index {
    /// Attaches idx.sig per core §0.1.
    pub fn sign(&mut self, signing_key: &SigningKey, kid: &str) -> Result<(), IdentityError> {
        self.sig = Some(sign(self, signing_key, kid)?);
        Ok(())
    }

    /// Verifies idx.sig against one of idx.keys identified by idx.sig.kid —
    /// the self-referential trust anchor for a domain index (core §1.1:
    /// "verified against a key in `keys`" via TOFU on first sight).
    pub fn verify_self_sig(&self) -> Result<(), IdentityError> {
        let sig = self.sig.as_ref().ok_or(IdentityError::NilSignature)?;
        let keys = self.keys.as_deref().unwrap_or(&[]);
        for k in keys {
            if k.kid == sig.kid {
                let pub_key = k.pub_key()?;
                return verify_sig(self, self.sig.as_ref(), &pub_key);
            }
        }
        Err(IdentityError::BadPublicKey(format!(
            "index sig kid {:?} not found in keys",
            sig.kid
        )))
    }
}

/// core §1.1 rule 2 verification: chain\[0\] is a previously trusted key
/// (taken on faith, e.g. via TOFU); for every i>0, chain\[i\].prev_sig MUST
/// be the Ed25519 signature of chain\[i\].pub's **raw bytes** (not its JSON
/// or base64 encoding) by chain\[i-1\]'s key — the one signature in this
/// system that does not sign JCS-canonicalized JSON.
#[derive(Debug, thiserror::Error)]
#[error("identity: rotation chain broken at link {index}: {reason}")]
pub struct BrokenRotation {
    pub index: usize,
    pub reason: String,
}

pub fn verify_rotation_chain(chain: &[Key]) -> Result<(), BrokenRotation> {
    if chain.is_empty() {
        return Err(BrokenRotation {
            index: 0,
            reason: "empty rotation chain".to_string(),
        });
    }
    for i in 1..chain.len() {
        let prev = &chain[i - 1];
        let cur = &chain[i];
        let prev_pub = prev.pub_key().map_err(|e| BrokenRotation {
            index: i,
            reason: e.to_string(),
        })?;
        let cur_pub_raw = b64::url_decode(&cur.pub_).map_err(|e| BrokenRotation {
            index: i,
            reason: e.to_string(),
        })?;
        let Some(prev_sig) = &cur.prev_sig else {
            return Err(BrokenRotation {
                index: i,
                reason: "missing prev_sig".to_string(),
            });
        };
        let sig_bytes = b64::url_decode(prev_sig).map_err(|e| BrokenRotation {
            index: i,
            reason: format!("prev_sig not valid base64url: {e}"),
        })?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| BrokenRotation {
                index: i,
                reason: "prev_sig has wrong length".to_string(),
            })?;
        let signature = Signature::from_bytes(&sig_arr);
        if prev_pub.verify(&cur_pub_raw, &signature).is_err() {
            return Err(BrokenRotation {
                index: i,
                reason: "prev_sig does not verify against previous key".to_string(),
            });
        }
    }
    Ok(())
}

/// Generates a fresh ed25519 keypair for a demo identity.
pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::rngs::OsRng;
    SigningKey::generate(&mut csprng)
}
