//! The AWP core §2.1 envelope: types, JCS canon (via identity::sign/
//! verify_sig), and ULID id generation.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::delegation::Link;
use crate::identity::{self, IdentityError, Sig};

/// core §2.1 serialized-envelope cap.
pub const MAX_SIZE: usize = 256 * 1024;

/// core §2.1 ttl bounds, in seconds.
pub const MIN_TTL: i64 = 60;
pub const MAX_TTL: i64 = 604800;

/// The unit of async communication (core §2.1). `in_reply_to`, `session`,
/// and `delegation` are always-present JSON keys — `null` when unset —
/// matching Go's non-omitempty `*string`/`[]T` fields exactly. sdk/go's
/// SendEnvelope never populates `delegation`, so it is always emitted as
/// `null` (a nil Go slice), never `[]`; ports must match that exact zero
/// value, not "a reasonable empty array."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub awp: String,
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub thread: String,
    pub in_reply_to: Option<String>,
    pub ts: String,
    pub ttl: i64,
    pub session: Option<String>,
    pub delegation: Option<Vec<Link>>,
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

/// Generates a sender-side envelope id: a lowercase Crockford base32 ULID
/// (core §0: "All ordering-sensitive IDs are ULIDs, lowercase Crockford
/// base32").
pub fn new_id() -> String {
    ulid::Ulid::new().to_string().to_lowercase()
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope: exceeds 256 KiB size limit")]
    TooLarge,
    #[error("envelope: ttl out of bounds [60, 604800]")]
    TtlOutOfBounds,
    #[error("envelope: {0:?} has no sig")]
    NoSig(String),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("envelope: serialize for size check: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl Envelope {
    /// Attaches env.sig per core §0.1, signed by domain_of(env.from)'s key.
    pub fn sign(&mut self, signing_key: &SigningKey, kid: &str) -> Result<(), EnvelopeError> {
        self.sig = Some(identity::sign(self, signing_key, kid)?);
        Ok(())
    }

    /// Checks e.sig against pub_key. Callers resolve pub_key via
    /// (identity::domain_of(e.from), e.sig.kid) against the sender's domain
    /// index.
    pub fn verify(&self, pub_key: &VerifyingKey) -> Result<(), EnvelopeError> {
        if self.sig.is_none() {
            return Err(EnvelopeError::NoSig(self.id.clone()));
        }
        identity::verify_sig(self, self.sig.as_ref(), pub_key)?;
        Ok(())
    }

    /// Enforces the core §2.1 ttl bounds.
    pub fn validate_ttl(&self) -> Result<(), EnvelopeError> {
        if self.ttl < MIN_TTL || self.ttl > MAX_TTL {
            return Err(EnvelopeError::TtlOutOfBounds);
        }
        Ok(())
    }

    /// Enforces the core §2.1 256 KiB serialized-size cap.
    pub fn validate_size(&self) -> Result<(), EnvelopeError> {
        let raw = serde_json::to_vec(self)?;
        if raw.len() > MAX_SIZE {
            return Err(EnvelopeError::TooLarge);
        }
        Ok(())
    }
}
