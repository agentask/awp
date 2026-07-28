//! The AWP core §1.2 entity manifest: types, signing, and sha256 content
//! pinning against a domain index's entities[].manifest_sha256.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::identity::{self, IdentityError, Sig};

/// Holds the manifest's input/output JSON Schema pair (core §1.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoSchema {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
}

/// Describes a wasm32-wasip1 stdio-json/1 distribution (core §1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Portable {
    pub url: String,
    pub sha256: String,
    pub runtime: String,
    pub interface: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Describes a sync HTTP distribution (core §1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hosted {
    pub endpoint: String,
}

/// Requires at least one of hosted / portable (core §1.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Distribution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosted: Option<Hosted>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<Portable>,
}

/// The manifest's auth block; sig is always "required" in v0.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// One signed entity manifest document (core §1.2). `pricing` and `inbox`
/// are always-present JSON keys (Go's `json.RawMessage`/`*string`, neither
/// `omitempty`) — `null` when unset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub awp: String,
    pub name: String,
    pub kind: String,
    pub version: String,
    pub updated: String,
    pub description: String,
    #[serde(default)]
    pub io: IoSchema,
    #[serde(default)]
    pub distribution: Distribution,
    pub state: String,
    pub auth: Auth,
    pub pricing: Value,
    pub inbox: Option<String>,
    /// awp-capabilities-v0.1.md §2: absent/empty or "production" means
    /// production; "sandbox" marks the entity as safe to integrate
    /// against with no real-world side effects.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
    /// awp-capabilities-v0.1.md §3: entity-level feature declarations.
    /// The only token that document defines is "dry-run".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// awp-versioning-v0.1.md §1: an informational pointer, not fetched
    /// or verified by anything in this crate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub changelog: String,
    /// awp-versioning-v0.1.md §2: the sha256 (hex) of the immediately-
    /// prior signed manifest this one supersedes. Only verifiable by a
    /// holder of the prior document's actual bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_sha256: String,
    /// awp-transactions-v0.1.md §1: the principal of the tool that
    /// undoes this one's effect. Absence means this tool declares no
    /// compensating action — a step relying on it is irreversible.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compensated_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest: {0:?} has no sig")]
    NoSig(String),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(
        "manifest: sha256 pin mismatch: index pins {want:?}, fetched document hashes to {got:?}"
    )]
    PinMismatch { want: String, got: String },
}

/// awp-capabilities-v0.1.md §3's token a manifest lists in `capabilities`
/// to declare it honors `AWP-Dry-Run`.
pub const DRY_RUN_CAPABILITY: &str = "dry-run";

/// awp-capabilities-v0.1.md §2's non-production marker.
/// `ENVIRONMENT_PRODUCTION` is the default and never needs to be set
/// explicitly — an absent/empty `environment` means production.
pub const ENVIRONMENT_SANDBOX: &str = "sandbox";
pub const ENVIRONMENT_PRODUCTION: &str = "production";

impl Manifest {
    /// Attaches m.sig per core §0.1, signed by domain_of(m.name)'s key.
    pub fn sign(&mut self, signing_key: &SigningKey, kid: &str) -> Result<(), ManifestError> {
        self.sig = Some(identity::sign(self, signing_key, kid)?);
        Ok(())
    }

    /// Reports whether m declares support for `capability` — e.g.
    /// `m.has_capability(DRY_RUN_CAPABILITY)`.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|c| c == capability)
    }

    /// Checks m.sig against pub_key. Callers resolve pub_key via
    /// (identity::domain_of(m.name), m.sig.kid) against the domain's
    /// index.
    pub fn verify(&self, pub_key: &VerifyingKey) -> Result<(), ManifestError> {
        if self.sig.is_none() {
            return Err(ManifestError::NoSig(self.name.clone()));
        }
        identity::verify_sig(self, self.sig.as_ref(), pub_key)?;
        Ok(())
    }
}

/// Checks the raw fetched manifest document bytes against the
/// index-pinned hex sha256 digest. This MUST be checked before the
/// manifest's own signature is verified (core §1.2) — hash the exact bytes
/// as received over the wire, not a reserialization of the parsed struct.
pub fn verify_pinned_sha256(raw: &[u8], want_hex: &str) -> Result<(), ManifestError> {
    let mut hasher = Sha256::new();
    hasher.update(raw);
    let got = hex::encode(hasher.finalize());
    if got != want_hex {
        return Err(ManifestError::PinMismatch {
            want: want_hex.to_string(),
            got,
        });
    }
    Ok(())
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
