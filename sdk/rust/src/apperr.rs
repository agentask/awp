//! The single {code, detail, retryable} error grammar shared by sync and
//! async paths (core §2.6).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub detail: String,
    pub retryable: bool,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

/// Wraps Error in the top-level {"error": ...} envelope used on the wire
/// (core §2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub error: Option<Error>,
}

pub const CODE_UNSUPPORTED_BODY: &str = "unsupported_body";
pub const CODE_UNAUTHORIZED_DELEGATION: &str = "unauthorized_delegation";
pub const CODE_CAPACITY: &str = "capacity";
pub const CODE_REFUSED: &str = "refused";
pub const CODE_INTERNAL: &str = "internal";

pub const CODE_MALFORMED: &str = "malformed";
pub const CODE_EXPIRED: &str = "expired";
pub const CODE_UNAUTHORIZED: &str = "unauthorized";
