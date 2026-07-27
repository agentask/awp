//! Two distinct base64 codecs are used on the wire, deliberately kept
//! separate rather than defaulting to one engine everywhere: signatures and
//! public keys use unpadded base64url (Go's `base64.RawURLEncoding`);
//! Content-Digest uses padded standard base64 (Go's `base64.StdEncoding`).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

pub fn url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

pub fn std_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
