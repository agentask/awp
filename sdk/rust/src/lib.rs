//! `awp` is the AWP reference Rust SDK: a thin client for sending
//! envelopes and calling sync tools.
//!
//! "Thin" is deliberate: unlike `awpd`, this client keeps no on-disk
//! state, runs no retry/outbox state machine, and does not receive
//! envelopes on its own — it is for third-party Rust programs that want to
//! speak AWP directly (sign, send, verify) without running a daemon.
//! Domain indexes are cached in memory for the lifetime of the
//! [`client::Client`] only.
//!
//! Beyond literal parity with `sdk/go`'s `Client`, this crate also exposes
//! inbound-envelope signature verification and identity-bootstrap helpers
//! (keypair generation, self-signed Index construction, Manifest signing)
//! — a Go program gets these for free by importing `internal/envelope` and
//! `internal/identity` directly, since `sdk/go` lives in the same module as
//! those packages; a Rust program has no such `internal/` to reach into,
//! so this crate provides the equivalent surface directly.

pub mod apperr;
pub mod b64;
pub mod client;
pub mod delegation;
pub mod envelope;
pub mod httpsig;
pub mod identity;
pub mod jcs;
pub mod manifest;
pub mod rfc3339;

pub use client::{CallOptions, Client, ClientError, SessionInfo};
