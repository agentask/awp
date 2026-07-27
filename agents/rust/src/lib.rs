//! `activities-agent`'s library surface: split out from `main.rs` purely so
//! `tests/` (an external integration-test crate per Cargo convention) can
//! exercise `Node`'s index construction and inbox gate directly, the same
//! way `agents/go/node_test.go` tests `Node` in-package. Nothing here is
//! meant for reuse outside this demo binary.

pub mod config;
pub mod llm;
pub mod node;
pub mod persona;
