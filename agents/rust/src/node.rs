//! A small in-memory (non-persistent) AWP participant: holds an ed25519
//! identity, serves a signed index + inbox over plain HTTP, and
//! dedupes/verifies inbound envelopes before handing `message`/`reply`
//! kinds to a message handler. The Rust counterpart to `agents/go/node.go`
//! and `agents/python/pyawp/node.py`, built on `sdk/rust`'s `Client` and
//! `identity`/`envelope` types rather than reimplementing any signing or
//! canonicalization.
//!
//! Simplified relative to the Go reference daemon in `internal/daemon` (see
//! `agents/rust/README.md` for the full list): the receiver gate below
//! implements core §2.2's checks in the mandated order, but "durably
//! enqueue" (step 5) means an in-memory `tokio::spawn`, not a persisted
//! queue that survives a restart — there is no `internal/store` here at
//! all. `seen`-id dedupe is an in-memory `HashMap`, not bbolt. Neither
//! changes the wire behavior a peer observes; both mean this process's
//! state is gone if it crashes, which `internal/store` is specifically
//! built to survive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use awp::client::Client;
use awp::envelope::Envelope;
use awp::identity::{self, domain_of, Index, Key};
use ed25519_dalek::SigningKey;
use serde_json::Value;

/// core §2.1's serialized-envelope cap, enforced at the inbox gate before
/// any parsing.
pub const MAX_ENVELOPE_SIZE: usize = 256 * 1024;

/// Lets a message handler reply within the thread it was invoked for,
/// without needing to know its own domain/thread bookkeeping.
pub type SendFn = Arc<
    dyn Fn(
            String,
            Value,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Envelope, awp::client::ClientError>> + Send,
            >,
        > + Send
        + Sync,
>;

/// Processes one inbound `message`/`reply` envelope.
pub type MessageHandler = Arc<
    dyn Fn(Envelope, SendFn) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

struct SeenEntry {
    accept_until: SystemTime,
}

/// A small in-memory AWP participant. Mirrors `agents/go/node.go`'s `Node`.
pub struct Node {
    pub domain: String,
    pub kid: String,
    signing_key: SigningKey,

    pub on_message: Mutex<Option<MessageHandler>>,

    client: Mutex<Option<Arc<Client>>>,
    index: Mutex<Index>,

    seen: Mutex<HashMap<String, SeenEntry>>,
}

impl Node {
    /// Generates a fresh ed25519 identity and an unfinalized signed index
    /// (inbox left empty until `finalize` is called, once the listen
    /// address is known).
    pub fn new(domain: impl Into<String>, kid: impl Into<String>) -> Self {
        let domain = domain.into();
        let kid = kid.into();
        let signing_key = identity::generate_keypair();
        let pub_b64 = awp::b64::url_encode(signing_key.verifying_key().as_bytes());

        let mut index = Index {
            awp: "0.1".to_string(),
            domain: domain.clone(),
            updated: identity::now_rfc3339_milli(),
            keys: Some(vec![Key {
                kid: kid.clone(),
                alg: "ed25519".to_string(),
                pub_: pub_b64,
                created: identity::now_rfc3339_milli(),
                expires: None,
                revoked: false,
                prev_sig: None,
            }]),
            entities: None,
            inbox: String::new(),
            peers: None,
            crawl: None,
            transports: None,
            capabilities: None,
            wake: None,
            sig: None,
        };
        index
            .sign(&signing_key, &kid)
            .expect("signing a freshly built index cannot fail");

        Node {
            domain,
            kid,
            signing_key,
            on_message: Mutex::new(None),
            client: Mutex::new(None),
            index: Mutex::new(index),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Sets this node's advertised inbox URL and re-signs the index — call
    /// once its own reachable address is known, before any peer is
    /// expected to fetch `/.well-known/awp.json`. `index_url` resolves a
    /// peer's domain to the base URL its index should be fetched from (the
    /// static-map DNS stand-in for these `*.local` demo domains).
    pub fn finalize<F>(&self, inbox_url: String, index_url: F)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        {
            let mut idx = self.index.lock().unwrap();
            idx.inbox = inbox_url;
            idx.updated = identity::now_rfc3339_milli();
            idx.sign(&self.signing_key, &self.kid)
                .expect("signing a finalized index cannot fail");
        }

        let signing_key_bytes = self.signing_key.to_bytes();
        let mut client = Client::new(
            self.domain.clone(),
            self.kid.clone(),
            SigningKey::from_bytes(&signing_key_bytes),
        );
        client.index_url = Some(Box::new(move |domain: &str| {
            format!("{}/.well-known/awp.json", index_url(domain))
        }));
        *self.client.lock().unwrap() = Some(Arc::new(client));
    }

    fn client(&self) -> Arc<Client> {
        self.client
            .lock()
            .unwrap()
            .clone()
            .expect("node: called before finalize()")
    }

    pub fn index_json(&self) -> Value {
        let idx = self.index.lock().unwrap();
        serde_json::to_value(&*idx).expect("Index always serializes")
    }

    /// Delivers a signed envelope of the given kind directly to `to`'s
    /// resolved inbox via the SDK client. Call `finalize` first.
    pub async fn send(
        &self,
        kind: &str,
        to: &str,
        thread: &str,
        in_reply_to: Option<String>,
        body: Value,
    ) -> Result<Envelope, awp::client::ClientError> {
        let client = self.client();
        client
            .send_envelope(kind, to, thread, in_reply_to, body, 0)
            .await
    }

    /// core §0.1's rotation-race handling: verifiers MUST re-fetch the
    /// signer's index once on failure before hard-failing.
    async fn resolve_with_retry(
        &self,
        domain: &str,
        kid: &str,
    ) -> Result<ed25519_dalek::VerifyingKey, awp::client::ClientError> {
        let client = self.client();
        match client.resolve(domain, kid).await {
            Ok(pk) => Ok(pk),
            Err(first_err) => {
                if client.refresh(domain).await.is_err() {
                    return Err(first_err);
                }
                client.resolve(domain, kid).await
            }
        }
    }

    /// Implements core §2.2's gate, in the mandated order:
    /// 1. parse (with size limit) -> 400
    /// 2. now <= ts + ttl -> 410
    /// 3. verify sig (one refresh-and-retry on failure) -> 401
    /// 4. dedupe on id -> 200 (already accepted, not reprocessed)
    /// 5. enqueue -> 202 (an in-memory tokio task here, not a durable
    ///    queue — see this module's doc comment)
    ///
    /// Returns `(status, body)`.
    pub async fn handle_inbox(self: &Arc<Self>, raw: &[u8]) -> (u16, Vec<u8>) {
        if raw.len() > MAX_ENVELOPE_SIZE {
            return (400, error_body("malformed", "envelope exceeds 256 KiB"));
        }

        let env: Envelope = match serde_json::from_slice(raw) {
            Ok(e) => e,
            Err(e) => return (400, error_body("malformed", &format!("parse error: {e}"))),
        };

        let ts = match awp::rfc3339::parse(&env.ts) {
            Ok(t) => t,
            Err(_) => return (400, error_body("malformed", "bad ts")),
        };
        let expires_at = ts + Duration::from_secs(env.ttl.max(0) as u64);
        if SystemTime::now() > expires_at {
            return (410, error_body("expired", "envelope ttl expired"));
        }

        let Some(sig) = env.sig.clone() else {
            return (401, error_body("unauthorized", "missing signature"));
        };
        let from_domain = domain_of(&env.from);
        let pub_key = match self.resolve_with_retry(&from_domain, &sig.kid).await {
            Ok(pk) => pk,
            Err(e) => {
                return (
                    401,
                    error_body("unauthorized", &format!("resolve signer failed: {e}")),
                )
            }
        };
        if let Err(e) = env.verify(&pub_key) {
            return (
                401,
                error_body(
                    "unauthorized",
                    &format!("signature verification failed: {e}"),
                ),
            );
        }

        {
            let mut seen = self.seen.lock().unwrap();
            let now = SystemTime::now();
            seen.retain(|_, entry| entry.accept_until > now);
            if let Some(entry) = seen.get(&env.id) {
                if entry.accept_until > now {
                    return (200, Vec::new());
                }
            }
            seen.insert(
                env.id.clone(),
                SeenEntry {
                    accept_until: expires_at,
                },
            );
        }

        let node = Arc::clone(self);
        tokio::spawn(async move {
            node.process(env).await;
        });
        (202, Vec::new())
    }

    /// Hands "content to respond to" envelopes to `on_message`. Per core
    /// §2.4, both `message` (opens/continues a thread unsolicited) and
    /// `reply` (a substantive response within one) carry content a
    /// participant should act on; `ack`/`close`/`error` do not. Matches
    /// `agents/go/node.go`'s `Node.process` (see that file's doc comment
    /// for why this deliberately differs from the stricter
    /// `agents/python/pyawp/node.py` filter): this agent has to correctly
    /// carry to completion both a thread it opens
    /// (activities.local -> trip-planner.local) and one opened against it
    /// (concierge.local -> activities.local), so its gate reacts to both
    /// kinds.
    async fn process(self: Arc<Self>, env: Envelope) {
        let handler = self.on_message.lock().unwrap().clone();
        let Some(handler) = handler else { return };
        match env.kind.as_str() {
            "message" | "reply" => {}
            _ => return,
        }

        let node = Arc::clone(&self);
        let from = env.from.clone();
        let thread = env.thread.clone();
        let in_reply_to = env.id.clone();
        let send: SendFn = Arc::new(move |kind: String, body: Value| {
            let node = Arc::clone(&node);
            let from = from.clone();
            let thread = thread.clone();
            let in_reply_to = in_reply_to.clone();
            Box::pin(async move {
                node.send(&kind, &from, &thread, Some(in_reply_to), body)
                    .await
            })
        });

        handler(env, send).await;
    }
}

fn error_body(code: &str, detail: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": {"code": code, "detail": detail, "retryable": false}
    }))
    .unwrap_or_default()
}
