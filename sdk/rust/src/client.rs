//! A thin AWP client, signing as (domain, kid, signing_key). All methods
//! take `&self`/`&Client` and are safe for concurrent use via an internal
//! mutex-guarded cache.
//!
//! "Thin" is deliberate: unlike `awpd`, this client keeps no on-disk
//! state, runs no retry/outbox state machine, and does not receive
//! envelopes on its own — it is for third-party Rust programs that want to
//! speak AWP directly (sign, send, verify) without running a daemon.
//! Domain indexes are cached in memory for the lifetime of the Client
//! only.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::delegation::{self, Link, Scope};
use crate::envelope::{self, Envelope};
use crate::httpsig::{self, Headers, SignableRequest};
use crate::identity::{self, domain_of, Index};
use crate::manifest::{self, Manifest};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("awp: build index request for {0}: {1}")]
    BuildIndexRequest(String, String),
    #[error("awp: fetch index {0}: {1}")]
    FetchIndex(String, String),
    #[error("awp: fetch index {0}: status {1}")]
    FetchIndexStatus(String, u16),
    #[error("awp: parse index for {0}: {1}")]
    ParseIndex(String, String),
    #[error("awp: {0} index signature invalid: {1}")]
    IndexSignatureInvalid(String, String),
    #[error("awp: key {0}/{1} is revoked")]
    KeyRevoked(String, String),
    #[error("awp: no key {0}/{1} in {2}'s index")]
    NoSuchKey(String, String, String),
    #[error("awp: {0} declares no inbox")]
    NoInbox(String),
    #[error("awp: {0} is not listed in {1}'s index")]
    NotListed(String, String),
    #[error("awp: build manifest request for {0}: {1}")]
    BuildManifestRequest(String, String),
    #[error("awp: fetch manifest {0}: {1}")]
    FetchManifest(String, String),
    #[error("awp: fetch manifest {0}: status {1}")]
    FetchManifestStatus(String, u16),
    #[error("awp: manifest for {0}: {1}")]
    ManifestPin(String, String),
    #[error("awp: parse manifest for {0}: {1}")]
    ParseManifest(String, String),
    #[error("awp: manifest for {0} has no signature")]
    ManifestNoSig(String),
    #[error("awp: resolve manifest signer for {0}: {1}")]
    ResolveManifestSigner(String, String),
    #[error("awp: manifest signature invalid for {0}: {1}")]
    ManifestSignatureInvalid(String, String),
    #[error(transparent)]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("awp: deliver to {0}: {1}")]
    Deliver(String, String),
    #[error("awp: {0} rejected envelope: status {1}: {2}")]
    Rejected(String, u16, String),
    #[error("awp: {0} has no hosted (sync) endpoint")]
    NoHostedEndpoint(String),
    #[error("awp: build tool call request: {0}")]
    BuildToolCallRequest(String),
    #[error("awp: marshal delegation chain: {0}")]
    MarshalDelegation(String),
    #[error("awp: marshal transaction header: {0}")]
    MarshalTransaction(String),
    #[error("awp: sign tool call: {0}")]
    SignToolCall(String),
    #[error("awp: call {0}: {1}")]
    CallTool(String, String),
    #[error("awp: read tool response: {0}")]
    ReadToolResponse(String),
    #[error("awp: tool response signature invalid: {0}: {1}")]
    ResponseSignatureInvalid(String, String),
    #[error("awp: tool call failed: {0}: {1}")]
    ToolCallFailed(String, String),
    #[error("awp: tool call failed: status {0}: {1}")]
    ToolCallFailedStatus(u16, String),
    #[error("awp: parse tool response: {0}")]
    ParseToolResponse(String),
    #[error("awp: sign delegation link: {0}")]
    SignDelegationLink(String),
    #[error("awp: resolve {0}: {1}")]
    Resolve(String, Box<ClientError>),
    #[error("awp: {0}")]
    Other(String),
}

/// A previously-issued sync-call session, returned by a "provider"-state
/// tool on a caller's first call (core §1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub token: String,
    pub sid: String,
    pub expires: String,
}

/// awp-transactions-v0.1.md §2: the decoded shape of an AWP-Transaction
/// header. `id` is a ULID minted once by the coordinator for the whole
/// transaction attempt; `step` is the 0-indexed position of this call in
/// the coordinator's sequence — compensating calls SHOULD reuse the
/// forward call's step, since `(id, step)` identifies "this logical unit
/// of work," not "this specific HTTP request."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub step: i64,
    pub coordinator: String,
}

impl Transaction {
    /// base64url(JSON(self)) — the exact `AWP-Transaction` header value.
    pub fn encode(&self) -> Result<String, ClientError> {
        let raw =
            serde_json::to_vec(self).map_err(|e| ClientError::MarshalTransaction(e.to_string()))?;
        Ok(crate::b64::url_encode(&raw))
    }
}

/// Configures an optional sync-call session/delegation/dry-run/transaction.
#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    /// A previously-issued AWP-Session token (core §1.3). Leave empty for
    /// the first call to a stateful ("provider") tool.
    pub session: Option<String>,
    /// A pre-built, pre-signed core §2.5 chain proving the caller is
    /// acting on a delegator's behalf.
    pub delegation: Vec<Link>,
    /// Sets `AWP-Dry-Run: true` (awp-capabilities-v0.1.md §3.1) — an
    /// ordinary `AWP-*` header, covered by the signature automatically
    /// with no change to `httpsig::sign`'s covered-component logic.
    /// Advisory: a provider that never declared the "dry-run" capability
    /// MAY ignore it silently rather than reject the call.
    pub dry_run: bool,
    /// Sets `AWP-Transaction` (awp-transactions-v0.1.md §2) — like
    /// `dry_run`, an ordinary `AWP-*` header covered by the signature
    /// automatically.
    pub transaction: Option<Transaction>,
}

/// An `IndexUrlFn` maps a domain to the URL its signed index should be
/// fetched from.
pub type IndexUrlFn = Box<dyn Fn(&str) -> String + Send + Sync>;

/// A thin AWP client, signing as (domain, kid, signing_key).
pub struct Client {
    pub domain: String,
    pub kid: String,
    pub signing_key: SigningKey,

    /// The HTTP client used for all outbound requests.
    pub http: reqwest::Client,

    /// Overrides where a domain's index is fetched from; `None` uses
    /// "https://" + domain + "/.well-known/awp.json". Override for
    /// local/test use (e.g. pointing at a local mock server).
    pub index_url: Option<IndexUrlFn>,

    cache: Mutex<HashMap<String, Index>>,
}

impl Client {
    pub fn new(domain: impl Into<String>, kid: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            domain: domain.into(),
            kid: kid.into(),
            signing_key,
            http: reqwest::Client::new(),
            index_url: None,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn index_url_for(&self, domain: &str) -> String {
        match &self.index_url {
            Some(f) => f(domain),
            None => format!("https://{domain}/.well-known/awp.json"),
        }
    }

    fn key_id(&self) -> String {
        format!("{}/{}", self.domain, self.kid)
    }

    /// Resolves domain's signed index, caching it for the lifetime of the
    /// Client. The index's self-signature is verified (TOFU: the first
    /// fetch establishes trust in whichever key it names).
    pub async fn fetch_index(&self, domain: &str) -> Result<Index, ClientError> {
        if let Some(idx) = self.cache.lock().unwrap().get(domain) {
            return Ok(idx.clone());
        }
        self.fetch_index_uncached(domain).await
    }

    /// Discards domain's cached index and re-fetches it. This SDK does not
    /// persist a rotation history across process runs, so refresh simply
    /// re-fetches and re-trusts (TOFU) the new document.
    pub async fn refresh(&self, domain: &str) -> Result<(), ClientError> {
        self.fetch_index_uncached(domain).await?;
        Ok(())
    }

    async fn fetch_index_uncached(&self, domain: &str) -> Result<Index, ClientError> {
        let url = self.index_url_for(domain);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::FetchIndex(url.clone(), e.to_string()))?;
        let status = resp.status();
        let raw = resp
            .bytes()
            .await
            .map_err(|e| ClientError::FetchIndex(url.clone(), e.to_string()))?;
        if !status.is_success() {
            return Err(ClientError::FetchIndexStatus(url, status.as_u16()));
        }
        let idx: Index = serde_json::from_slice(&raw)
            .map_err(|e| ClientError::ParseIndex(domain.to_string(), e.to_string()))?;
        idx.verify_self_sig()
            .map_err(|e| ClientError::IndexSignatureInvalid(domain.to_string(), e.to_string()))?;

        self.cache
            .lock()
            .unwrap()
            .insert(domain.to_string(), idx.clone());
        Ok(idx)
    }

    /// Looks up (domain, kid) in that domain's index, fetching it first if
    /// needed, rejecting revoked keys.
    pub async fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, ClientError> {
        let idx = self.fetch_index(domain).await?;
        let keys = idx.keys.as_deref().unwrap_or(&[]);
        for k in keys {
            if k.kid == kid {
                if k.revoked {
                    return Err(ClientError::KeyRevoked(domain.to_string(), kid.to_string()));
                }
                return k.pub_key().map_err(|e| ClientError::Other(e.to_string()));
            }
        }
        Err(ClientError::NoSuchKey(
            domain.to_string(),
            kid.to_string(),
            domain.to_string(),
        ))
    }

    /// Resolves principal's manifest via its domain's index, verifying its
    /// sha256 pin (core §1.2) and its own signature before returning it.
    pub async fn fetch_manifest(&self, principal: &str) -> Result<Manifest, ClientError> {
        let domain = domain_of(principal);
        let idx = self
            .fetch_index(&domain)
            .await
            .map_err(|e| ClientError::Resolve(domain.clone(), Box::new(e)))?;
        self.fetch_manifest_with_index(&idx, principal).await
    }

    async fn fetch_manifest_with_index(
        &self,
        idx: &Index,
        principal: &str,
    ) -> Result<Manifest, ClientError> {
        let entities = idx.entities.as_deref().unwrap_or(&[]);
        let entry = entities
            .iter()
            .find(|e| e.name == principal)
            .ok_or_else(|| ClientError::NotListed(principal.to_string(), domain_of(principal)))?;

        let resp = self
            .http
            .get(&entry.manifest)
            .send()
            .await
            .map_err(|e| ClientError::FetchManifest(entry.manifest.clone(), e.to_string()))?;
        let status = resp.status();
        let raw = resp
            .bytes()
            .await
            .map_err(|e| ClientError::FetchManifest(entry.manifest.clone(), e.to_string()))?;
        if !status.is_success() {
            return Err(ClientError::FetchManifestStatus(
                entry.manifest.clone(),
                status.as_u16(),
            ));
        }
        manifest::verify_pinned_sha256(&raw, &entry.manifest_sha256)
            .map_err(|e| ClientError::ManifestPin(principal.to_string(), e.to_string()))?;
        let m: Manifest = serde_json::from_slice(&raw)
            .map_err(|e| ClientError::ParseManifest(principal.to_string(), e.to_string()))?;
        if m.sig.is_none() {
            return Err(ClientError::ManifestNoSig(principal.to_string()));
        }
        let sig = m.sig.as_ref().unwrap();
        let pub_key = self
            .resolve(&domain_of(&m.name), &sig.kid)
            .await
            .map_err(|e| {
                ClientError::ResolveManifestSigner(principal.to_string(), e.to_string())
            })?;
        m.verify(&pub_key).map_err(|e| {
            ClientError::ManifestSignatureInvalid(principal.to_string(), e.to_string())
        })?;
        Ok(m)
    }

    /// Builds, signs, and delivers an envelope directly to `to`'s resolved
    /// inbox. This is a single synchronous delivery attempt — no retry, no
    /// persistence; a caller wanting outbox semantics (backoff,
    /// dead-lettering, resumable delivery across process restarts) should
    /// run `awpd` instead of this SDK.
    ///
    /// `ttl` of 0 defaults to 3600s. `in_reply_to` may be `None`.
    pub async fn send_envelope(
        &self,
        kind: &str,
        to: &str,
        thread: &str,
        in_reply_to: Option<String>,
        body: Value,
        ttl: i64,
    ) -> Result<Envelope, ClientError> {
        let ttl = if ttl == 0 { 3600 } else { ttl };
        let mut e = Envelope {
            awp: "0.1".to_string(),
            id: envelope::new_id(),
            kind: kind.to_string(),
            from: self.domain.clone(),
            to: to.to_string(),
            thread: thread.to_string(),
            in_reply_to,
            ts: identity::now_rfc3339_milli(),
            ttl,
            session: None,
            delegation: None,
            body,
            sig: None,
        };
        e.validate_ttl()?;
        e.sign(&self.signing_key, &self.kid)?;
        e.validate_size()?;
        let raw = serde_json::to_vec(&e).map_err(|err| ClientError::Other(err.to_string()))?;

        let domain = domain_of(to);
        let idx = self
            .fetch_index(&domain)
            .await
            .map_err(|err| ClientError::Resolve(domain.clone(), Box::new(err)))?;
        if idx.inbox.is_empty() {
            return Err(ClientError::NoInbox(domain));
        }

        let resp = self
            .http
            .post(&idx.inbox)
            .header("Content-Type", "application/awp+json")
            .body(raw)
            .send()
            .await
            .map_err(|err| ClientError::Deliver(idx.inbox.clone(), err.to_string()))?;
        let status = resp.status();
        let resp_body = resp.text().await.unwrap_or_default();
        if status.as_u16() != 200 && status.as_u16() != 202 {
            return Err(ClientError::Rejected(idx.inbox, status.as_u16(), resp_body));
        }
        Ok(e)
    }

    /// Builds, signs, and delivers one awp-streaming-v0.1.md §2
    /// stream_chunk envelope — a thin convenience wrapper over
    /// `send_envelope` with the correct body shape, nothing more. This
    /// SDK does not reassemble streams on the receiving side (it has no
    /// persistent state at all, per this module's own single-delivery-
    /// attempt design); a receiving daemon
    /// (`internal/daemon`'s `Config.StreamChunkHandler`) does that
    /// buffering/gap-filling.
    ///
    /// `kind` is typically "reply" (awp-streaming-v0.1.md §2) — pass
    /// "message" if a caller's protocol design calls for that instead.
    /// `stream_id` should be a fresh `envelope::new_id()` for `seq: 0` of
    /// a new stream, then the SAME value for every subsequent chunk of
    /// that stream. `seq` is 0-based and MUST strictly increase per
    /// `stream_id`. `final_` MUST be `true` on exactly one chunk: the
    /// last one (named `final_` — `final` is a reserved word in Rust).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_stream_chunk(
        &self,
        kind: &str,
        to: &str,
        thread: &str,
        in_reply_to: Option<String>,
        stream_id: &str,
        seq: i64,
        final_: bool,
        data: Value,
        ttl: i64,
    ) -> Result<Envelope, ClientError> {
        let body = serde_json::json!({
            "type": "stream_chunk",
            "stream_id": stream_id,
            "seq": seq,
            "final": final_,
            "data": data,
        });
        self.send_envelope(kind, to, thread, in_reply_to, body, ttl)
            .await
    }

    /// Resolves `tool_principal`'s manifest, signs a sync HTTP call per
    /// awp-sig, and returns its output. If the provider signs its response
    /// (awp-sig §3, SHOULD), that signature is verified — a
    /// present-but-invalid response signature is treated as an error, per
    /// spec; an absent one is not.
    pub async fn call_tool(
        &self,
        tool_principal: &str,
        input: Value,
        opts: CallOptions,
    ) -> Result<(Value, Option<SessionInfo>), ClientError> {
        let domain = domain_of(tool_principal);
        let idx = self
            .fetch_index(&domain)
            .await
            .map_err(|e| ClientError::Resolve(domain.clone(), Box::new(e)))?;
        let m = self.fetch_manifest_with_index(&idx, tool_principal).await?;
        let Some(hosted) = &m.distribution.hosted else {
            return Err(ClientError::NoHostedEndpoint(tool_principal.to_string()));
        };

        let input_bytes = serde_json::to_vec(&input)
            .map_err(|e| ClientError::BuildToolCallRequest(e.to_string()))?;

        let mut headers = Headers::new();
        if let Some(session) = &opts.session {
            if !session.is_empty() {
                headers.set("awp-session", session.clone());
            }
        }
        if !opts.delegation.is_empty() {
            let chain_json = serde_json::to_vec(&opts.delegation)
                .map_err(|e| ClientError::MarshalDelegation(e.to_string()))?;
            headers.set("awp-delegation", crate::b64::url_encode(&chain_json));
        }
        if opts.dry_run {
            headers.set("awp-dry-run", "true".to_string());
        }
        if let Some(transaction) = &opts.transaction {
            headers.set("awp-transaction", transaction.encode()?);
        }

        let mut sig_req = SignableRequest {
            method: "POST".to_string(),
            target_uri: hosted.endpoint.clone(),
            headers,
        };
        httpsig::sign(
            &mut sig_req,
            &input_bytes,
            &self.signing_key,
            &self.key_id(),
            SystemTime::now(),
        )
        .map_err(|e| ClientError::SignToolCall(e.to_string()))?;

        let mut req_builder = self.http.post(&hosted.endpoint).body(input_bytes.clone());
        for name in sig_req.headers.names() {
            if let Some(v) = sig_req.headers.get(name) {
                req_builder = req_builder.header(name, v);
            }
        }

        let resp = req_builder
            .send()
            .await
            .map_err(|e| ClientError::CallTool(hosted.endpoint.clone(), e.to_string()))?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| ClientError::ReadToolResponse(e.to_string()))?;

        let mut sig_resp_headers = Headers::new();
        for (name, value) in resp_headers.iter() {
            if let Ok(v) = value.to_str() {
                sig_resp_headers.set(name.as_str(), v.to_string());
            }
        }
        let sig_resp = crate::httpsig::SignableResponse {
            status: status.as_u16(),
            headers: sig_resp_headers,
        };
        // httpsig::verify_response's KeyResolver is a sync trait (it mirrors
        // the Go interface, backed there by an in-memory cache after the
        // first fetch — Resolve never itself does I/O on the Go side
        // either). Pre-fetch/cache the responding domain's index here,
        // async, before dropping into the sync verify call, rather than
        // giving verify_response a resolver that would need to block on
        // async I/O from inside an already-async task (which panics).
        if let Some(sig_input) = sig_resp.headers.get("signature-input") {
            if let Ok(parsed) = httpsig::parse_signature_input(sig_input) {
                if let Some((resp_domain, _)) = parsed.params.key_id.split_once('/') {
                    let _ = self.fetch_index(resp_domain).await;
                }
            }
        }
        let resolver = CachedKeyResolver(self);
        let verify_result =
            httpsig::verify_response(&sig_resp, &resp_body, SystemTime::now(), &resolver);
        if let Some(err) = verify_result.err {
            return Err(ClientError::ResponseSignatureInvalid(err.code, err.detail));
        }

        if status.as_u16() / 100 != 2 {
            if let Ok(err_body) = serde_json::from_slice::<crate::apperr::Body>(&resp_body) {
                if let Some(err) = err_body.error {
                    return Err(ClientError::ToolCallFailed(err.code, err.detail));
                }
            }
            return Err(ClientError::ToolCallFailedStatus(
                status.as_u16(),
                String::from_utf8_lossy(&resp_body).to_string(),
            ));
        }

        #[derive(Deserialize)]
        struct Out {
            #[serde(default)]
            output: Value,
            #[serde(default)]
            session: Option<SessionInfo>,
        }
        let out: Out = serde_json::from_slice(&resp_body)
            .map_err(|e| ClientError::ParseToolResponse(e.to_string()))?;
        Ok((out.output, out.session))
    }

    /// Builds and signs one core §2.5 delegation link with this Client as
    /// the delegator. `nonce` should be a fresh `envelope::new_id()` per
    /// link.
    pub fn sign_delegation_link(
        &self,
        delegate: &str,
        scope: Scope,
        expires: SystemTime,
        nonce: &str,
    ) -> Result<Link, ClientError> {
        let mut link = Link {
            delegator: self.domain.clone(),
            delegate: delegate.to_string(),
            scope,
            expires: crate::rfc3339::format_no_fraction(expires),
            nonce: nonce.to_string(),
            sig: None,
        };
        link.sign(&self.signing_key, &self.kid)
            .map_err(|e| ClientError::SignDelegationLink(e.to_string()))?;
        Ok(link)
    }

    /// Verifies an inbound envelope's signature, resolving the sender's
    /// key via the same index/resolve machinery `resolve` uses. Beyond
    /// literal sdk/go parity: sdk/go's Go callers get this for free by
    /// importing `internal/envelope`+`internal/identity` directly (it's
    /// one module); a Rust program building a receiving node on this SDK
    /// has no such `internal/` to reach into, so the Client exposes it
    /// directly.
    pub async fn verify_inbound_envelope(&self, e: &Envelope) -> Result<(), ClientError> {
        let sig = e
            .sig
            .as_ref()
            .ok_or_else(|| ClientError::Other(format!("envelope {:?} has no sig", e.id)))?;
        let domain = domain_of(&e.from);
        let pub_key = self.resolve(&domain, &sig.kid).await?;
        e.verify(&pub_key)
            .map_err(|err| ClientError::Other(err.to_string()))
    }
}

/// A purely in-memory-cache-reading resolver, handed to the sync
/// `httpsig::verify_response` call after the Client has already
/// async-fetched (and cached) whatever domain's index it needs. Deliberately
/// does no I/O of its own — `httpsig::KeyResolver`/`delegation::KeyResolver`
/// are sync traits (mirroring the Go interfaces, which are themselves
/// backed by an in-memory cache after the first fetch and never block on
/// I/O either), so a resolver that tried to `block_on` an async fetch from
/// inside this already-async call chain would panic (blocking the current
/// worker thread of the same runtime driving it). `refresh` is therefore a
/// deliberate no-op returning an error: the one caller of this resolver
/// (`call_tool`'s response verification) already performed its own
/// async refresh-equivalent (an unconditional fetch) before dropping into
/// sync `verify_response`, so step 4's "refresh once and retry" fallback
/// has nothing left to gain from a second, synchronous attempt.
struct CachedKeyResolver<'a>(&'a Client);

impl CachedKeyResolver<'_> {
    fn resolve_cached(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        let idx = self
            .0
            .cache
            .lock()
            .unwrap()
            .get(domain)
            .cloned()
            .ok_or_else(|| format!("{domain}'s index was not pre-fetched"))?;
        let keys = idx.keys.as_deref().unwrap_or(&[]);
        for k in keys {
            if k.kid == kid {
                if k.revoked {
                    return Err(format!("key {domain}/{kid} is revoked"));
                }
                return k.pub_key().map_err(|e| e.to_string());
            }
        }
        Err(format!("no key {domain}/{kid} in {domain}'s index"))
    }
}

impl httpsig::KeyResolver for CachedKeyResolver<'_> {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        self.resolve_cached(domain, kid)
    }

    fn refresh(&self, _domain: &str) -> Result<(), String> {
        Err("refresh is unavailable from a synchronous verify call; the async layer already refreshed".to_string())
    }
}

impl delegation::KeyResolver for CachedKeyResolver<'_> {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        self.resolve_cached(domain, kid)
    }
}
