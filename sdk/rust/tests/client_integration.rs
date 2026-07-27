//! Exercises `Client` end-to-end against a bare `hyper` mock server
//! standing in for a peer's `/.well-known/awp.json`, manifest endpoint,
//! inbox, and a sync tool endpoint — covering `fetch_index` (cache + TOFU
//! verify), `fetch_manifest` (pin-then-signature), `send_envelope`, and
//! `call_tool` (request signing + AWP-Session + response verification).

use awp::client::Client;
use awp::identity::{self, generate_keypair, Entity, Index, Key};
use awp::manifest::{Auth, Distribution, Hosted, IoSchema, Manifest};
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

struct PeerFixture {
    domain: String,
    signing_key: SigningKey,
    kid: String,
    index_json: Vec<u8>,
    manifest_json: Vec<u8>,
    manifest_sha256_hex: String,
}

fn build_peer(domain: &str, base_url: &str) -> PeerFixture {
    let signing_key = generate_keypair();
    let kid = "k1".to_string();

    let manifest_endpoint = format!("{base_url}/awp/tools/echo");
    let mut m = Manifest {
        awp: "0.1".to_string(),
        name: format!("{domain}#echo"),
        kind: "tool".to_string(),
        version: "1.0.0".to_string(),
        updated: identity::now_rfc3339_milli(),
        description: "echoes input".to_string(),
        io: IoSchema::default(),
        distribution: Distribution {
            hosted: Some(Hosted {
                endpoint: manifest_endpoint,
            }),
            portable: None,
        },
        state: "stateless".to_string(),
        auth: Auth {
            sig: "required".to_string(),
            scopes: None,
        },
        pricing: serde_json::Value::Null,
        inbox: None,
        sig: None,
    };
    m.sign(&signing_key, &kid).expect("sign manifest");
    let manifest_json = serde_json::to_vec(&m).unwrap();
    let manifest_sha256_hex = {
        let sum = Sha256::digest(&manifest_json);
        sum.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    let mut idx = Index {
        awp: "0.1".to_string(),
        domain: domain.to_string(),
        updated: identity::now_rfc3339_milli(),
        keys: Some(vec![Key {
            kid: kid.clone(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(signing_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: None,
        }]),
        entities: Some(vec![Entity {
            name: format!("{domain}#echo"),
            kind: "tool".to_string(),
            manifest: format!("{base_url}/manifest.json"),
            manifest_sha256: manifest_sha256_hex.clone(),
        }]),
        inbox: format!("{base_url}/awp/inbox"),
        peers: None,
        crawl: None,
        transports: None,
        sig: None,
    };
    idx.sign(&signing_key, &kid).expect("sign index");
    let index_json = serde_json::to_vec(&idx).unwrap();

    PeerFixture {
        domain: domain.to_string(),
        signing_key,
        kid,
        index_json,
        manifest_json,
        manifest_sha256_hex,
    }
}

/// Binds an ephemeral local port and returns its base URL without yet
/// starting to accept connections — used so a fixture's own signed
/// documents (index/manifest) can embed the real base URL before the
/// server that will serve them is spawned, avoiding a bind-serve-rebuild
/// chicken-and-egg dance.
async fn reserve_port() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    (listener, format!("http://{addr}"))
}

async fn serve(
    listener: TcpListener,
    fixture: Arc<PeerFixture>,
    inbox_hits: Arc<AtomicUsize>,
    last_inbox_body: Arc<AsyncMutex<Vec<u8>>>,
) {
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let io = TokioIo::new(stream);
            let fixture = fixture.clone();
            let inbox_hits = inbox_hits.clone();
            let last_inbox_body = last_inbox_body.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let fixture = fixture.clone();
                    let inbox_hits = inbox_hits.clone();
                    let last_inbox_body = last_inbox_body.clone();
                    async move { handle(req, fixture, inbox_hits, last_inbox_body).await }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
}

async fn handle(
    req: Request<Incoming>,
    fixture: Arc<PeerFixture>,
    inbox_hits: Arc<AtomicUsize>,
    last_inbox_body: Arc<AsyncMutex<Vec<u8>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    match path.as_str() {
        "/.well-known/awp.json" => Ok(Response::new(Full::new(Bytes::from(
            fixture.index_json.clone(),
        )))),
        "/manifest.json" => Ok(Response::new(Full::new(Bytes::from(
            fixture.manifest_json.clone(),
        )))),
        "/awp/inbox" => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            *last_inbox_body.lock().await = body.to_vec();
            inbox_hits.fetch_add(1, Ordering::SeqCst);
            Ok(Response::builder()
                .status(200)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        "/awp/tools/echo" => {
            let body = req
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let input: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            let out = json!({"output": {"echoed": input}});
            let out_bytes = serde_json::to_vec(&out).unwrap();

            let mut resp_headers = awp::httpsig::Headers::new();
            let mut sig_resp = awp::httpsig::SignableResponse {
                status: 200,
                headers: awp::httpsig::Headers::new(),
            };
            awp::httpsig::sign_response(
                &mut sig_resp,
                &out_bytes,
                &fixture.signing_key,
                &format!("{}/{}", fixture.domain, fixture.kid),
                std::time::SystemTime::now(),
            )
            .expect("sign response");
            for name in sig_resp.headers.names() {
                if let Some(v) = sig_resp.headers.get(name) {
                    resp_headers.set(name, v.to_string());
                }
            }

            let mut builder = Response::builder().status(200);
            for name in resp_headers.names() {
                if let Some(v) = resp_headers.get(name) {
                    builder = builder.header(name, v);
                }
            }
            Ok(builder.body(Full::new(Bytes::from(out_bytes))).unwrap())
        }
        _ => Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
}

fn make_client(
    domain: &str,
    signing_key: SigningKey,
    kid: &str,
    index_urls: std::collections::HashMap<String, String>,
) -> Client {
    let mut c = Client::new(domain, kid, signing_key);
    c.index_url = Some(Box::new(move |d: &str| {
        index_urls
            .get(d)
            .cloned()
            .unwrap_or_else(|| format!("https://{d}/.well-known/awp.json"))
    }));
    c
}

async fn start_peer(
    domain: &str,
) -> (
    Arc<PeerFixture>,
    String,
    Arc<AtomicUsize>,
    Arc<AsyncMutex<Vec<u8>>>,
) {
    let (listener, base) = reserve_port().await;
    let fixture = Arc::new(build_peer(domain, &base));
    let inbox_hits = Arc::new(AtomicUsize::new(0));
    let last_body = Arc::new(AsyncMutex::new(Vec::new()));
    serve(
        listener,
        fixture.clone(),
        inbox_hits.clone(),
        last_body.clone(),
    )
    .await;
    (fixture, base, inbox_hits, last_body)
}

#[tokio::test]
async fn fetch_index_verifies_self_sig_and_caches() {
    let (_fixture, base, _hits, _body) = start_peer("peer.local").await;

    let caller_key = generate_keypair();
    let mut index_urls = std::collections::HashMap::new();
    index_urls.insert(
        "peer.local".to_string(),
        format!("{base}/.well-known/awp.json"),
    );
    let client = make_client("caller.local", caller_key, "ck1", index_urls);

    let idx1 = client.fetch_index("peer.local").await.expect("fetch_index");
    assert_eq!(idx1.domain, "peer.local");
    let idx2 = client
        .fetch_index("peer.local")
        .await
        .expect("fetch_index cached");
    assert_eq!(
        idx1.updated, idx2.updated,
        "second fetch should return the cached document unchanged"
    );
}

#[tokio::test]
async fn fetch_manifest_verifies_pin_then_signature() {
    let (fixture, base, _hits, _body) = start_peer("tool.local").await;

    let caller_key = generate_keypair();
    let mut index_urls = std::collections::HashMap::new();
    index_urls.insert(
        "tool.local".to_string(),
        format!("{base}/.well-known/awp.json"),
    );
    let client = make_client("caller.local", caller_key, "ck1", index_urls);

    let m = client
        .fetch_manifest("tool.local#echo")
        .await
        .expect("fetch_manifest");
    assert_eq!(m.name, "tool.local#echo");
    assert!(m.sig.is_some());

    // Confirm the pin actually matches what the server serves (sanity,
    // not testing Client internals directly).
    let raw = fixture.manifest_json.clone();
    awp::manifest::verify_pinned_sha256(&raw, &fixture.manifest_sha256_hex)
        .expect("fixture's own pin must be self-consistent");
}

#[tokio::test]
async fn send_envelope_delivers_to_inbox() {
    let (_fixture, base, inbox_hits, last_body) = start_peer("recipient.local").await;

    let caller_key = generate_keypair();
    let mut index_urls = std::collections::HashMap::new();
    index_urls.insert(
        "recipient.local".to_string(),
        format!("{base}/.well-known/awp.json"),
    );
    let client = make_client("sender.local", caller_key, "sk1", index_urls);

    let sent = client
        .send_envelope(
            "message",
            "recipient.local#agent",
            &awp::envelope::new_id(),
            None,
            json!({"text": "hi"}),
            3600,
        )
        .await
        .expect("send_envelope");
    assert_eq!(sent.from, "sender.local");
    assert!(sent.sig.is_some());
    assert_eq!(inbox_hits.load(Ordering::SeqCst), 1);

    let delivered: serde_json::Value =
        serde_json::from_slice(&last_body.lock().await).expect("delivered body is valid JSON");
    assert_eq!(delivered["kind"], "message");
    assert_eq!(delivered["from"], "sender.local");
    assert_eq!(
        delivered["delegation"],
        serde_json::Value::Null,
        "SendEnvelope never sets delegation; must serialize as null"
    );
}

#[tokio::test]
async fn call_tool_signs_request_and_verifies_response() {
    let (_fixture, base, _hits, _body) = start_peer("tool.local").await;

    let caller_key = generate_keypair();
    let mut index_urls = std::collections::HashMap::new();
    index_urls.insert(
        "tool.local".to_string(),
        format!("{base}/.well-known/awp.json"),
    );
    let client = make_client("caller.local", caller_key, "ck1", index_urls);

    let (output, session) = client
        .call_tool(
            "tool.local#echo",
            json!({"n": 42}),
            awp::client::CallOptions::default(),
        )
        .await
        .expect("call_tool");
    assert_eq!(output["echoed"]["n"], 42);
    assert!(session.is_none());
}
