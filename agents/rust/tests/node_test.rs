//! Proves (a) this agent's self-signed index round-trips (build -> marshal
//! -> unmarshal -> verify self-sig), and (b) the inbox handler correctly
//! verifies a real signed envelope and rejects a tampered one. Fixtures
//! are built entirely from `sdk/rust`'s own signing primitives — no
//! reimplemented crypto here. The Rust counterpart to
//! `agents/go/node_test.go`.

use std::sync::Arc;

use activities_agent::node::Node;
use awp::identity::{self, Index, Key};

/// TestNode_IndexRoundTripsAndSelfVerifies's Rust counterpart: builds a
/// Node's signed index, marshals it (as it would be served at
/// /.well-known/awp.json), unmarshals it back (as a peer fetching it
/// would), and checks the self-signature verifies.
#[test]
fn index_round_trips_and_self_verifies() {
    let node = Node::new("activities.local", "k1");
    node.finalize("http://127.0.0.1:8003/awp/inbox".to_string(), |d| {
        format!("https://{d}")
    });

    let raw = serde_json::to_vec(&node.index_json()).expect("marshal index");

    let idx: Index = serde_json::from_slice(&raw).expect("unmarshal index");
    idx.verify_self_sig().expect("verify_self_sig");
    assert_eq!(idx.domain, "activities.local");
    assert_eq!(idx.inbox, "http://127.0.0.1:8003/awp/inbox");
}

/// A minimal signed identity for a fake sender, used to construct real
/// signed envelopes without a full second Node. Mirrors
/// `agents/go/node_test.go`'s `peerFixture`.
struct PeerFixture {
    domain: String,
    kid: String,
    signing_key: ed25519_dalek::SigningKey,
    index: Index,
}

impl PeerFixture {
    fn new(domain: &str) -> Self {
        let signing_key = identity::generate_keypair();
        let kid = "pk1".to_string();
        let pub_b64 = awp::b64::url_encode(signing_key.verifying_key().as_bytes());
        let mut index = Index {
            awp: "0.1".to_string(),
            domain: domain.to_string(),
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
        index.sign(&signing_key, &kid).expect("sign peer index");
        PeerFixture {
            domain: domain.to_string(),
            kid,
            signing_key,
            index,
        }
    }

    fn signed_envelope(
        &self,
        to: &str,
        thread: &str,
        body: serde_json::Value,
    ) -> awp::envelope::Envelope {
        let mut e = awp::envelope::Envelope {
            awp: "0.1".to_string(),
            id: awp::envelope::new_id(),
            kind: "message".to_string(),
            from: self.domain.clone(),
            to: to.to_string(),
            thread: thread.to_string(),
            in_reply_to: None,
            ts: identity::now_rfc3339_milli(),
            ttl: 3600,
            session: None,
            delegation: None,
            body,
            sig: None,
        };
        e.sign(&self.signing_key, &self.kid).expect("sign envelope");
        e
    }
}

/// Starts a receiving Node whose peer-index resolution is a static map
/// pointing straight at `pf`'s in-memory index — the same static-map DNS
/// stand-in `config::Config::index_url_for` uses for real `*.local`
/// domains, just inlined here rather than served over HTTP (the inbox
/// gate's signature check calls `Client::resolve`, which itself does an
/// HTTP GET — so this harness serves `pf`'s index from a tiny local mock
/// server rather than skip HTTP entirely).
async fn setup_receiving_node(pf_domain: String, pf_index: Index) -> (Arc<Node>, String) {
    let index_json = serde_json::to_string(&pf_index).unwrap();
    let mock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match mock.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let index_json = index_json.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = index_json.as_bytes();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    let mock_base = format!("http://{mock_addr}");

    let node = Arc::new(Node::new("activities.local", "k1"));
    let target_domain = pf_domain.clone();
    let index_url = move |d: &str| {
        if d == target_domain {
            mock_base.clone()
        } else {
            format!("https://{d}")
        }
    };
    node.finalize("http://127.0.0.1:0/awp/inbox".to_string(), index_url);
    (node, pf_domain)
}

#[tokio::test]
async fn inbox_accepts_real_signed_envelope() {
    let pf = PeerFixture::new("concierge.local");
    let (node, _) = setup_receiving_node(pf.domain.clone(), pf.index.clone()).await;

    let env = pf.signed_envelope(
        &node.domain,
        &awp::envelope::new_id(),
        serde_json::json!({"type": "text", "text": "hello from a fixture peer"}),
    );
    let raw = serde_json::to_vec(&env).unwrap();

    let (status, _) = node.handle_inbox(&raw).await;
    assert_eq!(
        status, 202,
        "expected 202 Accepted for a real signed envelope"
    );
}

#[tokio::test]
async fn inbox_rejects_tampered_envelope() {
    let pf = PeerFixture::new("concierge.local");
    let (node, _) = setup_receiving_node(pf.domain.clone(), pf.index.clone()).await;

    let mut env = pf.signed_envelope(
        "activities.local",
        &awp::envelope::new_id(),
        serde_json::json!({"type": "text", "text": "original"}),
    );
    // Tamper with the body after signing, without re-signing.
    env.body = serde_json::json!({"type": "text", "text": "tampered after signing"});
    let raw = serde_json::to_vec(&env).unwrap();

    let (status, _) = node.handle_inbox(&raw).await;
    assert_eq!(
        status, 401,
        "expected 401 Unauthorized for a tampered envelope"
    );
}

#[tokio::test]
async fn inbox_dedupes_repeated_id() {
    let pf = PeerFixture::new("concierge.local");
    let (node, _) = setup_receiving_node(pf.domain.clone(), pf.index.clone()).await;

    let env = pf.signed_envelope(
        &node.domain,
        &awp::envelope::new_id(),
        serde_json::json!({"type": "text", "text": "hello again"}),
    );
    let raw = serde_json::to_vec(&env).unwrap();

    let (status1, _) = node.handle_inbox(&raw).await;
    assert_eq!(status1, 202);
    let (status2, _) = node.handle_inbox(&raw).await;
    assert_eq!(status2, 200, "duplicate id should ack 200, not reprocess");
}
