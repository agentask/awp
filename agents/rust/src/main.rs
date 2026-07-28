//! Command `activities-agent` implements activities.local, one of three AWP
//! agents (Go, Python, Rust) forming a triangle demo: each node initiates
//! exactly one outbound thread and receives on the other edge, so all
//! three pairs talk directly (true all-to-all for n=3).
//!
//! activities.local (this binary) initiates a thread with
//! trip-planner.local and separately receives-and-replies on a thread
//! concierge.local opens with it. Both are ordinary AWP threads — this
//! binary doesn't need to know it's "in a triangle."

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use activities_agent::config::Config;
use activities_agent::llm::{ChatMessage, GrokClient};
use activities_agent::node::{self, Node, SendFn};
use activities_agent::persona::{self, ConversationTracker};

/// The one peer this agent initiates an outbound thread with.
const OPENER_PEER_DOMAIN: &str = "trip-planner.local";

#[tokio::main]
async fn main() {
    let cfg = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    };

    let node = Arc::new(Node::new(cfg.domain.clone(), "k1"));

    let llm = Arc::new(GrokClient::new(cfg.xai_api_key.clone(), cfg.model.clone()));
    let tracker = Arc::new(ConversationTracker::new());

    {
        let own_domain = cfg.domain.clone();
        let llm = Arc::clone(&llm);
        let tracker = Arc::clone(&tracker);
        let handler: node::MessageHandler = Arc::new(move |env, send: SendFn| {
            let own_domain = own_domain.clone();
            let llm = Arc::clone(&llm);
            let tracker = Arc::clone(&tracker);
            Box::pin(async move { handle_message(env, send, &llm, &own_domain, &tracker).await })
        });
        *node.on_message.lock().unwrap() = Some(handler);
    }

    let bind_addr = format!("0.0.0.0:{}", cfg.port);
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {bind_addr}: {e}");
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .route("/.well-known/awp.json", get(serve_index))
        .route("/awp/inbox", post(serve_inbox))
        .with_state(Arc::clone(&node));

    let server_node = Arc::clone(&node);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            eprintln!("serve: {e}");
        }
        let _ = server_node; // keep the Arc alive for the server's lifetime
    });

    // The bind address (0.0.0.0) is not something a peer can connect to —
    // the index advertises cfg.advertise_host instead (127.0.0.1
    // natively, this agent's own compose service name under docker
    // compose).
    let inbox_url = format!("http://{}:{}/awp/inbox", cfg.advertise_host, cfg.port);
    let finalize_cfg = cfg.clone();
    node.finalize(inbox_url.clone(), move |domain: &str| {
        finalize_cfg.index_url_for(domain)
    });

    println!(
        "{} listening on http://{}, advertising {} (peers: {:?})",
        cfg.domain, bind_addr, inbox_url, cfg.peers
    );

    let opener_node = Arc::clone(&node);
    let opener_cfg = cfg.clone();
    let opener_llm = Arc::clone(&llm);
    let opener_tracker = Arc::clone(&tracker);
    tokio::spawn(async move {
        send_opener(&opener_node, &opener_cfg, &opener_llm, &opener_tracker).await;
    });

    // Block forever serving the inbox; Ctrl-C exits.
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
}

async fn serve_index(State(node): State<Arc<Node>>) -> Response {
    let body = node.index_json();
    let raw = serde_json::to_vec(&body).unwrap_or_default();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        raw,
    )
        .into_response()
}

async fn serve_inbox(State(node): State<Arc<Node>>, raw: Bytes) -> Response {
    let (status, body) = node.handle_inbox(&raw).await;
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, body).into_response()
}

/// Sends the opening message to trip-planner.local shortly after startup,
/// matching the existing Go/Python demos' `_send_opener` pattern (1s delay
/// to let both sides finish starting up). The opener text is seeded into
/// `tracker`'s history as our own ("assistant") turn so that when
/// trip-planner.local's reply lands on this same thread, the Grok call
/// carrying the exchange forward sees the full conversation, not just the
/// inbound half of it.
async fn send_opener(
    node: &Arc<Node>,
    cfg: &Config,
    _llm: &Arc<GrokClient>,
    tracker: &Arc<ConversationTracker>,
) {
    tokio::time::sleep(Duration::from_secs(1)).await;

    if !cfg.peers.contains_key(OPENER_PEER_DOMAIN) {
        eprintln!(
            "{}: no AWP_PEERS entry for {}, skipping opener",
            cfg.domain, OPENER_PEER_DOMAIN
        );
        return;
    }

    let thread = awp::envelope::new_id();
    println!(
        "[{}] -> [{}] (opener): {}",
        cfg.domain,
        OPENER_PEER_DOMAIN,
        persona::OPENER_TEXT
    );
    let body = persona::text_body_json(persona::OPENER_TEXT);
    match node
        .send("message", OPENER_PEER_DOMAIN, &thread, None, body)
        .await
    {
        Ok(_) => {
            tracker.append(
                &thread,
                [ChatMessage {
                    role: "assistant".to_string(),
                    content: persona::OPENER_TEXT.to_string(),
                }],
            );
        }
        Err(e) => {
            eprintln!(
                "{}: send opener to {} failed: {}",
                cfg.domain, OPENER_PEER_DOMAIN, e
            );
        }
    }
}

/// Runs a Grok call on an inbound `message`/`reply`, for up to
/// `persona::MAX_TURNS` per thread before sending `close`.
async fn handle_message(
    env: awp::envelope::Envelope,
    send: SendFn,
    llm: &GrokClient,
    own_domain: &str,
    tracker: &ConversationTracker,
) {
    let turn = tracker.next_turn(&env.thread);
    let incoming_text = persona::extract_text(&env.body);
    println!(
        "[{}] -> [{}] (turn {}/{}): {}",
        env.from,
        own_domain,
        turn,
        persona::MAX_TURNS,
        incoming_text
    );

    let wrapped = persona::untrusted_wrapper(&env.from, &incoming_text);
    let history = tracker.get(&env.thread);
    let reply_text = match llm
        .complete(persona::SYSTEM_PROMPT, &history, &wrapped)
        .await
    {
        Ok(text) => text,
        Err(e) => {
            eprintln!("[{own_domain}] llm error: {e}");
            "(wrapping up here — thanks!)".to_string()
        }
    };
    tracker.append(
        &env.thread,
        [
            ChatMessage {
                role: "user".to_string(),
                content: wrapped,
            },
            ChatMessage {
                role: "assistant".to_string(),
                content: reply_text.clone(),
            },
        ],
    );

    let kind = if turn >= persona::MAX_TURNS {
        "close"
    } else {
        "reply"
    };
    println!("[{own_domain}] -> [{}] ({kind}): {reply_text}", env.from);
    let body = persona::text_body_json(reply_text);
    if let Err(e) = send(kind.to_string(), body).await {
        eprintln!("[{own_domain}] send error: {e}");
    }
}
