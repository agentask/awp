"""Command concierge implements concierge.local, one of three AWP agents
(Go, Python, Rust) forming a triangle demo: each node initiates exactly
one outbound thread and receives on the other edge, so all three pairs
talk directly (true all-to-all for n=3).

concierge.local (this process) initiates a thread with activities.local
and separately receives-and-replies on a thread trip-planner.local opens
with it. Both are ordinary AWP threads — this process doesn't need to know
it's "in a triangle."

Run with:

    uv run python -m concierge.main
"""

from __future__ import annotations

import asyncio
import sys

import uvicorn

from .config import Config, ConfigError, load_config
from .llm import GrokClient
from .node import Node
from .persona import ConversationTracker, OPENER_TEXT, make_message_handler, text_body

# The one peer this agent initiates an outbound thread with.
OPENER_PEER_DOMAIN = "activities.local"


async def _run_server(app, host: str, port: int) -> tuple[uvicorn.Server, asyncio.Task]:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task


async def _send_opener(node: Node, cfg: Config, tracker: ConversationTracker, thread: str) -> None:
    """Sends the opening message to activities.local shortly after
    startup, matching the old agent_a/main.py's _send_opener pattern (1s
    delay to let both sides finish starting up). The opener text is
    seeded into tracker's history as our own ("assistant") turn so that
    when activities.local's reply lands on this same thread, the Grok
    call carrying the exchange forward sees the full conversation, not
    just the inbound half of it."""
    await asyncio.sleep(1.0)

    if OPENER_PEER_DOMAIN not in cfg.peers:
        print(f"{cfg.domain}: no AWP_PEERS entry for {OPENER_PEER_DOMAIN}, skipping opener", file=sys.stderr)
        return

    print(f"[{cfg.domain}] -> [{OPENER_PEER_DOMAIN}] (opener): {OPENER_TEXT}")
    try:
        await node.send("message", OPENER_PEER_DOMAIN, thread, text_body(OPENER_TEXT))
    except Exception as e:
        print(f"{cfg.domain}: send opener to {OPENER_PEER_DOMAIN} failed: {e}", file=sys.stderr)
        return
    tracker.append(thread, {"role": "assistant", "content": OPENER_TEXT})


async def _async_main() -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"config: {e}", file=sys.stderr)
        return 1

    node = Node(cfg.domain, "k1")

    llm = GrokClient(cfg.xai_api_key, cfg.model)
    tracker = ConversationTracker()
    node.on_message = make_message_handler(llm, cfg.domain, tracker)

    from awp.envelope import new_id

    opener_thread = new_id()

    server, server_task = await _run_server(node.build_app(), "0.0.0.0", cfg.port)

    # The bind address (0.0.0.0) is not something a peer can connect to —
    # the index advertises cfg.advertise_host instead (127.0.0.1 natively,
    # this agent's own compose service name under docker compose).
    inbox_url = f"http://{cfg.advertise_host}:{cfg.port}/awp/inbox"
    node.finalize(inbox_url, cfg.index_url_for)

    print(f"{cfg.domain} listening on http://0.0.0.0:{cfg.port}, advertising {inbox_url} (peers: {cfg.peers})")

    asyncio.create_task(_send_opener(node, cfg, tracker, opener_thread))

    # Block forever serving the inbox; Ctrl-C exits.
    await server_task
    return 0


def main() -> None:
    sys.exit(asyncio.run(_async_main()))


if __name__ == "__main__":
    main()
