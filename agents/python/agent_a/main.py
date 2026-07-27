"""trip-planner.local — a trip-planning assistant, working on behalf of a
(hypothetical) user planning a weekend in Lisbon. It opens the
conversation with concierge.local and carries it for up to
common.MAX_TURNS exchanges. Run standalone with:

    uv run python -m agent_a.main

which starts it on http://127.0.0.1:8001, resolves concierge.local at
http://127.0.0.1:8002 (override both via env vars below), and sends the
opening message shortly after startup — for running the two agents as
genuinely separate processes/terminals rather than the single-process
demo.py.
"""

from __future__ import annotations

import asyncio
import logging
import os

import uvicorn
from dotenv import load_dotenv
from google.adk import Agent

from common import make_message_handler
from pyawp.envelope import new_id
from pyawp.node import Node

load_dotenv()

DOMAIN = "trip-planner.local"
PORT = int(os.environ.get("AWP_AGENT_A_PORT", "8001"))
PEER_DOMAIN = os.environ.get("AWP_AGENT_B_DOMAIN", "concierge.local")
PEER_BASE_URL = os.environ.get("AWP_AGENT_B_BASE_URL", "http://127.0.0.1:8002")

logging.basicConfig(level=logging.INFO)


def build_agent() -> Agent:
    return Agent(
        name="trip_planner",
        model=os.environ.get("AWP_MODEL", "gemini-2.5-flash"),
        instruction=(
            "You are a trip-planning assistant helping your user plan a long "
            "weekend in Lisbon, Portugal. You are talking to a local concierge "
            "agent (a separate AI agent, not your user) to gather recommendations "
            "on your user's behalf. Ask specific, useful follow-up questions based "
            "on what the concierge tells you, and once you have enough to work "
            "with, summarize a short plan. Keep each message to 2-3 sentences."
        ),
    )


def make_node() -> Node:
    handler = make_message_handler(build_agent(), DOMAIN)
    return Node(DOMAIN, on_message=handler)


def index_url_for(domain: str) -> str:
    if domain == PEER_DOMAIN:
        return f"{PEER_BASE_URL}/.well-known/awp.json"
    return f"https://{domain}/.well-known/awp.json"


async def _send_opener(node: Node) -> None:
    await asyncio.sleep(1.0)  # let both sides finish starting up
    thread = new_id()
    opener = (
        "Hi! I'm planning a long weekend in Lisbon for my user. "
        "Could you recommend a good neighborhood to stay in, and a restaurant "
        "for a first-night dinner?"
    )
    await node.send("message", PEER_DOMAIN, thread, {"type": "text", "text": opener})
    print(f"{DOMAIN} -> {PEER_DOMAIN} (thread {thread}): {opener}")


async def _run_standalone() -> None:
    node = make_node()
    config = uvicorn.Config(node.build_app(), host="127.0.0.1", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    node.finalize(f"http://127.0.0.1:{PORT}/awp/inbox", index_url_for)
    print(f"{DOMAIN} listening on http://127.0.0.1:{PORT} (peer: {PEER_DOMAIN} at {PEER_BASE_URL})")

    asyncio.create_task(_send_opener(node))
    await server_task


if __name__ == "__main__":
    asyncio.run(_run_standalone())
