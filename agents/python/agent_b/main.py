"""concierge.local — a local-recommendations agent for Lisbon. Purely
reactive: it never opens a thread itself, only replies on ones
trip-planner.local opens. Run standalone with:

    uv run python -m agent_b.main

which starts it on http://127.0.0.1:8002, resolving trip-planner.local at
http://127.0.0.1:8001 (override both via env vars below) — for running
the two agents as genuinely separate processes/terminals rather than the
single-process demo.py.
"""

from __future__ import annotations

import asyncio
import logging
import os

import uvicorn
from dotenv import load_dotenv
from google.adk import Agent

from common import make_message_handler
from pyawp.node import Node

load_dotenv()

DOMAIN = "concierge.local"
PORT = int(os.environ.get("AWP_AGENT_B_PORT", "8002"))
PEER_DOMAIN = os.environ.get("AWP_AGENT_A_DOMAIN", "trip-planner.local")
PEER_BASE_URL = os.environ.get("AWP_AGENT_A_BASE_URL", "http://127.0.0.1:8001")

logging.basicConfig(level=logging.INFO)


def build_agent() -> Agent:
    return Agent(
        name="concierge",
        model=os.environ.get("AWP_MODEL", "gemini-2.5-flash"),
        instruction=(
            "You are a friendly, knowledgeable local concierge for Lisbon, Portugal. "
            "Another AI agent (a trip-planning assistant working on behalf of its own "
            "user) will ask you for recommendations — restaurants, neighborhoods, "
            "activities. Answer concisely and specifically: name real kinds of places "
            "and areas, keep it to 2-3 sentences per reply, and stay in character as a "
            "concierge, not as an assistant talking about Lisbon in the abstract."
        ),
    )


def make_node() -> Node:
    handler = make_message_handler(build_agent(), DOMAIN)
    return Node(DOMAIN, on_message=handler)


def index_url_for(domain: str) -> str:
    if domain == PEER_DOMAIN:
        return f"{PEER_BASE_URL}/.well-known/awp.json"
    return f"https://{domain}/.well-known/awp.json"


async def _run_standalone() -> None:
    node = make_node()
    config = uvicorn.Config(node.build_app(), host="127.0.0.1", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    node.finalize(f"http://127.0.0.1:{PORT}/awp/inbox", index_url_for)
    print(f"{DOMAIN} listening on http://127.0.0.1:{PORT} (peer: {PEER_DOMAIN} at {PEER_BASE_URL})")
    await server_task


if __name__ == "__main__":
    asyncio.run(_run_standalone())
