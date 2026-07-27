"""Runs both agents in one process and drives one full conversation
between them over real AWP — real Ed25519 signatures, real JCS
canonicalization, real HTTP, real (uv-managed) google-adk agents. Run
with:

    uv run python demo.py

Requires GOOGLE_API_KEY (or Vertex AI ADC — set GOOGLE_GENAI_USE_VERTEXAI=true
and the usual GOOGLE_CLOUD_PROJECT/GOOGLE_CLOUD_LOCATION) in the
environment; each agent turn is a real Gemini call. See README.md for
what's real versus simplified here relative to the Go reference daemon.
"""

from __future__ import annotations

import asyncio
import os
import sys

import uvicorn
from dotenv import load_dotenv

load_dotenv()  # a .env file (see .env.example) is easier than exporting by hand

import agent_a.main as agent_a  # noqa: E402
import agent_b.main as agent_b  # noqa: E402


async def run_server(app, port: int) -> tuple[uvicorn.Server, asyncio.Task]:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task


def index_url(domain: str) -> str:
    if domain == agent_a.DOMAIN:
        return f"http://127.0.0.1:{agent_a.PORT}/.well-known/awp.json"
    if domain == agent_b.DOMAIN:
        return f"http://127.0.0.1:{agent_b.PORT}/.well-known/awp.json"
    return f"https://{domain}/.well-known/awp.json"


def check_credentials() -> None:
    has_api_key = bool(os.environ.get("GOOGLE_API_KEY"))
    uses_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("true", "1")
    if has_api_key or uses_vertex:
        return
    print(
        "No Gemini credentials found: set GOOGLE_API_KEY (in your shell, or in a\n"
        ".env file next to this script — see .env.example), or set\n"
        "GOOGLE_GENAI_USE_VERTEXAI=true plus GOOGLE_CLOUD_PROJECT/GOOGLE_CLOUD_LOCATION\n"
        "for Vertex AI. Every agent turn is a real Gemini call; there is no offline\n"
        "mode. See README.md.",
        file=sys.stderr,
    )
    sys.exit(1)


async def main() -> int:
    check_credentials()

    node_a = agent_a.make_node()
    node_b = agent_b.make_node()

    server_a, task_a = await run_server(node_a.build_app(), agent_a.PORT)
    server_b, task_b = await run_server(node_b.build_app(), agent_b.PORT)

    node_a.finalize(f"http://127.0.0.1:{agent_a.PORT}/awp/inbox", index_url)
    node_b.finalize(f"http://127.0.0.1:{agent_b.PORT}/awp/inbox", index_url)

    print(f"{agent_a.DOMAIN} up on :{agent_a.PORT}, {agent_b.DOMAIN} up on :{agent_b.PORT}\n")

    from pyawp.envelope import new_id

    thread = new_id()
    opener = (
        "Hi! I'm planning a long weekend in Lisbon for my user. Could you recommend "
        "a good neighborhood to stay in, and a restaurant for a first-night dinner?"
    )
    print(f"[{agent_a.DOMAIN}] -> [{agent_b.DOMAIN}] (opener): {opener}\n")
    await node_a.send("message", agent_b.DOMAIN, thread, {"type": "text", "text": opener})

    # common.MAX_TURNS exchanges each way, plus the opener/close — give it
    # generous real-world time since every turn is a real model call.
    from common import MAX_TURNS

    await asyncio.sleep(8 * MAX_TURNS)

    print("\ndone — shutting down.")
    server_a.should_exit = True
    server_b.should_exit = True
    await asyncio.gather(task_a, task_b)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
