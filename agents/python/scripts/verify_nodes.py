"""Standalone verification of pyawp.Node's wire protocol, with no ADK/LLM
involved at all: two real Node instances, real uvicorn servers on real
local ports, real signed envelopes over real HTTP. Run with:

    uv run python scripts/verify_nodes.py

Exits non-zero on any check failure.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyawp import envelope as envelope_mod  # noqa: E402
from pyawp import identity  # noqa: E402
from pyawp import node as node_mod  # noqa: E402

PORT_A = 18801
PORT_B = 18802


async def run_server(app, port: int) -> tuple[uvicorn.Server, asyncio.Task]:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task


async def main() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            ok = False

    received: list[dict] = []

    async def on_message(env: envelope_mod.Envelope, send) -> None:
        received.append({"from": env.from_, "body": env.body})
        await send("reply", {"type": "text", "text": f"echo: {env.body.get('text', '')}"})

    a = node_mod.Node("agent-a.local")
    b = node_mod.Node("agent-b.local", on_message=on_message)

    server_a, task_a = await run_server(a.build_app(), PORT_A)
    server_b, task_b = await run_server(b.build_app(), PORT_B)

    def index_url(domain: str) -> str:
        port = PORT_A if domain == "agent-a.local" else PORT_B
        return f"http://127.0.0.1:{port}/.well-known/awp.json"

    a.finalize(f"http://127.0.0.1:{PORT_A}/awp/inbox", index_url)
    b.finalize(f"http://127.0.0.1:{PORT_B}/awp/inbox", index_url)

    thread = envelope_mod.new_id()
    sent = await a.send("message", "agent-b.local", thread, {"type": "text", "text": "hello"})
    check("a.send() completed without raising", True)

    for _ in range(50):
        if received:
            break
        await asyncio.sleep(0.05)
    check("b's on_message ran with the right sender", bool(received) and received[0]["from"] == "agent-a.local")
    check("b saw the right body", bool(received) and received[0]["body"] == {"type": "text", "text": "hello"})

    await asyncio.sleep(0.3)  # let b's reply land at a's inbox
    check("a's inbox recorded b's reply (delivery worked)", len(a._seen) >= 1)

    # Resend the identical envelope: must dedupe (200), not reprocess.
    raw = json.dumps(sent.to_dict()).encode()
    async with httpx.AsyncClient() as http:
        resp1 = await http.post(f"http://127.0.0.1:{PORT_B}/awp/inbox", content=raw)
    check("resend of an already-seen id -> 200", resp1.status_code == 200)
    check("exactly one on_message invocation despite the resend", len(received) == 1)

    # Malformed body -> 400.
    async with httpx.AsyncClient() as http:
        resp2 = await http.post(f"http://127.0.0.1:{PORT_B}/awp/inbox", content=b"{not json")
    check("malformed body -> 400", resp2.status_code == 400)

    # Unsigned envelope -> 401.
    unsigned = envelope_mod.Envelope(
        id=envelope_mod.new_id(), kind="message", from_="agent-a.local", to="agent-b.local",
        thread=envelope_mod.new_id(), ts=identity.now_rfc3339_milli(), ttl=3600, body={},
    )
    async with httpx.AsyncClient() as http:
        resp3 = await http.post(
            f"http://127.0.0.1:{PORT_B}/awp/inbox", content=json.dumps(unsigned.to_dict()).encode()
        )
    check("unsigned envelope -> 401", resp3.status_code == 401)

    # Expired envelope -> 410.
    expired = envelope_mod.Envelope(
        id=envelope_mod.new_id(), kind="message", from_="agent-a.local", to="agent-b.local",
        thread=envelope_mod.new_id(), ts="2020-01-01T00:00:00.000Z", ttl=60, body={},
    )
    expired.sign(a.priv, a.kid)
    async with httpx.AsyncClient() as http:
        resp4 = await http.post(
            f"http://127.0.0.1:{PORT_B}/awp/inbox", content=json.dumps(expired.to_dict()).encode()
        )
    check("expired envelope -> 410", resp4.status_code == 410)

    server_a.should_exit = True
    server_b.should_exit = True
    await asyncio.gather(task_a, task_b)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
