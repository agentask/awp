"""Proves pyawp actually interoperates with the real Go reference
implementation — not just with itself. Starts a real Go
internal/daemon.Daemon (scripts/crosscheck_go/main.go) as a subprocess
and a real pyawp.Node in this process, then checks both directions:

  1. The Go daemon signs and sends a `message`; pyawp's gate must verify
     a signature produced by Go's ed25519 + gowebpki/jcs pipeline.
  2. pyawp signs and sends a `message` back; the Go daemon's own
     internal/inbox.Gate must accept a signature produced by Python's
     cryptography + rfc8785 pipeline.

If step 1's signature didn't verify, pyawp's JCS canonicalization or its
field-presence semantics (see identity.py's module doc) has drifted from
Go's. If step 2 fails, the same in the other direction. Run with:

    uv run python scripts/crosscheck_go.py

Exits non-zero on any check failure; always prints the Go subprocess's
own log output, pass or fail, so a failure is diagnosable without rerunning.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyawp import envelope as envelope_mod  # noqa: E402
from pyawp import node as node_mod  # noqa: E402

GO_ADDR = "127.0.0.1:19001"
PY_PORT = 19002
GO_DOMAIN = "go-agent.local"
PY_DOMAIN = "py-agent.local"
GO_RUN_SECONDS = 8
REPO_ROOT = Path(__file__).resolve().parents[3]


def build_go_binary() -> Path:
    out = Path("/tmp/awp-crosscheck-go-bin")
    subprocess.run(
        ["go", "build", "-o", str(out), "./agents/python/scripts/crosscheck_go"],
        cwd=REPO_ROOT, check=True,
    )
    return out


async def wait_for_go_ready(timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as http:
        while time.time() < deadline:
            try:
                resp = await http.get(f"http://{GO_ADDR}/.well-known/awp.json", timeout=1.0)
                if resp.status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    return False


async def main() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            ok = False

    go_bin = build_go_binary()

    received_from_go: list[dict] = []

    async def on_message(env: envelope_mod.Envelope, send) -> None:
        received_from_go.append({"from": env.from_, "body": env.body})
        await send("reply", {"type": "text", "text": "hello from pyawp"})

    py_node = node_mod.Node(PY_DOMAIN, on_message=on_message)
    config = uvicorn.Config(py_node.build_app(), host="127.0.0.1", port=PY_PORT, log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)

    def index_url(domain: str) -> str:
        if domain == GO_DOMAIN:
            return f"http://{GO_ADDR}/.well-known/awp.json"
        return f"http://127.0.0.1:{PY_PORT}/.well-known/awp.json"

    py_node.finalize(f"http://127.0.0.1:{PY_PORT}/awp/inbox", index_url)

    go_proc = subprocess.Popen(
        [
            str(go_bin),
            "-domain", GO_DOMAIN, "-addr", GO_ADDR,
            "-peer-domain", PY_DOMAIN, "-peer-base-url", f"http://127.0.0.1:{PY_PORT}",
            "-run-seconds", str(GO_RUN_SECONDS),
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        go_ready = await wait_for_go_ready()
        check("Go daemon subprocess came up and serves its index", go_ready)

        if go_ready:
            # Both directions must finish well inside GO_RUN_SECONDS — Go
            # exits (and prints its post-loop diagnostics) unconditionally
            # at that mark, and never gets a chance to print them if we
            # terminate it early instead of letting it exit on its own.

            # --- Direction 1: Go's signed message, verified by pyawp's gate ---
            for _ in range(int((GO_RUN_SECONDS - 2) / 0.1)):
                if received_from_go:
                    break
                await asyncio.sleep(0.1)
            check(
                "pyawp verified a real signature produced by Go (received the opener)",
                bool(received_from_go) and received_from_go[0]["from"] == GO_DOMAIN,
            )

            # --- Direction 2: pyawp's signed message, verified by Go's gate ---
            thread = envelope_mod.new_id()
            try:
                sent = await py_node.send(
                    "message", GO_DOMAIN, thread, {"type": "text", "text": "hello from pyawp, verify me"}
                )
                check("pyawp's send to the Go daemon's inbox did not raise", True)
            except Exception as e:
                sent = None
                check(f"pyawp's send to the Go daemon's inbox did not raise ({e})", False)

            if sent is not None:
                await asyncio.sleep(1.5)  # let Go's ProcessInboundOnce tick pick it up
    finally:
        # No early termination in the normal path: let Go's own
        # -run-seconds loop finish and print its diagnostics naturally.
        # The generous timeout here is only a safety net for a truly
        # hung subprocess.
        if go_proc.poll() is None:
            try:
                go_proc.wait(timeout=GO_RUN_SECONDS + 15)
            except subprocess.TimeoutExpired:
                go_proc.terminate()
                try:
                    go_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    go_proc.kill()
                    go_proc.wait(timeout=5)
        go_output = go_proc.stdout.read() if go_proc.stdout else ""
        print("--- go subprocess output ---")
        print(go_output)
        print("--- end go subprocess output ---")

        if go_proc.returncode not in (0, None):
            check("Go subprocess exited cleanly", False)

        check(
            "the real Go daemon accepted and processed pyawp's signed envelope",
            f"from={PY_DOMAIN}" in go_output and "verify me" in go_output,
        )

        server.should_exit = True
        await server_task

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
