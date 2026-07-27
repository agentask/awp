"""A minimal in-memory (non-persistent) AWP participant: holds an ed25519
identity, serves a signed index + inbox over plain HTTP, and
dedupes/verifies inbound envelopes before handing `message`/`reply` kinds
to a message handler. The Python counterpart to agents/go/node.go and
agents/rust/src/node.rs, built entirely on sdk/python (awp.bootstrap,
awp.client, awp.identity, awp.envelope) rather than reimplementing any
signing or canonicalization — this is this demo's counterpart to
internal/daemon.Daemon (Go), scoped down to exactly what a demo agent
needs.

Simplified relative to the Go reference daemon in internal/daemon (see
README.md for the full list): the receiver gate below implements core
§2.2's checks in the mandated order, but "durably enqueue" (step 5) means
an in-memory asyncio task, not a persisted queue that survives a restart —
there is no internal/store here at all. `seen`-id dedupe is an in-memory
dict, not bbolt. Neither changes the wire behavior a peer observes; both
mean this process's state is gone if it crashes, which internal/store is
specifically built to survive.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, Response

from awp import bootstrap, identity
from awp.client import Client
from awp.envelope import Envelope

from .persona import MessageHandler

# core §2.1's serialized-envelope cap, enforced at the inbox gate before
# any parsing.
MAX_ENVELOPE_SIZE = 256 * 1024


def _error_body(code: str, detail: str) -> bytes:
    return json.dumps({"error": {"code": code, "detail": detail, "retryable": False}}).encode()


class Node:
    """A small in-memory AWP participant. Mirrors agents/go/node.go's
    Node and agents/rust/src/node.rs's Node."""

    def __init__(self, domain: str, kid: str = "k1") -> None:
        self.domain = domain
        self.kid = kid
        self.on_message: MessageHandler | None = None

        # Fresh ed25519 identity and an unfinalized signed index (inbox
        # left empty until finalize() is called, once the listen address
        # is known) — via sdk/python's bootstrap helpers, not hand-rolled.
        self.priv, self.index = bootstrap.new_domain_identity(domain, kid)

        self._client: Client | None = None
        self._seen: dict[str, float] = {}  # envelope id -> accept-until unix ts

    def finalize(self, inbox_url: str, index_url: Callable[[str], str]) -> None:
        """Sets this node's advertised inbox URL and re-signs the index —
        call once its own reachable address is known, before any peer is
        expected to fetch /.well-known/awp.json. index_url resolves a
        peer's domain to the base URL its index should be fetched from
        (the static-map DNS stand-in for these *.local demo domains)."""
        bootstrap.finalize_index(self.index, self.priv, self.kid, inbox_url)

        def full_index_url(domain: str) -> str:
            return f"{index_url(domain)}/.well-known/awp.json"

        self._client = Client(self.domain, self.kid, self.priv, index_url=full_index_url)

    @property
    def client(self) -> Client:
        if self._client is None:
            raise RuntimeError("node: called before finalize()")
        return self._client

    async def send(
        self,
        kind: str,
        to: str,
        thread: str,
        body: Any,
        *,
        in_reply_to: str | None = None,
        ttl: int = 3600,
    ) -> Envelope:
        """Delivers a signed envelope of the given kind directly to `to`'s
        resolved inbox via the SDK client. Call finalize() first. The SDK
        client is synchronous (httpx.Client); run it off the event loop
        so a slow peer never blocks this node's own inbox."""
        return await asyncio.to_thread(self.client.send_envelope, kind, to, thread, in_reply_to, body, ttl)

    def build_app(self) -> FastAPI:
        """Wires the two AWP-facing endpoints: the signed index and the
        inbox. The Python counterpart to agents/go/node.go's ServeHTTP."""
        app = FastAPI()

        @app.get("/.well-known/awp.json")
        async def serve_index() -> Response:
            return Response(content=json.dumps(self.index.to_dict()), media_type="application/json")

        @app.post("/awp/inbox")
        async def serve_inbox(request: Request) -> Response:
            return await self._handle_inbox(request)

        return app

    async def _resolve_with_retry(self, domain: str, kid: str):
        """core §0.1's rotation-race handling: verifiers MUST re-fetch the
        signer's index once on failure before hard-failing."""
        try:
            return await asyncio.to_thread(self.client.resolve, domain, kid)
        except identity.BadSignatureError:
            await asyncio.to_thread(self.client.refresh, domain)
            return await asyncio.to_thread(self.client.resolve, domain, kid)

    async def _handle_inbox(self, request: Request) -> Response:
        """Implements core §2.2's gate, in the mandated order:
        1. parse (with size limit) -> 400
        2. now <= ts + ttl -> 410
        3. verify sig (one refresh-and-retry on failure) -> 401
        4. dedupe on id -> 200 (already accepted, not reprocessed)
        5. enqueue -> 202 (an in-memory asyncio task here, not a durable
           queue — see this module's doc comment)
        """
        raw = await request.body()
        if len(raw) > MAX_ENVELOPE_SIZE:
            return Response(_error_body("malformed", "envelope exceeds 256 KiB"), status_code=400)
        try:
            env = Envelope.from_dict(json.loads(raw))
        except Exception as e:
            return Response(_error_body("malformed", f"parse error: {e}"), status_code=400)

        try:
            ts = datetime.strptime(env.ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except Exception:
            return Response(_error_body("malformed", "bad ts"), status_code=400)
        expires_at = ts.timestamp() + env.ttl
        if time.time() > expires_at:
            return Response(_error_body("expired", "envelope ttl expired"), status_code=410)

        if env.sig is None:
            return Response(_error_body("unauthorized", "missing signature"), status_code=401)
        from_domain = identity.domain_of(env.from_)
        try:
            pub = await self._resolve_with_retry(from_domain, env.sig.kid)
            env.verify(pub)
        except Exception as e:
            return Response(
                _error_body("unauthorized", f"signature verification failed: {e}"), status_code=401
            )

        now = time.time()
        expired_ids = [eid for eid, until in self._seen.items() if until < now]
        for eid in expired_ids:
            del self._seen[eid]
        if env.id in self._seen:
            return Response(status_code=200)
        self._seen[env.id] = expires_at

        asyncio.create_task(self._process(env))
        return Response(status_code=202)

    async def _process(self, env: Envelope) -> None:
        """Hands "content to respond to" envelopes to on_message. Per core
        §2.4, both `message` (opens/continues a thread unsolicited) and
        `reply` (a substantive response within one) carry content a
        participant should act on; `ack`/`close`/`error` do not. Matches
        agents/go/node.go's Node.process and agents/rust/src/node.rs's
        Node::process: this agent has to correctly carry to completion
        both a thread it opens (concierge.local -> activities.local) and
        one opened against it (trip-planner.local -> concierge.local), so
        its gate reacts to both kinds — unlike the old
        agents/python/pyawp/node.py, which only invoked its handler on
        kind == "message" (a real gap in that reference, not a pattern
        this node copies)."""
        if self.on_message is None:
            return
        if env.kind not in ("message", "reply"):
            return

        async def send_reply(kind: str, body: Any) -> Envelope:
            return await self.send(kind, env.from_, env.thread, body, in_reply_to=env.id)

        try:
            await self.on_message(env, send_reply)
        except Exception:
            import logging

            logging.getLogger("concierge.node").exception("on_message handler failed for envelope %s", env.id)
