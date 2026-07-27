"""A minimal full AWP participant: serves a signed domain index, accepts
envelopes at an inbox, and hands `message` envelopes to a callback — the
Python counterpart to internal/daemon.Daemon (Go), scoped down to exactly
what a demo agent needs.

Simplified relative to the Go reference daemon (see agents/python/README.md
for the complete list): the receiver gate below implements core §2.2's
checks in the mandated order, but "durably enqueue" (step 5) means an
in-memory asyncio task, not a persisted queue that survives a restart —
there is no store here at all. `seen`-id dedupe is an in-memory dict, not
bbolt. Neither changes the wire behavior a peer observes; both mean this
process's state is gone if it crashes, which `internal/store` in Go is
specifically built to survive.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response

from . import client as client_mod
from . import envelope as envelope_mod
from . import identity

logger = logging.getLogger("pyawp.node")

MAX_ENVELOPE_SIZE = 256 * 1024  # core §2.1

SendFunc = Callable[[str, Any], Awaitable[envelope_mod.Envelope]]
MessageHandler = Callable[[envelope_mod.Envelope, SendFunc], Awaitable[None]]


def _error_body(code: str, detail: str) -> bytes:
    return json.dumps({"error": {"code": code, "detail": detail, "retryable": False}}).encode()


class Node:
    def __init__(
        self,
        domain: str,
        kid: str = "k1",
        on_message: MessageHandler | None = None,
    ) -> None:
        self.domain = domain
        self.kid = kid
        self.priv, self.pub = identity.generate_keypair()
        self.on_message = on_message

        self.index = identity.Index(
            domain=domain, updated=identity.now_rfc3339_milli(),
            keys=[identity.new_key(self.pub, kid)], inbox="",
        )
        self.index.sign(self.priv, kid)

        self._seen: dict[str, float] = {}  # envelope id -> accept-until unix ts
        self.client: client_mod.Client | None = None  # set by finalize()

    def finalize(self, inbox_url: str, index_url: Callable[[str], str]) -> None:
        """Sets this node's advertised inbox URL and re-signs the index —
        call once its own reachable address is known, before any peer is
        expected to fetch /.well-known/awp.json. The direct counterpart to
        internal/daemon.Daemon.FinalizeIndex."""
        self.index.inbox = inbox_url
        self.index.updated = identity.now_rfc3339_milli()
        self.index.sign(self.priv, self.kid)
        self.client = client_mod.Client(
            self.domain, self.kid, self.priv, http=httpx.AsyncClient(timeout=10.0), index_url=index_url
        )

    async def send(
        self, kind: str, to: str, thread: str, body: Any, *, in_reply_to: str | None = None, ttl: int = 3600
    ) -> envelope_mod.Envelope:
        assert self.client is not None, "call finalize() before send()"
        return await self.client.send_envelope(kind, to, thread, body, in_reply_to=in_reply_to, ttl=ttl)

    def build_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/.well-known/awp.json")
        async def serve_index() -> Response:
            return Response(
                content=json.dumps(self.index.to_dict()), media_type="application/json"
            )

        @app.post("/awp/inbox")
        async def serve_inbox(request: Request) -> Response:
            return await self._handle_inbox(request)

        return app

    async def _resolve_with_retry(self, domain: str, kid: str):
        """core §0.1: 'verifiers MUST re-fetch the signer's index once on
        failure before hard-failing (rotation race)'."""
        assert self.client is not None
        try:
            return await self.client.resolve(domain, kid)
        except identity.BadSignatureError:
            await self.client.refresh(domain)
            return await self.client.resolve(domain, kid)

    async def _handle_inbox(self, request: Request) -> Response:
        # Gate step 1: parse (with size limit) -> 400.
        raw = await request.body()
        if len(raw) > MAX_ENVELOPE_SIZE:
            return Response(_error_body("malformed", "envelope exceeds 256 KiB"), status_code=400)
        try:
            env = envelope_mod.Envelope.from_dict(json.loads(raw))
        except Exception as e:
            return Response(_error_body("malformed", f"parse error: {e}"), status_code=400)

        # Gate step 2: now <= ts + ttl -> 410.
        try:
            ts = datetime.fromisoformat(env.ts)
        except Exception:
            return Response(_error_body("malformed", "bad ts"), status_code=400)
        if time.time() > ts.timestamp() + env.ttl:
            return Response(_error_body("expired", "envelope ttl expired"), status_code=410)

        # Gate step 3: verify sig, one refresh-and-retry on failure -> 401.
        if env.sig is None:
            return Response(_error_body("unauthorized", "missing signature"), status_code=401)
        from_domain = identity.domain_of(env.from_)
        try:
            pub = await self._resolve_with_retry(from_domain, env.sig.kid)
            env.verify(pub)
        except Exception as e:
            return Response(_error_body("unauthorized", f"signature verification failed: {e}"), status_code=401)

        # Gate step 4: dedupe on id -> 200 (already accepted, not reprocessed).
        now = time.time()
        expired_ids = [eid for eid, until in self._seen.items() if until < now]
        for eid in expired_ids:
            del self._seen[eid]
        if env.id in self._seen:
            return Response(status_code=200)
        self._seen[env.id] = ts.timestamp() + env.ttl

        # Gate step 5: enqueue -> 202. "Enqueue" here is a background
        # asyncio task, not a durable queue — see this module's doc
        # comment. 202 is a transport ack only (core §2.2): the sender
        # gets it immediately, before (and regardless of) whatever
        # `on_message` below actually does.
        asyncio.create_task(self._process(env))
        return Response(status_code=202)

    async def _process(self, env: envelope_mod.Envelope) -> None:
        if env.kind != "message" or self.on_message is None:
            return

        async def send_reply(kind: str, body: Any) -> envelope_mod.Envelope:
            return await self.send(kind, env.from_, env.thread, body, in_reply_to=env.id)

        try:
            await self.on_message(env, send_reply)
        except Exception:
            logger.exception("on_message handler failed for envelope %s", env.id)
