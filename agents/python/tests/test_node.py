"""Proves concierge.node.Node builds a self-verifying signed index, and
that its inbox gate verifies a genuinely signed envelope (real ed25519
signature, real JCS canon via sdk/python's awp.identity + awp.envelope)
and rejects a tampered one. The Python counterpart to
agents/go/node_test.go and agents/rust/tests/node_test.rs.
"""

from __future__ import annotations

import json

import httpx
import pytest

from awp import identity
from awp.envelope import Envelope, new_id
from concierge.node import Node


def test_index_round_trips_and_self_verifies() -> None:
    """Builds a Node's signed index, marshals it (as it would be served at
    /.well-known/awp.json), unmarshals it back (as a peer fetching it
    would), and checks the self-signature verifies — the Phase 1 EARS gate
    ("round-tripped sign->verify SHALL produce byte-identical JCS canon
    and verify"), applied to this demo agent's own index construction."""
    node = Node("concierge.local", "k1")
    node.finalize("http://127.0.0.1:8002/awp/inbox", lambda d: f"https://{d}")

    raw = json.dumps(node.index.to_dict())
    idx = identity.Index.from_dict(json.loads(raw))
    idx.verify_self_sig()

    assert idx.domain == "concierge.local"
    assert idx.inbox == "http://127.0.0.1:8002/awp/inbox"


class PeerFixture:
    """A minimal signed identity for a fake sender, used to construct real
    signed envelopes without a full second Node."""

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.kid = "pk1"
        self.priv, self.pub = identity.generate_keypair()
        now = identity.now_rfc3339_milli()
        self.index = identity.Index(
            domain=domain,
            updated=now,
            keys=[identity.new_key(self.pub, self.kid, created=now)],
            inbox="",
        )
        self.index.sign(self.priv, self.kid)

    def signed_envelope(self, to: str, thread: str) -> Envelope:
        env = Envelope(
            id=new_id(),
            kind="message",
            from_=self.domain,
            to=to,
            thread=thread,
            ts=identity.now_rfc3339_milli(),
            ttl=3600,
            body={"type": "text", "text": "hello from a fixture peer"},
        )
        env.sign(self.priv, self.kid)
        return env


def _index_transport(pf: PeerFixture) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(pf.index.to_dict()).encode())

    return httpx.MockTransport(handler)


def _setup_receiving_node(pf: PeerFixture) -> Node:
    """Builds a Node whose peer-index resolution points at pf's fake
    index — the static-map DNS stand-in this whole demo uses for *.local
    domains."""
    node = Node("concierge.local", "k1")
    node.finalize("http://testserver/awp/inbox", lambda d: "http://peer-index")
    # Swap the client's http transport so fetching the peer's index hits
    # our in-memory fixture instead of a real network call.
    node.client._http = httpx.Client(transport=_index_transport(pf))
    return node


@pytest.fixture
def peer() -> PeerFixture:
    return PeerFixture("activities.local")


async def _post_inbox(node: Node, raw: bytes) -> httpx.Response:
    transport = httpx.ASGITransport(app=node.build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.post("/awp/inbox", content=raw, headers={"Content-Type": "application/awp+json"})


async def test_inbox_accepts_real_signed_envelope(peer: PeerFixture) -> None:
    node = _setup_receiving_node(peer)

    async def on_message(env, send):
        pass

    node.on_message = on_message

    env = peer.signed_envelope(node.domain, new_id())
    raw = json.dumps(env.to_dict()).encode()

    resp = await _post_inbox(node, raw)
    assert resp.status_code == 202


async def test_inbox_rejects_tampered_envelope(peer: PeerFixture) -> None:
    node = _setup_receiving_node(peer)

    env = peer.signed_envelope("concierge.local", new_id())
    env.body = {"type": "text", "text": "tampered after signing"}
    raw = json.dumps(env.to_dict()).encode()

    resp = await _post_inbox(node, raw)
    assert resp.status_code == 401


async def test_inbox_dedupes_repeated_id(peer: PeerFixture) -> None:
    node = _setup_receiving_node(peer)

    call_count = 0

    async def on_message(env, send):
        nonlocal call_count
        call_count += 1

    node.on_message = on_message

    env = peer.signed_envelope(node.domain, new_id())
    raw = json.dumps(env.to_dict()).encode()

    resp1 = await _post_inbox(node, raw)
    assert resp1.status_code == 202

    resp2 = await _post_inbox(node, raw)
    assert resp2.status_code == 200

    import asyncio

    await asyncio.sleep(0.1)
    assert call_count == 1
