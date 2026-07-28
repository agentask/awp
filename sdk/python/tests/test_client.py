"""Client integration tests against an in-process fake AWP peer, mirroring
sdk/go/awp_test.go's patterns (a real daemon there; a minimal
httpx.MockTransport-backed fake here, since sdk/python has no daemon of
its own to stand one up with).
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse

import httpx
import pytest

from awp import (
    apperr,
    bootstrap,
    client as client_mod,
    delegation,
    envelope as envelope_mod,
    httpsig,
    identity,
    manifest as manifest_mod,
)


class FakePeer:
    """A minimal in-process AWP participant: serves /.well-known/awp.json,
    a manifest, an inbox, and (optionally) a signed sync-tool endpoint --
    enough to exercise Client.fetch_index/fetch_manifest/send_envelope/
    call_tool without any real network I/O."""

    def __init__(self, domain: str, kid: str = "k1") -> None:
        self.domain = domain
        self.kid = kid
        self.priv, self.idx = bootstrap.new_domain_identity(domain, kid)
        self.pub = self.idx.keys[0].public_key()
        self.base_url = f"https://{domain}"
        bootstrap.finalize_index(self.idx, self.priv, kid, f"{self.base_url}/awp/inbox")

        self.received_envelopes: list[envelope_mod.Envelope] = []
        self.manifests: dict[str, tuple[bytes, manifest_mod.Manifest]] = {}
        self.tool_handlers = {}
        self.sessions: dict[str, str] = {}  # token -> caller principal
        self.last_tool_call_headers: dict[str, str] = {}

    def register_manifest(self, m: manifest_mod.Manifest, priv=None) -> None:
        priv = priv or self.priv
        m.sign(priv, self.kid)
        raw = json.dumps(m.to_dict()).encode("utf-8")
        sha = hashlib.sha256(raw).hexdigest()
        self.manifests[m.name] = (raw, m)
        entities = list(self.idx.entities or [])
        entities.append(identity.Entity(
            name=m.name, kind=m.kind,
            manifest=f"{self.base_url}/manifests/{urllib.parse.quote(m.name, safe='')}",
            manifest_sha256=sha,
        ))
        self.idx.entities = entities
        bootstrap.finalize_index(self.idx, self.priv, self.kid, self.idx.inbox)

    def register_tool(self, name: str, handler) -> None:
        self.tool_handlers[name] = handler

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/awp.json":
            return httpx.Response(200, content=json.dumps(self.idx.to_dict()).encode())
        if path.startswith("/manifests/"):
            name = urllib.parse.unquote(path[len("/manifests/"):])
            raw, _ = self.manifests[name]
            return httpx.Response(200, content=raw)
        if path == "/awp/inbox":
            env = envelope_mod.Envelope.from_dict(json.loads(request.content))
            self.received_envelopes.append(env)
            return httpx.Response(202)
        if path.startswith("/tools/"):
            return self._handle_tool_call(path, request)
        return httpx.Response(404)

    def _manifest_for_endpoint_path(self, path: str) -> manifest_mod.Manifest:
        for _, m in self.manifests.values():
            if httpx.URL(m.distribution.hosted.endpoint).path == path:
                return m
        raise KeyError(path)

    def _handle_tool_call(self, path: str, request: httpx.Request) -> httpx.Response:
        m = self._manifest_for_endpoint_path(path)
        name = m.name
        body = request.content

        class _Resolver:
            def resolve(self, domain, kid):
                return _CALLER_KEY_REGISTRY[(domain, kid)]

            def refresh(self, domain):
                return None

        headers = {k: v for k, v in request.headers.items()}
        self.last_tool_call_headers = headers
        result = httpsig.verify_request(
            method=request.method,
            url=str(request.url),
            headers=headers,
            body=body,
            now=time.time(),
            deps=httpsig.VerifyDeps(
                resolve_key=_Resolver(),
                target=m.name,
                verify_session=lambda token, caller: (
                    None if self.sessions.get(token) == caller else (_ for _ in ()).throw(ValueError("bad session"))
                ),
            ),
        )
        if result.err is not None:
            body_out = json.dumps({"error": result.err.to_dict()}).encode()
            return httpx.Response(result.status, content=body_out)

        handler = self.tool_handlers[name]
        try:
            out = handler(result.caller_principal, json.loads(body) if body else {})
        except Exception as e:
            code = getattr(e, "code", apperr.CODE_INTERNAL)
            detail = getattr(e, "detail", str(e))
            body_out = json.dumps({"error": {"code": code, "detail": detail, "retryable": False}}).encode()
            return httpx.Response(422, content=body_out)

        session = None
        if m.state == "provider" and not (headers.get("AWP-Session") or headers.get("awp-session")):
            token = envelope_mod.new_id()
            self.sessions[token] = result.caller_principal
            session = {"token": token, "sid": token, "expires": ""}

        resp_body = json.dumps({"output": out, "session": session}).encode()
        resp_headers = httpsig.sign_response(
            status=200, headers={}, body=resp_body, priv=self.priv, key_id=f"{self.domain}/{self.kid}",
        )
        return httpx.Response(200, content=resp_body, headers=resp_headers)


_CALLER_KEY_REGISTRY: dict[tuple[str, str], object] = {}


def make_client_over_peers(domain: str, kid: str, priv, peers: dict[str, FakePeer]) -> client_mod.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        peer = peers[request.url.host]
        return peer.handle(request)

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)

    def index_url(d: str) -> str:
        return f"https://{d}/.well-known/awp.json"

    c = client_mod.Client(domain, kid, priv, http=http, index_url=index_url)
    return c


@pytest.fixture(autouse=True)
def _clear_registry():
    _CALLER_KEY_REGISTRY.clear()
    yield
    _CALLER_KEY_REGISTRY.clear()


def test_fetch_index_caches_across_calls() -> None:
    peer = FakePeer("recipient.example.com")
    priv, pub = identity.generate_keypair()
    c = make_client_over_peers("sender.example.com", "sk1", priv, {"recipient.example.com": peer})

    idx1 = c.fetch_index("recipient.example.com")
    idx2 = c.fetch_index("recipient.example.com")
    assert idx1 is idx2


def test_fetch_index_verifies_self_signature() -> None:
    peer = FakePeer("recipient.example.com")
    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("sender.example.com", "sk1", priv, {"recipient.example.com": peer})
    idx = c.fetch_index("recipient.example.com")
    assert idx.domain == "recipient.example.com"


def test_resolve_finds_key_and_rejects_unknown() -> None:
    peer = FakePeer("recipient.example.com")
    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("sender.example.com", "sk1", priv, {"recipient.example.com": peer})
    pub = c.resolve("recipient.example.com", "k1")
    assert pub is not None
    with pytest.raises(identity.BadSignatureError):
        c.resolve("recipient.example.com", "no-such-kid")


def test_resolve_rejects_revoked_key() -> None:
    peer = FakePeer("recipient.example.com")
    peer.idx.keys[0].revoked = True
    bootstrap.finalize_index(peer.idx, peer.priv, peer.kid, peer.idx.inbox)
    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("sender.example.com", "sk1", priv, {"recipient.example.com": peer})
    with pytest.raises(identity.BadSignatureError):
        c.resolve("recipient.example.com", "k1")


def test_send_envelope_delivers_to_peer_inbox() -> None:
    sender_priv, sender_pub = identity.generate_keypair()
    peer = FakePeer("recipient.example.com")
    c = make_client_over_peers("sender.example.com", "sk1", sender_priv, {"recipient.example.com": peer})

    sent = c.send_envelope("message", "recipient.example.com#agent", envelope_mod.new_id(), None, {"text": "hi"}, 3600)
    assert sent.from_ == "sender.example.com"
    assert len(peer.received_envelopes) == 1
    received = peer.received_envelopes[0]
    assert received.id == sent.id

    # Verify the receiver's own signature-verification path (using this
    # SDK's own inbound-verification helper) against the sender's real key.
    peer_side_client = make_client_over_peers("recipient.example.com", "k1", peer.priv, {"sender.example.com": _SenderAsPeer(sender_priv, sender_pub)})
    peer_side_client.verify_inbound_envelope(received)


class _SenderAsPeer:
    """Stands in as a FakePeer for the sole purpose of serving the
    sender's own index, self-signed with the sender's real key, so
    verify_inbound_envelope can resolve and trust it."""

    def __init__(self, priv, pub) -> None:
        self.priv = priv
        self.idx = identity.Index(
            domain="sender.example.com", updated=identity.now_rfc3339_milli(),
            keys=[identity.new_key(pub, "sk1")], inbox="https://sender.example.com/awp/inbox",
        )
        self.idx.sign(priv, "sk1")

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/awp.json":
            return httpx.Response(200, content=json.dumps(self.idx.to_dict()).encode())
        return httpx.Response(404)


def test_send_envelope_rejects_ttl_out_of_bounds() -> None:
    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("sender.example.com", "sk1", priv, {})
    with pytest.raises(envelope_mod.TTLOutOfBoundsError):
        c.send_envelope("message", "recipient.example.com#agent", envelope_mod.new_id(), None, {}, 999999999)


def test_fetch_manifest_verifies_pin_and_signature() -> None:
    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)

    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("caller.example.com", "ck1", priv, {"tool.example.com": peer})
    fetched = c.fetch_manifest("tool.example.com#doubler")
    assert fetched.name == "tool.example.com#doubler"


def test_fetch_manifest_rejects_tampered_content_via_pin() -> None:
    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)
    # Tamper with the served bytes after pinning -- simulate a swapped manifest.
    raw, parsed = peer.manifests[m.name]
    tampered = raw.replace(b"doubles", b"BOGUS!!")
    peer.manifests[m.name] = (tampered, parsed)

    priv, _ = identity.generate_keypair()
    c = make_client_over_peers("caller.example.com", "ck1", priv, {"tool.example.com": peer})
    with pytest.raises(manifest_mod.PinMismatchError):
        c.fetch_manifest("tool.example.com#doubler")


def test_call_tool_stateless_round_trip() -> None:
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#doubler", lambda caller, inp: {"caller": caller, "double": inp["n"] * 2})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    output, session = c.call_tool("tool.example.com#doubler", {"n": 21})
    assert output == {"caller": "caller.example.com", "double": 42}
    assert session is None


def test_call_tool_dry_run_header_signed_and_delivered() -> None:
    """awp-capabilities-v0.1.md §3.1: AWP-Dry-Run is an ordinary AWP-*
    header — no httpsig change needed to cover it in the signature, and
    the call succeeds (proving the covered-components list matched what
    was actually signed)."""
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    m.capabilities = [manifest_mod.DRY_RUN_CAPABILITY]
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#doubler", lambda caller, inp: {"caller": caller, "double": inp["n"] * 2})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    output, _ = c.call_tool("tool.example.com#doubler", {"n": 21}, client_mod.CallOptions(dry_run=True))

    assert output == {"caller": "caller.example.com", "double": 42}
    assert peer.last_tool_call_headers.get("awp-dry-run") == "true"


def test_call_tool_without_dry_run_sends_no_header() -> None:
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#doubler", lambda caller, inp: {"double": inp["n"] * 2})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    c.call_tool("tool.example.com#doubler", {"n": 21})

    assert "awp-dry-run" not in peer.last_tool_call_headers


def test_call_tool_transaction_header_signed_and_delivered() -> None:
    """awp-transactions-v0.1.md §2: AWP-Transaction is an ordinary AWP-*
    header — no httpsig change needed to cover it in the signature."""
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#doubler", lambda caller, inp: {"double": inp["n"] * 2})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    txn = client_mod.Transaction(id="01hxxx", step=2, coordinator="caller.example.com")
    output, _ = c.call_tool("tool.example.com#doubler", {"n": 21}, client_mod.CallOptions(transaction=txn))

    assert output == {"double": 42}
    assert peer.last_tool_call_headers.get("awp-transaction") == txn.encode()


def test_call_tool_without_transaction_sends_no_header() -> None:
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#doubler", kind="tool", version="1.0.0",
        description="doubles", state="stateless", endpoint="https://tool.example.com/tools/doubler",
    )
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#doubler", lambda caller, inp: {"double": inp["n"] * 2})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    c.call_tool("tool.example.com#doubler", {"n": 21})

    assert "awp-transaction" not in peer.last_tool_call_headers


def test_call_tool_provider_session_lifecycle() -> None:
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#stateful", kind="tool", version="1.0.0",
        description="stateful", state="provider", endpoint="https://tool.example.com/tools/stateful",
    )
    peer.register_manifest(m)
    calls = {"n": 0}

    def handler(caller, inp):
        calls["n"] += 1
        return {"ok": True}

    peer.register_tool("tool.example.com#stateful", handler)

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    _, session = c.call_tool("tool.example.com#stateful", {})
    assert session is not None and session.token

    _, session2 = c.call_tool(
        "tool.example.com#stateful", {}, client_mod.CallOptions(session=session.token)
    )
    assert session2 is None
    assert calls["n"] == 2


def test_call_tool_unsigned_caller_rejected() -> None:
    caller_priv, _ = identity.generate_keypair()
    # Deliberately never register caller's key.

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#echo", kind="tool", version="1.0.0",
        description="echo", state="stateless", endpoint="https://tool.example.com/tools/echo",
    )
    peer.register_manifest(m)
    peer.register_tool("tool.example.com#echo", lambda caller, inp: {"ok": True})

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    with pytest.raises(client_mod.ToolCallError):
        c.call_tool("tool.example.com#echo", {})


def test_call_tool_handler_error_surfaces() -> None:
    caller_priv, caller_pub = identity.generate_keypair()
    _CALLER_KEY_REGISTRY[("caller.example.com", "ck1")] = caller_pub

    peer = FakePeer("tool.example.com")
    m = bootstrap.new_manifest(
        "tool.example.com#grumpy", kind="tool", version="1.0.0",
        description="grumpy", state="stateless", endpoint="https://tool.example.com/tools/grumpy",
    )
    peer.register_manifest(m)

    def error_handler(caller, inp):
        raise _HandlerError(apperr.CODE_REFUSED, "no thanks")

    peer.register_tool("tool.example.com#grumpy", error_handler)

    c = make_client_over_peers("caller.example.com", "ck1", caller_priv, {"tool.example.com": peer})
    with pytest.raises(client_mod.ToolCallError):
        c.call_tool("tool.example.com#grumpy", {})


class _HandlerError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def test_sign_delegation_link_produces_verifiable_link() -> None:
    priv, pub = identity.generate_keypair()
    c = client_mod.Client("delegator.example.com", "dk1", priv)
    link = c.sign_delegation_link(
        "delegate.example.com", delegation.Scope(to="tool.example.com#doubler"),
        time.time() + 3600, envelope_mod.new_id(),
    )
    assert link.delegator == "delegator.example.com"
    assert link.delegate == "delegate.example.com"
    assert link.sig is not None
    link.verify(pub)
