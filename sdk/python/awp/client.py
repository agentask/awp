"""A thin AWP client, the Python counterpart to sdk/go's awp.Client.

"Thin" is deliberate: unlike a full daemon, this client keeps no on-disk
state, runs no retry/outbox state machine, and does not receive envelopes
on its own — it is for third-party Python programs that want to speak AWP
directly (sign, send, verify) without running a daemon. Domain indexes are
cached in memory for the lifetime of the Client only.

Beyond sdk/go's literal Client surface, this module also exposes
`verify_inbound_envelope`, since a Python program building a receiving
node has no internal/envelope+internal/identity to import directly (unlike
Go code in this same module) — see this package's README.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import delegation, envelope as envelope_mod, httpsig, identity, manifest as manifest_mod


class RemoteRejectedError(Exception):
    pass


class ToolCallError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@dataclass
class CallOptions:
    session: str = ""
    delegation: list[delegation.Link] | None = None
    # dry_run sets AWP-Dry-Run: true (awp-capabilities-v0.1.md §3.1) — an
    # ordinary AWP-* header, so it's covered by the signature automatically
    # with no change to sign_request's covered-component logic. Advisory:
    # a provider that never declared the "dry-run" capability MAY ignore
    # it silently rather than reject the call.
    dry_run: bool = False


@dataclass
class SessionInfo:
    token: str
    sid: str
    expires: str

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "SessionInfo":
        return SessionInfo(token=d.get("token", ""), sid=d.get("sid", ""), expires=d.get("expires", ""))


def _default_index_url(domain: str) -> str:
    return f"https://{domain}/.well-known/awp.json"


class Client:
    """Signs as (domain, kid, priv). All methods are safe for concurrent
    use in the sense that they don't mutate shared state unsafely, though
    this is a synchronous-style client wrapped over httpx's sync API for
    parity with the simplicity of sdk/go's Client — construct one Client
    per thread/context if you need true concurrency guarantees beyond
    what a shared httpx.Client provides.
    """

    def __init__(
        self,
        domain: str,
        kid: str,
        priv: Ed25519PrivateKey,
        *,
        http: httpx.Client | None = None,
        index_url: Any = None,
    ) -> None:
        self.domain = domain
        self.kid = kid
        self.priv = priv
        self._http = http or httpx.Client()
        self._index_url = index_url or _default_index_url
        self._cache: dict[str, identity.Index] = {}

    def _key_id(self) -> str:
        return f"{self.domain}/{self.kid}"

    def fetch_index(self, domain: str) -> identity.Index:
        """Resolves domain's signed index, caching it for the lifetime of
        the Client. The index's self-signature is verified (TOFU: the
        first fetch establishes trust in whichever key it names)."""
        if domain in self._cache:
            return self._cache[domain]
        return self._fetch_index_uncached(domain)

    def refresh(self, domain: str) -> identity.Index:
        """Discards domain's cached index and re-fetches it, re-trusting
        (TOFU) whatever the new document names. This SDK does not persist
        a rotation history across process runs, so this simply re-fetches;
        long-running programs that need cross-restart rotation-continuity
        checking must track it themselves."""
        return self._fetch_index_uncached(domain)

    def _fetch_index_uncached(self, domain: str) -> identity.Index:
        url = self._index_url(domain)
        resp = self._http.get(url)
        raw = resp.content
        if resp.status_code != 200:
            raise RemoteRejectedError(f"awp: fetch index {url}: status {resp.status_code}")
        idx = identity.Index.from_dict(json.loads(raw))
        idx.verify_self_sig()
        self._cache[domain] = idx
        return idx

    def resolve(self, domain: str, kid: str) -> Ed25519PublicKey:
        """Implements httpsig.KeyResolver and delegation.KeyResolver: look
        up (domain, kid) in that domain's index, fetching it first if
        needed."""
        idx = self.fetch_index(domain)
        for k in idx.keys or []:
            if k.kid == kid:
                if k.revoked:
                    raise identity.BadSignatureError(f"awp: key {domain}/{kid} is revoked")
                return k.public_key()
        raise identity.BadSignatureError(f"awp: no key {domain}/{kid} in {domain}'s index")

    # httpsig.KeyResolver protocol
    def resolve_key(self, domain: str, kid: str) -> Ed25519PublicKey:
        return self.resolve(domain, kid)

    def refresh_key_domain(self, domain: str) -> None:
        self.refresh(domain)

    def fetch_manifest(self, principal: str) -> manifest_mod.Manifest:
        """Resolves principal's manifest via its domain's index, verifying
        its sha256 pin (core §1.2) and its own signature before returning
        it."""
        domain = identity.domain_of(principal)
        idx = self.fetch_index(domain)
        return self._fetch_manifest(idx, principal)

    def _fetch_manifest(self, idx: identity.Index, principal: str) -> manifest_mod.Manifest:
        entry = None
        for e in idx.entities or []:
            if e.name == principal:
                entry = e
                break
        if entry is None:
            raise RemoteRejectedError(
                f"awp: {principal} is not listed in {identity.domain_of(principal)}'s index"
            )

        resp = self._http.get(entry.manifest)
        raw = resp.content
        if resp.status_code != 200:
            raise RemoteRejectedError(f"awp: fetch manifest {entry.manifest}: status {resp.status_code}")

        manifest_mod.verify_pinned_sha256(raw, entry.manifest_sha256)

        m = manifest_mod.Manifest.from_dict(json.loads(raw))
        if m.sig is None:
            raise RemoteRejectedError(f"awp: manifest for {principal} has no signature")
        pub = self.resolve(identity.domain_of(m.name), m.sig.kid)
        m.verify(pub)
        return m

    def send_envelope(
        self,
        kind: str,
        to: str,
        thread: str,
        in_reply_to: str | None,
        body: Any,
        ttl: int = 0,
    ) -> envelope_mod.Envelope:
        """Builds, signs, and delivers an envelope directly to `to`'s
        resolved inbox. A single synchronous delivery attempt — no retry,
        no persistence; a caller wanting outbox semantics (backoff,
        dead-lettering, resumable delivery across restarts) needs a real
        daemon instead of this SDK.

        ttl of 0 defaults to 3600s. in_reply_to may be None.
        """
        if ttl == 0:
            ttl = 3600
        e = envelope_mod.Envelope(
            id=envelope_mod.new_id(), kind=kind, from_=self.domain, to=to, thread=thread,
            in_reply_to=in_reply_to, ts=identity.now_rfc3339_milli(), ttl=ttl, body=body,
        )
        e.validate_ttl()
        e.sign(self.priv, self.kid)
        e.validate_size()

        raw = json.dumps(e.to_dict()).encode("utf-8")

        domain = identity.domain_of(to)
        idx = self.fetch_index(domain)
        if not idx.inbox:
            raise RemoteRejectedError(f"awp: {domain} declares no inbox")

        resp = self._http.post(
            idx.inbox, content=raw, headers={"Content-Type": "application/awp+json"}
        )
        if resp.status_code not in (200, 202):
            raise RemoteRejectedError(
                f"awp: {idx.inbox} rejected envelope: status {resp.status_code}: {resp.text}"
            )
        return e

    def call_tool(
        self,
        tool_principal: str,
        input: Any,
        opts: CallOptions | None = None,
    ) -> tuple[Any, SessionInfo | None]:
        """Resolves tool_principal's manifest, signs a sync HTTP call per
        awp-sig, and returns its output. If the provider signs its
        response (awp-sig §3, SHOULD), that signature is verified — a
        present-but-invalid response signature is treated as an error, per
        spec; an absent one is not."""
        opts = opts or CallOptions()
        domain = identity.domain_of(tool_principal)
        idx = self.fetch_index(domain)
        m = self._fetch_manifest(idx, tool_principal)
        if m.distribution.hosted is None:
            raise RemoteRejectedError(f"awp: {tool_principal} has no hosted (sync) endpoint")

        endpoint = m.distribution.hosted.endpoint
        input_bytes = json.dumps(input).encode("utf-8") if not isinstance(input, (bytes, bytearray)) else bytes(input)

        headers: dict[str, str] = {}
        if opts.session:
            headers["AWP-Session"] = opts.session
        if opts.delegation:
            headers["AWP-Delegation"] = httpsig.encode_delegation_header(opts.delegation)
        if opts.dry_run:
            headers["AWP-Dry-Run"] = "true"

        signed_headers = httpsig.sign_request(
            method="POST", url=endpoint, headers=headers, body=input_bytes,
            priv=self.priv, key_id=self._key_id(),
        )

        resp = self._http.post(endpoint, content=input_bytes, headers=signed_headers)
        resp_body = resp.content

        verify_result = httpsig.verify_response(
            status=resp.status_code, headers=dict(resp.headers), body=resp_body,
            now=time.time(), resolve_key=self,
        )
        if verify_result.err is not None:
            raise ToolCallError(
                verify_result.err.code,
                f"tool response signature invalid: {verify_result.err.detail}",
            )

        if resp.status_code // 100 != 2:
            try:
                err_body = json.loads(resp_body)
                err = err_body.get("error")
            except Exception:
                err = None
            if err:
                raise ToolCallError(err.get("code", "internal"), err.get("detail", ""))
            raise ToolCallError("internal", f"tool call failed: status {resp.status_code}: {resp_body!r}")

        out = json.loads(resp_body) if resp_body else {}
        output = out.get("output")
        session_raw = out.get("session")
        session = SessionInfo.from_dict(session_raw) if session_raw else None
        return output, session

    def sign_delegation_link(
        self, delegate: str, scope: delegation.Scope, expires: float, nonce: str
    ) -> delegation.Link:
        """Builds and signs one core §2.5 delegation link with this Client
        as the delegator. `expires` is a unix timestamp (seconds); `nonce`
        should be a fresh envelope_mod.new_id() per link."""
        from datetime import datetime, timezone

        link = delegation.Link(
            delegator=self.domain, delegate=delegate, scope=scope,
            expires=delegation.format_rfc3339(datetime.fromtimestamp(expires, tz=timezone.utc)),
            nonce=nonce,
        )
        link.sign(self.priv, self.kid)
        return link

    def verify_inbound_envelope(self, env: envelope_mod.Envelope) -> None:
        """Verifies an INBOUND envelope's signature, resolving the
        sender's key via this Client's Index/Resolve machinery — sdk/go's
        equivalent lives in internal/envelope+internal/identity, directly
        importable by Go code in the same module; Python has no such
        internal/ to reach into, so this method exists to let a receiving
        node built on this SDK avoid hand-rolling the same crypto."""
        if env.sig is None:
            raise identity.BadSignatureError(f"awp: envelope {env.id!r} has no sig")
        from_domain = identity.domain_of(env.from_)
        try:
            pub = self.resolve(from_domain, env.sig.kid)
            env.verify(pub)
        except identity.BadSignatureError:
            self.refresh(from_domain)
            pub = self.resolve(from_domain, env.sig.kid)
            env.verify(pub)
