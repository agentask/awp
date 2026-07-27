"""A thin AWP client — the Python counterpart to sdk/go's awp.Client:
sign and send one envelope at a time, no retry, no persistence, no
receiving. See pyawp/node.py for the receiving half (the counterpart to
running cmd/awpd / embedding internal/daemon), exactly mirroring the
sdk/go-vs-internal/daemon split documented in docs/sdk-go.md.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import envelope as envelope_mod
from . import identity


class RemoteRejectedError(Exception):
    pass


class Client:
    """Signs as (domain, kid, priv). IndexURL defaults to
    "https://{domain}/.well-known/awp.json" (core §1.1); override for
    local/demo use, exactly like sdk/go's Client.IndexURL field — there is
    no DNS in this demo, only two local ports.
    """

    def __init__(
        self,
        domain: str,
        kid: str,
        priv: Ed25519PrivateKey,
        http: httpx.AsyncClient,
        index_url: Callable[[str], str] | None = None,
    ) -> None:
        self.domain = domain
        self.kid = kid
        self.priv = priv
        self._http = http
        self._index_url = index_url or (lambda d: f"https://{d}/.well-known/awp.json")
        self._cache: dict[str, identity.Index] = {}

    async def fetch_index(self, domain: str) -> identity.Index:
        if domain in self._cache:
            return self._cache[domain]
        return await self.refresh(domain)

    async def refresh(self, domain: str) -> identity.Index:
        """Force a re-fetch, discarding any cached index — core §0.1's
        rotation-race retry, and the direct counterpart to sdk/go's
        Client.Refresh. This demo has no rotation-continuity checking
        (see internal/keyresolver in Go for what that actually requires);
        every fetch is a fresh TOFU trust of whatever key the index names.
        """
        url = self._index_url(domain)
        resp = await self._http.get(url)
        resp.raise_for_status()
        idx = identity.Index.from_dict(resp.json())
        idx.verify_self_sig()
        self._cache[domain] = idx
        return idx

    async def resolve(self, domain: str, kid: str) -> Ed25519PublicKey:
        idx = await self.fetch_index(domain)
        for k in idx.keys or []:
            if k.kid == kid:
                if k.revoked:
                    raise identity.BadSignatureError(f"key {domain}/{kid} is revoked")
                return k.public_key()
        raise identity.BadSignatureError(f"no key {domain}/{kid} in {domain}'s index")

    async def send_envelope(
        self,
        kind: str,
        to: str,
        thread: str,
        body: Any,
        *,
        in_reply_to: str | None = None,
        ttl: int = 3600,
    ) -> envelope_mod.Envelope:
        """Builds, signs, and POSTs one envelope to `to`'s resolved inbox —
        one delivery attempt, synchronously. The direct counterpart to
        sdk/go's Client.SendEnvelope; see its doc comment for why this has
        no retry/outbox semantics on purpose."""
        e = envelope_mod.Envelope(
            id=envelope_mod.new_id(), kind=kind, from_=self.domain, to=to, thread=thread,
            in_reply_to=in_reply_to, ts=identity.now_rfc3339_milli(), ttl=ttl, body=body,
        )
        e.validate_ttl()
        e.sign(self.priv, self.kid)

        to_domain = identity.domain_of(to)
        idx = await self.fetch_index(to_domain)
        if not idx.inbox:
            raise RemoteRejectedError(f"{to_domain} declares no inbox")

        raw = json.dumps(e.to_dict()).encode("utf-8")
        resp = await self._http.post(
            idx.inbox, content=raw, headers={"Content-Type": "application/awp+json"}
        )
        if resp.status_code not in (200, 202):
            raise RemoteRejectedError(
                f"{idx.inbox} rejected envelope: status {resp.status_code}: {resp.text}"
            )
        return e
