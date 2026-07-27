"""Identity bootstrap helpers for a demo/standalone AWP participant that
has no Go internal/identity to import directly: generate an ed25519
keypair, build+self-sign a domain Index, and build+sign an entity
Manifest — enough to mint a fresh `*.local` identity and serve
`/.well-known/awp.json` without hand-rolling any of the crypto in
identity.py/manifest.py yourself.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import identity, manifest as manifest_mod


def new_domain_identity(domain: str, kid: str = "k1") -> tuple[Ed25519PrivateKey, identity.Index]:
    """Generates a fresh ed25519 keypair and a self-signed Index naming it
    as the domain's sole key. `inbox` is left blank — call
    `finalize_index` once the node's own reachable base URL is known."""
    priv, pub = identity.generate_keypair()
    idx = identity.Index(
        domain=domain,
        updated=identity.now_rfc3339_milli(),
        keys=[identity.new_key(pub, kid)],
        entities=None,
        inbox="",
    )
    idx.sign(priv, kid)
    return priv, idx


def finalize_index(idx: identity.Index, priv: Ed25519PrivateKey, kid: str, inbox_url: str) -> None:
    """Sets the index's advertised inbox URL, bumps `updated`, and
    re-signs — call once the node's HTTP server is listening and its own
    reachable base URL is known, before any peer is expected to fetch
    `/.well-known/awp.json`."""
    idx.inbox = inbox_url
    idx.updated = identity.now_rfc3339_milli()
    idx.sign(priv, kid)


def new_manifest(
    name: str,
    *,
    kind: str,
    version: str,
    description: str,
    state: str,
    endpoint: str | None = None,
    io_input: Any = None,
    io_output: Any = None,
    scopes: list[str] | None = None,
) -> manifest_mod.Manifest:
    """Builds an unsigned Manifest for a hosted (sync) entity — the common
    case for a demo tool provider. Sign it with `.sign(priv, kid)` before
    serving it, and register its sha256 in the domain index's
    entities[].manifest_sha256 pin (compute the hash over the exact bytes
    you serve, i.e. after signing and JSON-encoding).
    """
    return manifest_mod.Manifest(
        name=name, kind=kind, version=version,
        updated=identity.now_rfc3339_milli(), description=description,
        io=manifest_mod.IOSchema(input=io_input, output=io_output),
        distribution=manifest_mod.Distribution(
            hosted=manifest_mod.Hosted(endpoint=endpoint) if endpoint else None
        ),
        state=state,
        auth=manifest_mod.Auth(sig="required", scopes=scopes),
    )
