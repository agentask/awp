""".env / env var loading and AWP_PEERS static-map DNS resolution — the
Python counterpart to agents/go/config.go and agents/rust/src/config.rs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_PEERS = "trip-planner.local=http://127.0.0.1:8001,activities.local=http://127.0.0.1:8003"


class ConfigError(Exception):
    pass


@dataclass
class Config:
    """Every env-driven setting for this agent. See .env.example for the
    full list and defaults."""

    xai_api_key: str
    model: str
    port: int
    domain: str
    peers: dict[str, str]  # domain -> base URL

    # advertise_host is the host peers use to reach this agent's inbox —
    # baked into the self-signed index served at /.well-known/awp.json.
    # Distinct from the bind address (always 0.0.0.0, see main.py):
    # natively all agents share one machine's loopback, so 127.0.0.1
    # works; under docker compose, a peer container can't reach another
    # container via 127.0.0.1 (that's its own loopback), so it must be
    # set to this agent's own compose service name instead.
    advertise_host: str

    def index_url_for(self, domain: str) -> str:
        """Resolves a peer domain's index base URL from the static
        AWP_PEERS map — the DNS stand-in for these *.local demo domains,
        same pattern as agents/go/config.go's indexURLFor and
        agents/rust/src/config.rs's index_url_for."""
        base = self.peers.get(domain)
        if base is not None:
            return base
        return f"https://{domain}"


def _env_default(key: str, default: str) -> str:
    return os.environ.get(key) or default


def _parse_peers(s: str) -> dict[str, str]:
    """Parses the "domain=baseURL,domain=baseURL" form of AWP_PEERS."""
    peers: dict[str, str] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ConfigError(f"AWP_PEERS: malformed pair {pair!r} (want domain=baseURL)")
        domain, base_url = pair.split("=", 1)
        peers[domain.strip()] = base_url.strip()
    return peers


def load_config() -> Config:
    """Loads a .env file if present (missing is fine — plain exported env
    vars work too) and reads this agent's settings."""
    load_dotenv()  # ok if .env doesn't exist; real env vars still apply

    api_key = os.environ.get("XAI_API_KEY")
    if not api_key:
        raise ConfigError("XAI_API_KEY is required (set it in the environment or agents/python/.env)")

    model = _env_default("AWP_MODEL", "grok-4-fast")
    domain = _env_default("AWP_SELF_DOMAIN", "concierge.local")

    port_str = _env_default("AWP_SELF_PORT", "8002")
    try:
        port = int(port_str)
    except ValueError as e:
        raise ConfigError(f"AWP_SELF_PORT {port_str!r} is not a valid port: {e}") from e

    peers_str = _env_default("AWP_PEERS", DEFAULT_PEERS)
    peers = _parse_peers(peers_str)

    advertise_host = _env_default("AWP_ADVERTISE_HOST", "127.0.0.1")

    return Config(
        xai_api_key=api_key, model=model, port=port, domain=domain, peers=peers, advertise_host=advertise_host
    )
