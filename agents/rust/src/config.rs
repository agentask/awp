//! `.env` / env var loading and `AWP_PEERS` static-map DNS resolution — the
//! Rust counterpart to `agents/go/config.go` and the env-var reading in
//! `agents/python/agent_a/main.py`.

use std::collections::HashMap;
use std::env;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("XAI_API_KEY is required (set it in the environment or agents/rust/.env)")]
    MissingApiKey,
    #[error("AWP_SELF_PORT {0:?} is not a valid port: {1}")]
    BadPort(String, std::num::ParseIntError),
    #[error("AWP_PEERS: malformed pair {0:?} (want domain=baseURL)")]
    MalformedPeer(String),
}

/// Every env-driven setting for this agent. See `.env.example` for the
/// full list and defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub xai_api_key: String,
    pub model: String,
    pub port: u16,
    pub domain: String,
    pub peers: HashMap<String, String>, // domain -> base URL

    /// The host peers use to reach this agent's inbox — baked into the
    /// self-signed index served at `/.well-known/awp.json`. Distinct from
    /// the bind address (always `0.0.0.0`, see `main.rs`): natively all
    /// agents share one machine's loopback, so `127.0.0.1` works; under
    /// docker compose, a peer container can't reach another container via
    /// `127.0.0.1` (that's its own loopback), so it must be set to this
    /// agent's own compose service name instead.
    pub advertise_host: String,
}

const DEFAULT_PEERS: &str =
    "trip-planner.local=http://127.0.0.1:8001,concierge.local=http://127.0.0.1:8002";

impl Config {
    /// Loads a `.env` file if present (missing is fine — plain exported env
    /// vars work too) and reads this agent's settings.
    pub fn load() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv(); // ok if .env doesn't exist; real env vars still apply

        let xai_api_key = env::var("XAI_API_KEY").map_err(|_| ConfigError::MissingApiKey)?;
        if xai_api_key.is_empty() {
            return Err(ConfigError::MissingApiKey);
        }

        let model = env_default("AWP_MODEL", "grok-4-fast");
        let domain = env_default("AWP_SELF_DOMAIN", "activities.local");

        let port_str = env_default("AWP_SELF_PORT", "8003");
        let port: u16 = port_str
            .parse()
            .map_err(|e| ConfigError::BadPort(port_str.clone(), e))?;

        let peers_str = env_default("AWP_PEERS", DEFAULT_PEERS);
        let peers = parse_peers(&peers_str)?;

        let advertise_host = env_default("AWP_ADVERTISE_HOST", "127.0.0.1");

        Ok(Config {
            xai_api_key,
            model,
            port,
            domain,
            peers,
            advertise_host,
        })
    }

    /// Resolves a peer domain's index base URL from the static `AWP_PEERS`
    /// map — the DNS stand-in for these `*.local` demo domains, same
    /// pattern as `agents/python/agent_a/main.py`'s `index_url_for` and
    /// `agents/go/config.go`'s `indexURLFor`.
    pub fn index_url_for(&self, domain: &str) -> String {
        match self.peers.get(domain) {
            Some(base) => base.clone(),
            None => format!("https://{domain}"),
        }
    }
}

fn env_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parses the "domain=baseURL,domain=baseURL" form of `AWP_PEERS`.
fn parse_peers(s: &str) -> Result<HashMap<String, String>, ConfigError> {
    let mut peers = HashMap::new();
    for pair in s.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (domain, base_url) = pair
            .split_once('=')
            .ok_or_else(|| ConfigError::MalformedPeer(pair.to_string()))?;
        peers.insert(domain.trim().to_string(), base_url.trim().to_string());
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_peers() {
        let peers = parse_peers("a.local=http://x,  b.local = http://y ").unwrap();
        assert_eq!(peers.get("a.local").unwrap(), "http://x");
        assert_eq!(peers.get("b.local").unwrap(), "http://y");
    }

    #[test]
    fn rejects_malformed_peer() {
        assert!(parse_peers("nodelimiter").is_err());
    }
}
