package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// config holds every env-driven setting for this agent. See .env.example
// for the full list and defaults.
type config struct {
	XAIAPIKey string
	Model     string
	Port      int
	Domain    string
	Peers     map[string]string // domain -> base URL

	// AdvertiseHost is the host peers use to reach this agent's inbox —
	// baked into the self-signed index served at /.well-known/awp.json.
	// Distinct from the bind address (always 0.0.0.0, see main.go):
	// natively all agents share one machine's loopback, so 127.0.0.1
	// works; under docker compose, a peer container can't reach another
	// container via 127.0.0.1 (that's its own loopback), so it must be
	// set to this agent's own compose service name instead.
	AdvertiseHost string
}

// loadConfig loads a .env file if present (missing is fine — plain
// exported env vars work too) and reads this agent's settings.
func loadConfig() (*config, error) {
	_ = godotenv.Load() // ok if .env doesn't exist; real env vars still apply

	apiKey := os.Getenv("XAI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("XAI_API_KEY is required (set it in the environment or agents/go/.env)")
	}

	model := getEnvDefault("AWP_MODEL", "grok-4-fast")
	domain := getEnvDefault("AWP_SELF_DOMAIN", "trip-planner.local")

	portStr := getEnvDefault("AWP_SELF_PORT", "8001")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("AWP_SELF_PORT %q is not a valid port: %w", portStr, err)
	}

	peersStr := getEnvDefault("AWP_PEERS", "concierge.local=http://127.0.0.1:8002,activities.local=http://127.0.0.1:8003")
	peers, err := parsePeers(peersStr)
	if err != nil {
		return nil, fmt.Errorf("AWP_PEERS: %w", err)
	}

	advertiseHost := getEnvDefault("AWP_ADVERTISE_HOST", "127.0.0.1")

	return &config{
		XAIAPIKey:     apiKey,
		Model:         model,
		Port:          port,
		Domain:        domain,
		Peers:         peers,
		AdvertiseHost: advertiseHost,
	}, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parsePeers parses the "domain=baseURL,domain=baseURL" form of AWP_PEERS.
func parsePeers(s string) (map[string]string, error) {
	peers := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, baseURL, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("malformed pair %q (want domain=baseURL)", pair)
		}
		peers[strings.TrimSpace(domain)] = strings.TrimSpace(baseURL)
	}
	return peers, nil
}

// indexURLFor resolves a peer domain's index base URL from the static
// AWP_PEERS map — the DNS stand-in for these *.local demo domains, same
// pattern as agents/python/agent_a/main.py's index_url_for.
func (c *config) indexURLFor(domain string) string {
	if base, ok := c.Peers[domain]; ok {
		return base
	}
	return "https://" + domain
}
