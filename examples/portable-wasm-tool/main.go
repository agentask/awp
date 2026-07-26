// Command portable-wasm-tool demonstrates AWP's other tool distribution
// path (core §1.2): "portable" means the CALLER fetches the manifest,
// downloads the pinned wasm32-wasip1 binary, and runs it in its OWN
// wazero sandbox — no per-call network round trip to the provider at all,
// unlike a Hosted tool. The provider is trusted only for the manifest's
// signature and the binary's sha256 pin; the caller decides what
// capabilities (clock, random) to actually grant when it runs the binary
// itself, since it's the one holding the sandbox.
//
// ./tool is compiled to wasm at run time via `go build GOOS=wasip1
// GOARCH=wasm`, the same way internal/wasmrt's own tests build their
// fixtures — there's no wasm binary checked into this repo.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/store"
	"github.com/agentask/awp/internal/wasmrt"
	awp "github.com/agentask/awp/sdk/go"
)

// noopResolver satisfies daemon.Config's Resolver requirement. Nothing in
// this example ever makes a signed sync call or delivers an async
// envelope, so it's never actually invoked — the provider daemon only
// needs a non-nil Resolver to construct.
type noopResolver struct{}

func (noopResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	return nil, fmt.Errorf("no key known for %s/%s", domain, kid)
}
func (noopResolver) Refresh(string) error                { return nil }
func (noopResolver) ResolveInbox(string) (string, error) { return "", nil }
func (noopResolver) ResolveTransport(string, string) (string, bool, error) {
	return "", false, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	wasmBytes, shaHex, err := buildToolWasm()
	if err != nil {
		return fmt.Errorf("build ./tool for wasm32-wasip1: %w", err)
	}
	fmt.Printf("compiled ./tool -> %d bytes, sha256 %s\n\n", len(wasmBytes), shaHex)

	// Where the provider actually hosts the binary for download. Plain
	// HTTP is fine here — this artifact fetch isn't part of AWP's signed
	// wire protocol; the sha256 pin (checked below, and again by
	// wasmrt.Compile) is what protects its integrity, the same way a
	// swapped manifest is caught by its own pin before its signature is
	// even checked.
	distSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(wasmBytes)
	}))
	defer distSrv.Close()

	// The provider daemon needs a working executor to register a tool at
	// all (RegisterTool requires exactly one of Handler/Module), even
	// though this example deliberately never calls it over the network —
	// the whole point of "portable" is that the caller runs its own copy
	// instead. A real operator that also wants to serve this tool over
	// HTTP for callers who'd rather not run wasm themselves could still
	// call it at /awp/tools/wordcount; this demo just doesn't.
	providerMod, err := wasmrt.Compile(ctx, wasmBytes, shaHex)
	if err != nil {
		return fmt.Errorf("wasmrt.Compile (provider): %w", err)
	}
	defer providerMod.Close(ctx)

	toolDomain := "wasm-tool.example"
	_, toolPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(os.TempDir(), "portable-wasm-tool.db")
	defer os.Remove(dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	d, err := daemon.New(daemon.Config{
		Domain: toolDomain, Kid: "k1", Priv: toolPriv,
		Store: st, Clock: clock.Real{}, Resolver: noopResolver{},
	})
	if err != nil {
		return fmt.Errorf("construct daemon: %w", err)
	}
	srv := httptest.NewTLSServer(d)
	defer srv.Close()
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		return fmt.Errorf("finalize index: %w", err)
	}

	toolManifest := &manifest.Manifest{
		Awp: "0.1", Name: toolDomain + "#wordcount", Kind: "tool", Version: "1.0.0",
		Description: "Counts words and characters in a text; portable wasm32-wasip1 distribution.",
		IO:          manifest.IOSchema{Input: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}}}`)},
		Distribution: manifest.Distribution{Portable: &manifest.Portable{
			URL: distSrv.URL + "/tool.wasm", Sha256: shaHex,
			Runtime: "wasm32-wasip1", Interface: "stdio-json/1",
			Capabilities: []string{"clock"}, // this tool wants wall-clock time
		}},
		State:   "stateless",
		Auth:    manifest.Auth{Sig: "required"},
		Pricing: json.RawMessage("null"),
	}
	if err := d.RegisterTool(srv.URL, daemon.Tool{Manifest: toolManifest, Module: providerMod}); err != nil {
		return fmt.Errorf("register tool: %w", err)
	}

	// --- Caller: fetch the manifest, download the binary, run it locally ---
	callerDomain := "agent.example"
	client := &awp.Client{
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, //nolint:gosec // local self-signed demo cert
		IndexURL: func(domain string) string {
			if domain == toolDomain {
				return srv.URL + "/.well-known/awp.json"
			}
			return "https://" + domain + "/.well-known/awp.json"
		},
	}

	m, err := client.FetchManifest(ctx, toolDomain+"#wordcount")
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}
	if m.Distribution.Portable == nil {
		return fmt.Errorf("%s has no portable distribution", m.Name)
	}
	fmt.Printf("manifest declares capabilities: %v\n", m.Distribution.Portable.Capabilities)

	downloaded, err := downloadAndVerify(m.Distribution.Portable.URL, m.Distribution.Portable.Sha256)
	if err != nil {
		return fmt.Errorf("download tool binary: %w", err)
	}

	// The caller compiles its OWN copy from the bytes it independently
	// fetched and verified — it never touches the provider's in-memory
	// providerMod.
	callerMod, err := wasmrt.Compile(ctx, downloaded, m.Distribution.Portable.Sha256)
	if err != nil {
		return fmt.Errorf("wasmrt.Compile (caller): %w", err)
	}
	defer callerMod.Close(ctx)

	input, err := json.Marshal(map[string]string{"text": "the quick brown fox jumps over the lazy dog"})
	if err != nil {
		return err
	}
	req := wasmrt.Request{Awp: "0.1", Caller: callerDomain, Input: input}

	fmt.Println("\nrunning locally with no clock capability granted (host policy, despite the manifest's request):")
	resp := callerMod.Run(ctx, req, wasmrt.Config{})
	printWasmResponse(resp)

	fmt.Println("\nrunning locally with clock capability granted:")
	resp = callerMod.Run(ctx, req, wasmrt.Config{Capabilities: []wasmrt.Capability{wasmrt.CapabilityClock}})
	printWasmResponse(resp)

	fmt.Println("\nnote: no network call happened for either run above — that's the whole point of a portable tool.")
	return nil
}

func downloadAndVerify(url, wantSha256Hex string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // local demo dist server URL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSha256Hex {
		return nil, fmt.Errorf("sha256 mismatch: manifest pins %q, downloaded binary hashes to %q", wantSha256Hex, got)
	}
	return data, nil
}

func printWasmResponse(resp wasmrt.Response) {
	if resp.Error != nil {
		fmt.Printf("  error: %s: %s\n", resp.Error.Code, resp.Error.Detail)
		return
	}
	fmt.Printf("  output: %s\n", bytes.TrimSpace(resp.Output))
}

// buildToolWasm cross-compiles ./tool to wasm32-wasip1 and returns its
// bytes and hex sha256 — the pin a manifest's distribution.portable.sha256
// carries, and what wasmrt.Compile checks the binary against before it
// ever runs.
func buildToolWasm() (wasmBytes []byte, shaHex string, err error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, "", fmt.Errorf("determine this file's own path")
	}
	toolDir := filepath.Join(filepath.Dir(thisFile), "tool")

	outPath := filepath.Join(os.TempDir(), "portable-wasm-tool.wasm")
	defer os.Remove(outPath)
	cmd := exec.Command("go", "build", "-o", outPath, toolDir)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("go build: %w\n%s", err, out)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}
