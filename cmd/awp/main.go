// Command awp is the AWP reference CLI: `awp conformance <domain>` runs
// the core §5 + awp-quic §8 checklists against any implementation;
// `awp outbox ls --dead` inspects a local awpd data directory's dead
// letters.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/agentask/awp/internal/conformance"
	"github.com/agentask/awp/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "conformance":
		os.Exit(runConformance(os.Args[2:]))
	case "outbox":
		os.Exit(runOutbox(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "awp: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `awp — AWP reference CLI

Usage:
  awp conformance <domain> [flags]
      Run the core §5 + awp-quic §8 conformance checklists against domain.
      Flags:
        -base-url string   Override the base URL domain resolves to (testing/local use).
        -key string        Path to a PEM-encoded ed25519 private key (self-test identity).
        -kid string        Key id matching -key, as registered in the target's own index.
        -timeout duration  Overall run timeout (default 30s).
        -quic-insecure     Skip TLS certificate verification when dialing awp/1 (dev only).

  awp outbox ls --dead -data <dir>
      List dead-lettered outbound envelopes from a local awpd data directory.
`)
}

func runConformance(args []string) int {
	fs := flag.NewFlagSet("conformance", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "override the base URL domain resolves to")
	keyPath := fs.String("key", "", "path to a PEM-encoded ed25519 private key")
	kid := fs.String("kid", "", "key id matching -key")
	timeout := fs.Duration("timeout", 30*time.Second, "overall run timeout")
	quicInsecure := fs.Bool("quic-insecure", false, "skip TLS certificate verification when dialing awp/1")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "awp conformance: expected exactly one argument, <domain>")
		return 2
	}
	domain := fs.Arg(0)

	opts := conformance.Options{HTTP: &http.Client{Timeout: 10 * time.Second}}
	if *baseURL != "" {
		opts.BaseURL = func(string) string { return *baseURL }
	}
	if *quicInsecure {
		opts.QUICTLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in dev flag
	}
	if *keyPath != "" {
		if *kid == "" {
			fmt.Fprintln(os.Stderr, "awp conformance: -kid is required alongside -key")
			return 2
		}
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "awp conformance: %v\n", err)
			return 2
		}
		opts.CallerDomain = domain
		opts.CallerKid = *kid
		opts.CallerPriv = priv
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := conformance.Run(ctx, domain, opts)
	printReport(report)
	if report.OK() {
		return 0
	}
	return 1
}

func printReport(report conformance.Report) {
	fmt.Printf("awp conformance: %s\n\n", report.Domain)
	for _, r := range report.Results {
		symbol := map[conformance.Status]string{
			conformance.Pass: "PASS",
			conformance.Fail: "FAIL",
			conformance.Skip: "SKIP",
		}[r.Status]
		fmt.Printf("[%s] %-28s %s\n", symbol, r.ID, r.Description)
		if r.Detail != "" {
			fmt.Printf("       %s\n", r.Detail)
		}
	}
	fmt.Println()
	if report.OK() {
		fmt.Println("Result: OK (no failures)")
	} else {
		fmt.Println("Result: FAILED")
	}
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: not a valid ed25519 private key PEM", path)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

func runOutbox(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "awp outbox: expected a subcommand (ls)")
		return 2
	}
	switch args[0] {
	case "ls":
		return runOutboxLs(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "awp outbox: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runOutboxLs(args []string) int {
	fs := flag.NewFlagSet("outbox ls", flag.ExitOnError)
	dead := fs.Bool("dead", false, "list only dead-lettered records")
	dataDir := fs.String("data", "./awpd-data", "awpd data directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*dead {
		fmt.Fprintln(os.Stderr, "awp outbox ls: only -dead is currently supported")
		return 2
	}

	st, err := store.OpenReadOnly(filepath.Join(*dataDir, "awpd.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "awp outbox ls: %v\n", err)
		return 1
	}
	defer st.Close()

	records, err := st.ListDead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "awp outbox ls: %v\n", err)
		return 1
	}
	if len(records) == 0 {
		fmt.Println("(no dead-lettered envelopes)")
		return 0
	}
	for _, r := range records {
		fmt.Printf("%s\tstate=%s\tattempts=%d\treason=%s\n", r.ID, r.State, r.Attempts, r.DeadReason)
	}
	return 0
}
