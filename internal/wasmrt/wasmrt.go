// Package wasmrt implements the core §1.2 `stdio-json/1` portable tool
// runtime on wazero: exactly one JSON request on stdin, exactly one JSON
// response on stdout, exit 0 is the only success. Grantable capabilities
// are "clock" and "random"; network and filesystem are never grantable.
package wasmrt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/agentask/awp/internal/apperr"
)

// Capability is a grantable stdio-json/1 capability (core §1.2).
type Capability string

const (
	CapabilityClock  Capability = "clock"
	CapabilityRandom Capability = "random"
)

// DefaultTimeout is core §1.2's reference execution timeout.
const DefaultTimeout = 30 * time.Second

// Request is the stdio-json/1 stdin document (core §1.2).
type Request struct {
	Awp     string          `json:"awp"`
	Caller  string          `json:"caller"`
	Session *string         `json:"session"`
	Input   json.RawMessage `json:"input"`
}

// Response is the stdio-json/1 stdout document: exactly one of Output or
// Error is populated.
type Response struct {
	Output json.RawMessage `json:"output,omitempty"`
	Error  *apperr.Error   `json:"error,omitempty"`
}

// Module is a sha256-verified, compiled portable tool module, ready to be
// Run any number of times (each Run gets a fresh, isolated instantiation —
// core §1.2 gives no cross-call state guarantee, and `state: stateless`
// tools are the only kind this runtime profile serves).
type Module struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	SHA256   string
}

// Compile verifies wasmBytes against wantSHA256Hex (core §1.2: "Hosts MUST
// verify sha256 of the fetched module before execution") and compiles it.
// The returned Module owns a wazero.Runtime; call Close when done.
func Compile(ctx context.Context, wasmBytes []byte, wantSHA256Hex string) (*Module, error) {
	sum := sha256.Sum256(wasmBytes)
	got := hex.EncodeToString(sum[:])
	if got != wantSHA256Hex {
		return nil, fmt.Errorf("wasmrt: sha256 mismatch: module hashes to %q, want %q", got, wantSHA256Hex)
	}

	rt := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("wasmrt: instantiate wasi_snapshot_preview1: %w", err)
	}
	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("wasmrt: compile module: %w", err)
	}
	return &Module{runtime: rt, compiled: compiled, SHA256: got}, nil
}

// Close releases the underlying wazero runtime and compiled module.
func (m *Module) Close(ctx context.Context) error {
	return m.runtime.Close(ctx)
}

// Config controls one execution.
type Config struct {
	Capabilities []Capability
	// Timeout defaults to DefaultTimeout (core §1.2: "SHOULD impose an
	// execution timeout (reference: 30s)").
	Timeout time.Duration
}

func (c Config) has(cap Capability) bool {
	return slices.Contains(c.Capabilities, cap)
}

func (c Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// Run executes the module once against req. Exit code 0 with a valid
// stdout document is the ONLY success (core §1.2); nonzero exit, empty
// stdout, unparseable stdout, or a timeout are all host-side
// error(internal). Anything written to stderr is discarded by the caller
// of Run except via the returned Response — see RunWithStderr if the
// caller wants it for host logs (core §1.2: "host logs only, never
// caller-visible").
func (m *Module) Run(ctx context.Context, req Request, cfg Config) Response {
	resp, _ := m.RunWithStderr(ctx, req, cfg)
	return resp
}

// RunWithStderr is Run, additionally returning the module's raw stderr
// output for the host to log — core §1.2: "Anything the module writes to
// stderr is host log material, never returned to the caller." Callers MUST
// route stderr to logs only, never surface it to whoever invoked the tool.
func (m *Module) RunWithStderr(ctx context.Context, req Request, cfg Config) (Response, []byte) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return internalError("marshal request: " + err.Error()), nil
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()

	var stdout, stderr bytes.Buffer
	modCfg := wazero.NewModuleConfig().
		WithStdin(bytes.NewReader(reqBytes)).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithName("") // anonymous: allows repeated instantiation of the same CompiledModule

	// Grantable capabilities, per core §1.2. wazero's own default (no
	// WithSysWalltime/WithSysNanotime/WithRandSource) is a deterministic
	// fake clock/random source, not a missing import — see this package's
	// doc on the deliberate reading of "unbacked... not stubs" this
	// implements (docs/experiments.md has the full reasoning). Network and
	// filesystem are never grantable: wazero's ModuleConfig already
	// defaults to no filesystem access absent WithFS/WithFSConfig, and
	// WASI preview1 has no networking syscalls to gate in the first place.
	if cfg.has(CapabilityClock) {
		modCfg = modCfg.WithSysWalltime().WithSysNanotime()
	}
	if cfg.has(CapabilityRandom) {
		modCfg = modCfg.WithRandSource(rand.Reader)
	}

	mod, err := m.runtime.InstantiateModule(runCtx, m.compiled, modCfg)
	if mod != nil {
		defer mod.Close(ctx)
	}

	if err != nil {
		var exitErr *sys.ExitError
		switch {
		case errors.As(err, &exitErr):
			if exitErr.ExitCode() != 0 {
				return internalError(fmt.Sprintf("module exited %d", exitErr.ExitCode())), stderr.Bytes()
			}
			// ExitCode() == 0: fall through to check stdout below.
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			return internalError(fmt.Sprintf("execution exceeded timeout (%s)", cfg.timeout())), stderr.Bytes()
		default:
			return internalError("execution failed: " + err.Error()), stderr.Bytes()
		}
	}

	if stdout.Len() == 0 {
		return internalError("empty stdout"), stderr.Bytes()
	}
	var resp Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return internalError("unparseable stdout: " + err.Error()), stderr.Bytes()
	}
	if resp.Output == nil && resp.Error == nil {
		return internalError("stdout document has neither output nor error"), stderr.Bytes()
	}
	return resp, stderr.Bytes()
}

func internalError(detail string) Response {
	return Response{Error: &apperr.Error{Code: apperr.CodeInternal, Detail: detail, Retryable: false}}
}
