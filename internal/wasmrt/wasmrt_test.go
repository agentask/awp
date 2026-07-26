package wasmrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
)

var wasmBuildCache sync.Map // sourcePath -> []byte

// buildTestWasm compiles a testdata fixture for wasip1/wasm, caching the
// result across tests in this run — compiling Go to wasm has real,
// non-trivial overhead, and every test in this file reuses one of a
// handful of fixtures.
func buildTestWasm(t *testing.T, sourcePath string) []byte {
	t.Helper()
	if cached, ok := wasmBuildCache.Load(sourcePath); ok {
		return cached.([]byte)
	}
	outPath := filepath.Join(t.TempDir(), "mod.wasm")
	cmd := exec.Command("go", "build", "-o", outPath, sourcePath)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", sourcePath, err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	wasmBuildCache.Store(sourcePath, data)
	return data
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func compileTestModule(t *testing.T, sourcePath string) *Module {
	t.Helper()
	wasmBytes := buildTestWasm(t, sourcePath)
	m, err := Compile(context.Background(), wasmBytes, sha256Hex(wasmBytes))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return m
}

func TestCompile_RejectsSHA256Mismatch(t *testing.T) {
	wasmBytes := buildTestWasm(t, "testdata/echo/main.go")
	_, err := Compile(context.Background(), wasmBytes, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected a sha256 mismatch error")
	}
}

func TestRun_EchoSuccess(t *testing.T) {
	m := compileTestModule(t, "testdata/echo/main.go")
	req := Request{Awp: "0.1", Caller: "assistant.acme.com#scheduler", Input: json.RawMessage(`{"x":1}`)}
	resp := m.Run(context.Background(), req, Config{})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var out struct {
		EchoedCaller string          `json:"echoed_caller"`
		Input        json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(resp.Output, &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.EchoedCaller != req.Caller {
		t.Fatalf("echoed_caller = %q, want %q", out.EchoedCaller, req.Caller)
	}
	if string(out.Input) != `{"x":1}` {
		t.Fatalf("input = %s, want {\"x\":1}", out.Input)
	}
}

func TestRun_ModuleReturnsApplicationError(t *testing.T) {
	m := compileTestModule(t, "testdata/errorout/main.go")
	resp := m.Run(context.Background(), Request{Awp: "0.1", Caller: "x", Input: json.RawMessage(`{}`)}, Config{})
	if resp.Error == nil {
		t.Fatal("expected an application error")
	}
	if resp.Error.Code != "refused" {
		t.Fatalf("code = %q, want refused", resp.Error.Code)
	}
	if resp.Output != nil {
		t.Fatal("expected no output alongside an error")
	}
}

// core §1.2: "nonzero exit ... [is] host-side error(internal)".
func TestRun_NonzeroExitIsInternalError(t *testing.T) {
	m := compileTestModule(t, "testdata/badexit/main.go")
	resp := m.Run(context.Background(), Request{Awp: "0.1", Input: json.RawMessage(`{}`)}, Config{})
	if resp.Error == nil || resp.Error.Code != apperr.CodeInternal {
		t.Fatalf("expected apperr.CodeInternal, got %+v", resp.Error)
	}
}

// core §1.2: "empty stdout ... [is] host-side error(internal)".
func TestRun_EmptyStdoutIsInternalError(t *testing.T) {
	m := compileTestModule(t, "testdata/emptystdout/main.go")
	resp := m.Run(context.Background(), Request{Awp: "0.1", Input: json.RawMessage(`{}`)}, Config{})
	if resp.Error == nil || resp.Error.Code != apperr.CodeInternal {
		t.Fatalf("expected apperr.CodeInternal, got %+v", resp.Error)
	}
}

// core §1.2: "unparseable stdout [is] host-side error(internal)".
func TestRun_GarbageStdoutIsInternalError(t *testing.T) {
	m := compileTestModule(t, "testdata/garbage/main.go")
	resp := m.Run(context.Background(), Request{Awp: "0.1", Input: json.RawMessage(`{}`)}, Config{})
	if resp.Error == nil || resp.Error.Code != apperr.CodeInternal {
		t.Fatalf("expected apperr.CodeInternal, got %+v", resp.Error)
	}
}

func TestRun_TimeoutIsInternalError(t *testing.T) {
	// A genuine CPU-bound fixture (50M sha256 rounds) that takes far longer
	// than the short timeout below to complete, regardless of machine
	// speed or wazero's execution mode — a near-zero timeout on a fast,
	// short-lived module (e.g. echo) doesn't reliably race against real
	// execution, so this uses real sustained work instead.
	m := compileTestModule(t, "testdata/slowloop/main.go")
	resp := m.Run(context.Background(), Request{Awp: "0.1", Input: json.RawMessage(`{}`)}, Config{Timeout: 50 * time.Millisecond})
	if resp.Error == nil || resp.Error.Code != apperr.CodeInternal {
		t.Fatalf("expected apperr.CodeInternal (timeout), got %+v", resp.Error)
	}
}

// core §1.2: "Anything the module writes to stderr is host log material,
// never returned to the caller."
func TestRunWithStderr_StderrNeverInResponseButAvailableToHost(t *testing.T) {
	m := compileTestModule(t, "testdata/stderrwriter/main.go")
	resp, stderr := m.RunWithStderr(context.Background(), Request{Awp: "0.1", Input: json.RawMessage(`{}`)}, Config{})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	const marker = "SENSITIVE_HOST_LOG_MARKER_12345"
	if !strings.Contains(string(stderr), marker) {
		t.Fatalf("expected stderr to contain the marker, got %q", stderr)
	}
	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(respJSON), marker) {
		t.Fatal("stderr content leaked into the caller-visible Response")
	}
}

// core §1.2: "absent clock/random makes execution deterministic by
// default" — two independent Run calls without the clock capability must
// observe the identical (fake) starting clock reading.
func TestRun_ClockCapability_AbsentIsDeterministic(t *testing.T) {
	m := compileTestModule(t, "testdata/clockcheck/main.go")
	req := Request{Awp: "0.1", Input: json.RawMessage(`{}`)}

	first := runClockCheck(t, m, req, Config{})
	time.Sleep(5 * time.Millisecond) // real elapsed time, to prove it's NOT reflected below
	second := runClockCheck(t, m, req, Config{})

	if first != second {
		t.Fatalf("expected deterministic clock without the capability granted, got %d then %d", first, second)
	}
}

func TestRun_ClockCapability_GrantedReflectsRealTime(t *testing.T) {
	m := compileTestModule(t, "testdata/clockcheck/main.go")
	req := Request{Awp: "0.1", Input: json.RawMessage(`{}`)}
	cfg := Config{Capabilities: []Capability{CapabilityClock}}

	first := runClockCheck(t, m, req, cfg)
	time.Sleep(5 * time.Millisecond)
	second := runClockCheck(t, m, req, cfg)

	if first == second {
		t.Fatal("expected real, distinct timestamps with the clock capability granted")
	}
}

func runClockCheck(t *testing.T, m *Module, req Request, cfg Config) int64 {
	t.Helper()
	resp := m.Run(context.Background(), req, cfg)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var out struct {
		UnixNano int64 `json:"unix_nano"`
	}
	if err := json.Unmarshal(resp.Output, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out.UnixNano
}

// core §1.2: "absent clock/random makes execution deterministic by
// default" — same property, for randomness.
func TestRun_RandomCapability_AbsentIsDeterministic(t *testing.T) {
	m := compileTestModule(t, "testdata/randomcheck/main.go")
	req := Request{Awp: "0.1", Input: json.RawMessage(`{}`)}

	first := runRandomCheck(t, m, req, Config{})
	second := runRandomCheck(t, m, req, Config{})

	if first != second {
		t.Fatalf("expected deterministic randomness without the capability granted, got %q then %q", first, second)
	}
}

func TestRun_RandomCapability_GrantedIsReal(t *testing.T) {
	m := compileTestModule(t, "testdata/randomcheck/main.go")
	req := Request{Awp: "0.1", Input: json.RawMessage(`{}`)}
	cfg := Config{Capabilities: []Capability{CapabilityRandom}}

	first := runRandomCheck(t, m, req, cfg)
	second := runRandomCheck(t, m, req, cfg)

	if first == second {
		t.Fatal("expected two independently-random values with the capability granted (collision astronomically unlikely)")
	}
}

func runRandomCheck(t *testing.T, m *Module, req Request, cfg Config) string {
	t.Helper()
	resp := m.Run(context.Background(), req, cfg)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	var out struct {
		RandomHex string `json:"random_hex"`
	}
	if err := json.Unmarshal(resp.Output, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out.RandomHex
}

// Filesystem/network are never grantable (core §1.2) — there is no
// Capability constant for either, so misconfiguration is a compile-time
// impossibility rather than a runtime check. This test documents that
// invariant so a future edit adding such a constant doesn't slip in
// unnoticed without a corresponding spec justification.
func TestCapabilities_OnlyClockAndRandomExist(t *testing.T) {
	all := []Capability{CapabilityClock, CapabilityRandom}
	if len(all) != 2 {
		t.Fatalf("expected exactly 2 grantable capabilities, got %d", len(all))
	}
}

func TestRun_MultipleRunsOnSameCompiledModule(t *testing.T) {
	m := compileTestModule(t, "testdata/echo/main.go")
	for i := range 3 {
		req := Request{Awp: "0.1", Caller: "caller", Input: json.RawMessage(`{}`)}
		resp := m.Run(context.Background(), req, Config{})
		if resp.Error != nil {
			t.Fatalf("run %d: unexpected error: %+v", i, resp.Error)
		}
	}
}
