package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/session"
	"github.com/agentask/awp/internal/wasmrt"
)

// maxSyncBodySize bounds a sync tool call's request body — reusing the
// core §2.1 envelope cap as a reasonable ceiling; sync calls have no
// spec-defined size limit of their own.
const maxSyncBodySize = 256 * 1024

// syncSessionTTL is how long a sync-call session token (core §1.3) is
// valid for before the caller must re-authenticate with a fresh signed
// request. Not spec-mandated; a reasonable reference default.
const syncSessionTTL = time.Hour

// ToolHandler executes a hosted tool call. caller is the verified signing
// principal (from httpsig.Verify); chain is the delegation chain, if any,
// already verified against this tool's own principal as scope.To. Return
// exactly one of (output, nil) or (nil, err).
type ToolHandler func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error)

// Tool is one kind:tool entity this daemon serves — exactly one of Handler
// (native Go, "hosted") or Module (wazero-executed, "portable") must be
// set, matching the manifest's own distribution field.
type Tool struct {
	Manifest     *manifest.Manifest
	Handler      ToolHandler
	Module       *wasmrt.Module
	Capabilities []wasmrt.Capability // used only when Module is set
}

type registeredTool struct {
	tool           Tool
	manifestRaw    []byte
	manifestSHA256 string
}

// RegisterTool signs t.Manifest (setting distribution.hosted.endpoint /
// this entity's manifest URL from baseURL), serves it at
// {baseURL}/awp/manifests/{entity}.json, serves calls at
// {baseURL}/awp/tools/{entity} verified via internal/httpsig, and adds a
// pinned entities[] entry to this daemon's own signed index. Call after
// the daemon's own reachable address is known (same pattern as
// FinalizeIndex).
func (d *Daemon) RegisterTool(baseURL string, t Tool) error {
	if t.Manifest == nil {
		return errors.New("daemon: tool manifest is required")
	}
	if (t.Handler == nil) == (t.Module == nil) {
		return errors.New("daemon: exactly one of Tool.Handler or Tool.Module must be set")
	}
	entity, err := entityFragment(t.Manifest.Name)
	if err != nil {
		return err
	}

	m := *t.Manifest // shallow copy: don't mutate the caller's struct
	if m.Distribution.Hosted != nil {
		hosted := *m.Distribution.Hosted
		hosted.Endpoint = baseURL + "/awp/tools/" + entity
		m.Distribution.Hosted = &hosted
	}
	m.Updated = d.Clock.Now().UTC().Format(RFC3339Milli)
	if err := m.Sign(d.priv, d.Kid); err != nil {
		return fmt.Errorf("daemon: sign manifest for %s: %w", entity, err)
	}
	raw, err := json.Marshal(&m)
	if err != nil {
		return fmt.Errorf("daemon: marshal manifest for %s: %w", entity, err)
	}
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	t.Manifest = &m

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tools == nil {
		d.tools = map[string]*registeredTool{}
	}
	d.tools[entity] = &registeredTool{tool: t, manifestRaw: raw, manifestSHA256: shaHex}

	manifestURL := baseURL + "/awp/manifests/" + entity + ".json"
	d.index.Entities = append(withoutEntity(d.index.Entities, m.Name), identity.Entity{
		Name: m.Name, Kind: m.Kind, Manifest: manifestURL, ManifestSha256: shaHex,
	})
	d.index.Updated = d.Clock.Now().UTC().Format(RFC3339Milli)
	return d.index.Sign(d.priv, d.Kid)
}

func withoutEntity(entities []identity.Entity, name string) []identity.Entity {
	out := entities[:0:0]
	for _, e := range entities {
		if e.Name != name {
			out = append(out, e)
		}
	}
	return out
}

func entityFragment(principal string) (string, error) {
	_, entity, ok := strings.Cut(principal, "#")
	if !ok || entity == "" {
		return "", fmt.Errorf("daemon: tool principal %q must be domain#entity", principal)
	}
	return entity, nil
}

func (d *Daemon) lookupTool(entity string) (*registeredTool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rt, ok := d.tools[entity]
	return rt, ok
}

func (d *Daemon) serveManifest(w http.ResponseWriter, r *http.Request) {
	entity := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/awp/manifests/"), ".json")
	rt, ok := d.lookupTool(entity)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rt.manifestRaw)
}

func (d *Daemon) serveToolCall(w http.ResponseWriter, r *http.Request) {
	entity := strings.TrimPrefix(r.URL.Path, "/awp/tools/")
	rt, ok := d.lookupTool(entity)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSyncBodySize))
	if err != nil {
		writeSyncError(w, 400, apperr.CodeMalformed, "body too large or unreadable")
		return
	}
	httpsig.AbsolutizeServerRequestURL(r)

	deps := httpsig.Deps{ResolveKey: d.Gate.Keys, Target: rt.tool.Manifest.Name}
	isProvider := rt.tool.Manifest.State == "provider"
	if isProvider {
		deps.VerifySession = d.verifySyncSession
	}
	result := httpsig.Verify(r, body, d.Clock.Now(), deps)
	if result.Err != nil {
		writeSyncError(w, result.Status, result.Err.Code, result.Err.Detail)
		return
	}

	output, toolErr := d.invokeTool(r.Context(), rt, result, body)
	if toolErr != nil {
		writeSyncError(w, statusForErrorCode(toolErr.Code), toolErr.Code, toolErr.Detail)
		return
	}

	respBody := syncSuccessBody{Output: output}
	if isProvider && !result.HasSession {
		info, err := d.issueSyncSession(result.CallerPrincipal, rt.tool.Manifest.Name)
		if err != nil {
			writeSyncError(w, 500, apperr.CodeInternal, "issue session: "+err.Error())
			return
		}
		respBody.Session = info
	}

	buf, err := json.Marshal(respBody)
	if err != nil {
		writeSyncError(w, 500, apperr.CodeInternal, "marshal response: "+err.Error())
		return
	}

	// awp-sig §3 SHOULD: sign successful responses. Built via a throwaway
	// *http.Response so httpsig.SignResponse's existing digest/signature
	// construction can be reused as-is, then copied onto the real
	// ResponseWriter's headers before they're sent.
	signed := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	if err := httpsig.SignResponse(signed, buf, d.priv, d.Domain+"/"+d.Kid, d.Clock.Now()); err != nil {
		writeSyncError(w, 500, apperr.CodeInternal, "sign response: "+err.Error())
		return
	}
	maps.Copy(w.Header(), signed.Header)
	w.Header().Set("Content-Type", "application/awp+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

// invokeTool dispatches to the hosted handler or the portable wasm module.
func (d *Daemon) invokeTool(ctx context.Context, rt *registeredTool, result httpsig.VerifyResult, body []byte) (json.RawMessage, *apperr.Error) {
	if rt.tool.Handler != nil {
		return rt.tool.Handler(ctx, result.CallerPrincipal, result.Delegation, body)
	}
	req := wasmrt.Request{Awp: "0.1", Caller: result.CallerPrincipal, Input: body}
	resp := rt.tool.Module.Run(ctx, req, wasmrt.Config{Capabilities: rt.tool.Capabilities})
	return resp.Output, resp.Error
}

// verifySyncSession checks a core §1.3 session token using THIS domain's
// own current key — no storage read on the hot path, per spec.
func (d *Daemon) verifySyncSession(token, callerPrincipal string) error {
	pub := d.priv.Public().(ed25519.PublicKey)
	return session.Verify(token, callerPrincipal, pub, d.Clock.Now())
}

// issueSyncSession mints a fresh session for (caller, entity) — the core
// §1.3 "first sync call returns {session: {...}}" response.
func (d *Daemon) issueSyncSession(caller, entity string) (*syncSessionInfo, error) {
	sid := envelope.NewID()
	expires := d.Clock.Now().Add(syncSessionTTL)
	token, err := session.Issue(sid, caller, entity, expires, d.priv)
	if err != nil {
		return nil, err
	}
	return &syncSessionInfo{Token: token, Sid: sid, Expires: expires.UTC().Format(RFC3339Milli)}, nil
}

type syncSuccessBody struct {
	Output  json.RawMessage  `json:"output,omitempty"`
	Session *syncSessionInfo `json:"session,omitempty"`
}

type syncSessionInfo struct {
	Token   string `json:"token"`
	Sid     string `json:"sid"`
	Expires string `json:"expires"`
}

func writeSyncError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/awp+json")
	w.WriteHeader(status)
	buf, _ := json.Marshal(apperr.Body{Error: &apperr.Error{Code: code, Detail: detail}})
	_, _ = w.Write(buf)
}

func statusForErrorCode(code string) int {
	switch code {
	case apperr.CodeUnauthorizedDelegation:
		return 403
	case apperr.CodeCapacity:
		return 503
	case apperr.CodeInternal:
		return 500
	default:
		return 400
	}
}
