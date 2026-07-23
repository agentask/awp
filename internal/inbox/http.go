package inbox

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/agentask/awp/internal/apperr"
)

// ServeHTTP is the thin HTTP adapter over Gate (core §2.2: "Every domain
// exposes POST {inbox} accepting application/awp+json, one envelope per
// request"). All gate logic lives in Accept; this only translates transport
// bytes to a GateResult and a GateResult to a status code + core §2.6 error
// body.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	limited := http.MaxBytesReader(w, r.Body, int64(g.maxSize())+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		writeError(w, 400, &apperr.Error{Code: apperr.CodeMalformed, Detail: "body unreadable or too large", Retryable: false})
		return
	}

	result := g.Accept(raw)
	if result.Err != nil {
		writeError(w, result.Status, result.Err)
		return
	}
	w.WriteHeader(result.Status)
}

func writeError(w http.ResponseWriter, status int, e *apperr.Error) {
	w.Header().Set("Content-Type", "application/awp+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apperr.Body{Error: e})
}
