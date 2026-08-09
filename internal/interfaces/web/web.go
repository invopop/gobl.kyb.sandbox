// Package web is the HTTP transport adapter for the sandbox KYB
// verification service. It exposes the standard GOBL Net well-known
// endpoints (inbox / who / keys / jwks) plus the human-facing
// /confirm pages behind the emailed link. The who and inbox endpoints
// require a bearer request token (spec §5.5); key discovery stays
// open, and /confirm is authenticated by the unguessable link token
// itself. Handlers are thin: they parse the request, delegate to the
// domain services, and map domain errors onto HTTP status codes.
package web

import (
	"errors"
	"log/slog"
	"net/http"

	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb.sandbox/internal/domain"
)

// inboxMaxBody caps the request body read by the inbox handler.
const inboxMaxBody = 1 << 20 // 1 MiB

// NewMux constructs the HTTP request multiplexer for the verification
// service. The returned handler is wrapped in the structured
// access-log middleware.
func NewMux(setup *domain.Setup, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()

	mux.HandleFunc("POST "+goblnet.InboxPath, requireAuth(setup, log, handleInbox(setup, log)))
	mux.HandleFunc("GET "+goblnet.WhoPath, requireAuth(setup, log, handleWho(setup, log)))
	mux.HandleFunc("GET "+goblnet.KeysPath+"/{kid}", handleKey(setup, log))
	mux.HandleFunc("GET "+goblnet.JWKSPath, handleJWKS(setup, log))
	mux.HandleFunc("GET /confirm/{token}", handleConfirmPage(setup, log))
	mux.HandleFunc("POST /confirm/{token}", handleConfirmSubmit(setup, log))
	mux.HandleFunc("GET /healthz", handleHealth())

	return withAccessLog(log, mux)
}

// writeJSON writes body as application/json with the given status.
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError maps a domain error onto an HTTP status + message. Any
// non-domain error is treated as an internal failure.
func writeError(w http.ResponseWriter, err error) {
	var de *domain.Error
	if !errors.As(err, &de) {
		de = domain.ErrInternal.WithCause(err)
	}
	msg := de.Message()
	if msg == "" {
		msg = de.Error()
	}
	// Map the status from the resolved domain error so it always matches
	// the message being returned.
	http.Error(w, msg, statusForError(de))
}

// statusForError resolves the HTTP status for a domain error kind.
func statusForError(err error) int {
	switch {
	case errors.Is(err, domain.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, domain.ErrGone):
		return http.StatusGone
	case errors.Is(err, domain.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
	}
}
