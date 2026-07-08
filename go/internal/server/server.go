// Package server exposes the transport-neutral verifiers in internal/verify
// over HTTP. It is a thin, stateless adapter: each endpoint reads an artifact
// JSON body, runs the matching verifier, and returns a JSON verdict. It holds
// no keys and performs no issuing; the cryptographic behavior is exactly what
// internal/verify already does for the CLI, just reached over a second
// transport so the same logic can serve as an interop and conformance endpoint.
//
// Status mapping mirrors the CLI exit-code contract:
//
//	200  a verdict was produced; body {"ok":bool,"kind":string} carries it
//	400  bad input (malformed JSON, missing/unknown field) {"ok":false,"error":"bad_input"}
//	404  unknown route
//	405  known route, wrong method
//	413  body over the size cap
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ad-Astra-Computing/ink/go/internal/verify"
)

// maxBodyBytes caps a single request body, matching the CLI's input cap so the
// two transports share one limit. An artifact is kilobytes; this bounds memory
// against a hostile client without constraining real input.
const maxBodyBytes = 4 << 20 // 4 MiB

type verifier func([]byte) (verify.Result, error)

// routes pairs each URL path segment with its verifier. The path segments match
// the CLI subcommand names minus the verify- prefix.
var routes = []struct {
	path string
	fn   verifier
}{
	{"card", verify.Card},
	{"signature", verify.Signature},
	{"receipt", verify.Receipt},
	{"audit-response", verify.AuditResponse},
	{"handshake", verify.Handshake},
	{"connection", verify.Connection},
	{"checkpoint", verify.Checkpoint},
	{"inclusion", verify.Inclusion},
	{"consistency", verify.Consistency},
}

// Handler builds the HTTP routing for the verification service.
func Handler() http.Handler {
	mux := http.NewServeMux()
	for _, r := range routes {
		fn := r.fn
		mux.HandleFunc("POST /verify/"+r.path, func(w http.ResponseWriter, req *http.Request) {
			handleVerify(w, req, fn)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// known maps each registered path to its required method. The catch-all uses
	// it to tell a wrong-method request on a real route (405) from a request on a
	// path that does not exist (404). A bare catch-all would otherwise shadow the
	// mux's own method check and answer every miss with 404.
	known := map[string]string{"/healthz": http.MethodGet}
	for _, r := range routes {
		known["/verify/"+r.path] = http.MethodPost
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if want, ok := known[req.URL.Path]; ok && req.Method != want {
			w.Header().Set("Allow", want)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found"})
	})
	return mux
}

func handleVerify(w http.ResponseWriter, req *http.Request, fn verifier) {
	req.Body = http.MaxBytesReader(w, req.Body, maxBodyBytes)
	data, err := io.ReadAll(req.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", maxBodyBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read body: "+err.Error())
		return
	}
	res, err := fn(data)
	if err != nil {
		// A verifier error is bad input (malformed envelope, missing field): the
		// request was not well-formed enough to produce a verdict.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// OK true or false are both verdicts on a well-formed artifact.
	writeJSON(w, http.StatusOK, res)
}

// Serve runs the verification service on addr until the process is stopped.
func Serve(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds the whole request read, so a client cannot trickle a
		// body byte by byte and pin a connection: MaxBytesReader caps size, this
		// caps time. The window is generous for a 4 MiB body over a slow link.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return srv.ListenAndServe()
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": "bad_input", "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
