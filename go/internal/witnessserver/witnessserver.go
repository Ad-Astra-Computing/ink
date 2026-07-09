// Package witnessserver exposes a single in-memory INK WitnessLog over HTTP. It
// is an issuing endpoint: it holds an Ed25519 witness key, stamps a server-side
// timestamp, appends each submitted audit event as a new leaf, and returns a
// signed inclusion receipt. It also serves the current signed checkpoint and the
// inclusion and consistency proofs of its append-only tree.
//
// Unlike the stateless verify server, this server is stateful and key-holding,
// so it is deliberately scoped small and security-shaped: it is a single
// process, in-memory and non-durable (a restart starts an empty log), it caps
// the tree size so an unbounded append cannot exhaust memory, and submit is
// authenticated by default. It is a development and interop witness, not a
// durable production log.
//
// Status mapping:
//
//	200  success (a signed receipt, a checkpoint, or a proof)
//	400  bad input (malformed event, bad query parameter, impossible proof)
//	401  submit without a valid bearer token
//	404  unknown route
//	405  known route, wrong method
//	413  submit body over the size cap
//	507  the log has reached its configured capacity
package witnessserver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

// maxBodyBytes caps a single submit body, matching the verify server's cap so
// the two transports share one limit. An audit event is kilobytes; this bounds
// memory against a hostile client without constraining real input.
const maxBodyBytes = 4 << 20 // 4 MiB

// maxSafeInteger is the JavaScript safe-integer ceiling. Proof query parameters
// are rejected above it so the wire numbers stay portable to a JS verifier.
const maxSafeInteger = 9007199254740991

// defaultMaxLeaves bounds the in-memory tree by default so an authenticated but
// abusive client, or a misconfigured one, cannot grow the log without limit.
const defaultMaxLeaves = 1 << 20

// timestampLayout is the INK millisecond timestamp grammar in Go reference form.
// The trailing Z is a literal: the instant is floored to UTC first.
const timestampLayout = "2006-01-02T15:04:05.000Z"

// Config configures a witness server. Origin and PrivateKey are required. A
// submit token is required unless AllowUnauthenticated is set, so the default
// posture is authenticated submit.
type Config struct {
	Origin               string
	PrivateKey           ed25519.PrivateKey
	SubmitToken          string
	AllowUnauthenticated bool
	// MaxLeaves caps the tree size; 0 selects defaultMaxLeaves. It is a soft
	// bound checked before append: a small overshoot is possible under
	// concurrency, but the underlying log still enforces its own hard ceiling.
	MaxLeaves int
	// Now supplies the receipt timestamp clock; nil selects time.Now. It is
	// injectable so a test can assert a deterministic stamped timestamp.
	Now func() time.Time
}

type server struct {
	log     *ink.WitnessLog
	origin  string
	authOff bool
	// tokenHash is the SHA-256 of the configured submit token. Comparing hashes
	// rather than the raw tokens keeps both sides a fixed 32 bytes, so a constant
	// time comparison cannot leak the token length.
	tokenHash [sha256.Size]byte
	maxLeaves int
	now       func() time.Time
}

// New validates the configuration and returns the server's HTTP handler. It
// fails if the origin or key is invalid, or if no submit token is set and
// unauthenticated submit was not explicitly allowed.
func New(cfg Config) (http.Handler, error) {
	log, err := ink.NewWitnessLog(cfg.Origin, cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	if !cfg.AllowUnauthenticated && cfg.SubmitToken == "" {
		return nil, errors.New("a submit token is required unless unauthenticated submit is explicitly allowed")
	}
	maxLeaves := cfg.MaxLeaves
	if maxLeaves <= 0 {
		maxLeaves = defaultMaxLeaves
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	s := &server{
		log:       log,
		origin:    cfg.Origin,
		authOff:   cfg.AllowUnauthenticated,
		tokenHash: sha256.Sum256([]byte(cfg.SubmitToken)),
		maxLeaves: maxLeaves,
		now:       now,
	}
	return s.handler(), nil
}

// route pairs a method-qualified path with its handler and the method the
// catch-all reports in Allow when the path is hit with the wrong method.
type route struct {
	method  string
	path    string
	handler http.HandlerFunc
}

func (s *server) routes() []route {
	return []route{
		{http.MethodPost, "/submit", s.handleSubmit},
		{http.MethodGet, "/checkpoint", s.handleCheckpoint},
		{http.MethodGet, "/inclusion", s.handleInclusion},
		{http.MethodGet, "/consistency", s.handleConsistency},
		{http.MethodGet, "/healthz", s.handleHealthz},
	}
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	known := map[string]string{}
	for _, r := range s.routes() {
		known[r.path] = r.method
		mux.HandleFunc(r.method+" "+r.path, r.handler)
	}
	// The catch-all distinguishes a wrong method on a real route (405, with
	// Allow) from a path that does not exist (404). Without it the mux answers
	// every miss, including a wrong method, with a bare 404.
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

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleSubmit(w http.ResponseWriter, req *http.Request) {
	if !s.authOff && !s.authorized(req) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "a valid bearer token is required")
		return
	}
	// Best-effort fast path: refuse before reading the body when the tree is
	// already at capacity, so an at-capacity server does not read a large body
	// only to reject it. The authoritative bound is enforced atomically in
	// SubmitWithCapacity below, so a concurrent burst cannot overshoot it.
	if s.log.Size() >= s.maxLeaves {
		writeError(w, http.StatusInsufficientStorage, "the log has reached its configured capacity")
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxBodyBytes)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", maxBodyBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read body: "+err.Error())
		return
	}
	// The server owns the receipt timestamp: a client-supplied one is never
	// trusted. The instant is floored to the millisecond so it is a valid INK
	// timestamp.
	timestamp := s.now().UTC().Truncate(time.Millisecond).Format(timestampLayout)
	receipt, err := s.log.SubmitWithCapacity(body, timestamp, s.maxLeaves)
	if err != nil {
		if errors.Is(err, ink.ErrCapacity) {
			writeError(w, http.StatusInsufficientStorage, "the log has reached its configured capacity")
			return
		}
		// The log validates the event and only appends on success, so any other
		// error here is a malformed submission and the tree is unchanged.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

// authorized compares the request bearer token against the configured one. Both
// sides are hashed to a fixed 32 bytes first, so the constant-time comparison
// reveals neither the token bytes nor its length. The Bearer prefix check is not
// itself constant-time, but it discloses only whether an Authorization header of
// the expected form was sent, not any token material.
func (s *server) authorized(req *http.Request) bool {
	const prefix = "Bearer "
	h := req.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return false
	}
	got := sha256.Sum256([]byte(h[len(prefix):]))
	return subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) == 1
}

func (s *server) handleCheckpoint(w http.ResponseWriter, _ *http.Request) {
	note, err := s.log.Checkpoint()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot sign checkpoint")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkpoint": note})
}

func (s *server) handleInclusion(w http.ResponseWriter, req *http.Request) {
	index, ok := scalarParam(req, "index")
	if !ok {
		writeError(w, http.StatusBadRequest, "index must be a decimal integer within the safe range")
		return
	}
	proof, size, err := s.log.InclusionProof(index)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"index": index, "size": size, "proof": proof})
}

func (s *server) handleConsistency(w http.ResponseWriter, req *http.Request) {
	first, ok1 := scalarParam(req, "first")
	second, ok2 := scalarParam(req, "second")
	if !ok1 || !ok2 {
		writeError(w, http.StatusBadRequest, "first and second must be decimal integers within the safe range")
		return
	}
	proof, err := s.log.ConsistencyProof(first, second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"first": first, "second": second, "proof": proof})
}

// scalarParam reads a query parameter that must appear exactly once and be a
// canonical non-negative decimal integer no greater than the safe-integer
// ceiling. It rejects a sign, whitespace, a float, an exponent, hex, a leading
// zero, and any value that would not fit a Go int, so the wire number stays a
// portable JCS-safe integer.
func scalarParam(req *http.Request, name string) (int, bool) {
	values, present := req.URL.Query()[name]
	if !present || len(values) != 1 {
		return 0, false
	}
	raw := values[0]
	if raw == "" {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v > maxSafeInteger {
		return 0, false
	}
	if uint64(int(v)) != v {
		return 0, false
	}
	return int(v), true
}

// PrivateKeyFromSeedHex decodes a hex-encoded 32-byte Ed25519 seed into a
// private key, so the command can provision the witness key from an environment
// variable or a file without embedding raw key bytes in a flag.
func PrivateKeyFromSeedHex(seedHex string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, errors.New("witness seed must be hex")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("witness seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Serve runs the witness server on addr until the process is stopped. The
// timeouts mirror the verify server: MaxBytesReader caps body size, these cap
// the time a slow client can hold a connection.
func Serve(addr string, cfg Config) error {
	handler, err := New(cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": http.StatusText(status), "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
