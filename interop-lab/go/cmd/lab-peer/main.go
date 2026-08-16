// Command lab-peer is the Go half of the interop lab's cross-implementation
// checks. It is a lab fixture, not a product: it exposes over HTTP the two
// consuming operations the shipped Go services do not expose, so the
// TypeScript driver can hand real wire bytes to the Go implementation and read
// back an observable HTTP result.
//
//	GET  /peer/info                  the peer's identity and its static X25519
//	                                 encryption key, so a sender can seal to it
//	POST /peer/open                  open an INK encrypted envelope (§3.4)
//	POST /peer/verify-card-signature verify an Agent Card proof, the check the
//	                                 verify service's /verify/card does not run
//	GET  /healthz                    readiness
//
// Every cryptographic decision is made by the reference Go library; this file
// only decodes a request, calls the library, and encodes the typed result. Both
// keypairs are minted at process start and never leave the container, so the
// lab holds no committed key material.
package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

// maxBodyBytes caps a single request. Lab traffic is kilobytes; the cap keeps a
// malformed or hostile POST from pinning the peer before the library's own
// length checks run.
const maxBodyBytes = 1 << 20

type peer struct {
	agentDid       string
	signingKey     ed25519.PrivateKey
	encryptionKey  *ecdh.PrivateKey
	encryptionHex  string
	encryptionPub  string
	signingKeyMulb string
}

func newPeer() (*peer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key: %w", err)
	}
	multibase, err := ink.EncodePublicKeyMultibase(pub)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 key: %w", err)
	}
	return &peer{
		agentDid:       "did:key:" + multibase,
		signingKey:     priv,
		encryptionKey:  enc,
		encryptionHex:  hex.EncodeToString(enc.Bytes()),
		encryptionPub:  hex.EncodeToString(enc.PublicKey().Bytes()),
		signingKeyMulb: multibase,
	}, nil
}

func main() {
	addr := flag.String("addr", ":8090", "address to listen on")
	flag.Parse()

	p, err := newPeer()
	if err != nil {
		log.Fatalf("lab-peer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /peer/info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"agentDid":               p.agentDid,
			"signingKeyMultibase":    p.signingKeyMulb,
			"encryptionPublicKeyHex": p.encryptionPub,
		})
	})
	mux.HandleFunc("POST /peer/open", p.handleOpen)
	mux.HandleFunc("POST /peer/verify-card-signature", p.handleVerifyCardSignature)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("lab-peer listening on %s as %s", *addr, p.agentDid)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type openRequest struct {
	Envelope map[string]any `json:"envelope"`
}

// handleOpen opens an INK encrypted envelope addressed to this peer. The
// recipient identity is the peer's own DID, never a value the caller supplies:
// the library binds the opened plaintext's `to` to it, and a caller that could
// choose it would defeat that binding.
func (p *peer) handleOpen(w http.ResponseWriter, r *http.Request) {
	var req openRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	plaintext, err := ink.DecryptInkPayload(req.Envelope, p.encryptionHex, p.agentDid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "decrypt_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "plaintext": plaintext})
}

type verifyCardRequest struct {
	Card                map[string]any `json:"card"`
	AgentID             string         `json:"agentId"`
	DidVerificationKeys *struct {
		Status           string   `json:"status"`
		VerificationKeys []string `json:"verificationKeys"`
	} `json:"didVerificationKeys"`
	Profile string `json:"profile"`
}

// handleVerifyCardSignature runs the Agent Card proof, rooting and continuity
// verifier over a card the caller fetched. The caller supplies the resolved DID
// document keys because the library never fetches.
func (p *peer) handleVerifyCardSignature(w http.ResponseWriter, r *http.Request) {
	var req verifyCardRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	opts := ink.CardVerifyOptions{Profile: req.Profile}
	if opts.Profile == "" {
		opts.Profile = ink.ProfilePre10
	}
	if req.DidVerificationKeys != nil {
		opts.DidVerificationKeys = &ink.DidResolution{
			Status:           req.DidVerificationKeys.Status,
			VerificationKeys: req.DidVerificationKeys.VerificationKeys,
		}
	}
	result := ink.VerifyAgentCardSignature(req.Card, req.AgentID, opts)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            result.Authenticated,
		"authenticated": result.Authenticated,
		"rejected":      result.Rejected,
		"reason":        string(result.Reason),
		"auditEvents":   result.AuditEvents,
	})
}

func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return errors.New("cannot read body")
	}
	if len(body) > maxBodyBytes {
		return errors.New("body too large")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
