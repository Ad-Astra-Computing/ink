// Command lab-driver runs the Go-produces half of the interop lab: it mints a
// Go identity, discovers the TypeScript reference receiver over HTTP, and drives
// a full INK exchange against it. Every decision is read from an observable HTTP
// status or a typed library result; nothing is inferred from a log line.
//
// The driver exits 0 when every check passes and 1 when any check fails, so a
// caller can gate on the process exit code alone.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

const inboxPath = "/ink/v1/inbound"

// The receiver's own DID, derived from the INK_RECEIVER_HOST the lab starts it
// with. The driver needs it before discovery because the normative card path is
// keyed on the agentId: GET <base>/ink/v1/<agentId>/agent.json, the path the
// reference library's fetchAgentCard builds.
const receiverDidDefault = "did:web:ts-receiver.example"

// versionedCardPath is the discovery path for an agentId, percent-encoded as a
// single path segment. Go's PathEscape leaves ":" alone (it is legal in a path
// segment) while the JavaScript encodeURIComponent the reference library uses
// escapes it, so the colons are escaped explicitly: the lab must request the
// exact bytes the library would.
func versionedCardPath(agentID string) string {
	return "/ink/v1/" + strings.ReplaceAll(url.PathEscape(agentID), ":", "%3A") + "/agent.json"
}

func main() {
	cfg := config{
		receiver:    envOr("TS_RECEIVER_URL", "http://ts-receiver:8787"),
		receiverDid: envOr("TS_RECEIVER_DID", receiverDidDefault),
		verifier:    envOr("GO_VERIFIER_URL", "http://go-verifier:8080"),
		tsPeer:      envOr("TS_PEER_URL", "http://ts-peer:8790"),
	}
	fmt.Println("go-driver: Go produces, TypeScript verifies")
	r := &run{}
	if err := drive(cfg, r); err != nil {
		r.fail("driver", err.Error())
	}
	os.Exit(r.report("go-driver: Go produces, TypeScript verifies"))
}

type config struct {
	receiver    string
	receiverDid string
	verifier    string
	tsPeer      string
}

func drive(cfg config, r *run) error {
	for _, dep := range []struct{ name, url string }{
		{"ts-receiver", cfg.receiver + versionedCardPath(cfg.receiverDid)},
		{"go-verifier", cfg.verifier + "/healthz"},
		{"ts-peer", cfg.tsPeer + "/healthz"},
	} {
		if err := waitReady(dep.url); err != nil {
			return fmt.Errorf("%s never became ready: %w", dep.name, err)
		}
	}

	// ── discovery ────────────────────────────────────────────────────────────
	// The versioned path is the discovery surface a consumer reaches knowing
	// only the agentId and the origin, so that is what the driver fetches.
	cardStatus, cardBytes, err := get(cfg.receiver + versionedCardPath(cfg.receiverDid))
	if err != nil {
		return fmt.Errorf("agent card fetch: %w", err)
	}
	r.check("versioned card path returns 200", cardStatus == 200, fmt.Sprintf("status %d", cardStatus))

	// The well-known path stays as an alias and MUST serve the same bytes.
	//
	// Scope of this check: every request in the lab hits one receiver process,
	// so this proves the two ROUTES agree, not that the card is stable across
	// processes or over time. The receiver builds its card as a pure function
	// of configuration and key material, and that is what makes the claim hold
	// in a multi-isolate deployment; the proof lives in the receiver's own
	// examples/reference-receiver/test/card-determinism.test.ts, which runs the
	// build in two separate OS processes under different clocks. Do not read a
	// pass here as evidence of cross-process stability.
	aliasStatus, aliasBytes, err := get(cfg.receiver + "/.well-known/ink/agent.json")
	if err != nil {
		return fmt.Errorf("well-known card fetch: %w", err)
	}
	r.check("well-known alias returns 200", aliasStatus == 200, fmt.Sprintf("status %d", aliasStatus))
	r.check("well-known alias is byte-identical to the versioned card",
		bytes.Equal(aliasBytes, cardBytes), fmt.Sprintf("%d vs %d bytes", len(aliasBytes), len(cardBytes)))
	var card map[string]any
	if err := json.Unmarshal(cardBytes, &card); err != nil {
		return fmt.Errorf("agent card is not JSON: %w", err)
	}
	receiverDid, _ := card["agentId"].(string)
	r.check("card carries an agentId", receiverDid != "", receiverDid)
	// Identity binding: the card served at /ink/v1/<agentId>/agent.json must
	// announce that same agentId.
	r.check("card agentId matches the requested discovery path", receiverDid == cfg.receiverDid, receiverDid)

	// The Go schema validator accepts the TypeScript-produced card.
	r.check("Go schema accepts the TypeScript card", ink.ValidateAgentCard(card), "ValidateAgentCard")

	// The Go verification service accepts it over HTTP.
	verdict, err := postVerify(cfg.verifier+"/verify/card", cardBytes)
	if err != nil {
		return fmt.Errorf("verify service card call: %w", err)
	}
	r.check("verify service accepts the card", verdict, "POST /verify/card ok=true")

	// ── card signature (Phase B) ─────────────────────────────────────────────
	didStatus, didBytes, err := get(cfg.receiver + "/.well-known/did.json")
	if err != nil {
		return fmt.Errorf("did document fetch: %w", err)
	}
	r.check("did document returns 200", didStatus == 200, fmt.Sprintf("status %d", didStatus))
	didKeys, err := didDocumentKeys(didBytes)
	if err != nil {
		return fmt.Errorf("did document: %w", err)
	}
	r.check("did document publishes a verification key", len(didKeys) > 0, strings.Join(didKeys, ","))

	resolution := &ink.DidResolution{Status: ink.DidResolved, VerificationKeys: didKeys}
	signed := ink.VerifyAgentCardSignature(card, receiverDid, ink.CardVerifyOptions{
		DidVerificationKeys: resolution,
		Profile:             ink.ProfilePre10,
	})
	r.check("Go authenticates the TypeScript card signature",
		signed.Authenticated, string(signed.Reason))

	// A card whose bytes changed after signing must not authenticate.
	tampered := cloneMap(card)
	tampered["displayName"] = "not the signed display name"
	tamperedResult := ink.VerifyAgentCardSignature(tampered, receiverDid, ink.CardVerifyOptions{
		DidVerificationKeys: resolution,
		Profile:             ink.ProfilePre10,
	})
	r.check("Go rejects a tampered card signature",
		!tamperedResult.Authenticated && tamperedResult.Rejected, string(tamperedResult.Reason))

	// The same tampered card is still schema-valid, which is why a consumer must
	// run the card-signature verifier and not stop at the schema check.
	tamperedBytes, err := json.Marshal(tampered)
	if err != nil {
		return fmt.Errorf("marshal tampered card: %w", err)
	}
	schemaVerdict, err := postVerify(cfg.verifier+"/verify/card", tamperedBytes)
	if err != nil {
		return fmt.Errorf("verify service tampered card call: %w", err)
	}
	r.check("schema check alone does not catch the tamper", schemaVerdict,
		"POST /verify/card ok=true on a card the signature verifier rejects")

	// ── a signed plaintext intent, Go sender to TypeScript receiver ──────────
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("sender key: %w", err)
	}
	multibase, err := ink.EncodePublicKeyMultibase(pub)
	if err != nil {
		return fmt.Errorf("encode sender key: %w", err)
	}
	senderDid := "did:key:" + multibase

	msg, err := newEnvelope(senderDid, receiverDid, "a signed intent from the Go implementation", priv)
	if err != nil {
		return fmt.Errorf("build envelope: %w", err)
	}
	authHeader, err := signTransport(msg, receiverDid, priv)
	if err != nil {
		return fmt.Errorf("sign transport: %w", err)
	}
	status, body, err := postInbox(cfg.receiver, msg.raw, authHeader)
	if err != nil {
		return fmt.Errorf("inbound POST: %w", err)
	}
	r.check("receiver accepts the Go-signed intent", status == 200,
		fmt.Sprintf("status %d body %s", status, trim(body)))
	var ack map[string]any
	_ = json.Unmarshal(body, &ack)
	r.check("acknowledgement correlates to the sent envelope",
		ack["inReplyTo"] == msg.id && ack["ok"] == true, trim(body))

	// The TypeScript body-signature verifier accepts the Go-built canonical bytes.
	envelopeVerdict, err := postPeerVerifyEnvelope(cfg.tsPeer, msg.raw)
	if err != nil {
		return fmt.Errorf("ts-peer envelope verify: %w", err)
	}
	r.check("TypeScript verifies the Go envelope body signature", envelopeVerdict,
		"POST /peer/verify-envelope ok=true")

	// ── replay ───────────────────────────────────────────────────────────────
	replayStatus, replayBody, err := postInbox(cfg.receiver, msg.raw, authHeader)
	if err != nil {
		return fmt.Errorf("replayed POST: %w", err)
	}
	r.check("receiver rejects the replayed nonce",
		replayStatus == 400 && verdictIs(replayBody, "signature"),
		fmt.Sprintf("status %d body %s", replayStatus, trim(replayBody)))

	// ── tampered transport signature ─────────────────────────────────────────
	fresh, err := newEnvelope(senderDid, receiverDid, "an intent whose header was altered", priv)
	if err != nil {
		return fmt.Errorf("build envelope: %w", err)
	}
	freshHeader, err := signTransport(fresh, receiverDid, priv)
	if err != nil {
		return fmt.Errorf("sign transport: %w", err)
	}
	badHeader, err := flipSignature(freshHeader)
	if err != nil {
		return fmt.Errorf("flip signature: %w", err)
	}
	tamperStatus, tamperBody, err := postInbox(cfg.receiver, fresh.raw, badHeader)
	if err != nil {
		return fmt.Errorf("tampered-signature POST: %w", err)
	}
	r.check("receiver rejects a tampered transport signature",
		tamperStatus == 400 && verdictIs(tamperBody, "signature"),
		fmt.Sprintf("status %d body %s", tamperStatus, trim(tamperBody)))

	// ── body altered after signing ───────────────────────────────────────────
	altered, err := newEnvelope(senderDid, receiverDid, "the note the sender signed", priv)
	if err != nil {
		return fmt.Errorf("build envelope: %w", err)
	}
	alteredHeader, err := signTransport(altered, receiverDid, priv)
	if err != nil {
		return fmt.Errorf("sign transport: %w", err)
	}
	swapped := bytes.Replace(altered.raw, []byte("the note the sender signed"),
		[]byte("the note nobody signed!!!!"), 1)
	if bytes.Equal(swapped, altered.raw) {
		return fmt.Errorf("body substitution did not change the request bytes")
	}
	swapStatus, swapBody, err := postInbox(cfg.receiver, swapped, alteredHeader)
	if err != nil {
		return fmt.Errorf("altered-body POST: %w", err)
	}
	r.check("receiver rejects a body altered after signing",
		swapStatus == 400 && verdictIs(swapBody, "signature"),
		fmt.Sprintf("status %d body %s", swapStatus, trim(swapBody)))

	// ── encrypted payload, Go seals and TypeScript opens ─────────────────────
	peerDid, peerKeyHex, err := peerInfo(cfg.tsPeer)
	if err != nil {
		return fmt.Errorf("ts-peer info: %w", err)
	}
	secret := "sealed by the Go implementation"
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	// Both implementations bind the inner envelope to the outer one: the sealed
	// plaintext MUST carry `from` equal to the outer sender and `to` equal to the
	// recipient asserting the identity, or no conformant decrypter opens it.
	sealed, err := ink.EncryptInkPayload(
		map[string]any{"from": senderDid, "to": peerDid, "note": secret},
		senderDid, peerKeyHex, now, randomID(),
		&ink.InkEncryptOptions{RecipientDid: &peerDid},
	)
	if err != nil {
		return fmt.Errorf("seal payload: %w", err)
	}
	opened, err := postPeerOpen(cfg.tsPeer, sealed)
	if err != nil {
		return fmt.Errorf("ts-peer open: %w", err)
	}
	r.check("TypeScript opens the Go-sealed payload", opened["note"] == secret,
		fmt.Sprintf("%v", opened["note"]))

	// A ciphertext that changed in transit must not open.
	corrupt := cloneMap(sealed)
	ct, _ := corrupt["ciphertext"].(string)
	corrupt["ciphertext"] = flipBase64URL(ct)
	if _, err := postPeerOpen(cfg.tsPeer, corrupt); err != nil {
		r.check("TypeScript refuses a corrupted ciphertext", true, err.Error())
	} else {
		r.check("TypeScript refuses a corrupted ciphertext", false, "the peer opened it")
	}
	return nil
}

// ── envelope construction ───────────────────────────────────────────────────

type envelope struct {
	id  string
	raw []byte
}

// newEnvelope builds a signed INK intent envelope using only the library's
// exported producing surface: ink.SignInkBody mints the body signature (over the
// version-keyed domain that the signed `protocol` member selects) and
// ink.JCSCanonicalize serializes the wire bytes. The lab does no canonicalization
// of its own, so what it puts on the socket is what any Go sender would emit.
func newEnvelope(from, to, note string, priv ed25519.PrivateKey) (*envelope, error) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	id := randomID()
	body := map[string]any{
		"correlationId": randomID(),
		"createdAt":     now,
		"from":          from,
		"id":            id,
		"intent":        "ping",
		"nonce":         randomID(),
		"payload":       map[string]any{"note": note},
		"protocol":      "ink/0.1",
		"timestamp":     now,
		"to":            to,
	}
	sig, err := ink.SignInkBody(body, priv)
	if err != nil {
		return nil, err
	}
	body["signature"] = sig
	raw, err := ink.JCSCanonicalize(body)
	if err != nil {
		return nil, err
	}
	return &envelope{id: id, raw: []byte(raw)}, nil
}

// signTransport produces the §3.3 Authorization header over the exact bytes the
// driver is about to POST.
func signTransport(msg *envelope, recipientDid string, priv ed25519.PrivateKey) (string, error) {
	body, err := ink.ParseSignedBody(msg.raw)
	if err != nil {
		return "", err
	}
	timestamp, err := jsonString(msg.raw, "timestamp")
	if err != nil {
		return "", err
	}
	_, header, err := ink.SignInkRequest(ink.InkSignInput{
		Method:       "POST",
		Path:         inboxPath,
		RecipientDid: recipientDid,
		Body:         body,
		Timestamp:    timestamp,
	}, priv, "")
	return header, err
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

var client = &http.Client{Timeout: 10 * time.Second}

func waitReady(url string) error {
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		status, _, err := get(url)
		if err == nil && status < 500 {
			return nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timed out")
	}
	return last
}

func get(url string) (int, []byte, error) {
	res, err := client.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, body, err
}

func post(url string, body []byte, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, out, err
}

func postInbox(base string, body []byte, authHeader string) (int, []byte, error) {
	return post(base+inboxPath, body, map[string]string{"authorization": authHeader})
}

// postVerify calls the Go verification service and returns its ok verdict.
func postVerify(url string, body []byte) (bool, error) {
	status, out, err := post(url, body, nil)
	if err != nil {
		return false, err
	}
	if status != 200 && status != 422 {
		return false, fmt.Errorf("unexpected status %d: %s", status, trim(out))
	}
	var res struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return false, err
	}
	return res.OK, nil
}

func peerInfo(base string) (did, encryptionKeyHex string, err error) {
	status, body, err := get(base + "/peer/info")
	if err != nil {
		return "", "", err
	}
	if status != 200 {
		return "", "", fmt.Errorf("peer info status %d", status)
	}
	var info struct {
		AgentDid               string `json:"agentDid"`
		EncryptionPublicKeyHex string `json:"encryptionPublicKeyHex"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "", err
	}
	return info.AgentDid, info.EncryptionPublicKeyHex, nil
}

func postPeerOpen(base string, sealed map[string]any) (map[string]any, error) {
	payload, err := json.Marshal(map[string]any{"envelope": sealed})
	if err != nil {
		return nil, err
	}
	status, body, err := post(base+"/peer/open", payload, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("peer refused the envelope: status %d %s", status, trim(body))
	}
	var res struct {
		Plaintext map[string]any `json:"plaintext"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Plaintext, nil
}

func postPeerVerifyEnvelope(base string, raw []byte) (bool, error) {
	status, body, err := post(base+"/peer/verify-envelope", raw, nil)
	if err != nil {
		return false, err
	}
	if status != 200 && status != 400 {
		return false, fmt.Errorf("unexpected status %d: %s", status, trim(body))
	}
	var res struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return false, err
	}
	return res.OK, nil
}

// ── small utilities ─────────────────────────────────────────────────────────

func didDocumentKeys(doc []byte) ([]string, error) {
	var parsed struct {
		VerificationMethod []struct {
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		} `json:"verificationMethod"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(parsed.VerificationMethod))
	for _, vm := range parsed.VerificationMethod {
		if vm.PublicKeyMultibase != "" {
			keys = append(keys, vm.PublicKeyMultibase)
		}
	}
	return keys, nil
}

// verdictIs reports whether a receiver rejection body carries the expected
// error verdict, so a check pins the reason and not merely the status code.
func verdictIs(body []byte, want string) bool {
	var res struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return false
	}
	return res.Error == want
}

func jsonString(raw []byte, key string) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		return "", err
	}
	return s, nil
}

// flipSignature rewrites one character of the base64url signature in an INK
// Authorization header, keeping the header syntactically valid so the receiver
// rejects it on the cryptographic check rather than on parsing.
func flipSignature(header string) (string, error) {
	parts := strings.SplitN(header, " ", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected authorization header shape")
	}
	parts[1] = flipBase64URL(parts[1])
	return strings.Join(parts, " "), nil
}

func flipBase64URL(s string) string {
	if s == "" {
		return s
	}
	swap := map[byte]byte{'A': 'B', 'B': 'A'}
	b := []byte(s)
	if r, ok := swap[b[0]]; ok {
		b[0] = r
	} else if b[0] == 'z' {
		b[0] = 'y'
	} else {
		b[0] = 'z'
	}
	return string(b)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── assertion bookkeeping ───────────────────────────────────────────────────

type run struct {
	passed int
	failed int
}

func (r *run) check(name string, ok bool, detail string) {
	if ok {
		r.passed++
		fmt.Printf("  PASS  %s\n", name)
		return
	}
	r.failed++
	fmt.Printf("  FAIL  %s\n        %s\n", name, detail)
}

func (r *run) fail(name, detail string) {
	r.failed++
	fmt.Printf("  FAIL  %s\n        %s\n", name, detail)
}

func (r *run) report(title string) int {
	fmt.Printf("\n%s: %d passed, %d failed\n", title, r.passed, r.failed)
	if r.failed > 0 {
		return 1
	}
	return 0
}
