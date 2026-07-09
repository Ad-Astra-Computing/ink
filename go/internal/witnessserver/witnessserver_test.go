package witnessserver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

const testOrigin = "example.com/ink-witness"
const testServiceDid = "did:web:witness.example"
const testToken = "s3cret-submit-token"

// fixedClock returns a clock whose instant is a valid INK timestamp when floored
// to the millisecond, so a receipt the server stamps is deterministic in tests.
func fixedClock() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 7, 9, 12, 0, 0, 500*int(time.Millisecond), time.UTC)
	}
}

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("ink-witness-server-test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

func newServer(t *testing.T, cfg Config) (http.Handler, ed25519.PublicKey) {
	t.Helper()
	priv, pub := testKey(t)
	if cfg.Origin == "" {
		cfg.Origin = testOrigin
	}
	if cfg.ServiceDid == "" {
		cfg.ServiceDid = testServiceDid
	}
	if cfg.PrivateKey == nil {
		cfg.PrivateKey = priv
	}
	if cfg.SubmitToken == "" && !cfg.AllowUnauthenticated {
		cfg.SubmitToken = testToken
	}
	if cfg.Now == nil {
		cfg.Now = fixedClock()
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, pub
}

func event(i int) ([]byte, map[string]interface{}) {
	m := map[string]interface{}{
		"id":   fmt.Sprintf("evt-%d", i),
		"type": "connection_request",
		"note": fmt.Sprintf("note-%d", i),
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		panic(err)
	}
	return b, parsed
}

type reqOpt func(*http.Request)

func withToken(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func do(h http.Handler, method, path, body string, opts ...reqOpt) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var res map[string]any
	if b := rec.Body.Bytes(); len(b) > 0 {
		_ = json.Unmarshal(b, &res)
	}
	return rec, res
}

func submit(t *testing.T, h http.Handler, i int) (*httptest.ResponseRecorder, ink.InclusionReceipt) {
	t.Helper()
	raw, _ := event(i)
	rec := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(string(raw)))
	rec.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rec)
	var r ink.InclusionReceipt
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &r); err != nil {
			t.Fatalf("decode receipt: %v (%s)", err, rr.Body.String())
		}
	}
	return rr, r
}

func checkpoint(t *testing.T, h http.Handler, pub ed25519.PublicKey) ink.CheckpointData {
	t.Helper()
	rec, res := do(h, http.MethodGet, "/checkpoint", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("checkpoint status %d (%s)", rec.Code, rec.Body.String())
	}
	note, _ := res["checkpoint"].(string)
	data, ok := ink.VerifyCheckpoint(note, pub, testOrigin)
	if !ok {
		t.Fatalf("checkpoint did not verify: %q", note)
	}
	return data
}

func TestConfigValidation(t *testing.T) {
	priv, _ := testKey(t)
	if _, err := New(Config{Origin: testOrigin, PrivateKey: priv}); err == nil {
		t.Error("no submit token and not AllowUnauthenticated: want error")
	}
	if _, err := New(Config{Origin: "", PrivateKey: priv, SubmitToken: testToken}); err == nil {
		t.Error("empty origin accepted")
	}
	if _, err := New(Config{Origin: "has space", PrivateKey: priv, SubmitToken: testToken}); err == nil {
		t.Error("origin with a space accepted")
	}
	if _, err := New(Config{Origin: testOrigin, PrivateKey: make([]byte, 5), SubmitToken: testToken}); err == nil {
		t.Error("bad key length accepted")
	}
	if _, err := New(Config{Origin: testOrigin, PrivateKey: priv, SubmitToken: testToken}); err == nil {
		t.Error("empty serviceDid accepted")
	}
	if _, err := New(Config{Origin: testOrigin, PrivateKey: priv, ServiceDid: testServiceDid, AllowUnauthenticated: true}); err != nil {
		t.Errorf("AllowUnauthenticated without a token should be allowed: %v", err)
	}
}

func TestHealthz(t *testing.T) {
	h, _ := newServer(t, Config{})
	rec, res := do(h, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK || res["ok"] != true {
		t.Errorf("healthz = status %d body %v", rec.Code, res)
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	h, _ := newServer(t, Config{})
	rec, res := do(h, http.MethodGet, "/bogus", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if res["error"] != "not_found" {
		t.Errorf("unexpected body: %v", res)
	}
}

func TestWrongMethodIs405(t *testing.T) {
	h, _ := newServer(t, Config{})
	cases := []struct {
		method, path, allow string
	}{
		{http.MethodGet, "/submit", http.MethodPost},
		{http.MethodGet, "/audit-query", http.MethodPost},
		{http.MethodPost, "/checkpoint", http.MethodGet},
		{http.MethodPost, "/inclusion", http.MethodGet},
		{http.MethodPost, "/consistency", http.MethodGet},
		{http.MethodPost, "/healthz", http.MethodGet},
	}
	for _, c := range cases {
		rec, _ := do(h, c.method, c.path, "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want 405", c.method, c.path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != c.allow {
			t.Errorf("%s %s Allow = %q, want %q", c.method, c.path, allow, c.allow)
		}
	}
}

func TestSubmitRequiresAuth(t *testing.T) {
	h, _ := newServer(t, Config{})
	raw, _ := event(0)
	// Missing token.
	rec, _ := do(h, http.MethodPost, "/submit", string(raw))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token status = %d, want 401", rec.Code)
	}
	// Wrong token.
	rec, _ = do(h, http.MethodPost, "/submit", string(raw), withToken("nope"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", rec.Code)
	}
	// A rejected auth must not have grown the log.
	if data := checkpoint(t, h, mustPub(t)); data.TreeSize != 0 {
		t.Errorf("unauthorized submits grew the log to %d", data.TreeSize)
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	_, pub := testKey(t)
	return pub
}

func TestSubmitAcceptsAndSequences(t *testing.T) {
	h, pub := newServer(t, Config{})
	for i := 0; i < 3; i++ {
		rr, r := submit(t, h, i)
		if rr.Code != http.StatusOK {
			t.Fatalf("submit %d status %d (%s)", i, rr.Code, rr.Body.String())
		}
		if r.LeafIndex != i || r.TreeSize != i+1 {
			t.Errorf("submit %d: leafIndex=%d treeSize=%d", i, r.LeafIndex, r.TreeSize)
		}
		if r.Timestamp != "2026-07-09T12:00:00.500Z" {
			t.Errorf("submit %d: timestamp = %q, want the server-stamped instant", i, r.Timestamp)
		}
		if _, ok := ink.ParseInkTimestampMs(r.Timestamp); !ok {
			t.Errorf("submit %d: stamped timestamp %q is not a valid INK timestamp", i, r.Timestamp)
		}
		_, parsed := event(i)
		if !ink.VerifyInclusionReceipt(r, pub, ink.ReceiptVerifyOptions{Event: parsed}) {
			t.Errorf("submit %d: receipt did not verify against the event", i)
		}
	}
	if data := checkpoint(t, h, pub); data.TreeSize != 3 {
		t.Errorf("final tree size = %d, want 3", data.TreeSize)
	}
}

func TestSubmitRejectsBadEvent(t *testing.T) {
	h, pub := newServer(t, Config{})
	bad := map[string]string{
		"not json":     `{not json`,
		"non object":   `"a-string"`,
		"missing id":   `{"type":"x"}`,
		"empty id":     `{"id":"","type":"x"}`,
		"invalid utf8": "{\"id\":\"e\xff\"}",
	}
	for name, body := range bad {
		rec, res := do(h, http.MethodPost, "/submit", body, withToken(testToken))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
		if res["ok"] != false {
			t.Errorf("%s: body = %v", name, res)
		}
	}
	if data := checkpoint(t, h, pub); data.TreeSize != 0 {
		t.Errorf("rejected submits grew the log to %d", data.TreeSize)
	}
}

func TestSubmitOversizeIs413(t *testing.T) {
	h, _ := newServer(t, Config{})
	big := `{"id":"x","pad":"` + strings.Repeat("a", (4<<20)+1) + `"}`
	rec, _ := do(h, http.MethodPost, "/submit", big, withToken(testToken))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestSubmitCapacityIs507(t *testing.T) {
	h, pub := newServer(t, Config{MaxLeaves: 2})
	for i := 0; i < 2; i++ {
		if rr, _ := submit(t, h, i); rr.Code != http.StatusOK {
			t.Fatalf("submit %d status %d", i, rr.Code)
		}
	}
	rr, _ := submit(t, h, 2)
	if rr.Code != http.StatusInsufficientStorage {
		t.Errorf("at-capacity submit status = %d, want 507", rr.Code)
	}
	if data := checkpoint(t, h, pub); data.TreeSize != 2 {
		t.Errorf("capacity-rejected submit grew the log to %d", data.TreeSize)
	}
}

func TestUnauthenticatedModeAcceptsWithoutToken(t *testing.T) {
	h, _ := newServer(t, Config{AllowUnauthenticated: true})
	raw, _ := event(0)
	rec, _ := do(h, http.MethodPost, "/submit", string(raw))
	if rec.Code != http.StatusOK {
		t.Errorf("unauthenticated mode status = %d, want 200", rec.Code)
	}
}

func TestInclusionProofVerifiesAgainstCheckpoint(t *testing.T) {
	h, pub := newServer(t, Config{})
	const n = 5
	for i := 0; i < n; i++ {
		if rr, _ := submit(t, h, i); rr.Code != http.StatusOK {
			t.Fatalf("submit %d status %d", i, rr.Code)
		}
	}
	cp := checkpoint(t, h, pub)
	for i := 0; i < n; i++ {
		rec, res := do(h, http.MethodGet, fmt.Sprintf("/inclusion?index=%d", i), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("inclusion %d status %d (%s)", i, rec.Code, rec.Body.String())
		}
		size := int(res["size"].(float64))
		if size != int(cp.TreeSize) {
			t.Errorf("inclusion %d size = %d, want %d", i, size, int(cp.TreeSize))
		}
		proof := toStrings(res["proof"])
		_, ev := event(i)
		leaf, ok := ink.ComputeAuditMerkleLeafHash(ev)
		if !ok {
			t.Fatalf("leaf hash %d", i)
		}
		if !ink.VerifyInclusionProof(leaf, proof, i, size, cp.RootHash) {
			t.Errorf("inclusion %d did not verify against the checkpoint root", i)
		}
	}
}

func TestInclusionRejectsBadIndex(t *testing.T) {
	h, _ := newServer(t, Config{})
	for i := 0; i < 3; i++ {
		submit(t, h, i)
	}
	bad := []string{
		"/inclusion",                        // missing
		"/inclusion?index=",                 // empty
		"/inclusion?index=-1",               // sign
		"/inclusion?index=+1",               // sign
		"/inclusion?index=1.0",              // float
		"/inclusion?index=1e2",              // exponent
		"/inclusion?index=0x1",              // hex
		"/inclusion?index=%201",             // whitespace
		"/inclusion?index=01",               // leading zero
		"/inclusion?index=9007199254740992", // above maxSafeInteger
		"/inclusion?index=3",                // out of range (size 3)
		"/inclusion?index=1&index=2",        // duplicate
	}
	for _, path := range bad {
		rec, _ := do(h, http.MethodGet, path, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
	}
}

func TestConsistencyProofVerifies(t *testing.T) {
	h, pub := newServer(t, Config{})
	for i := 0; i < 3; i++ {
		submit(t, h, i)
	}
	first := checkpoint(t, h, pub)
	for i := 3; i < 8; i++ {
		submit(t, h, i)
	}
	second := checkpoint(t, h, pub)

	rec, res := do(h, http.MethodGet, fmt.Sprintf("/consistency?first=%d&second=%d", int(first.TreeSize), int(second.TreeSize)), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("consistency status %d (%s)", rec.Code, rec.Body.String())
	}
	proof := toStrings(res["proof"])
	if !ink.VerifyConsistencyProof(int(first.TreeSize), first.RootHash, int(second.TreeSize), second.RootHash, proof) {
		t.Errorf("consistency proof did not verify")
	}
	// N -> N is a valid, empty consistency request.
	rec, _ = do(h, http.MethodGet, fmt.Sprintf("/consistency?first=%d&second=%d", int(second.TreeSize), int(second.TreeSize)), "")
	if rec.Code != http.StatusOK {
		t.Errorf("N->N status = %d, want 200", rec.Code)
	}
}

func TestConsistencyRejectsBadParams(t *testing.T) {
	h, _ := newServer(t, Config{})
	for i := 0; i < 4; i++ {
		submit(t, h, i)
	}
	bad := []string{
		"/consistency?first=2",                         // missing second
		"/consistency?second=2",                        // missing first
		"/consistency?first=3&second=2",                // first > second
		"/consistency?first=2&second=9007199254740992", // overflow
		"/consistency?first=-1&second=2",               // sign
		"/consistency?first=2&second=2.0",              // float
		"/consistency?first=2&second=99",               // second above current size
	}
	for _, path := range bad {
		rec, _ := do(h, http.MethodGet, path, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
	}
}

func TestConcurrentSubmit(t *testing.T) {
	h, pub := newServer(t, Config{})
	const n = 30
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr, _ := submit(t, h, i)
			codes[i] = rr.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("submit %d status %d", i, c)
		}
	}
	if data := checkpoint(t, h, pub); data.TreeSize != n {
		t.Errorf("final tree size = %d, want %d", data.TreeSize, n)
	}
}

// auditEventJSON returns a raw audit event scoped to (messageID, requester).
func auditEventJSON(i int, messageID, agentID, counterpartyID string) string {
	m := map[string]interface{}{
		"id":             fmt.Sprintf("evt-%d", i),
		"type":           "connection_request",
		"messageId":      messageID,
		"agentId":        agentID,
		"counterpartyId": counterpartyID,
		"seq":            i,
		"agentSignature": fmt.Sprintf("sig-%d", i),
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestAuditQueryEndpoint(t *testing.T) {
	h, pub := newServer(t, Config{})
	const messageID = "msg-1"
	const alice = "did:web:alice.example"
	const bob = "did:web:bob.example"
	for i := 0; i < 3; i++ {
		body := auditEventJSON(i, messageID, alice, bob)
		rec, _ := do(h, http.MethodPost, "/submit", body, withToken(testToken))
		if rec.Code != http.StatusOK {
			t.Fatalf("submit %d: status %d", i, rec.Code)
		}
	}

	// Missing auth is rejected.
	q := fmt.Sprintf(`{"requester":%q,"messageId":%q}`, alice, messageID)
	if rec, _ := do(h, http.MethodPost, "/audit-query", q); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated audit-query status = %d, want 401", rec.Code)
	}
	// Empty fields are bad input.
	if rec, _ := do(h, http.MethodPost, "/audit-query", `{"requester":"","messageId":"m"}`, withToken(testToken)); rec.Code != http.StatusBadRequest {
		t.Errorf("empty requester status = %d, want 400", rec.Code)
	}
	if rec, _ := do(h, http.MethodPost, "/audit-query", `{not json`, withToken(testToken)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json status = %d, want 400", rec.Code)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/audit-query", strings.NewReader(q))
	req.Header.Set("Authorization", "Bearer "+testToken)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit-query status = %d (%s)", rec.Code, rec.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opts := ink.AuditQueryVerifyOptions{
		ExpectedRequester:  alice,
		ExpectedMessageID:  messageID,
		ExpectedServiceDid: testServiceDid,
		VerifyEventSignature: func(ev map[string]interface{}) bool {
			sig, _ := ev["agentSignature"].(string)
			return sig != ""
		},
	}
	if !ink.VerifyInkAuditQueryResponse(response, pub, opts) {
		t.Error("audit-query response did not verify end to end")
	}
	if evs, _ := response["events"].([]interface{}); len(evs) != 3 {
		t.Errorf("returned %d events, want 3", len(evs))
	}
}

func TestConcurrentSubmitRespectsCapacity(t *testing.T) {
	h, pub := newServer(t, Config{MaxLeaves: 5})
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			submit(t, h, i)
		}(i)
	}
	wg.Wait()
	if data := checkpoint(t, h, pub); data.TreeSize != 5 {
		t.Errorf("tree size = %d, want exactly 5 (no capacity overshoot)", data.TreeSize)
	}
}

func TestUnauthorizedSetsWWWAuthenticate(t *testing.T) {
	h, _ := newServer(t, Config{})
	raw, _ := event(0)
	rec, _ := do(h, http.MethodPost, "/submit", string(raw))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
}

func TestKeyNeverExposed(t *testing.T) {
	h, _ := newServer(t, Config{})
	for _, path := range []string{"/healthz", "/checkpoint"} {
		rec, _ := do(h, http.MethodGet, path, "")
		body := strings.ToLower(rec.Body.String())
		for _, needle := range []string{"private", "seed", "secret"} {
			if strings.Contains(body, needle) {
				t.Errorf("%s body leaks %q: %s", path, needle, rec.Body.String())
			}
		}
	}
}

func TestPrivateKeyFromSeedHex(t *testing.T) {
	priv, pub := testKey(t)
	seed := priv.Seed()
	got, err := PrivateKeyFromSeedHex(hex.EncodeToString(seed))
	if err != nil {
		t.Fatalf("PrivateKeyFromSeedHex: %v", err)
	}
	if !got.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("derived public key does not match")
	}
	for _, bad := range []string{"", "zz", hex.EncodeToString(make([]byte, 16))} {
		if _, err := PrivateKeyFromSeedHex(bad); err == nil {
			t.Errorf("bad seed %q accepted", bad)
		}
	}
}

func toStrings(v any) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		out[i], _ = e.(string)
	}
	return out
}
