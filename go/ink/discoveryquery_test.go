package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// parseObj unmarshals a JSON object literal into the generic form the verifier
// validates. It fails the test on malformed JSON.
func parseObj(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad test JSON: %v", err)
	}
	return m
}

// dummySig is a well-formed 86-char base64url string; validation checks
// structure before any signature work, so its value is irrelevant here.
var dummySig = strings.Repeat("A", 86)

func discoveryEnvelope(query, extra string) string {
	base := `"protocol":"ink/0.1","type":"network.tulpa.discovery_query",` +
		`"from":"tulpa:requester","to":"did:web:directory.example",` +
		`"nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z",` +
		`"query":` + query + `,"signature":"` + dummySig + `"`
	return "{" + base + extra + "}"
}

func TestValidateDiscoveryQueryEnvelopeAcceptsWellFormed(t *testing.T) {
	for _, q := range []string{`{}`, `{"tags":["go","typescript"]}`, `{"scope":"public","limit":10}`} {
		if _, ok := validateDiscoveryQueryEnvelope(parseObj(t, discoveryEnvelope(q, ""))); !ok {
			t.Errorf("well-formed query %s failed validation", q)
		}
	}
}

// TestValidateDiscoveryQueryEnvelopeRejects pins the schema decisions that must
// match the TypeScript zod schema, including the null-vs-absent distinction: an
// optional field set to JSON null is a rejection, not an absent field.
func TestValidateDiscoveryQueryEnvelopeRejects(t *testing.T) {
	cases := map[string]string{
		"null tags":             discoveryEnvelope(`{"tags":null}`, ""),
		"null scope":            discoveryEnvelope(`{"scope":null}`, ""),
		"null limit":            discoveryEnvelope(`{"limit":null}`, ""),
		"null query":            `{"protocol":"ink/0.1","type":"network.tulpa.discovery_query","from":"a","to":"b","nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z","query":null,"signature":"` + dummySig + `"}`,
		"unknown top-level key": discoveryEnvelope(`{}`, `,"extra":1`),
		"unknown query key":     discoveryEnvelope(`{"rank":"best"}`, ""),
		"missing signature":     `{"protocol":"ink/0.1","type":"network.tulpa.discovery_query","from":"a","to":"b","nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z","query":{}}`,
		"missing query":         `{"protocol":"ink/0.1","type":"network.tulpa.discovery_query","from":"a","to":"b","nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z","signature":"` + dummySig + `"}`,
		"wrong protocol":        strings.Replace(discoveryEnvelope(`{}`, ""), "ink/0.1", "ink/0.2", 1),
		"bad type":              strings.Replace(discoveryEnvelope(`{}`, ""), "network.tulpa.discovery_query", "network.tulpa.other", 1),
		"invalid timestamp":     strings.Replace(discoveryEnvelope(`{}`, ""), "2026-07-09T00:00:00.000Z", "2026-07-09 00:00", 1),
		"short nonce":           strings.Replace(discoveryEnvelope(`{}`, ""), "0123456789abcdef", "short", 1),
		"limit over 100":        discoveryEnvelope(`{"limit":101}`, ""),
		"non-integer limit":     discoveryEnvelope(`{"limit":1.5}`, ""),
		"invalid scope":         discoveryEnvelope(`{"scope":"secret"}`, ""),
		"empty tags array":      discoveryEnvelope(`{"tags":[]}`, ""),
		"null required from":    strings.Replace(discoveryEnvelope(`{}`, ""), `"from":"tulpa:requester"`, `"from":null`, 1),
		"null required type":    strings.Replace(discoveryEnvelope(`{}`, ""), `"type":"network.tulpa.discovery_query"`, `"type":null`, 1),
	}
	for name, envelope := range cases {
		if _, ok := validateDiscoveryQueryEnvelope(parseObj(t, envelope)); ok {
			t.Errorf("%s: envelope validated but should have been rejected", name)
		}
	}
}

func TestValidateDiscoveryQueryEnvelopeRejectsTooManyTags(t *testing.T) {
	tags := make([]string, 33)
	for i := range tags {
		tags[i] = "t"
	}
	raw, _ := json.Marshal(tags)
	if _, ok := validateDiscoveryQueryEnvelope(parseObj(t, discoveryEnvelope(`{"tags":`+string(raw)+`}`, ""))); ok {
		t.Error("33 tags validated but should have been rejected")
	}
}

// TestValidateDiscoveryQueryEnvelopeDuplicateKeyLastWins pins that a duplicate
// member resolves to the last value, matching JSON.parse, so validation and
// canonicalization see the same object a JavaScript verifier would.
func TestValidateDiscoveryQueryEnvelopeDuplicateKeyLastWins(t *testing.T) {
	firstInvalidThenValid := `{"protocol":"ink/0.1","type":"network.tulpa.discovery_query","from":"a","to":"b","nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z","query":{"rank":"x"},"query":{},"signature":"` + dummySig + `"}`
	if _, ok := validateDiscoveryQueryEnvelope(parseObj(t, firstInvalidThenValid)); !ok {
		t.Error("last-value valid query should validate (last-wins)")
	}
	firstValidThenInvalid := `{"protocol":"ink/0.1","type":"network.tulpa.discovery_query","from":"a","to":"b","nonce":"0123456789abcdef","timestamp":"2026-07-09T00:00:00.000Z","query":{},"query":{"rank":"x"},"signature":"` + dummySig + `"}`
	if _, ok := validateDiscoveryQueryEnvelope(parseObj(t, firstValidThenInvalid)); ok {
		t.Error("last-value invalid query should reject (last-wins)")
	}
}

func TestVerifyDiscoveryQueryEnvelopeRejectsInvalidUTF8(t *testing.T) {
	raw := []byte(discoveryEnvelope(`{}`, ""))
	raw[len(raw)/2] = 0xff
	if ok, _ := VerifyDiscoveryQueryEnvelope(raw, make([]byte, 32), discoveryCtx()); ok {
		t.Error("invalid UTF-8 envelope verified")
	}
}

// TestVerifyDiscoveryQueryEnvelopeRejectsOversizedBody pins the byte-length cap
// the Go verifier applies before json.Unmarshal. A body one byte past the cap is
// rejected without decoding.
func TestVerifyDiscoveryQueryEnvelopeRejectsOversizedBody(t *testing.T) {
	if MaxDiscoveryQueryBodyBytes != 64*1024 {
		t.Errorf("MaxDiscoveryQueryBodyBytes: got %d, want %d", MaxDiscoveryQueryBodyBytes, 64*1024)
	}
	raw := make([]byte, MaxDiscoveryQueryBodyBytes+1)
	for i := range raw {
		raw[i] = 'x'
	}
	if ok, _ := VerifyDiscoveryQueryEnvelope(raw, make([]byte, 32), discoveryCtx()); ok {
		t.Error("oversized discovery query body verified")
	}
}

// TestVerifyDiscoveryQueryEnvelopeAcceptsBodyUnderCap pins that a body under the
// cap is still handed to the decoder (rejected here only because its content is
// not a valid envelope, not because of the byte cap).
func TestVerifyDiscoveryQueryEnvelopeAcceptsBodyUnderCap(t *testing.T) {
	raw := []byte(discoveryEnvelope(`{}`, ""))
	if len(raw) > MaxDiscoveryQueryBodyBytes {
		t.Fatalf("fixture envelope %d bytes exceeds cap %d", len(raw), MaxDiscoveryQueryBodyBytes)
	}
	// A valid-shaped envelope under the cap reaches signature verification and
	// fails there (dummy signature, zero key), not at the byte cap.
	if ok, _ := VerifyDiscoveryQueryEnvelope(raw, make([]byte, 32), discoveryCtx()); ok {
		t.Error("dummy-signed envelope unexpectedly verified")
	}
}

// TestVerifyDiscoveryQueryEnvelopeRejectsOverDeepBody pins the post-parse
// structural walk, which is parity with the TypeScript verifyDiscoveryQueryEnvelope
// isWithinBounds call. A body under the byte cap that nests past the depth cap is
// rejected before schema validation.
func TestVerifyDiscoveryQueryEnvelopeRejectsOverDeepBody(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxBodyDepth+2) + "1" + strings.Repeat(`}`, maxBodyDepth+2)
	raw := []byte(strings.Replace(discoveryEnvelope(`{}`, ""), `"query":{}`, `"query":`+deep, 1))
	if ok, _ := VerifyDiscoveryQueryEnvelope(raw, make([]byte, 32), discoveryCtx()); ok {
		t.Error("over-deep discovery query body verified")
	}
}

// ── verification context: audience, freshness, replay ───────────────────────

const (
	discoveryTestDirectory = "did:web:directory.example"
	discoveryTestFrom      = "tulpa:requester"
	discoveryTestNonce     = "0123456789abcdef"
	discoveryTestTimestamp = "2026-07-09T00:00:00.000Z"
)

// discoveryCtx is the context a well-behaved directory supplies: itself, a clock
// one second past the signed timestamp and no burned nonces.
func discoveryCtx() DiscoveryQueryContext {
	return DiscoveryQueryContext{
		Audience: []string{discoveryTestDirectory},
		Now:      "2026-07-09T00:00:01.000Z",
	}
}

// discoverySeed derives a fixed Ed25519 key for the signed-envelope tests.
func discoverySeed(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("ink-discovery-query-go-test-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// signedDiscoveryEnvelope builds and signs a valid envelope, so the context
// checks that run only after a valid signature can be reached.
func signedDiscoveryEnvelope(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	unsigned := map[string]interface{}{
		"protocol":  "ink/0.1",
		"type":      "network.tulpa.discovery_query",
		"from":      discoveryTestFrom,
		"to":        discoveryTestDirectory,
		"nonce":     discoveryTestNonce,
		"timestamp": discoveryTestTimestamp,
		"query":     map[string]interface{}{"tags": []interface{}{"go"}, "limit": float64(10)},
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		t.Fatalf("canonicalize envelope: %v", err)
	}
	sig := ed25519.Sign(priv, []byte("tulpa/sign\n"+canonical))
	unsigned["signature"] = base64.RawURLEncoding.EncodeToString(sig)
	raw, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

func TestVerifyDiscoveryQueryEnvelopeAcceptsInContext(t *testing.T) {
	priv, pub := discoverySeed(t)
	raw := signedDiscoveryEnvelope(t, priv)
	if ok, reason := VerifyDiscoveryQueryEnvelope(raw, pub, discoveryCtx()); !ok {
		t.Errorf("valid envelope rejected: %s", reason)
	}
}

// TestVerifyDiscoveryQueryEnvelopeContextRejections pins the reason each context
// check returns, and the order they run in: signature before audience, audience
// before the window, the window before replay.
func TestVerifyDiscoveryQueryEnvelopeContextRejections(t *testing.T) {
	priv, pub := discoverySeed(t)
	raw := signedDiscoveryEnvelope(t, priv)

	withCtx := func(mutate func(*DiscoveryQueryContext)) DiscoveryQueryContext {
		ctx := discoveryCtx()
		mutate(&ctx)
		return ctx
	}
	burned := DiscoveryQueryKey{From: discoveryTestFrom, Nonce: discoveryTestNonce}

	cases := map[string]struct {
		ctx  DiscoveryQueryContext
		want DiscoveryQueryReason
	}{
		"other directory": {withCtx(func(c *DiscoveryQueryContext) { c.Audience = []string{"did:web:other.example"} }), DiscoveryQueryReasonAudience},
		"case-folded audience": {withCtx(func(c *DiscoveryQueryContext) {
			c.Audience = []string{"DID:WEB:DIRECTORY.EXAMPLE"}
		}), DiscoveryQueryReasonAudience},
		"empty audience set":   {withCtx(func(c *DiscoveryQueryContext) { c.Audience = nil }), DiscoveryQueryReasonSchema},
		"empty audience entry": {withCtx(func(c *DiscoveryQueryContext) { c.Audience = []string{""} }), DiscoveryQueryReasonSchema},
		"stale": {withCtx(func(c *DiscoveryQueryContext) {
			c.Now = "2026-07-09T00:05:00.001Z"
		}), DiscoveryQueryReasonExpired},
		"past the skew allowance": {withCtx(func(c *DiscoveryQueryContext) {
			c.Now = "2026-07-08T23:59:29.999Z"
		}), DiscoveryQueryReasonNotYetValid},
		"malformed clock": {withCtx(func(c *DiscoveryQueryContext) { c.Now = "2026-07-09 00:00" }), DiscoveryQueryReasonSchema},
		"burned nonce": {withCtx(func(c *DiscoveryQueryContext) {
			c.SeenNonces = []DiscoveryQueryKey{burned}
		}), DiscoveryQueryReasonReplay},
		// The window is checked before replay, so a stale replay reports the window.
		"stale replay": {withCtx(func(c *DiscoveryQueryContext) {
			c.Now = "2026-07-09T00:05:00.001Z"
			c.SeenNonces = []DiscoveryQueryKey{burned}
		}), DiscoveryQueryReasonExpired},
	}
	for name, tc := range cases {
		ok, reason := VerifyDiscoveryQueryEnvelope(raw, pub, tc.ctx)
		if ok {
			t.Errorf("%s: envelope accepted but should have been rejected", name)
			continue
		}
		if reason != tc.want {
			t.Errorf("%s: reason = %q, want %q", name, reason, tc.want)
		}
	}
}

// TestVerifyDiscoveryQueryEnvelopeSignatureBeforeContext pins that a rejection
// on a bad signature never reveals whether the audience would have matched.
func TestVerifyDiscoveryQueryEnvelopeSignatureBeforeContext(t *testing.T) {
	priv, _ := discoverySeed(t)
	raw := signedDiscoveryEnvelope(t, priv)
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	ctx := discoveryCtx()
	ctx.Audience = []string{"did:web:other.example"}
	ok, reason := VerifyDiscoveryQueryEnvelope(raw, other, ctx)
	if ok || reason != DiscoveryQueryReasonSignature {
		t.Errorf("verify = %v/%q, want false/signature", ok, reason)
	}
}

// TestVerifyDiscoveryQueryEnvelopeContextBounds pins the inclusive bounds of the
// freshness window and the (from, nonce) keying of the replay seam.
func TestVerifyDiscoveryQueryEnvelopeContextBounds(t *testing.T) {
	priv, pub := discoverySeed(t)
	raw := signedDiscoveryEnvelope(t, priv)

	accepts := map[string]DiscoveryQueryContext{}
	atAge := discoveryCtx()
	atAge.Now = "2026-07-09T00:05:00.000Z"
	accepts["exactly at the age bound"] = atAge
	atSkew := discoveryCtx()
	atSkew.Now = "2026-07-08T23:59:30.000Z"
	accepts["exactly at the skew bound"] = atSkew
	alias := discoveryCtx()
	alias.Audience = []string{"https://directory.example", "directory.example", discoveryTestDirectory}
	accepts["one of several self-identifiers"] = alias
	otherRequester := discoveryCtx()
	otherRequester.SeenNonces = []DiscoveryQueryKey{{From: "tulpa:someone-else", Nonce: discoveryTestNonce}}
	accepts["another requester's identical nonce"] = otherRequester

	for name, ctx := range accepts {
		if ok, reason := VerifyDiscoveryQueryEnvelope(raw, pub, ctx); !ok {
			t.Errorf("%s: rejected with %q, want accept", name, reason)
		}
	}
}
