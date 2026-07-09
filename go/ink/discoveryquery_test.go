package ink

import (
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
	if VerifyDiscoveryQueryEnvelope(raw, make([]byte, 32)) {
		t.Error("invalid UTF-8 envelope verified")
	}
}
