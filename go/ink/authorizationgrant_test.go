package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// signGrantForTest signs a grant object under the ink/0.1 body-signature domain
// (tulpa/sign) so the negative-path context checks that run only after a valid
// signature can be reached. It mirrors buildAuthorizationGrant: JCS over the
// unsigned object, Ed25519 over the domain-prefixed canonical bytes.
func signGrantForTest(t *testing.T, unsigned map[string]interface{}, priv ed25519.PrivateKey) string {
	t.Helper()
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		t.Fatalf("canonicalize grant: %v", err)
	}
	sig := ed25519.Sign(priv, []byte("tulpa/sign\n"+canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// grantSeed derives a fixed Ed25519 key for the signed-grant tests.
func grantSeed(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("ink-authorization-grant-go-test-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// grantObject builds an authorization grant JSON literal. scope, extra, and the
// optional owner clause let a case vary one field while the rest stay valid.
// The signature is the dummy 86-char base64url string; validation checks
// structure before any signature work.
func grantObject(scope, extra string) string {
	base := `"protocol":"ink/0.1","type":"network.tulpa.authorization_grant",` +
		`"issuer":"tulpa:issuer","subject":"did:web:subject.example",` +
		`"audience":"did:web:service.example","scope":` + scope + `,` +
		`"grantId":"conformance-grant-000000001",` +
		`"issuedAt":"2026-07-11T12:00:00.000Z","expiresAt":"2026-07-11T12:05:00.000Z",` +
		`"signature":"` + dummySig + `"`
	return "{" + base + extra + "}"
}

func TestValidateAuthorizationGrantAcceptsWellFormed(t *testing.T) {
	cases := []string{
		grantObject(`["profile:read"]`, ""),
		grantObject(`["profile:read","messages:send"]`, ""),
		grantObject(`["profile:read"]`, `,"requireVerifiedOwner":true`),
		grantObject(`["profile:read"]`, `,"requireVerifiedOwner":false`),
		// A window exactly at the ten-minute ceiling is in profile.
		strings.Replace(grantObject(`["profile:read"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11T12:10:00.000Z", 1),
	}
	for _, c := range cases {
		if _, ok := validateAuthorizationGrant(parseObj(t, c)); !ok {
			t.Errorf("well-formed grant failed validation: %s", c)
		}
	}
}

// TestValidateAuthorizationGrantRejects pins the schema decisions a second
// implementation must make identically, independent of the conformance corpus.
func TestValidateAuthorizationGrantRejects(t *testing.T) {
	cases := map[string]string{
		"empty scope":             grantObject(`[]`, ""),
		"duplicate scope":         grantObject(`["a","a"]`, ""),
		"non-string scope":        grantObject(`["a",1]`, ""),
		"null scope":              grantObject(`null`, ""),
		"unknown top-level key":   grantObject(`["a"]`, `,"extra":1`),
		"missing signature":       `{"protocol":"ink/0.1","type":"network.tulpa.authorization_grant","issuer":"i","subject":"s","audience":"a","scope":["x"],"grantId":"0123456789abcdef","issuedAt":"2026-07-11T12:00:00.000Z","expiresAt":"2026-07-11T12:05:00.000Z"}`,
		"missing scope":           `{"protocol":"ink/0.1","type":"network.tulpa.authorization_grant","issuer":"i","subject":"s","audience":"a","grantId":"0123456789abcdef","issuedAt":"2026-07-11T12:00:00.000Z","expiresAt":"2026-07-11T12:05:00.000Z","signature":"` + dummySig + `"}`,
		"wrong protocol":          strings.Replace(grantObject(`["a"]`, ""), "ink/0.1", "ink/0.2", 1),
		"bad type":                strings.Replace(grantObject(`["a"]`, ""), "network.tulpa.authorization_grant", "network.tulpa.other", 1),
		"invalid issuedAt":        strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:00:00.000Z", "2026-07-11 12:00", 1),
		"invalid expiresAt":       strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11 12:05", 1),
		"inverted window":         strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11T12:00:00.000Z", 1),
		"over maximum lifetime":   strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11T12:11:00.000Z", 1),
		"over-length scope entry": grantObject(`["`+strings.Repeat("x", 129)+`"]`, ""),
		"short grantId":           strings.Replace(grantObject(`["a"]`, ""), "conformance-grant-000000001", "short", 1),
		"non-bool owner":          grantObject(`["a"]`, `,"requireVerifiedOwner":"yes"`),
		"null required issuer":    strings.Replace(grantObject(`["a"]`, ""), `"issuer":"tulpa:issuer"`, `"issuer":null`, 1),
		"null required type":      strings.Replace(grantObject(`["a"]`, ""), `"type":"network.tulpa.authorization_grant"`, `"type":null`, 1),
	}
	for name, grant := range cases {
		if _, ok := validateAuthorizationGrant(parseObj(t, grant)); ok {
			t.Errorf("%s: expected rejection, got accept", name)
		}
	}
}

func TestValidateAuthorizationGrantRejectsOverbroadScope(t *testing.T) {
	entries := make([]string, 65)
	for i := range entries {
		entries[i] = `"s` + string(rune('0'+i%10)) + string(rune('a'+i)) + `"`
	}
	grant := grantObject("["+strings.Join(entries, ",")+"]", "")
	if _, ok := validateAuthorizationGrant(parseObj(t, grant)); ok {
		t.Error("expected rejection of a scope with more than 64 entries")
	}
}

// TestVerifyAuthorizationGrantContextChecks exercises the context decisions the
// schema layer does not cover, against a grant that passes structural
// validation but fails signature (the fixed dummy signature never verifies).
// Every case here must reach a context check only after the signature check, so
// they all reject; the distinct reasons are pinned by the conformance corpus
// where the signature is real.
func TestVerifyAuthorizationGrantFailsClosedOnBadSignature(t *testing.T) {
	raw := []byte(grantObject(`["profile:read"]`, ""))
	pub := make([]byte, 32)
	pub[0] = 1 // a syntactically sized but non-strong key
	ok, _ := VerifyAuthorizationGrant(raw, pub, AuthorizationGrantContext{
		Audience: "did:web:service.example",
		Now:      "2026-07-11T12:02:00.000Z",
	})
	if ok {
		t.Error("a grant with an unverifiable signature must fail closed")
	}
}

// TestVerifyAuthorizationGrantRejectsOversizedBody pins the byte-length cap the
// Go verifier applies before json.Unmarshal, mirroring the pre-parse complexity
// bound the reference runs. A body past the cap is rejected as schema without
// parsing, so a pathological blob cannot be handed to the decoder at all.
func TestVerifyAuthorizationGrantRejectsOversizedBody(t *testing.T) {
	if MaxGrantBodyBytes != 65536 {
		t.Errorf("MaxGrantBodyBytes: got %d, want 65536 (spec byte bound)", MaxGrantBodyBytes)
	}
	raw := make([]byte, MaxGrantBodyBytes+1)
	for i := range raw {
		raw[i] = 'x'
	}
	pub := make([]byte, 32)
	pub[0] = 1
	ok, reason := VerifyAuthorizationGrant(raw, pub, AuthorizationGrantContext{
		Audience: "did:web:service.example",
		Now:      "2026-07-11T12:02:00.000Z",
	})
	if ok || reason != GrantReasonSchema {
		t.Errorf("oversized body: got ok=%v reason=%q, want reject schema", ok, reason)
	}
}

// TestVerifyAuthorizationGrantRejectsOverDeepBody pins the post-parse structural
// bounds walk. A grant that stays under the byte cap but nests an object past the
// depth cap is rejected as schema, matching the reference node/depth walk, so both
// implementations reject the same pathological structure.
func TestVerifyAuthorizationGrantRejectsOverDeepBody(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxBodyDepth+2)
	deep += "1"
	deep += strings.Repeat(`}`, maxBodyDepth+2)
	// A grant whose subject value is replaced by a deeply nested object. The
	// wrong type also fails the schema, but the bounds walk runs first and short
	// circuits before the field-type checks.
	raw := []byte(strings.Replace(grantObject(`["profile:read"]`, ""), `"subject":"did:web:subject.example"`, `"subject":`+deep, 1))
	pub := make([]byte, 32)
	pub[0] = 1
	ok, reason := VerifyAuthorizationGrant(raw, pub, AuthorizationGrantContext{
		Audience: "did:web:service.example",
		Now:      "2026-07-11T12:02:00.000Z",
	})
	if ok || reason != GrantReasonSchema {
		t.Errorf("over-deep body: got ok=%v reason=%q, want reject schema", ok, reason)
	}
}

// TestVerifyAuthorizationGrantRejectsNonJcsSafeNumber pins number parity between
// withinBodyBounds and the reference isWithinBounds walk. A grant carrying a
// non-JCS-safe number (here an exponential-magnitude value in the scope array) is
// rejected as schema during the bounds walk, before schema validation or any
// signature work, so both implementations reject the same body. The bounds walk
// visits the scope array member, so the bad number is caught even though the
// field type would also fail schema.
func TestVerifyAuthorizationGrantRejectsNonJcsSafeNumber(t *testing.T) {
	raw := []byte(strings.Replace(grantObject(`["profile:read"]`, ""), `["profile:read"]`, `["profile:read",1e21]`, 1))
	pub := make([]byte, 32)
	pub[0] = 1
	ok, reason := VerifyAuthorizationGrant(raw, pub, AuthorizationGrantContext{
		Audience: "did:web:service.example",
		Now:      "2026-07-11T12:02:00.000Z",
	})
	if ok || reason != GrantReasonSchema {
		t.Errorf("non-JCS-safe number: got ok=%v reason=%q, want reject schema", ok, reason)
	}
	// Direct assertion on the bounds walk: a fractional value and a magnitude past
	// the safe-integer range are both rejected, matching isJcsSafeNumber.
	for _, bad := range []interface{}{1e21, 3.14, float64(1) / float64(3)} {
		if withinBodyBounds(map[string]interface{}{"n": bad}) {
			t.Errorf("withinBodyBounds accepted a non-JCS-safe number %v", bad)
		}
	}
	// A safe integer stays within bounds.
	if !withinBodyBounds(map[string]interface{}{"n": float64(42)}) {
		t.Error("withinBodyBounds rejected a safe integer")
	}
}

// TestVerifyAuthorizationGrantNegativeCallerLifetimeRejects pins that a negative
// MaxLifetimeMs is a verifier input error that fails closed as schema, after the
// signature, while a zero value means unset and the grant still verifies. It
// signs a real grant so the caller-tightened lifetime check is reached.
func TestVerifyAuthorizationGrantNegativeCallerLifetimeRejects(t *testing.T) {
	priv, pub := grantSeed(t)
	unsigned := map[string]interface{}{
		"protocol":  "ink/0.1",
		"type":      "network.tulpa.authorization_grant",
		"issuer":    "tulpa:issuer",
		"subject":   "did:web:subject.example",
		"audience":  "did:web:service.example",
		"scope":     []interface{}{"profile:read"},
		"grantId":   "conformance-grant-000000001",
		"issuedAt":  "2026-07-11T12:00:00.000Z",
		"expiresAt": "2026-07-11T12:05:00.000Z",
	}
	sig := signGrantForTest(t, unsigned, priv)
	signed := make(map[string]interface{}, len(unsigned)+1)
	for k, v := range unsigned {
		signed[k] = v
	}
	signed["signature"] = sig
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed grant: %v", err)
	}
	base := AuthorizationGrantContext{Audience: "did:web:service.example", Now: "2026-07-11T12:02:00.000Z"}

	negative := base
	negative.MaxLifetimeMs = -1
	if ok, reason := VerifyAuthorizationGrant(raw, pub, negative); ok || reason != GrantReasonSchema {
		t.Errorf("negative MaxLifetimeMs: got ok=%v reason=%q, want reject schema", ok, reason)
	}

	zero := base
	zero.MaxLifetimeMs = 0
	if ok, reason := VerifyAuthorizationGrant(raw, pub, zero); !ok {
		t.Errorf("zero MaxLifetimeMs: got ok=%v reason=%q, want accept (unset)", ok, reason)
	}
}
