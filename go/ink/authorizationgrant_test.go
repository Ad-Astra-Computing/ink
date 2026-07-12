package ink

import (
	"strings"
	"testing"
)

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
		"empty scope":           grantObject(`[]`, ""),
		"duplicate scope":       grantObject(`["a","a"]`, ""),
		"non-string scope":      grantObject(`["a",1]`, ""),
		"null scope":            grantObject(`null`, ""),
		"unknown top-level key": grantObject(`["a"]`, `,"extra":1`),
		"missing signature":     `{"protocol":"ink/0.1","type":"network.tulpa.authorization_grant","issuer":"i","subject":"s","audience":"a","scope":["x"],"grantId":"0123456789abcdef","issuedAt":"2026-07-11T12:00:00.000Z","expiresAt":"2026-07-11T12:05:00.000Z"}`,
		"missing scope":         `{"protocol":"ink/0.1","type":"network.tulpa.authorization_grant","issuer":"i","subject":"s","audience":"a","grantId":"0123456789abcdef","issuedAt":"2026-07-11T12:00:00.000Z","expiresAt":"2026-07-11T12:05:00.000Z","signature":"` + dummySig + `"}`,
		"wrong protocol":        strings.Replace(grantObject(`["a"]`, ""), "ink/0.1", "ink/0.2", 1),
		"bad type":              strings.Replace(grantObject(`["a"]`, ""), "network.tulpa.authorization_grant", "network.tulpa.other", 1),
		"invalid issuedAt":      strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:00:00.000Z", "2026-07-11 12:00", 1),
		"invalid expiresAt":     strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11 12:05", 1),
		"inverted window":       strings.Replace(grantObject(`["a"]`, ""), "2026-07-11T12:05:00.000Z", "2026-07-11T12:00:00.000Z", 1),
		"short grantId":         strings.Replace(grantObject(`["a"]`, ""), "conformance-grant-000000001", "short", 1),
		"non-bool owner":        grantObject(`["a"]`, `,"requireVerifiedOwner":"yes"`),
		"null required issuer":  strings.Replace(grantObject(`["a"]`, ""), `"issuer":"tulpa:issuer"`, `"issuer":null`, 1),
		"null required type":    strings.Replace(grantObject(`["a"]`, ""), `"type":"network.tulpa.authorization_grant"`, `"type":null`, 1),
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
