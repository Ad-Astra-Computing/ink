package ink

import (
	"testing"
)

// The Go extractor takes an unvalidated decoded card, so every keys.signing
// entry it returns must satisfy the key-entry schema on its own. An entry
// that omits a schema-required field is skipped rather than admitted with an
// open validity window.
// A malformed keys member must not read as a legacy card: that hands back the
// top-level key as active and ignores what the set said about rotation.
func TestExtractCandidateKeysRefusesMalformedKeysMember(t *testing.T) {
	k := fixedKeypair(t, 0x31)
	for _, keys := range []interface{}{nil, "x", float64(7), []interface{}{}, false} {
		card := map[string]interface{}{
			"agentId":            "tulpa:z6Mk",
			"publicKeyMultibase": k.multibase,
			"keys":               keys,
		}
		if got := ExtractCandidateKeys(card); len(got) != 0 {
			t.Errorf("keys %v: got %d candidate keys, want 0", keys, len(got))
		}
	}
}

func TestExtractCandidateKeysRequiresSchemaFields(t *testing.T) {
	k := fixedKeypair(t, 0x31)
	cases := []struct {
		name  string
		entry map[string]interface{}
		want  int
	}{
		{"complete entry", signingEntry("k1", k, "active"), 1},
		{"missing algorithm", map[string]interface{}{
			"keyId": "k1", "publicKeyMultibase": k.multibase, "status": "active", "validFrom": testValidFrom,
		}, 0},
		{"wrong algorithm", map[string]interface{}{
			"keyId": "k1", "algorithm": "X25519", "publicKeyMultibase": k.multibase, "status": "active", "validFrom": testValidFrom,
		}, 0},
		{"missing validFrom", map[string]interface{}{
			"keyId": "k1", "algorithm": "Ed25519", "publicKeyMultibase": k.multibase, "status": "active",
		}, 0},
		{"empty keyId", map[string]interface{}{
			"keyId": "", "algorithm": "Ed25519", "publicKeyMultibase": k.multibase, "status": "active", "validFrom": testValidFrom,
		}, 0},
		{"non-string revokeReason", func() map[string]interface{} {
			e := signingEntry("k1", k, "revoked")
			e["revokedAt"] = testValidFrom
			e["revokeReason"] = 7
			return e
		}(), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			card := baseCard(deriveAgentID(k), k.multibase)
			card["keys"] = keySet(tc.entry)
			got := ExtractCandidateKeys(card)
			if len(got) != tc.want {
				t.Fatalf("got %d candidates, want %d", len(got), tc.want)
			}
			if tc.want == 1 && !got[0].ValidFrom.Present {
				t.Fatalf("validFrom not carried through")
			}
		})
	}
}

// A schema-invalid entry must not admit an artifact dated before any window
// the card could have published: the codex scenario of a 1900 artifact under
// a windowless entry.
func TestExtractCandidateKeysSkipsWindowlessEntryForOldArtifact(t *testing.T) {
	k := fixedKeypair(t, 0x32)
	card := baseCard(deriveAgentID(k), k.multibase)
	card["keys"] = keySet(map[string]interface{}{
		"keyId": "k1", "publicKeyMultibase": k.multibase, "status": "active",
	})
	keys := ExtractCandidateKeys(card)
	old, ok := ParseInkTimestampMs("1900-01-01T00:00:00Z")
	if !ok {
		t.Fatal("parse")
	}
	r := VerifyDetachedSignatureWithKeys(func([]byte) bool { return true }, keys, old, "k1")
	if r.Verified {
		t.Fatal("windowless entry verified a 1900 artifact")
	}
}

// One bad entry is skipped on its own; the others still count and the set
// never collapses to the legacy single key.
func TestExtractCandidateKeysSkipsOnlyTheBadEntry(t *testing.T) {
	a := fixedKeypair(t, 0x33)
	b := fixedKeypair(t, 0x34)
	card := baseCard(deriveAgentID(a), a.multibase)
	bad := signingEntry("bad", b, "active")
	delete(bad, "algorithm")
	card["keys"] = keySet(signingEntry("good", a, "active"), bad)
	got := ExtractCandidateKeys(card)
	if len(got) != 1 || got[0].KeyID != "good" {
		t.Fatalf("got %+v", got)
	}
}

// A verifyWithKey callback that panics counts as a failed check for that
// key, matching the reference primitive which catches a throwing callback
// per key rather than letting it escape the verifier.
func TestVerifyDetachedSignatureWithKeysRecoversCallbackPanic(t *testing.T) {
	k := fixedKeypair(t, 0x35)
	keys := []CandidateKey{
		{KeyID: "k1", PublicKey: []byte{1}, Status: "active"},
		{KeyID: "k2", PublicKey: k.pub, Status: "active"},
	}
	calls := 0
	r := VerifyDetachedSignatureWithKeys(func(pub []byte) bool {
		calls++
		if len(pub) != 32 {
			panic("boom")
		}
		return true
	}, keys, 1783296000000, "k1")
	if !r.Verified || r.KeyID != "k2" {
		t.Fatalf("got %+v", r)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	r = VerifyDetachedSignatureWithKeys(func([]byte) bool { panic("boom") }, keys[:1], 1783296000000, "k1")
	if r.Verified || r.KeyID != "" {
		t.Fatalf("panicking callback verified: %+v", r)
	}
}
