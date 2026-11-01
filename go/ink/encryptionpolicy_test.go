package ink

import (
	"sort"
	"testing"
)

func TestConfidentialIntentsMatchTheSpecSet(t *testing.T) {
	got := append([]string(nil), ConfidentialIntents...)
	sort.Strings(got)
	want := []string{"context_share", "multi_party_sync", "schedule_meeting"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, intent := range ConfidentialIntents {
		if !IsWellFormedIntent(intent) {
			t.Fatalf("%q is not a well-formed intent", intent)
		}
	}
}

func TestIntentRequiresEncryptionIsExact(t *testing.T) {
	for _, intent := range RegisteredIntents {
		if IntentRequiresEncryption(intent) != confidentialIntentSet[intent] {
			t.Fatalf("%q disagrees with the set", intent)
		}
	}
	for _, s := range []string{"Schedule_Meeting", " schedule_meeting", "schedule_meeting_response", "context_share2", "", "telepathy"} {
		if IntentRequiresEncryption(s) {
			t.Fatalf("%q matched", s)
		}
	}
}

func TestCheckEncryptionRequired(t *testing.T) {
	for _, intent := range ConfidentialIntents {
		r := CheckEncryptionRequired(map[string]interface{}{"intent": intent})
		if r.Allowed || r.Reason != "encryption_required" || r.Intent != intent {
			t.Fatalf("%s: got %+v", intent, r)
		}
	}
	for _, intent := range RegisteredIntents {
		if confidentialIntentSet[intent] {
			continue
		}
		if r := CheckEncryptionRequired(map[string]interface{}{"intent": intent}); !r.Allowed || r.Reason != "" || r.Intent != "" {
			t.Fatalf("%s: got %+v", intent, r)
		}
	}
	for name, env := range map[string]map[string]interface{}{
		"nil":               nil,
		"empty":             {},
		"non-string intent": {"intent": 7},
		"null intent":       {"intent": nil},
	} {
		if r := CheckEncryptionRequired(env); !r.Allowed {
			t.Fatalf("%s: got %+v", name, r)
		}
	}
	r := CheckEncryptionRequired(map[string]interface{}{"intent": "opportunity"}, "opportunity")
	if r.Allowed || r.Intent != "opportunity" {
		t.Fatalf("widened set: got %+v", r)
	}
	if r := CheckEncryptionRequired(map[string]interface{}{"intent": "ping"}, "opportunity"); !r.Allowed {
		t.Fatalf("widened set leaked: got %+v", r)
	}
}

func TestIsIntentSupported(t *testing.T) {
	for _, core := range CoreIntents {
		if !IsIntentSupported(core, nil) {
			t.Errorf("%q must be supported even with no supportedIntents listed", core)
		}
	}
	if IsIntentSupported("ping", nil) {
		t.Fatal("a non-core intent must not be supported with an empty list")
	}
	if !IsIntentSupported("ping", []string{"ping"}) {
		t.Fatal("ping must be supported once listed")
	}
	if IsIntentSupported("com.example.custom", []string{"ping"}) {
		t.Fatal("an unlisted vendor intent must not be supported")
	}
}

// A decrypted inner envelope's support decision must use IsIntentSupported
// directly, never CheckIntentDisposition: calling the composed function on an
// already-encrypted-in-transit envelope would wrongly refuse a supported
// confidential intent, since CheckEncryptionRequired has no notion of
// "already delivered encrypted". This pins that IsIntentSupported alone never
// produces an encryption_required refusal, even for a confidential intent.
func TestIsIntentSupportedNeverGatesOnConfidentiality(t *testing.T) {
	if !IsIntentSupported("schedule_meeting", []string{"schedule_meeting"}) {
		t.Fatal("a supported confidential intent must report supported, with no confidentiality opinion")
	}
	for _, intent := range ConfidentialIntents {
		if !IsIntentSupported(intent, []string{intent}) {
			t.Errorf("%q: IsIntentSupported must not refuse a listed confidential intent", intent)
		}
	}
}
