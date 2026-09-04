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
		if !envelopeIntentTypes[intent] {
			t.Fatalf("%q is not an allocated intent", intent)
		}
	}
}

func TestIntentRequiresEncryptionIsExact(t *testing.T) {
	for intent := range envelopeIntentTypes {
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
	for intent := range envelopeIntentTypes {
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
