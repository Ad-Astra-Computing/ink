package ink

import "testing"

func validEnvelope() map[string]interface{} {
	return map[string]interface{}{
		"protocol":      "ink/0.1",
		"id":            "msg-1",
		"correlationId": "corr-1",
		"createdAt":     "2026-01-01T00:00:00.000Z",
		"from":          "did:web:sender.example",
		"to":            "did:web:receiver.example",
		"intent":        "connection_request",
		"payload":       map[string]interface{}{"method": "intro"},
		"signature":     "AbcdefghijklmnopqrstuvwxyzAbcdefghijklmnopqrstuvwxyzAbcdefghijklmnopqrstuvwxyz012345",
	}
}

func TestValidateMessageEnvelopeAcceptsCompleteEnvelope(t *testing.T) {
	if !ValidateMessageEnvelope(validEnvelope()) {
		t.Fatal("a complete §3.1 envelope must validate")
	}
}

func TestValidateMessageEnvelopeRequiresEveryMust(t *testing.T) {
	for _, key := range []string{"protocol", "id", "correlationId", "createdAt", "from", "to", "intent", "signature"} {
		env := validEnvelope()
		delete(env, key)
		if ValidateMessageEnvelope(env) {
			t.Errorf("envelope missing %q must be rejected (§3.1 MUST)", key)
		}
	}
}

func TestValidateMessageEnvelopeIsStrict(t *testing.T) {
	env := validEnvelope()
	env["extension"] = "x"
	if ValidateMessageEnvelope(env) {
		t.Error("an unknown top-level member must be rejected on the strict intent envelope")
	}
}

func TestValidateMessageEnvelopeClosedSets(t *testing.T) {
	env := validEnvelope()
	env["protocol"] = "ink/0.9"
	if ValidateMessageEnvelope(env) {
		t.Error("an unknown protocol value must be rejected, never inferred")
	}
	env = validEnvelope()
	env["intent"] = "not_an_intent"
	if ValidateMessageEnvelope(env) {
		t.Error("an unallocated intent must be rejected")
	}
}

func TestValidateMessageEnvelopeCapsScalarsInUTF16Units(t *testing.T) {
	env := validEnvelope()
	long := make([]rune, 257)
	for i := range long {
		long[i] = 'a'
	}
	env["id"] = string(long)
	if ValidateMessageEnvelope(env) {
		t.Error("an id over the 256 code-unit cap must be rejected")
	}
	// 128 astral runes are 128 code points but 256 UTF-16 code units, exactly at
	// the cap: an implementation measuring code points or UTF-8 bytes disagrees.
	astral := make([]rune, 128)
	for i := range astral {
		astral[i] = '\U0001F511'
	}
	env = validEnvelope()
	env["id"] = string(astral)
	if !ValidateMessageEnvelope(env) {
		t.Error("an id of exactly 256 UTF-16 code units is within the cap")
	}
	env["id"] = string(append(astral, 'a'))
	if ValidateMessageEnvelope(env) {
		t.Error("an id of 257 UTF-16 code units exceeds the cap")
	}
}

func TestValidateMessageEnvelopeOptionalMembers(t *testing.T) {
	env := validEnvelope()
	env["timestamp"] = "2026-01-01T00:00:00.000Z"
	env["nonce"] = "firstcontactnonce0001"
	env["signingKeyId"] = "k1"
	env["expiresAt"] = "2026-01-02T00:00:00.000Z"
	env["provenance"] = map[string]interface{}{
		"origin":         "agent_approved",
		"extensionId":    "ext-1",
		"installationId": "11111111-1111-4111-8111-111111111111",
	}
	if !ValidateMessageEnvelope(env) {
		t.Fatal("the documented optional members must be accepted")
	}
	env["provenance"] = map[string]interface{}{"origin": "somewhere_else", "extensionId": "ext-1", "installationId": "11111111-1111-4111-8111-111111111111"}
	if ValidateMessageEnvelope(env) {
		t.Error("an origin outside the closed set must be rejected")
	}
}
