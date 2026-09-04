package ink

// ConfidentialIntents is the set of intents Protocol §3.4 requires to be sent
// encrypted. A receiver MUST refuse them in plaintext with encryption_required.
// It mirrors CONFIDENTIAL_INTENTS in src/ink/encryption-policy.ts.
var ConfidentialIntents = []string{"schedule_meeting", "context_share", "multi_party_sync"}

var confidentialIntentSet = func() map[string]bool {
	m := make(map[string]bool, len(ConfidentialIntents))
	for _, i := range ConfidentialIntents {
		m[i] = true
	}
	return m
}()

// IntentRequiresEncryption reports whether intent is one the protocol
// requires to be sent encrypted. The match is exact.
func IntentRequiresEncryption(intent string) bool {
	return confidentialIntentSet[intent]
}

// EncryptionRequirementResult is the decision of CheckEncryptionRequired. On
// a refusal Reason is "encryption_required" and Intent names the offending
// intent.
type EncryptionRequirementResult struct {
	Allowed bool
	Reason  string
	Intent  string
}

// CheckEncryptionRequired decides whether a plaintext intent envelope may
// proceed, mirroring checkEncryptionRequired in the reference. It runs after
// ValidateMessageEnvelope and before any work that depends on the intent, in
// the position the intent allowlist sits: a confidential intent in plaintext
// is refused for being plaintext, whatever else the receiver would have said
// about it. An envelope whose intent is absent or not a string is allowed
// through, since there is no intent to gate and the envelope schema is what
// rejects it. An encrypted outer envelope (§3.4) never reaches this gate.
//
// extra widens the set with intents of the receiver's own; the protocol set
// always applies.
func CheckEncryptionRequired(envelope map[string]interface{}, extra ...string) EncryptionRequirementResult {
	intent, ok := envelope["intent"].(string)
	if !ok {
		return EncryptionRequirementResult{Allowed: true}
	}
	if IntentRequiresEncryption(intent) {
		return EncryptionRequirementResult{Reason: "encryption_required", Intent: intent}
	}
	for _, e := range extra {
		if e == intent {
			return EncryptionRequirementResult{Reason: "encryption_required", Intent: intent}
		}
	}
	return EncryptionRequirementResult{Allowed: true}
}
