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
// proceed, mirroring checkEncryptionRequired in the reference. It assumes
// the caller already decided the receiver supports the intent;
// CheckIntentDisposition below composes both checks in the required order
// and is the normative reference for it. MUST NOT be called on a decrypted
// inner envelope, which is by construction never plaintext: it has no way
// to know the envelope already arrived encrypted.
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

var coreIntentSet = func() map[string]bool {
	m := make(map[string]bool, len(CoreIntents))
	for _, i := range CoreIntents {
		m[i] = true
	}
	return m
}()

// IsIntentSupported reports whether a receiver supports intent: a core
// intent, always, or one of its own supportedIntents. The support-only half
// of CheckIntentDisposition below, exposed because the confidentiality half
// does not apply to a decrypted inner envelope (§3.4), which is by
// construction never plaintext. A decrypted inner envelope's support
// decision calls this function directly instead of the composed one.
func IsIntentSupported(intent string, supportedIntents []string) bool {
	if coreIntentSet[intent] {
		return true
	}
	for _, s := range supportedIntents {
		if s == intent {
			return true
		}
	}
	return false
}

// IntentDispositionResult is the decision of CheckIntentDisposition. On a
// refusal Reason is "unsupported_intent" or "encryption_required" and Intent
// names the offending intent.
type IntentDispositionResult struct {
	Allowed bool
	Reason  string
	Intent  string
}

// CheckIntentDisposition decides whether a PLAINTEXT envelope may proceed,
// in the order Protocol §3.4 requires: unsupported_intent before
// encryption_required. Call this only on a plaintext or not-yet-decrypted
// outer envelope; a decrypted inner envelope uses IsIntentSupported
// directly instead, since it is by construction never plaintext.
func CheckIntentDisposition(envelope map[string]interface{}, supportedIntents []string, extraConfidentialIntents ...string) IntentDispositionResult {
	intent, ok := envelope["intent"].(string)
	if !ok {
		return IntentDispositionResult{Allowed: true}
	}
	if !IsIntentSupported(intent, supportedIntents) {
		return IntentDispositionResult{Reason: "unsupported_intent", Intent: intent}
	}
	enc := CheckEncryptionRequired(envelope, extraConfidentialIntents...)
	if !enc.Allowed {
		return IntentDispositionResult{Reason: "encryption_required", Intent: intent}
	}
	return IntentDispositionResult{Allowed: true}
}
