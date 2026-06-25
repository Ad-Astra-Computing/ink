package ink

import (
	"regexp"
	"time"
)

// zodDatetimeRe matches the format the reference's z.string().datetime() accepts:
// a UTC date-time with a literal Z (no numeric offset) and optional fractional
// seconds. time.Parse then range-validates the calendar and clock fields, so an
// out-of-range value like month 13 is rejected the same way the reference
// rejects it. This is the handshake-message timestamp contract; it is distinct
// from the stricter signed-body timestamp grammar (which also accepts offsets).
var zodDatetimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)

func isHandshakeDatetime(s string) bool {
	if !zodDatetimeRe.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func hsString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}

// reqStr returns true if key is a present string of at most maxUTF16 UTF-16
// code units (matching Zod .max(), which counts JS string length).
func reqStr(m map[string]interface{}, key string, maxUTF16 int) bool {
	v, ok := hsString(m, key)
	return ok && utf16Len(v) <= maxUTF16
}

// optStr returns true if key is absent, or a present string within the cap. A
// present non-string fails. Zod treats an explicit undefined like absent, but
// JSON has no undefined, so only absence and the right type are modeled.
func optStr(m map[string]interface{}, key string, maxUTF16 int) bool {
	v, present := m[key]
	if !present {
		return true
	}
	s, ok := v.(string)
	return ok && utf16Len(s) <= maxUTF16
}

func inEnum(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// optStrArray validates an optional array of strings, at most maxLen entries,
// each at most maxUTF16 code units. Absent is valid; a present non-array or a
// non-string element fails.
func optStrArray(m map[string]interface{}, key string, maxLen, maxUTF16 int) bool {
	v, present := m[key]
	if !present {
		return true
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) > maxLen {
		return false
	}
	for _, e := range arr {
		s, ok := e.(string)
		if !ok || utf16Len(s) > maxUTF16 {
			return false
		}
	}
	return true
}

func base(m map[string]interface{}, suffix string) bool {
	if p, ok := hsString(m, "protocol"); !ok || p != "ink/0.1" {
		return false
	}
	if t, ok := hsString(m, "type"); !ok || !dualWireType(t, suffix) {
		return false
	}
	if !reqStr(m, "intentRef", 256) {
		return false
	}
	if !reqStr(m, "nonce", 256) {
		return false
	}
	ts, ok := hsString(m, "timestamp")
	return ok && isHandshakeDatetime(ts)
}

// ValidateInkChallenge validates a network.tulpa.challenge message
// (InkChallengeSchema). It returns true iff the reference Zod schema would
// accept the same object. Unknown top-level keys are ignored, matching Zod's
// default strip behavior.
func ValidateInkChallenge(m map[string]interface{}) bool {
	if !base(m, "challenge") {
		return false
	}
	ct, ok := hsString(m, "challengeType")
	if !ok || !inEnum(ct, "mutual_connection_proof", "identity_verification", "availability_query", "context_request", "none") {
		return false
	}
	return optStrArray(m, "fields", 32, 256) &&
		optStrArray(m, "availableWindows", 32, 64) &&
		optStrArray(m, "contextFields", 32, 256)
}

// ValidateInkRejection validates a network.tulpa.rejection message
// (InkRejectionSchema).
func ValidateInkRejection(m map[string]interface{}) bool {
	if !base(m, "rejection") {
		return false
	}
	reason, ok := hsString(m, "reason")
	if !ok || !inEnum(reason,
		"policy_violation", "trust_threshold", "capacity", "unsupported_intent", "rate_limited", "expired",
		"handshake_budget_exhausted", "counterparty_cooldown", "sender_rate_limited", "delegation_budget_exhausted", "transport_scope_violation") {
		return false
	}
	if !optStr(m, "detail", 500) || !optStr(m, "retryAfter", 64) {
		return false
	}
	if bh, present := m["backoffHint"]; present {
		hint, ok := bh.(map[string]interface{})
		if !ok || !validateBackoffHint(hint) {
			return false
		}
	}
	return true
}

func validateBackoffHint(m map[string]interface{}) bool {
	if v, present := m["retryAfterSeconds"]; present {
		// Zod z.number().int().positive() also rejects values outside the JS
		// safe-integer range, so cap at 2^53-1 to match.
		f, ok := v.(float64)
		if !ok || f != float64(int64(f)) || f <= 0 || f > maxSafeInteger {
			return false
		}
	}
	if v, present := m["cooldownUntil"]; present {
		s, ok := v.(string)
		if !ok || !isHandshakeDatetime(s) {
			return false
		}
	}
	if v, present := m["backoffClass"]; present {
		s, ok := v.(string)
		if !ok || !inEnum(s, "sender", "intent_ref", "counterparty") {
			return false
		}
	}
	return true
}

// ValidateInkResolution validates a network.tulpa.resolution message
// (InkResolutionSchema).
func ValidateInkResolution(m map[string]interface{}) bool {
	if !base(m, "resolution") {
		return false
	}
	outcome, ok := hsString(m, "outcome")
	if !ok || !inEnum(outcome, "accepted", "declined", "escalated_to_human", "expired") {
		return false
	}
	if !optStr(m, "counterpartyDid", 512) {
		return false
	}
	if d, present := m["details"]; present {
		details, ok := d.(map[string]interface{})
		if !ok {
			return false
		}
		// ResolutionDetails is .passthrough(): unknown keys allowed; the two
		// known keys are optional strings with caps.
		if !optStr(details, "scheduledAt", 64) || !optStr(details, "duration", 64) {
			return false
		}
	}
	return true
}

// ValidateHandshakeMessage dispatches on the message type and validates the
// matching handshake schema. An unknown or missing type is rejected.
func ValidateHandshakeMessage(m map[string]interface{}) bool {
	t, ok := hsString(m, "type")
	if !ok {
		return false
	}
	switch t {
	case "network.tulpa.challenge", "network.ink.challenge":
		return ValidateInkChallenge(m)
	case "network.tulpa.rejection", "network.ink.rejection":
		return ValidateInkRejection(m)
	case "network.tulpa.resolution", "network.ink.resolution":
		return ValidateInkResolution(m)
	default:
		return false
	}
}
