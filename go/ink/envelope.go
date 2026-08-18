package ink

import "regexp"

// Scalar caps for the intent envelope, measured in UTF-16 code units to match
// the reference (Protocol §3.1 states the bounds are UTF-16 code units, and
// MessageEnvelopeSchema in src/models/intent.ts enforces them through
// JavaScript's String.length).
const (
	envelopeIDMax        = 256
	envelopeDIDMax       = 512
	envelopeTimestampMax = 64
	envelopeSignatureMax = 256
	envelopeKeyIDMax     = 128
)

// envelopeIntentTypes is the allocated intent set (§6 registry, mirrored from
// IntentTypeSchema). An intent outside it is rejected, never inferred.
var envelopeIntentTypes = map[string]bool{
	"schedule_meeting":          true,
	"schedule_meeting_response": true,
	"intro_request":             true,
	"intro_response":            true,
	"opportunity":               true,
	"opportunity_response":      true,
	"follow_up":                 true,
	"ask":                       true,
	"ask_response":              true,
	"connection_request":        true,
	"connection_response":       true,
	"context_share":             true,
	"ping":                      true,
	"retract":                   true,
	"multi_party_sync":          true,
}

// envelopeProvenanceOrigins is the closed origin set of the optional
// `provenance` member.
var envelopeProvenanceOrigins = map[string]bool{
	"human":            true,
	"agent_approved":   true,
	"agent_autonomous": true,
}

var envelopeUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateMessageEnvelope reports whether a decoded object is a valid INK intent
// envelope under Protocol §3.1. The envelope is a STRICT surface: `protocol`,
// `id`, `correlationId`, `createdAt`, `from`, `to`, `intent` and `signature` are
// all required, every scalar is capped in UTF-16 code units, `protocol` and
// `intent` are closed sets, and an unknown top-level member is rejected rather
// than ignored (ink-compatibility-policy.md §3.1).
//
// A receiver runs this BEFORE it spends signature work, so a malformed envelope
// costs a schema walk and not a curve operation. It mirrors MessageEnvelopeSchema
// in the reference, including its treatment of `payload`: the schema declares the
// member without constraining its type, so this function does not require or
// type-check it either. The intent-specific payload schema is a separate check
// (ValidateConnectionPayload and friends), exactly as validateMessage layers the
// two in the reference.
func ValidateMessageEnvelope(m map[string]interface{}) bool {
	if m == nil {
		return false
	}
	for k := range m {
		switch k {
		case "protocol", "id", "correlationId", "createdAt", "expiresAt", "from", "to",
			"intent", "payload", "signature", "signingKeyId", "timestamp", "nonce", "provenance":
		default:
			return false // strict surface: an unknown top-level member rejects
		}
	}

	protocol, ok := m["protocol"].(string)
	if !ok || (protocol != "ink/0.1" && protocol != "ink/0.2") {
		return false
	}
	intent, ok := m["intent"].(string)
	if !ok || !envelopeIntentTypes[intent] {
		return false
	}
	required := []struct {
		key string
		max int
	}{
		{"id", envelopeIDMax},
		{"correlationId", envelopeIDMax},
		{"createdAt", envelopeTimestampMax},
		{"from", envelopeDIDMax},
		{"to", envelopeDIDMax},
		{"signature", envelopeSignatureMax},
	}
	for _, r := range required {
		s, ok := m[r.key].(string)
		if !ok || utf16Len(s) > r.max {
			return false
		}
	}
	optional := []struct {
		key string
		max int
	}{
		{"expiresAt", envelopeTimestampMax},
		{"signingKeyId", envelopeKeyIDMax},
		{"timestamp", envelopeTimestampMax},
		{"nonce", envelopeIDMax},
	}
	for _, o := range optional {
		v, present := m[o.key]
		if !present {
			continue
		}
		s, ok := v.(string)
		if !ok || utf16Len(s) > o.max {
			return false
		}
	}
	if v, present := m["provenance"]; present {
		if !validateEnvelopeProvenance(v) {
			return false
		}
	}
	return true
}

// validateEnvelopeProvenance checks the optional origin-metadata member, a
// strict object of exactly {origin, extensionId, installationId}.
func validateEnvelopeProvenance(v interface{}) bool {
	p, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	for k := range p {
		switch k {
		case "origin", "extensionId", "installationId":
		default:
			return false
		}
	}
	origin, ok := p["origin"].(string)
	if !ok || !envelopeProvenanceOrigins[origin] {
		return false
	}
	extensionID, ok := p["extensionId"].(string)
	if !ok || utf16Len(extensionID) > envelopeIDMax {
		return false
	}
	installationID, ok := p["installationId"].(string)
	if !ok || !envelopeUUIDRe.MatchString(installationID) {
		return false
	}
	return true
}
