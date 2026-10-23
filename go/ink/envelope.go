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

// RegisteredIntents are the intents this implementation ships a payload
// schema for (Protocol §3.1.1), not the full set a receiver may accept: an
// intent is well-formed as any bare or vendor token, registered or not.
var RegisteredIntents = []string{
	"schedule_meeting",
	"schedule_meeting_response",
	"intro_request",
	"intro_response",
	"opportunity",
	"opportunity_response",
	"follow_up",
	"ask",
	"ask_response",
	"connection_request",
	"connection_response",
	"context_share",
	"ping",
	"retract",
	"multi_party_sync",
}

// CoreIntents are the two intents every conformant implementation MUST
// handle, since first contact depends on them. Every other registered or
// vendor intent is optional.
var CoreIntents = []string{"connection_request", "connection_response"}

// bareIntentRe matches a registered-shape bare intent token: a letter, then
// up to 62 more letters, digits or `_` (63 chars total, the same cap a DNS
// label uses). It never contains a dot.
var bareIntentRe = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,62}\z`)

// vendorIntentRe matches a vendor-shape reverse-domain intent token: at
// least two labels separated by dots, each 1-63 chars of [a-z0-9], - or _,
// not starting or ending with - or _. A single label with no dot (for
// example "com") is a well-formed, unregistered BARE token under
// bareIntentRe, not a vendor token.
var vendorLabel = `[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?`
var vendorIntentRe = regexp.MustCompile(`\A` + vendorLabel + `(?:\.` + vendorLabel + `)+\z`)

// intentMax is the total length cap for either intent form, in UTF-16 code
// units. Both grammars are pure ASCII, so this is also a byte and code-point
// count.
const intentMax = 253

// IsWellFormedIntent reports whether intent matches either grammar
// (Protocol §3.1.1); support is a separate, application-level decision
// (CheckIntentDisposition). Exact string match: no case folding, no
// trimming, no Unicode normalization.
func IsWellFormedIntent(intent string) bool {
	if len(intent) == 0 || len(intent) > intentMax {
		return false
	}
	return bareIntentRe.MatchString(intent) || vendorIntentRe.MatchString(intent)
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
// all required, every scalar is capped in UTF-16 code units, `protocol` is a
// closed set, `intent` is the open §3.1.1 grammar (a registered bare token or a
// vendor reverse-domain token, not a closed enum), and an unknown top-level
// member is rejected rather than ignored (ink-compatibility-policy.md §3.1).
//
// A receiver runs this BEFORE signature work. It mirrors validateEnvelope
// in the reference: `payload` must be a JSON object for every intent, and
// the intent-specific payload schema is a separate, later check, run only
// once CheckIntentDisposition has decided the caller supports the intent.
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
	if !ok || !IsWellFormedIntent(intent) {
		return false
	}
	// `payload` is a required JSON object for every intent, registered or
	// not: json.Unmarshal decodes a JSON object to map[string]interface{}
	// and a JSON array to []interface{}, so this also rejects an array or
	// any scalar payload.
	if _, ok := m["payload"].(map[string]interface{}); !ok {
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
	// The loops above bound individual scalars, not the canonical byte size
	// of the whole signature-stripped body. Apply JCSCanonicalize's ceiling
	// here too, so an oversized envelope is refused before signature work.
	unsigned := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}
	if _, err := JCSCanonicalize(unsigned); err != nil {
		return false
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
