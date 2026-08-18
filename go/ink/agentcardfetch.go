package ink

import (
	"strconv"
	"strings"
)

// MaxAgentCardBytes is the Agent Card discovery body cap, by Content-Length and
// by actual decoded bytes.
const MaxAgentCardBytes = 64 * 1024

// EvaluateAgentCardFetch pins the Agent Card discovery RESPONSE-handling
// contract, mirroring the TypeScript evaluateAgentCardFetch. Given synthetic
// response metadata it decides whether the response yields a valid Agent Card
// bound to the requested agentId. The request-side SSRF gate and card-content
// host checks are intentionally NOT part of this contract (see the spec).
//
//  1. status MUST be exactly 200.
//  2. A base-10 non-negative Content-Length over the cap rejects; a non-canonical
//     or absent value is not decided on here.
//  3. Content-Type MUST be single-valued application/json (case-insensitive); a
//     charset parameter, when present, MUST be utf-8.
//  4. The body's UTF-8 byte length MUST NOT exceed the cap.
//  5. The body MUST parse as a JSON object.
//  6. It MUST satisfy the Agent Card schema.
//  7. protocol MUST be "ink/0.1".
//  8. agentId MUST equal the requested agentId.
//  9. When resolutionDID is non-nil and the card carries an ownerDid, ownerDid
//     MUST equal resolutionDID (owner anti-substitution).
//
// resolutionDID is the owner's DID, set only when the resolution began at an
// owner's DID document and followed it to this card. Every other caller passes
// nil, including one that reached the card through the agent's own DID
// document. Passing an agent identifier rejects every card whose owner and
// agent differ.
func EvaluateAgentCardFetch(status int, contentType *string, contentLength *string, bodyRaw string, requestedAgentID string, resolutionDID *string) bool {
	// 1. Status.
	if status != 200 {
		return false
	}

	// 2. Declared length.
	if contentLengthExceedsCap(contentLength) {
		return false
	}

	// 3. Content-Type.
	if !isJSONContentType(contentType) {
		return false
	}

	// 4. Actual body size. len() of a Go string is its UTF-8 byte length.
	if len(bodyRaw) > MaxAgentCardBytes {
		return false
	}

	// 5. JSON parse; must be an object. The card carries a signature verified
	//    over its canonical form, so it is signature-relevant and goes through
	//    the shared signed-artifact parser rather than a bare json.Unmarshal.
	card, ok := ParseSignedObject([]byte(bodyRaw))
	if !ok {
		return false
	}

	// 6. Schema.
	if !ValidateAgentCard(card) {
		return false
	}

	// 7. Protocol literal (also enforced by the schema; explicit for the contract).
	if proto, _ := card["protocol"].(string); proto != "ink/0.1" {
		return false
	}

	// 8. Identity binding.
	if aid, _ := card["agentId"].(string); aid != requestedAgentID {
		return false
	}

	// 9. Owner anti-substitution. Byte for byte, no canonicalization, and only
	// when the fetch was mediated by a DID and the card actually carries an
	// ownerDid. Passing proves the card names the DID it was reached through,
	// never that the owner consented to the agent: ownerDid is self-asserted.
	if resolutionDID != nil {
		if owner, present := card["ownerDid"]; present {
			if s, _ := owner.(string); s != *resolutionDID {
				return false
			}
		}
	}

	return true
}

// contentLengthExceedsCap reports whether a Content-Length header declares a
// size over the cap. The comparison is on the digit string itself, not a parsed
// integer, so a value larger than int64 still classifies identically to the
// TypeScript evaluator (a strconv.ParseInt would overflow and diverge).
func contentLengthExceedsCap(header *string) bool {
	if header == nil {
		return false
	}
	t := strings.TrimSpace(*header)
	if !isAllDigits(t) {
		return false
	}
	return digitsGreaterThan(t, strconv.Itoa(MaxAgentCardBytes))
}

// digitsGreaterThan compares two non-empty ASCII decimal digit strings
// numerically without parsing them into a bounded integer.
func digitsGreaterThan(value, cap string) bool {
	v := strings.TrimLeft(value, "0")
	if v == "" {
		v = "0"
	}
	if len(v) != len(cap) {
		return len(v) > len(cap)
	}
	return v > cap
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isJSONContentType reports whether the header names exactly the application/json
// media type with no ambiguity. Rejects absent, empty, a value carrying a comma
// (a combined or duplicated header), a non-json media type, or a non-utf-8
// charset parameter.
func isJSONContentType(value *string) bool {
	if value == nil {
		return false
	}
	header := strings.TrimSpace(*value)
	if header == "" {
		return false
	}
	if strings.Contains(header, ",") {
		return false
	}
	parts := strings.Split(header, ";")
	mediaType := strings.ToLower(strings.TrimSpace(parts[0]))
	if mediaType != "application/json" {
		return false
	}
	for _, p := range parts[1:] {
		param := strings.TrimSpace(p)
		if param == "" {
			continue
		}
		eq := strings.Index(param, "=")
		if eq == -1 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(param[:eq]))
		if name == "charset" {
			charset := strings.ToLower(strings.TrimSpace(param[eq+1:]))
			if len(charset) >= 2 && strings.HasPrefix(charset, `"`) && strings.HasSuffix(charset, `"`) {
				charset = charset[1 : len(charset)-1]
			}
			if charset != "utf-8" {
				return false
			}
		}
	}
	return true
}
