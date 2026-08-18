package ink

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// ParseSignedBody validates and parses a raw JSON signed body. It rejects raw
// invalid UTF-8, a lone UTF-16 surrogate escape, a number literal outside the
// IEEE-754 double range, and an object member name written with an escape
// sequence, all before unmarshaling. The first two matter because
// encoding/json would otherwise silently rewrite either to U+FFFD and the body
// that reaches VerifyInkSignature would differ from the one the signer signed.
// The third matters because parsers disagree about it outright: JSON.parse
// decodes 1e309 to Infinity and returns the document, encoding/json refuses it,
// so the rule is enforced here rather than left to the parser. The fourth
// matters in the other direction: encoding/json decodes escaped member names
// correctly, so Go enforces a rule it does not itself need, in order to admit
// the same set of bodies as an implementation running on an affected V8.
// A receiver MUST parse a signed body through this rather than json.Unmarshal
// directly; VerifyInkSignature takes an already-parsed body and cannot recover
// dropped bytes on its own.
func ParseSignedBody(rawBody []byte) (interface{}, error) {
	if !utf8.Valid(rawBody) {
		return nil, errors.New("signed body is not valid UTF-8")
	}
	if ContainsLoneSurrogateEscape(rawBody) {
		return nil, errors.New("signed body contains an unpaired UTF-16 surrogate")
	}
	if ContainsOutOfRangeNumberLiteral(rawBody) {
		return nil, errors.New("signed body contains a number literal outside the IEEE-754 double range")
	}
	if ContainsEscapedMemberName(rawBody) {
		return nil, errors.New("signed body contains an object member name written with an escape sequence")
	}
	var body interface{}
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return nil, err
	}
	return body, nil
}

// ContainsLoneSurrogateEscape reports whether raw JSON text contains a \uXXXX
// escape for an unpaired UTF-16 surrogate inside any JSON string. A signed body
// must be rejected when this is true: encoding/json silently replaces a lone
// surrogate with U+FFFD at parse time, so a body that reached canonicalization
// would be signed over different bytes than an implementation that preserves
// the surrogate, a cross-implementation consensus hazard.
//
// This is a deliberate byte-level scanner, not encoding/json, utf16, or
// strconv: those normalize, which would defeat the check. It tracks whether it
// is inside a JSON string, treats a backslash as escaping the next byte (so a
// literal "\\uD800" is two characters, never a Unicode escape), reads exactly
// four hex digits, and requires a high surrogate (D800..DBFF) to be immediately
// followed by a low surrogate (DC00..DFFF) escape. A low surrogate with no
// preceding high, or a high with no following low, is unpaired.
func ContainsLoneSurrogateEscape(raw []byte) bool {
	inString := false
	n := len(raw)
	for i := 0; i < n; {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		if c == '"' {
			inString = false
			i++
			continue
		}
		if c != '\\' {
			i++
			continue
		}
		// Escape sequence inside a string.
		if i+1 >= n {
			return false // truncated escape; invalid JSON, not our concern
		}
		if raw[i+1] != 'u' {
			i += 2 // \\, \", \n, etc. — consume the escaped byte
			continue
		}
		hi, ok := parseHex4(raw, i+2)
		if !ok {
			i += 2 // malformed \u escape; the JSON parser will reject it
			continue
		}
		if hi >= 0xDC00 && hi <= 0xDFFF {
			return true // lone low surrogate
		}
		if hi >= 0xD800 && hi <= 0xDBFF {
			j := i + 6 // byte after this \uXXXX
			if j+1 < n && raw[j] == '\\' && raw[j+1] == 'u' {
				if lo, ok2 := parseHex4(raw, j+2); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
					i = j + 6 // valid pair: skip both escapes
					continue
				}
			}
			return true // high surrogate not immediately followed by a low
		}
		i += 6 // ordinary \uXXXX
	}
	return false
}

// parseHex4 reads exactly four hex digits at idx, returning the value and
// whether all four were valid hex. Accepts upper and lower case.
func parseHex4(b []byte, idx int) (int, bool) {
	if idx+4 > len(b) {
		return 0, false
	}
	v := 0
	for k := 0; k < 4; k++ {
		d := b[idx+k]
		v <<= 4
		switch {
		case d >= '0' && d <= '9':
			v |= int(d - '0')
		case d >= 'a' && d <= 'f':
			v |= int(d-'a') + 10
		case d >= 'A' && d <= 'F':
			v |= int(d-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// ParseSignedObject is ParseSignedBody for a caller that requires a JSON object
// at the root, which every signed INK artifact does. It exists so the four
// text-level rules live in exactly one place: a verifier that inlined its own
// subset fell behind when a rule was added, and Go then admitted artifacts the
// reference rejected.
func ParseSignedObject(raw []byte) (map[string]interface{}, bool) {
	v, err := ParseSignedBody(raw)
	if err != nil {
		return nil, false
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	return obj, true
}
