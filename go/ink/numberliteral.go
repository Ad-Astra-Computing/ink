package ink

import (
	"math"
	"strconv"
)

// ContainsOutOfRangeNumberLiteral reports whether raw JSON text contains a
// number literal whose value is outside the IEEE-754 double range. A signed
// body must be rejected when this is true.
//
// A literal such as 1e309 is not portable across JSON parsers: ECMAScript's
// JSON.parse decodes it to Infinity and returns the document, while
// encoding/json refuses the document with a range error. INK's number profile
// is a check on decoded values, so it catches an Infinity that reaches
// canonicalization but never sees a literal that a later duplicate member
// shadows, because JSON member semantics are last-wins. The check therefore
// runs on the raw text, alongside the UTF-8 and lone-surrogate gates, so the
// admitted set is a property of the protocol rather than of whichever parser an
// implementation happens to use. Go rejects the same bodies through
// encoding/json today; running the scan explicitly keeps the rule and its
// ordering visible instead of inherited.
//
// This is a byte-level scanner, not encoding/json: it tracks whether it is
// inside a JSON string (where a backslash escapes the next byte, so number-like
// text in a string is never a token), reads a maximal run of number characters
// outside one, and evaluates that run as a double. A run that is not a number
// at all is left alone; the JSON parser rejects it on its own. A run that
// underflows to zero (1e-400) is in range, because every IEEE-754 parser
// decodes it to 0 and the implementations already agree on it.
func ContainsOutOfRangeNumberLiteral(raw []byte) bool {
	inString := false
	n := len(raw)
	for i := 0; i < n; {
		c := raw[i]
		if inString {
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		if c == '"' {
			inString = true
			i++
			continue
		}
		if !isNumberStartByte(c) {
			i++
			continue
		}
		j := i + 1
		for j < n && isNumberByte(raw[j]) {
			j++
		}
		// ParseFloat returns ±Inf with ErrRange for an out-of-range magnitude,
		// the nearest representable value (0) for an underflow, and 0 for a
		// syntax error, so IsInf on the returned value is exactly the range
		// test and a malformed run falls through to the JSON parser.
		if v, _ := strconv.ParseFloat(string(raw[i:j]), 64); math.IsInf(v, 0) {
			return true
		}
		i = j
	}
	return false
}

// isNumberByte reports whether b may appear inside a JSON number token.
func isNumberByte(b byte) bool {
	return (b >= '0' && b <= '9') || b == '-' || b == '+' || b == '.' || b == 'e' || b == 'E'
}

// isNumberStartByte reports whether b may begin a JSON number token.
func isNumberStartByte(b byte) bool {
	return (b >= '0' && b <= '9') || b == '-'
}
