package ink

// Escaped-member-name detection for signed INK bodies.
//
// V8 returns a wrong property key from JSON.parse when an object member name is
// written with an escape sequence: GetKeyChars in V8's JSON parser builds a
// character span from a pointer into the raw source but sizes it with the
// decoded length, and the hidden-class transition matcher then reuses a
// matching transition's name as the property key without decoding the escape.
// Go's encoding/json is unaffected. That asymmetry is the problem: without this
// rule a Go receiver and a receiver on Node 24+ or Cloudflare workerd would
// canonicalize different bytes for the same signed document and reach opposite
// verify results.
//
// Go therefore enforces the rule it does not need, so the admitted set is a
// property of the protocol rather than of whichever parser an implementation
// happens to use. This mirrors ContainsOutOfRangeNumberLiteral, which Go also
// enforces explicitly despite encoding/json already rejecting those bodies.
//
// See specs/ink-signed-string-safety.md §5.

// ContainsEscapedMemberName reports whether raw JSON text contains an object
// member name written with any escape sequence. A signed body must be rejected
// when this is true.
//
// A string is a member name exactly when the next non-whitespace byte after its
// closing quote is a colon, which is precise for well-formed JSON. Text this
// misreads is malformed and fails the subsequent unmarshal, so a misread cannot
// admit a body. The scan never decodes an escape; it only records that one
// occurred.
func ContainsEscapedMemberName(raw []byte) bool {
	n := len(raw)
	for i := 0; i < n; i++ {
		if raw[i] != '"' {
			continue
		}

		sawEscape := false
		j := i + 1
		for ; j < n; j++ {
			c := raw[j]
			if c == '\\' {
				// A backslash consumes the next byte, so an escaped quote is
				// not a terminator. \uXXXX needs no special case: the hex
				// digits cannot terminate the string.
				sawEscape = true
				j++
				continue
			}
			if c == '"' {
				break
			}
		}
		if j >= n {
			return false // unterminated string; the parser will reject it
		}

		if sawEscape {
			k := j + 1
			for k < n {
				w := raw[k]
				if w == ' ' || w == '\t' || w == '\n' || w == '\r' {
					k++
					continue
				}
				break
			}
			if k < n && raw[k] == ':' {
				return true
			}
		}

		i = j // resume after the closing quote
	}
	return false
}

// keyRequiresEscape reports whether a string would have to be escaped to appear
// as a JSON member name. RFC 8785 serializes with minimal JSON escaping, so
// exactly a quote, a backslash and U+0000-U+001F force an escape. U+007F is not
// escaped and is therefore safe.
func keyRequiresEscape(key string) bool {
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c == '"' || c == '\\' || c < 0x20 {
			return true
		}
	}
	return false
}

// HasUnsafeObjectKey reports whether a parsed value contains an object key that
// would serialize as an escaped member name. Used on the producer side, where
// the body is a value rather than raw text: such a key produces bytes a
// receiver rejects, so signing it would emit a body nobody can verify.
func HasUnsafeObjectKey(value interface{}) bool {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if keyRequiresEscape(key) {
				return true
			}
			if HasUnsafeObjectKey(val) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if HasUnsafeObjectKey(item) {
				return true
			}
		}
	}
	return false
}
