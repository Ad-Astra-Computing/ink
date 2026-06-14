package ink

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf16"
)

const hexDigits = "0123456789abcdef"

// canonicalizeJSON serializes a decoded JSON value to its RFC 8785 (JCS)
// canonical form: object members sorted by UTF-16 code unit, no insignificant
// whitespace, minimal string escaping. Numbers are out of scope for v1: INK
// signed bodies are strings and small integers, and the conformance signed
// envelopes contain no numbers, so a number here is an error rather than a
// silently divergent serialization.
func canonicalizeJSON(v interface{}) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return canonicalizeString(x), nil
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(canonicalizeString(k))
			sb.WriteByte(':')
			val, err := canonicalizeJSON(x[k])
			if err != nil {
				return "", err
			}
			sb.WriteString(val)
		}
		sb.WriteByte('}')
		return sb.String(), nil
	case []interface{}:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			val, err := canonicalizeJSON(e)
			if err != nil {
				return "", err
			}
			sb.WriteString(val)
		}
		sb.WriteByte(']')
		return sb.String(), nil
	default:
		return "", errors.New("unsupported JSON type in canonicalization (numbers are out of scope for v1)")
	}
}

// canonicalizeString emits a JSON string with the minimal escaping RFC 8785
// requires: the quote, the backslash, the short control escapes, and any other
// control character below U+0020 as \u00XX. No HTML or U+2028/U+2029 escaping.
func canonicalizeString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\t':
			sb.WriteString(`\t`)
		case '\n':
			sb.WriteString(`\n`)
		case '\f':
			sb.WriteString(`\f`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexDigits[(r>>4)&0xf])
				sb.WriteByte(hexDigits[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// utf16Less compares two strings as sequences of UTF-16 code units, the
// ordering RFC 8785 specifies for object member sorting.
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
