package ink

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const hexDigits = "0123456789abcdef"

// maxSafeInteger is 2^53 - 1, the largest integer that round-trips exactly
// through an IEEE-754 double, matching JavaScript's Number.MAX_SAFE_INTEGER.
const maxSafeInteger = 9007199254740991

// canonicalizeJSON serializes a decoded JSON value to its RFC 8785 (JCS)
// canonical form: object members sorted by UTF-16 code unit, no insignificant
// whitespace, minimal string escaping. Numbers are restricted to the safe-integer
// profile (see canonicalizeNumber); a fraction, an out-of-range magnitude, or a
// negative zero is an error rather than a silently divergent serialization.
//
// encoding/json decodes every JSON number to float64, so a body parsed from the
// wire only ever reaches the float64 case. A Go caller may also construct a body
// in memory with native integer types, so those are accepted under the same
// safe-integer profile and canonicalize identically; the reference treats 42 and
// 42.0 alike, and so must this implementation.
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
			// A member name that needs escaping is refused here, in the one
			// place every canonicalization path passes through, rather than at
			// each entry point. Guarding only the wrappers left the exported
			// transport, audit and card paths calling canonicalizeJSON directly
			// and therefore unguarded, which is how the reference and this
			// implementation came to disagree about what could be signed.
			// Checking inside the key loop keeps it O(n) over the whole value.
			if keyRequiresEscape(k) {
				return "", errors.New("ink: object key contains a quote, backslash or control character")
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
	case float64:
		return canonicalizeNumber(x)
	case int:
		return canonicalizeInt64(int64(x))
	case int8:
		return canonicalizeInt64(int64(x))
	case int16:
		return canonicalizeInt64(int64(x))
	case int32:
		return canonicalizeInt64(int64(x))
	case int64:
		return canonicalizeInt64(x)
	case uint:
		return canonicalizeUint64(uint64(x))
	case uint8:
		return canonicalizeUint64(uint64(x))
	case uint16:
		return canonicalizeUint64(uint64(x))
	case uint32:
		return canonicalizeUint64(uint64(x))
	case uint64:
		return canonicalizeUint64(x)
	default:
		return "", errors.New("unsupported JSON type in canonicalization")
	}
}

// canonicalizeNumber serializes a JSON number under INK's safe-integer profile:
// a value with no fractional part in |v| <= 2^53-1, not negative zero, not Inf
// or NaN, emitted as a plain base-10 integer. encoding/json decodes every JSON
// number to float64, so this is the only numeric case. Fractions, out-of-range
// magnitudes (which would otherwise serialize in exponential notation), and
// negative zero are rejected so the bytes match the reference exactly. The
// profile is on the decoded value, not the JSON token, so 1e2 (decoded to 100)
// canonicalizes to "100".
func canonicalizeNumber(v float64) (string, error) {
	if math.IsInf(v, 0) || math.IsNaN(v) ||
		v != math.Trunc(v) ||
		math.Abs(v) > maxSafeInteger ||
		(v == 0 && math.Signbit(v)) {
		return "", errors.New("number is not a JCS-safe integer")
	}
	return strconv.FormatInt(int64(v), 10), nil
}

// canonicalizeInt64 serializes a native Go signed integer under the same
// safe-integer profile as canonicalizeNumber. Working in int64 avoids the float64
// precision loss a large integer would suffer, so the range check is exact.
func canonicalizeInt64(v int64) (string, error) {
	if v < -maxSafeInteger || v > maxSafeInteger {
		return "", errors.New("number is not a JCS-safe integer")
	}
	return strconv.FormatInt(v, 10), nil
}

// canonicalizeUint64 serializes a native Go unsigned integer under the
// safe-integer profile; a value above 2^53-1 is out of range and rejected.
func canonicalizeUint64(v uint64) (string, error) {
	if v > maxSafeInteger {
		return "", errors.New("number is not a JCS-safe integer")
	}
	return strconv.FormatUint(v, 10), nil
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
