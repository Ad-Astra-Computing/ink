package ink

import (
	"math"
	"testing"
)

// canonicalizeNumber implements INK's safe-integer profile. These cases pin the
// exact accept/reject boundary and the emitted bytes, which must match the
// reference (ECMAScript String(n)) for every accepted value.
func TestCanonicalizeNumber(t *testing.T) {
	accept := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{42, "42"},
		{-7, "-7"},
		{100, "100"},
		{maxSafeInteger, "9007199254740991"},
		{-maxSafeInteger, "-9007199254740991"},
	}
	for _, c := range accept {
		got, err := canonicalizeNumber(c.in)
		if err != nil {
			t.Errorf("canonicalizeNumber(%v) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("canonicalizeNumber(%v) = %q, want %q", c.in, got, c.want)
		}
	}

	reject := []float64{
		1.5,
		-123.25,
		math.Inf(1),
		math.Inf(-1),
		math.NaN(),
		maxSafeInteger + 1,
		-maxSafeInteger - 1,
		1e21,
		math.Copysign(0, -1), // negative zero
	}
	for _, v := range reject {
		if got, err := canonicalizeNumber(v); err == nil {
			t.Errorf("canonicalizeNumber(%v) = %q, want error", v, got)
		}
	}
}

// A Go caller may build a body with native integer types rather than the float64
// encoding/json produces. canonicalizeJSON must accept them under the same
// safe-integer profile and emit the same bytes the reference does for 42 vs 42.0,
// so a Go-originated signed body matches a wire-parsed one.
func TestCanonicalizeJSONNativeIntegers(t *testing.T) {
	accept := []struct {
		in   interface{}
		want string
	}{
		{int(42), "42"},
		{int(-7), "-7"},
		{int8(-128), "-128"},
		{int16(1000), "1000"},
		{int32(-2000000000), "-2000000000"},
		{int64(maxSafeInteger), "9007199254740991"},
		{int64(-maxSafeInteger), "-9007199254740991"},
		{uint(0), "0"},
		{uint8(255), "255"},
		{uint64(maxSafeInteger), "9007199254740991"},
	}
	for _, c := range accept {
		got, err := canonicalizeJSON(c.in)
		if err != nil {
			t.Errorf("canonicalizeJSON(%v) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("canonicalizeJSON(%v) = %q, want %q", c.in, got, c.want)
		}
	}

	reject := []interface{}{
		int64(maxSafeInteger + 1),
		int64(-maxSafeInteger - 1),
		uint64(maxSafeInteger + 1),
		int64(math.MaxInt64),
		int64(math.MinInt64),
		uint64(math.MaxUint64),
	}
	for _, v := range reject {
		if got, err := canonicalizeJSON(v); err == nil {
			t.Errorf("canonicalizeJSON(%v) = %q, want error", v, got)
		}
	}
}
