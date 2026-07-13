package ink

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOptionalTimestampUnmarshal(t *testing.T) {
	cases := []struct {
		json       string
		present    bool
		wellFormed bool
		value      string
	}{
		{`"2026-06-11T00:00:00Z"`, true, true, "2026-06-11T00:00:00Z"},
		{`""`, true, true, ""},
		{`null`, true, false, ""},
		{`0`, true, false, ""},
		{`true`, true, false, ""},
		{`{}`, true, false, ""},
		{`[]`, true, false, ""},
	}
	for _, c := range cases {
		var o OptionalTimestamp
		if err := json.Unmarshal([]byte(c.json), &o); err != nil {
			t.Errorf("%s: unexpected error %v", c.json, err)
			continue
		}
		if o.Present != c.present || o.WellFormed != c.wellFormed || o.Value != c.value {
			t.Errorf("%s: got {present:%v wellFormed:%v value:%q}, want {present:%v wellFormed:%v value:%q}",
				c.json, o.Present, o.WellFormed, o.Value, c.present, c.wellFormed, c.value)
		}
	}

	// An absent field leaves the zero value.
	var absent struct {
		ValidFrom OptionalTimestamp `json:"validFrom"`
	}
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if absent.ValidFrom.Present {
		t.Errorf("absent field was marked present")
	}

	// Reuse must not carry stale Value/WellFormed: decoding null after a string
	// has to reset to present-but-not-well-formed.
	var reused OptionalTimestamp
	if err := json.Unmarshal([]byte(`"2026-06-11T00:00:00Z"`), &reused); err != nil {
		t.Fatalf("reuse seed: %v", err)
	}
	if err := json.Unmarshal([]byte(`null`), &reused); err != nil {
		t.Fatalf("reuse null: %v", err)
	}
	if reused.WellFormed || reused.Value != "" {
		t.Errorf("stale state survived reuse: got {wellFormed:%v value:%q}", reused.WellFormed, reused.Value)
	}

	// The supported decode pattern is a fresh destination per key entry, the way
	// the conformance runner decodes each case. An absent field then reads as
	// absent even after a previous entry set it, because encoding/json cannot
	// clear an absent field on a reused destination.
	type entry struct {
		ValidUntil OptionalTimestamp `json:"validUntil"`
	}
	var withWindow entry
	if err := json.Unmarshal([]byte(`{"validUntil":"2026-06-11T00:00:00Z"}`), &withWindow); err != nil {
		t.Fatalf("present window: %v", err)
	}
	if !withWindow.ValidUntil.Present {
		t.Errorf("present validUntil read as absent")
	}
	var noWindow entry
	if err := json.Unmarshal([]byte(`{}`), &noWindow); err != nil {
		t.Fatalf("absent window: %v", err)
	}
	if noWindow.ValidUntil.Present {
		t.Errorf("absent validUntil read as present on a fresh destination")
	}
}

// TestOptionalTimestampUnmarshalRejectsOversizedToken pins the byte cap on the
// raw timestamp token. The cap sits above the worst-case encoding of the longest
// well-formed timestamp, so it rejects only tokens that cannot decode to any
// valid RFC 3339 bound.
func TestOptionalTimestampUnmarshalRejectsOversizedToken(t *testing.T) {
	if maxTimestampTokenBytes != 512 {
		t.Errorf("maxTimestampTokenBytes: got %d, want 512", maxTimestampTokenBytes)
	}
	big := `"` + strings.Repeat("2", maxTimestampTokenBytes) + `"`
	var o OptionalTimestamp
	if err := json.Unmarshal([]byte(big), &o); err != nil {
		t.Fatalf("oversized token: unexpected error %v", err)
	}
	if !o.Present {
		t.Error("oversized token read as absent")
	}
	if o.WellFormed {
		t.Error("oversized token accepted as well-formed")
	}
	// A short strict timestamp under the cap is still well-formed.
	var ok OptionalTimestamp
	if err := json.Unmarshal([]byte(`"2026-06-11T00:00:00Z"`), &ok); err != nil {
		t.Fatalf("short token: %v", err)
	}
	if !ok.WellFormed {
		t.Error("short timestamp rejected as not well-formed")
	}
}

// TestOptionalTimestampUnmarshalAcceptsEscapedTimestamp pins parity with the
// reference: a valid RFC 3339 timestamp written entirely with JSON \u escapes has
// a raw token far larger than 128 bytes but must still decode and validate as
// well-formed, because the string it decodes to is a valid bound. The reference
// String.length check applies to the decoded value, not the raw token, so a Go
// byte cap below the worst-case escaped length would reject a bound TypeScript
// accepts.
func TestOptionalTimestampUnmarshalAcceptsEscapedTimestamp(t *testing.T) {
	const ts = "2026-06-11T00:00:00.000+00:00"
	var esc strings.Builder
	esc.WriteByte('"')
	for _, r := range ts {
		esc.WriteString("\\u")
		esc.WriteString(hex4(r))
	}
	esc.WriteByte('"')
	token := esc.String()
	if len(token) <= 128 {
		t.Fatalf("escaped token %d bytes, expected over 128", len(token))
	}
	var o OptionalTimestamp
	if err := json.Unmarshal([]byte(token), &o); err != nil {
		t.Fatalf("escaped token: unexpected error %v", err)
	}
	if !o.WellFormed || o.Value != ts {
		t.Errorf("escaped valid timestamp: got {wellFormed:%v value:%q}, want well-formed %q", o.WellFormed, o.Value, ts)
	}
}

func hex4(r rune) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(r>>12)&0xf],
		digits[(r>>8)&0xf],
		digits[(r>>4)&0xf],
		digits[r&0xf],
	})
}
