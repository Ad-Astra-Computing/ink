package ink

import (
	"encoding/json"
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
