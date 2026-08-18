package ink

import "testing"

func TestContainsOutOfRangeNumberLiteral(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`{"note":"hello"}`, false},
		{`{"a":0,"b":-7,"c":1e2,"d":3.14,"e":1E+21}`, false},
		{`{"n":1.7976931348623157e308}`, false},
		{`{"n":1e-400}`, false}, // underflows to zero on every IEEE-754 parser
		{`{"a":true,"b":false,"c":null}`, false},
		{`{"note":"1e309"}`, false}, // number-like text inside a string
		{`{"1e309":"v"}`, false},
		{`{"note":"a\"1e309"}`, false}, // string ends after the escaped quote
		{`{"a":1e}`, false},            // malformed run; the parser decides
		{`{"n":1e309}`, true},
		{`{"n":1.7976931348623159e308}`, true},
		{`{"n":-1e1000}`, true},
		{`1e309`, true},
		{`{"a":1e309,"a":1}`, true}, // shadowed by a later duplicate member
		{`{"a":[1,{"b":9e999}]}`, true},
	}
	for _, c := range cases {
		if got := ContainsOutOfRangeNumberLiteral([]byte(c.raw)); got != c.want {
			t.Errorf("ContainsOutOfRangeNumberLiteral(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestParseSignedBodyNumberRange(t *testing.T) {
	if _, err := ParseSignedBody([]byte(`{"n":1e309}`)); err == nil {
		t.Error("expected an out-of-range number literal to be rejected")
	}
	// The case the value-level number profile cannot see: last-wins member
	// semantics hide the literal, so without the raw scan this would parse.
	if _, err := ParseSignedBody([]byte(`{"a":1e309,"a":1}`)); err == nil {
		t.Error("expected a shadowed out-of-range literal to be rejected")
	}
	if _, err := ParseSignedBody([]byte(`1e309`)); err == nil {
		t.Error("expected a bare out-of-range literal to be rejected")
	}
	if _, err := ParseSignedBody([]byte(`{"a":2,"a":1}`)); err != nil {
		t.Errorf("expected an in-range duplicate member to parse: %v", err)
	}
	if _, err := ParseSignedBody([]byte(`{"n":1e-400}`)); err != nil {
		t.Errorf("expected an underflowing exponent to parse: %v", err)
	}
}
