package ink

import (
	"encoding/json"
	"testing"
)

func TestContainsEscapedMemberNameAccepts(t *testing.T) {
	cases := []string{
		`{"a":1}`,
		`{"a":1,"b":{"c":[1,2,3]}}`,
		`{"é":1,"𝄞":2}`,
		`{"a.b-c_d":1,"":2}`,
		// Escapes in string values and array elements are fine.
		`{"a":"line\nbreak"}`,
		`{"a":"back\\slash"}`,
		`{"a":"\u0041"}`,
		`{"a":"quote\"inside"}`,
		`{"a":["\n","\\","\u0041"]}`,
		`["\n","\\"]`,
		// A colon inside a string value is not a key separator.
		`{"a":"b:c","d":"\n:e"}`,
		// A value ending in an escaped quote must not desynchronise the scan.
		`{"a":"ends with \"","b":1}`,
		// Bare top-level scalars.
		`"\n"`,
		`123`,
		`null`,
	}
	for _, c := range cases {
		if ContainsEscapedMemberName([]byte(c)) {
			t.Errorf("ContainsEscapedMemberName(%s) = true, want false", c)
		}
	}
}

func TestContainsEscapedMemberNameRejects(t *testing.T) {
	cases := []string{
		`{"\n":1}`,
		`{"\t":1}`,
		`{"\r":1}`,
		`{"\b":1}`,
		`{"\f":1}`,
		`{"\/":1}`,
		`{"\"":1}`,
		`{"\\":1}`,
		// \uXXXX, even decoding to something ordinary.
		`{"\u0041":1}`,
		`{"\u00e9":1}`,
		// Escape anywhere in the name, not only at the start.
		`{"a\nb":1}`,
		`{"ab\\":1}`,
		// Nested at any depth.
		`{"a":{"\n":1}}`,
		`{"a":[{"b":{"\\":1}}]}`,
		`[[{"\t":1}]]`,
		// Whitespace before the colon.
		`{"\n"  :  1}`,
		"{\"\\n\"\n\t: 1}",
		// A value ending in an escaped quote followed by an escaped key.
		`{"a":"ends with \"","\n":1}`,
		// The measured V8 corruption vectors.
		`{"x":{"\\":1},"y":{"\n":2}}`,
		`{"A":1,"\"":2}`,
	}
	for _, c := range cases {
		if !ContainsEscapedMemberName([]byte(c)) {
			t.Errorf("ContainsEscapedMemberName(%s) = false, want true", c)
		}
	}
}

func TestContainsEscapedMemberNameTruncated(t *testing.T) {
	// Must not read past the end on a truncated escape.
	for _, c := range []string{`{"a":"\`, `{"\`, `{"a"`, `{`, ``} {
		_ = ContainsEscapedMemberName([]byte(c))
	}
}

func TestParseSignedBodyRejectsEscapedMemberName(t *testing.T) {
	if _, err := ParseSignedBody([]byte(`{"\n":1}`)); err == nil {
		t.Fatal("ParseSignedBody accepted an escaped member name")
	}
	if _, err := ParseSignedBody([]byte(`{"a":"\n"}`)); err != nil {
		t.Fatalf("ParseSignedBody rejected an escaped string value: %v", err)
	}
}

func TestHasUnsafeObjectKey(t *testing.T) {
	safe := []interface{}{
		map[string]interface{}{"a": 1.0, "b": map[string]interface{}{"c": []interface{}{1.0}}},
		map[string]interface{}{"é": 1.0, "𝄞": 2.0, "": 3.0, "\u007f": 4.0},
		map[string]interface{}{"a": "quote \" backslash \\ newline \n"},
		map[string]interface{}{"a": []interface{}{"\\", "\"", "\x00"}},
	}
	for _, v := range safe {
		if HasUnsafeObjectKey(v) {
			t.Errorf("HasUnsafeObjectKey(%v) = true, want false", v)
		}
	}

	unsafe := []interface{}{
		map[string]interface{}{"a\"b": 1.0},
		map[string]interface{}{"a\\b": 1.0},
		map[string]interface{}{"a\nb": 1.0},
		map[string]interface{}{"\x00": 1.0},
		map[string]interface{}{"\x1f": 1.0},
		map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c\\d": 1.0}}},
		map[string]interface{}{"a": []interface{}{map[string]interface{}{"b\nc": 1.0}}},
	}
	for _, v := range unsafe {
		if !HasUnsafeObjectKey(v) {
			t.Errorf("HasUnsafeObjectKey(%v) = false, want true", v)
		}
	}
}

// The two halves must agree: a key the producer side accepts never serializes
// to a member name the receiver side rejects, and every key it rejects does.
func TestMemberNameRoundTrip(t *testing.T) {
	safe := map[string]interface{}{"é": 1.0, "𝄞": 2.0, "a.b-c_d/e": 3.0, "": 4.0, "\u007f": 5.0}
	if HasUnsafeObjectKey(safe) {
		t.Fatal("HasUnsafeObjectKey rejected a safe key set")
	}
	enc, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsEscapedMemberName(enc) {
		t.Errorf("safe key set serialized to an escaped member name: %s", enc)
	}

	for _, key := range []string{"a\"b", "a\\b", "a\nb", "\x00", "\x1f"} {
		v := map[string]interface{}{key: 1.0}
		if !HasUnsafeObjectKey(v) {
			t.Errorf("HasUnsafeObjectKey(%q) = false, want true", key)
		}
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !ContainsEscapedMemberName(enc) {
			t.Errorf("unsafe key %q serialized without an escape: %s", key, enc)
		}
	}
}
