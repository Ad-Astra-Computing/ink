package ink

import "testing"

// bs is a single backslash. Surrogate escape sequences are built by
// concatenation (bs + "uD800") so the test source never contains a literal
// \uXXXX escape that a tool might fold into a real code point.
const bs = "\\"

func TestContainsLoneSurrogateEscape(t *testing.T) {
	hi := bs + "uD83D" // high surrogate escape of an astral pair
	lo := bs + "uDE00" // matching low surrogate escape
	loneHi := bs + "uD800"
	loneHiUpperBound := bs + "uDBFF"
	loneLo := bs + "uDC00"
	loneLoUpperBound := bs + "uDFFF"
	lowerLoneHi := bs + "ud800"
	bmpA := bs + "u0041"
	litBackslashU := bs + bs + "uD800" // an escaped backslash then literal uD800

	cases := []struct {
		name string
		raw  string
		want bool
	}{
		// Accepted: no unpaired surrogate.
		{"plain string", `{"note":"hello"}`, false},
		{"empty string", `{"note":""}`, false},
		{"no strings", `{"n":1,"b":true,"x":null}`, false},
		{"valid surrogate pair escaped", `{"note":"` + hi + lo + `"}`, false},
		{"lowercase valid pair escaped", `{"note":"` + bs + "ud83d" + bs + "ude00" + `"}`, false},
		{"literal escaped backslash u", `{"note":"` + litBackslashU + `"}`, false},
		{"bmp unicode escape", `{"note":"` + bmpA + `"}`, false},
		{"raw utf8 multibyte", `{"note":"héllo 😀"}`, false},
		{"two valid pairs escaped", `{"a":"` + hi + lo + `","b":"` + hi + lo + `"}`, false},
		{"surrogate-shaped hex outside any string", loneHi, false},

		// Rejected: an unpaired surrogate inside a string.
		{"lone high at end", `{"note":"` + loneHi + `"}`, true},
		{"lone low", `{"note":"` + loneLo + `"}`, true},
		{"lowercase lone high", `{"note":"` + lowerLoneHi + `"}`, true},
		{"high then bmp escape", `{"note":"` + loneHi + bmpA + `"}`, true},
		{"high split by char", `{"note":"` + loneHi + "x" + loneLo + `"}`, true},
		{"high then literal escaped backslash u", `{"note":"` + loneHi + bs + bs + "uDC00" + `"}`, true},
		{"lone high in object key", `{"` + loneHi + `":"v"}`, true},
		{"lone low in array element", `{"a":["x","` + loneLo + `"]}`, true},
		{"truncated lone high at input end", `{"note":"` + loneHi, true},
		{"high boundary DBFF lone", `{"note":"` + loneHiUpperBound + `"}`, true},
		{"low boundary DFFF lone", `{"note":"` + loneLoUpperBound + `"}`, true},
	}
	for _, c := range cases {
		if got := ContainsLoneSurrogateEscape([]byte(c.raw)); got != c.want {
			t.Errorf("%s: ContainsLoneSurrogateEscape(%q) = %v, want %v", c.name, c.raw, got, c.want)
		}
	}
}

func TestParseSignedBody(t *testing.T) {
	if _, err := ParseSignedBody([]byte(`{"note":"hello"}`)); err != nil {
		t.Errorf("valid body rejected: %v", err)
	}
	if _, err := ParseSignedBody([]byte(`{"note":"` + bs + `uD800"}`)); err == nil {
		t.Errorf("lone surrogate body accepted")
	}
	if _, err := ParseSignedBody([]byte(`{not json`)); err == nil {
		t.Errorf("malformed JSON accepted")
	}
}

func TestParseHex4(t *testing.T) {
	cases := []struct {
		in    string
		want  int
		valid bool
	}{
		{"D800", 0xD800, true},
		{"d800", 0xD800, true},
		{"0041", 0x0041, true},
		{"FFFF", 0xFFFF, true},
		{"00", 0, false},   // too short
		{"D80G", 0, false}, // non-hex digit
		{"xyza", 0, false},
	}
	for _, c := range cases {
		got, ok := parseHex4([]byte(c.in), 0)
		if ok != c.valid || (ok && got != c.want) {
			t.Errorf("parseHex4(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.valid)
		}
	}
}
