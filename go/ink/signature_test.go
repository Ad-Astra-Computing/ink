package ink

import "testing"

// A newline inside a signed body string is escaped by JCS, so it cannot shift
// the newline-delimited signature base boundaries.
func TestBodyNewlineIsEscaped(t *testing.T) {
	got := canonicalizeString("a\nb\r\tc")
	want := `"a\nb\r\tc"`
	if got != want {
		t.Errorf("canonicalizeString = %q, want %q", got, want)
	}
}

// A CR or LF in a scalar field is rejected outright, so it cannot inject a
// boundary into the signature base.
func TestScalarNewlineRejected(t *testing.T) {
	base := InkSignInput{
		Method:       "POST",
		Path:         "/ink/v1/x/intent",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	for _, mut := range []func(*InkSignInput){
		func(in *InkSignInput) { in.RecipientDid = "tulpa:\nz" },
		func(in *InkSignInput) { in.Path = "/a\r/b" },
		func(in *InkSignInput) { in.Method = "PO\nST" },
		func(in *InkSignInput) { in.Timestamp = "2026\n" },
	} {
		in := base
		mut(&in)
		if _, err := BuildSignatureBase(in); err == nil {
			t.Errorf("expected error for scalar containing a newline: %+v", in)
		}
	}
}

// Numbers in a signed body are out of scope for v1 and fail closed rather than
// producing a possibly divergent serialization.
func TestNumberInBodyFailsClosed(t *testing.T) {
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{"n": float64(1)},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if _, err := BuildSignatureBase(in); err == nil {
		t.Errorf("expected error for a number in the signed body")
	}
}
