package signcmd

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

const (
	seedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	goodReq = `{"privateKeyHex":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",` +
		`"signInput":{"method":"POST","path":"/ink/v1/x/intent","recipientDid":"tulpa:z",` +
		`"body":{"protocol":"ink/0.1","intent":"ping"},"timestamp":"2026-06-11T00:00:00.000Z"},` +
		`"keyId":"key-2026"}`
)

// TestRequestSignsAndVerifies pins that a signed request round-trips: the
// emitted signature verifies under the library verifier with the emitted public
// key, and the Authorization header carries the signature and keyId.
func TestRequestSignsAndVerifies(t *testing.T) {
	res, err := Request([]byte(goodReq))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	pub, err := hex.DecodeString(res.PublicKeyHex)
	if err != nil {
		t.Fatalf("bad public key hex: %v", err)
	}
	if want := "INK-Ed25519 " + res.Signature + " keyId=key-2026"; res.AuthHeader != want {
		t.Errorf("authHeader = %q, want %q", res.AuthHeader, want)
	}
	body, err := ink.ParseSignedBody([]byte(`{"protocol":"ink/0.1","intent":"ping"}`))
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	ok := ink.VerifyInkSignature(ink.InkSignInput{
		Method:       "POST",
		Path:         "/ink/v1/x/intent",
		RecipientDid: "tulpa:z",
		Body:         body,
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}, res.Signature, pub)
	if !ok {
		t.Error("library verifier rejected a signcmd-signed request")
	}
}

// TestRequestOmitsKeyId pins that a request without a keyId emits the bare
// two-token header.
func TestRequestOmitsKeyId(t *testing.T) {
	req := strings.Replace(goodReq, `,"keyId":"key-2026"`, "", 1)
	res, err := Request([]byte(req))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if want := "INK-Ed25519 " + res.Signature; res.AuthHeader != want {
		t.Errorf("authHeader = %q, want %q", res.AuthHeader, want)
	}
}

// TestRequestRejectsBadInput pins that malformed requests are errors, not
// silent zero-value signatures.
func TestRequestRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"not json":          `{`,
		"unknown field":     `{"privateKeyHex":"` + seedHex + `","signInput":{},"extra":1}`,
		"duplicate key":     `{"privateKeyHex":"` + seedHex + `","privateKeyHex":"` + seedHex + `","signInput":{}}`,
		"missing key":       `{"signInput":{"method":"POST","path":"/x","recipientDid":"z","body":{},"timestamp":"t"}}`,
		"short seed":        `{"privateKeyHex":"00","signInput":{"method":"POST","path":"/x","recipientDid":"z","body":{},"timestamp":"t"}}`,
		"non-hex seed":      `{"privateKeyHex":"zz","signInput":{"method":"POST","path":"/x","recipientDid":"z","body":{},"timestamp":"t"}}`,
		"missing signInput": `{"privateKeyHex":"` + seedHex + `"}`,
		"newline in path":   `{"privateKeyHex":"` + seedHex + `","signInput":{"method":"POST","path":"/a\n/b","recipientDid":"z","body":{},"timestamp":"t"}}`,
		"empty keyId":       strings.Replace(goodReq, `"keyId":"key-2026"`, `"keyId":""`, 1),
		"space keyId":       strings.Replace(goodReq, `"keyId":"key-2026"`, `"keyId":"bad key"`, 1),
	}
	for name, in := range cases {
		if _, err := Request([]byte(in)); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

// TestResultSignInputEchoesInput pins that the echoed signInput is the exact
// bytes supplied, so a verifier reconstructs the base from the same fields.
func TestResultSignInputEchoesInput(t *testing.T) {
	res, err := Request([]byte(goodReq))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	var got, want map[string]interface{}
	if err := json.Unmarshal(res.SignInput, &got); err != nil {
		t.Fatalf("unmarshal echoed signInput: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"method":"POST","path":"/ink/v1/x/intent","recipientDid":"tulpa:z","body":{"protocol":"ink/0.1","intent":"ping"},"timestamp":"2026-06-11T00:00:00.000Z"}`), &want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	gotB, _ := json.Marshal(got)
	wantB, _ := json.Marshal(want)
	if string(gotB) != string(wantB) {
		t.Errorf("echoed signInput = %s, want %s", gotB, wantB)
	}
}
