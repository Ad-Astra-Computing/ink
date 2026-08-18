package sealcmd

import (
	"testing"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

const (
	// RFC 7748 §6.1 vectors: recipient is Alice, ephemeral is Bob.
	recipientPubHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	recipientPrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

	goodReq = `{"recipientPublicKeyHex":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",` +
		`"senderDid":"did:web:sender.example",` +
		`"timestamp":"2026-07-11T12:00:00.000Z",` +
		`"messageNonce":"0123456789abcdef0123456789abcdef",` +
		`"plaintext":{"from":"did:web:sender.example","to":"did:web:recipient.example","body":"hi"},` +
		`"messageType":"network.ink.encrypted"}`
)

// TestSealRoundTrips pins that a sealed envelope decrypts back to the exact inner
// plaintext with the library decrypter.
func TestSealRoundTrips(t *testing.T) {
	res, err := Seal([]byte(goodReq))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if res.Envelope["type"] != "network.ink.encrypted" {
		t.Errorf("type = %v, want network.ink.encrypted", res.Envelope["type"])
	}
	got, err := ink.DecryptInkPayload(res.Envelope, recipientPrivHex, "did:web:recipient.example")
	if err != nil {
		t.Fatalf("library decrypter rejected a sealcmd envelope: %v", err)
	}
	if got["body"] != "hi" {
		t.Errorf("decrypted body = %v, want hi", got["body"])
	}
}

// TestSealIsNonDeterministic pins that two seals of the same request draw a
// fresh ephemeral key and nonce (the CLI exposes no determinism override), so an
// operator cannot drive the CLI into AES-GCM key/nonce reuse.
func TestSealIsNonDeterministic(t *testing.T) {
	a, err := Seal([]byte(goodReq))
	if err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	b, err := Seal([]byte(goodReq))
	if err != nil {
		t.Fatalf("Seal b: %v", err)
	}
	if a.Envelope["ephemeralKey"] == b.Envelope["ephemeralKey"] {
		t.Error("two seals reused the same ephemeral key")
	}
	if a.Envelope["nonce"] == b.Envelope["nonce"] {
		t.Error("two seals reused the same AES nonce")
	}
}

// TestSealRejectsBadInput pins the request guards.
func TestSealRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing plaintext": `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n"}`,
		"unknown field":     `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":{"a":1},"bogus":true}`,
		"non-hex recipient": `{"recipientPublicKeyHex":"zz","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":{"a":1}}`,
		"plaintext array":   `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":[1,2]}`,
		"bad messageType":   `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":{"a":1},"messageType":"network.other.encrypted"}`,
		"duplicate key":     `{"senderDid":"a","senderDid":"b","recipientPublicKeyHex":"` + recipientPubHex + `","timestamp":"t","messageNonce":"n","plaintext":{"a":1}}`,
		// A lone UTF-16 surrogate escape in an AAD-bound scalar would be rewritten
		// to U+FFFD by encoding/json; the reference rejects it, so the CLI must too.
		"surrogate in senderDid": `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"a\ud800b","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":{"a":1}}`,
		"surrogate in plaintext": `{"recipientPublicKeyHex":"` + recipientPubHex + `","senderDid":"did:web:s","timestamp":"2026-07-11T12:00:00.000Z","messageNonce":"n","plaintext":{"a":"x\ud800y"}}`,
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Seal([]byte(req)); err == nil {
				t.Errorf("%s: accepted", name)
			}
		})
	}
}

// sealReq builds a request with the given trailing members appended, so the
// recipientDid cases differ from the accepted baseline in exactly one field.
func sealReq(extra string) string {
	req := `{"recipientPublicKeyHex":"` + recipientPubHex + `",` +
		`"senderDid":"did:web:sender.example",` +
		`"timestamp":"2026-07-11T12:00:00.000Z",` +
		`"messageNonce":"0123456789abcdef0123456789abcdef",` +
		`"plaintext":{"from":"did:web:sender.example","to":"did:web:recipient.example","body":"hi"}`
	if extra != "" {
		req += "," + extra
	}
	return req + "}"
}

// TestSealAssertsRecipientDid pins that a CLI caller can reach the stronger
// inner binding: recipientDid is passed through to InkEncryptOptions, so the
// asserted identity must equal the inner plaintext "to". Without the
// passthrough a CLI caller could only ever get the unasserted rule.
func TestSealAssertsRecipientDid(t *testing.T) {
	res, err := Seal([]byte(sealReq(`"recipientDid":"did:web:recipient.example"`)))
	if err != nil {
		t.Fatalf("Seal with a matching recipientDid: %v", err)
	}
	got, err := ink.DecryptInkPayload(res.Envelope, recipientPrivHex, "did:web:recipient.example")
	if err != nil {
		t.Fatalf("library decrypter rejected an asserted envelope: %v", err)
	}
	if got["body"] != "hi" {
		t.Errorf("decrypted body = %v, want hi", got["body"])
	}
}

// TestSealRejectsRecipientDidMismatch pins that the assertion is enforced at
// seal time rather than left for the decrypter to discover: an envelope whose
// inner "to" disagrees with the asserted recipient is never minted.
func TestSealRejectsRecipientDidMismatch(t *testing.T) {
	cases := map[string]string{
		"other identity": `"recipientDid":"did:web:someone-else.example"`,
		// An asserted empty string is an assertion no inner "to" can satisfy,
		// because "to" must itself be non-empty. The reference tests
		// `!== undefined`, so it rejects here too; treating it as unasserted
		// would seal an envelope the reference producer refuses.
		"asserted empty": `"recipientDid":""`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Seal([]byte(sealReq(extra))); err == nil {
				t.Errorf("%s: accepted", name)
			}
		})
	}
}

// TestSealWithoutRecipientDidStillSeals pins that the field is optional and
// that omitting it leaves the previous behaviour untouched: the seal succeeds
// under the weaker rule that the inner "to" is a non-empty string, and a null
// member reads as absent the way every other optional member does.
func TestSealWithoutRecipientDidStillSeals(t *testing.T) {
	for name, req := range map[string]string{
		"absent": sealReq(""),
		"null":   sealReq(`"recipientDid":null`),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Seal([]byte(req))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if _, err := ink.DecryptInkPayload(res.Envelope, recipientPrivHex, "did:web:recipient.example"); err != nil {
				t.Fatalf("library decrypter rejected an unasserted envelope: %v", err)
			}
		})
	}
}
