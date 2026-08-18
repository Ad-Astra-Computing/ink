package ink

import "testing"

// The escaped-member-name rule was first added only to JCSCanonicalize, which
// left every path that calls canonicalizeJSON directly unguarded: the exported
// transport signature base, audit event and leaf hashing, audit query
// responses, card domain verification and the authorization artifacts. Go then
// signed inputs the reference refused, which is the cross-implementation
// disagreement the rule exists to prevent.
//
// The check now lives in canonicalizeJSON's key loop, so it holds for every
// caller by construction. This test pins that: each entry point below is a
// distinct path that reaches canonicalization, and each must refuse a key
// needing an escape. A new signing path that bypasses canonicalizeJSON will not
// be caught here, so add it to this list when you add it to the package.
func TestSignatureBoundPathsRefuseUnsafeKeys(t *testing.T) {
	const unsafe = `a"b`

	t.Run("canonicalizeJSON itself", func(t *testing.T) {
		if _, err := canonicalizeJSON(map[string]interface{}{unsafe: 1.0}); err == nil {
			t.Fatal("canonicalizeJSON accepted a key needing an escape")
		}
	})

	t.Run("nested under an object", func(t *testing.T) {
		v := map[string]interface{}{"a": map[string]interface{}{unsafe: 1.0}}
		if _, err := canonicalizeJSON(v); err == nil {
			t.Fatal("canonicalizeJSON accepted a nested unsafe key")
		}
	})

	t.Run("nested under an array", func(t *testing.T) {
		v := map[string]interface{}{"a": []interface{}{map[string]interface{}{unsafe: 1.0}}}
		if _, err := canonicalizeJSON(v); err == nil {
			t.Fatal("canonicalizeJSON accepted an unsafe key inside an array")
		}
	})

	t.Run("JCSCanonicalize", func(t *testing.T) {
		if _, err := JCSCanonicalize(map[string]interface{}{unsafe: 1.0}); err == nil {
			t.Fatal("JCSCanonicalize accepted a key needing an escape")
		}
	})

	t.Run("BuildSignatureBase, the transport path", func(t *testing.T) {
		_, err := BuildSignatureBase(InkSignInput{
			Method:       "POST",
			Path:         "/ink/v1/messages",
			RecipientDid: "did:web:example.com",
			Body:         map[string]interface{}{unsafe: 1.0},
			Timestamp:    "2026-01-01T00:00:00.000Z",
		})
		if err == nil {
			t.Fatal("BuildSignatureBase accepted a key needing an escape")
		}
	})

	// Every rule the key check must not disturb: escapes in string VALUES and in
	// array elements stay legal, and so do non-ASCII keys.
	t.Run("leaves safe input alone", func(t *testing.T) {
		// U+007F is not escaped by JCS, so it stays a legal key. It is built from
		// an escape rather than written literally: a raw control character in
		// source makes the file read as binary to grep, which hides the rest of
		// it, and that is how a NUL sentinel elsewhere went unnoticed.
		const del = "\u007f"
		v := map[string]interface{}{
			"note": "line\nbreak",
			"list": []interface{}{"\\", "\""},
			"é":    1.0,
			"":     2.0,
			del:    3.0,
		}
		if _, err := canonicalizeJSON(v); err != nil {
			t.Fatalf("canonicalizeJSON rejected safe input: %v", err)
		}
	})
}
