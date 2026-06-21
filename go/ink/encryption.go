package ink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// errDecrypt is the single reject sentinel for DecryptInkPayload. The
// conformance contract is accept-vs-reject only, so every reject branch
// returns a non-nil error; callers MUST NOT branch on the specific cause.
// Folding all rejects onto one sentinel also avoids leaking which gate
// fired (a constant-error surface), matching the reference decrypt path
// that throws on every failure before returning the plaintext.
var errDecrypt = errors.New("ink: decrypt rejected")

// AAD scalar fields are capped by UTF-16 code-unit count (the reuse of the
// package's utf16Len), matching the reference's String.length checks so the Go
// and TS implementations agree on accept/reject for multi-byte scalars.

// envString fetches key from a decoded JSON object and asserts it is a
// string. The second return is false when the field is absent or not a
// JSON string, mirroring the reference's `typeof x !== "string"` rejects.
func envString(env map[string]any, key string) (string, bool) {
	v, ok := env[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// DecryptInkPayload decrypts an INK v0.1 ECIES envelope using the
// recipient's X25519 private key and verifies inner/outer consistency.
// It is a byte-for-byte port of decryptInkPayload in src/crypto/ink.ts:
// both implementations make identical accept/reject decisions on the
// shared conformance corpus.
//
// The envelope is the decoded outer JSON object. recipientPrivKeyHex is
// the recipient's 32-byte X25519 private key, hex-encoded. recipientDid
// is optional: when non-nil it MUST be a non-empty string, and the
// decrypted inner "to" field MUST equal it (binding the ciphertext to
// this recipient).
//
// Security properties preserved from the reference:
//   - Pre-auth scalar caps (from/timestamp/messageNonce, measured in
//     UTF-16 code units) bound the AAD canonicalize + allocation work an
//     attacker can force before the AES-GCM tag check fires.
//   - Encoded-length pre-checks on ephemeralKey/nonce/ciphertext bound
//     base64url decode allocations before the exact-length checks.
//   - An all-zero ECDH shared secret is rejected: a low-order ephemeral
//     key would otherwise derive a publicly-known AES key, making the
//     ciphertext decryptable by anyone. crypto/ecdh already errors on
//     such points, but the result is also checked defensively.
//   - AAD binds protocol/type/from/ephemeralKey/nonce/timestamp/
//     messageNonce so a ciphertext cannot be replayed under modified
//     outer metadata or reattributed to a different sender.
//
// Every reject path returns a non-nil error (the errDecrypt sentinel).
func DecryptInkPayload(envelope map[string]any, recipientPrivKeyHex string, recipientDid *string) (map[string]any, error) {
	// 1. Envelope must be a non-null JSON object. A nil map is the Go
	// analogue of the reference's null/non-object reject.
	if envelope == nil {
		return nil, errDecrypt
	}

	// 2. Protocol + type discriminators.
	if p, ok := envString(envelope, "protocol"); !ok || p != "ink/0.1" {
		return nil, errDecrypt
	}
	if ty, ok := envString(envelope, "type"); !ok || ty != "network.tulpa.encrypted" {
		return nil, errDecrypt
	}

	// 3. Pre-auth scalar caps + non-empty. Measured in UTF-16 code units
	// to match the reference's String.length checks exactly.
	from, ok := envString(envelope, "from")
	if !ok {
		return nil, errDecrypt
	}
	if n := utf16Len(from); n < 1 || n > 512 {
		return nil, errDecrypt
	}
	timestamp, ok := envString(envelope, "timestamp")
	if !ok {
		return nil, errDecrypt
	}
	if n := utf16Len(timestamp); n < 1 || n > 64 {
		return nil, errDecrypt
	}
	messageNonce, ok := envString(envelope, "messageNonce")
	if !ok {
		return nil, errDecrypt
	}
	if n := utf16Len(messageNonce); n < 1 || n > 256 {
		return nil, errDecrypt
	}

	// 4. Ephemeral public key: encoded-length pre-check, then base64url
	// (RawURLEncoding, unpadded) decode to exactly 32 bytes.
	ephKeyStr, ok := envString(envelope, "ephemeralKey")
	if !ok || utf16Len(ephKeyStr) > 64 {
		return nil, errDecrypt
	}
	ephPub, err := base64.RawURLEncoding.DecodeString(ephKeyStr)
	if err != nil || len(ephPub) != 32 {
		return nil, errDecrypt
	}

	// 5. Recipient private key: hex-decode to exactly 32 bytes.
	recipientPriv, err := hex.DecodeString(recipientPrivKeyHex)
	if err != nil || len(recipientPriv) != 32 {
		return nil, errDecrypt
	}

	// 6. X25519 ECDH shared secret. crypto/ecdh returns an error for
	// low-order points that would yield an all-zero output; treat that
	// as a reject, and defensively reject an all-zero result as well.
	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, errDecrypt
	}
	pubKey, err := curve.NewPublicKey(ephPub)
	if err != nil {
		return nil, errDecrypt
	}
	shared, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, errDecrypt
	}
	if isAllZero(shared) {
		return nil, errDecrypt
	}

	// 7. HKDF-SHA256 → 32-byte AES key.
	key, err := hkdf.Key(sha256.New, shared, []byte("ink/0.1"), "ink/0.1/encrypt", 32)
	if err != nil {
		return nil, errDecrypt
	}

	// 8. AES-GCM nonce: encoded-length pre-check, then decode to exactly
	// 12 bytes.
	nonceStr, ok := envString(envelope, "nonce")
	if !ok || utf16Len(nonceStr) > 32 {
		return nil, errDecrypt
	}
	aesNonce, err := base64.RawURLEncoding.DecodeString(nonceStr)
	if err != nil || len(aesNonce) != 12 {
		return nil, errDecrypt
	}

	// 9. Ciphertext: encoded-length cap, then decode. Web Crypto appends
	// the 16-byte GCM tag to the ciphertext (ciphertext||tag), which is
	// exactly what crypto/cipher's GCM Open expects, so no splitting.
	ctStr, ok := envString(envelope, "ciphertext")
	if !ok || utf16Len(ctStr) > 1_400_000 {
		return nil, errDecrypt
	}
	ciphertextWithTag, err := base64.RawURLEncoding.DecodeString(ctStr)
	if err != nil {
		return nil, errDecrypt
	}

	// 10. AAD: bind the security-relevant outer fields via JCS. The AAD
	// object uses the ORIGINAL envelope string values (not re-encoded
	// forms) so the canonical bytes match the reference exactly. JCS
	// sorts keys by UTF-16 code unit (RFC 8785), the same ordering the TS
	// jcsCanonicalize uses.
	aadObject := map[string]any{
		"protocol":     "ink/0.1",
		"type":         "network.tulpa.encrypted",
		"from":         from,
		"ephemeralKey": ephKeyStr,
		"nonce":        nonceStr,
		"timestamp":    timestamp,
		"messageNonce": messageNonce,
	}
	canonical, err := canonicalizeJSON(aadObject)
	if err != nil {
		return nil, errDecrypt
	}
	aad := []byte("ink/0.1:envelope\n" + canonical)

	// 11. AES-256-GCM open. An authentication failure is a reject.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errDecrypt
	}
	plaintext, err := gcm.Open(nil, aesNonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, errDecrypt
	}

	// 12. Parse plaintext: must be a non-null JSON object (not array or
	// scalar). The ciphertext is now authenticated, but the inner shape
	// is still validated before field access.
	var decryptedRaw any
	if err := json.Unmarshal(plaintext, &decryptedRaw); err != nil {
		return nil, errDecrypt
	}
	decrypted, ok := decryptedRaw.(map[string]any)
	if !ok {
		return nil, errDecrypt
	}

	// 13. Inner/outer consistency. Inner "from" must equal the outer
	// envelope "from". When recipientDid is supplied it MUST be a
	// non-empty string and inner "to" must equal it.
	if df, ok := decrypted["from"].(string); !ok || df != from {
		return nil, errDecrypt
	}
	if recipientDid != nil {
		if *recipientDid == "" {
			return nil, errDecrypt
		}
		if dt, ok := decrypted["to"].(string); !ok || dt != *recipientDid {
			return nil, errDecrypt
		}
	}

	// 14. Accept.
	return decrypted, nil
}

// isAllZero reports whether every byte of b is zero. Used to reject an
// all-zero ECDH shared secret (see DecryptInkPayload step 6).
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
