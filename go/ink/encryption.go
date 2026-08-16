package ink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// is MANDATORY: it MUST be a non-empty string, and the decrypted inner "to"
// field MUST equal it (binding the ciphertext to this recipient identity on
// top of the AAD recipientKey binding).
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
//   - AAD binds protocol/type/from/recipientKey/ephemeralKey/nonce/
//     timestamp/messageNonce so a ciphertext cannot be replayed under
//     modified outer metadata, reattributed to a different sender, or
//     accepted by a different recipient (recipientKey is recomputed from
//     the local private key, not read from the envelope).
//
// Every reject path returns a non-nil error (the errDecrypt sentinel).
func DecryptInkPayload(envelope map[string]any, recipientPrivKeyHex string, recipientDid string) (map[string]any, error) {
	// 1. Envelope must be a non-null JSON object. A nil map is the Go
	// analogue of the reference's null/non-object reject.
	if envelope == nil {
		return nil, errDecrypt
	}

	// 2. Protocol + type discriminators.
	if p, ok := envString(envelope, "protocol"); !ok || p != "ink/0.1" {
		return nil, errDecrypt
	}
	// Receivers dual-accept both the legacy and vendor-neutral spelling. The
	// actual type is bound into the AAD below (never normalized), so a
	// relabelled envelope reconstructs a different AAD and fails the GCM tag.
	messageType, ok := envString(envelope, "type")
	if !ok || !dualWireType(messageType, "encrypted") {
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

	// 7. HKDF-SHA256 → 32-byte AES key. Shared with the seal path so both
	// directions derive the key from identical salt/info bytes.
	key, err := inkEncryptKey(shared)
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
	// jcsCanonicalize uses. recipientKey is recomputed locally from the
	// recipient's own private key, so a ciphertext encrypted for a
	// different recipient derives a different AAD and fails the GCM tag.
	recipientKey := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	aad, err := inkEncryptAAD(messageType, from, recipientKey, ephKeyStr, nonceStr, timestamp, messageNonce)
	if err != nil {
		return nil, errDecrypt
	}

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
	//
	// No structural walk runs here, matching the reference: the TypeScript
	// decryptInkPayload in src/crypto/ink.ts applies no node/depth/character
	// bound to the authenticated plaintext, so a Go walk would reject inner
	// bodies the reference accepts. The decode cost is already bounded by the
	// step-9 ciphertext cap (a ciphertext string over 1,400,000 UTF-16 code
	// units is rejected before base64url decode, bounding the plaintext to
	// about 1,050,000 bytes), and Go's encoding/json enforces its own hard
	// nesting limit (about 10000) as a stack backstop, so no separate depth
	// guard is needed.
	var decryptedRaw any
	if err := json.Unmarshal(plaintext, &decryptedRaw); err != nil {
		return nil, errDecrypt
	}
	decrypted, ok := decryptedRaw.(map[string]any)
	if !ok {
		return nil, errDecrypt
	}

	// 13. Inner/outer consistency. Inner "from" must equal the outer
	// envelope "from". recipientDid is MANDATORY: the decrypter must
	// assert which recipient identity it is, and inner "to" must equal it.
	if df, ok := decrypted["from"].(string); !ok || df != from {
		return nil, errDecrypt
	}
	if recipientDid == "" {
		return nil, errDecrypt
	}
	if dt, ok := decrypted["to"].(string); !ok || dt != recipientDid {
		return nil, errDecrypt
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

// inkEncryptKey derives the 32-byte AES-256 key from the X25519 shared secret:
// HKDF-SHA256(secret, salt = "ink/0.1", info = "ink/0.1/encrypt", 32). Shared by
// EncryptInkPayload and DecryptInkPayload so the seal and open directions can
// never drift on the salt/info bytes.
func inkEncryptKey(shared []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, []byte("ink/0.1"), "ink/0.1/encrypt", 32)
}

// inkEncryptAAD builds the ECIES additional-authenticated-data bytes:
// "ink/0.1:envelope\n" followed by the RFC 8785 JCS canonicalization of the
// bound member set { protocol, type, from, recipientKey, ephemeralKey, nonce,
// timestamp, messageNonce }. Every argument except protocol is a caller string;
// recipientKey/ephemeralKey/nonce are the base64url encodings the envelope
// carries (or, on the seal side, will carry), so both directions canonicalize
// identical bytes. This is the single AAD construction both EncryptInkPayload
// and DecryptInkPayload use, so a tamper of any bound field on either side
// changes these bytes and fails the AES-GCM tag.
func inkEncryptAAD(messageType, from, recipientKey, ephemeralKey, nonce, timestamp, messageNonce string) ([]byte, error) {
	aadObject := map[string]any{
		"protocol":     "ink/0.1",
		"type":         messageType,
		"from":         from,
		"recipientKey": recipientKey,
		"ephemeralKey": ephemeralKey,
		"nonce":        nonce,
		"timestamp":    timestamp,
		"messageNonce": messageNonce,
	}
	canonical, err := canonicalizeJSON(aadObject)
	if err != nil {
		return nil, err
	}
	return []byte("ink/0.1:envelope\n" + canonical), nil
}

// maxEncryptPlaintextBytes bounds the JSON-encoded inner plaintext a seal will
// accept, mirroring the reference encryptInkPayload cap (MAX_SIGBASE_BODY_BYTES)
// so the seal path cannot mint a ciphertext larger than the decrypt-side
// ciphertext cap would ever accept. The reference measures the UTF-16 length of
// the JSON string; this measures the UTF-8 byte length of the marshaled JSON.
// The two agree for ASCII payloads and the byte count is the conservative bound.
const maxEncryptPlaintextBytes = 1_048_576

// InkEncryptOptions carries the optional inputs to EncryptInkPayload.
//
// EphemeralPrivateKey and AESNonce are a TEST-ONLY determinism seam. Supplying
// them makes the sealed envelope reproducible for the conformance corpus and the
// AAD/key pin. They MUST NOT be set on production traffic: reusing a fixed
// ephemeral key against the same recipient derives the same AES key, and a
// fixed/colliding AES nonce then reuses the (key, nonce) pair, which is
// catastrophic for AES-GCM (forgery plus plaintext recovery). Leave both nil so
// each call draws a fresh ephemeral key and a random nonce.
type InkEncryptOptions struct {
	EphemeralPrivateKey []byte
	AESNonce            []byte
	// MessageType selects the wire-namespace type to emit. Empty defaults to the
	// legacy network.tulpa.encrypted; a sender that has negotiated the
	// vendor-neutral namespace may set network.ink.encrypted. The chosen type is
	// bound into the AAD, so it is authenticated, not malleable.
	MessageType string
	// RecipientDid is the recipient identity this envelope is addressed to. When
	// set, the inner plaintext's "to" MUST equal it, so the seal cannot mint an
	// envelope whose inner binding disagrees with the recipient the sender
	// intends. It is the outer half of the binding DecryptInkPayload enforces with
	// its mandatory recipientDid argument.
	//
	// It is a pointer, not a string, because asserting a recipient and declining
	// to assert one must be distinguishable: the reference (src/crypto/ink.ts)
	// checks `options.recipientDid !== undefined`, so a caller that asserts the
	// empty string there gets a reject rather than a silent skip, since no inner
	// "to" can equal it. A plain string field would make that assertion
	// indistinguishable from an absent one and let the Go seal mint an envelope
	// the reference refuses.
	RecipientDid *string
}

// EncryptInkPayload seals an inner plaintext object into an INK v0.1 ECIES
// envelope (§3.4 / specs/ink-payload-encryption.md). It is the producing mirror
// of DecryptInkPayload and a byte-faithful port of encryptInkPayload in
// src/crypto/ink.ts: it draws an ephemeral X25519 keypair, does ECDH against the
// recipient's static X25519 public key, derives the AES-256 key with HKDF-SHA256
// (via inkEncryptKey), and runs AES-256-GCM over the JSON-encoded plaintext with
// the outer envelope bound as AAD (via inkEncryptAAD).
//
// recipientEncryptionKeyHex is the recipient's 32-byte static X25519 PUBLIC key,
// hex-encoded (the same key whose base64url form is bound as recipientKey). The
// returned envelope is a decoded JSON object ready to marshal onto the wire and
// round-trips through DecryptInkPayload and the reference decryptInkPayload.
//
// Because the ephemeral key and AES nonce are random, the ciphertext is
// non-deterministic; that is expected, so there is no byte-exact ciphertext pin.
// The caller owns inner/outer consistency: to satisfy the decrypt-side check the
// plaintext MUST carry "from" equal to senderDid and "to" equal to the
// recipient DID the decrypter will assert.
func EncryptInkPayload(
	plaintext map[string]any,
	senderDid string,
	recipientEncryptionKeyHex string,
	timestamp string,
	messageNonce string,
	opts *InkEncryptOptions,
) (map[string]any, error) {
	messageType := "network.tulpa.encrypted"
	if opts != nil && opts.MessageType != "" {
		if !dualWireType(opts.MessageType, "encrypted") {
			return nil, fmt.Errorf("ink: invalid messageType %q", opts.MessageType)
		}
		messageType = opts.MessageType
	}

	// Pre-AAD scalar caps, measured in UTF-16 code units to match the
	// decrypt-side guards exactly so the seal cannot mint an envelope a
	// conformant decrypter would refuse.
	if n := utf16Len(senderDid); n < 1 || n > 512 {
		return nil, errors.New("ink: senderDid must be 1 to 512 code units")
	}
	if n := utf16Len(timestamp); n < 1 || n > 64 {
		return nil, errors.New("ink: timestamp must be 1 to 64 code units")
	}
	if n := utf16Len(messageNonce); n < 1 || n > 256 {
		return nil, errors.New("ink: messageNonce must be 1 to 256 code units")
	}
	if plaintext == nil {
		return nil, errors.New("ink: plaintext must be a non-nil object")
	}

	// Inner/outer binding. DecryptInkPayload requires the sealed plaintext to
	// carry "from" equal to the outer envelope sender and "to" equal to the
	// recipient identity the decrypter asserts (which is mandatory and non-empty),
	// so a plaintext that fails either rule produces an envelope no conformant
	// decrypter will ever open. Checking it here keeps the seal path to the same
	// rule as every other guard on it: never mint what decrypt refuses. "to" is
	// checked against opts.RecipientDid when the caller asserts one; with or
	// without that assertion it must still be a non-empty string, because an
	// absent or non-string "to" cannot match any recipient identity. An asserted
	// empty RecipientDid is an assertion no inner "to" can satisfy, so it is
	// rejected rather than treated as unasserted, matching the reference.
	if innerFrom, ok := plaintext["from"].(string); !ok || innerFrom != senderDid {
		return nil, errors.New("ink: plaintext from must equal senderDid")
	}
	innerTo, ok := plaintext["to"].(string)
	if !ok || innerTo == "" {
		return nil, errors.New("ink: plaintext to must be a non-empty string")
	}
	if opts != nil && opts.RecipientDid != nil && innerTo != *opts.RecipientDid {
		return nil, errors.New("ink: plaintext to must equal the asserted RecipientDid")
	}

	// Recipient static X25519 public key.
	recipientPub, err := hex.DecodeString(recipientEncryptionKeyHex)
	if err != nil || len(recipientPub) != 32 {
		return nil, errors.New("ink: recipientEncryptionKeyHex must decode to 32 bytes")
	}
	curve := ecdh.X25519()
	recipientPubKey, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ink: invalid recipient public key: %w", err)
	}

	// Ephemeral X25519 keypair: fresh random unless the test seam supplies one.
	var ephPriv *ecdh.PrivateKey
	if opts != nil && opts.EphemeralPrivateKey != nil {
		if len(opts.EphemeralPrivateKey) != 32 {
			return nil, errors.New("ink: EphemeralPrivateKey must be exactly 32 bytes")
		}
		ephPriv, err = curve.NewPrivateKey(opts.EphemeralPrivateKey)
	} else {
		ephPriv, err = curve.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("ink: ephemeral key: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()

	// ECDH shared secret. crypto/ecdh errors on a low-order recipient key that
	// would yield an all-zero secret; reject that (and defensively an all-zero
	// result) exactly as the decrypt path does, so the seal never derives a
	// publicly known AES key.
	shared, err := ephPriv.ECDH(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("ink: ecdh: %w", err)
	}
	if isAllZero(shared) {
		return nil, errors.New("ink: ECDH shared secret is all zeros")
	}

	key, err := inkEncryptKey(shared)
	if err != nil {
		return nil, fmt.Errorf("ink: hkdf: %w", err)
	}

	// AES-GCM nonce: fresh random unless the test seam supplies one.
	var aesNonce []byte
	if opts != nil && opts.AESNonce != nil {
		if len(opts.AESNonce) != 12 {
			return nil, errors.New("ink: AESNonce must be exactly 12 bytes")
		}
		aesNonce = opts.AESNonce
	} else {
		aesNonce = make([]byte, 12)
		if _, err := rand.Read(aesNonce); err != nil {
			return nil, fmt.Errorf("ink: nonce: %w", err)
		}
	}

	// Bound the plaintext before serialization, mirroring the reference
	// encryptInkPayload preflight (isWithinCanonicalizeBounds): reject an
	// over-complex shape or a non-JCS-safe number (fractional, out-of-range, or
	// negative zero) so the seal cannot mint an envelope the normative reference
	// producer would refuse. This is an encrypt-only guard: the decrypt path
	// deliberately applies no structural walk to the authenticated plaintext,
	// because the reference decryptInkPayload applies none.
	if !withinBodyBounds(plaintext) {
		return nil, errors.New("ink: plaintext exceeds maximum allowed complexity")
	}

	// JSON-encode the inner plaintext, bounded to mirror the decrypt-side
	// ciphertext cap. Map key ordering is Go-canonical (sorted); it does not
	// affect the round trip because the decrypter reparses the plaintext.
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ink: marshal plaintext: %w", err)
	}
	if len(plaintextBytes) > maxEncryptPlaintextBytes {
		return nil, errors.New("ink: plaintext exceeds maximum allowed size")
	}

	ephKeyStr := base64.RawURLEncoding.EncodeToString(ephPub)
	nonceStr := base64.RawURLEncoding.EncodeToString(aesNonce)
	recipientKey := base64.RawURLEncoding.EncodeToString(recipientPub)
	aad, err := inkEncryptAAD(messageType, senderDid, recipientKey, ephKeyStr, nonceStr, timestamp, messageNonce)
	if err != nil {
		return nil, fmt.Errorf("ink: aad: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ink: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ink: gcm: %w", err)
	}
	// Seal appends the 16-byte tag after the ciphertext (ciphertext||tag), the
	// same layout Web Crypto emits, so the base64url output decodes cleanly on
	// the decrypt side without any tag splitting.
	ciphertextWithTag := gcm.Seal(nil, aesNonce, plaintextBytes, aad)

	envelope := map[string]any{
		"protocol":     "ink/0.1",
		"type":         messageType,
		"from":         senderDid,
		"ephemeralKey": ephKeyStr,
		"nonce":        nonceStr,
		"ciphertext":   base64.RawURLEncoding.EncodeToString(ciphertextWithTag),
		"timestamp":    timestamp,
		"messageNonce": messageNonce,
	}
	return envelope, nil
}
