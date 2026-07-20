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
	"strings"
	"testing"
)

// encryptForTest builds a valid INK v0.1 ECIES envelope for the recipient's
// X25519 public key, mirroring DecryptInkPayload's own steps so the round trip
// exercises the real decrypt path. plaintext is the inner message body the test
// wants to smuggle past the AES-GCM tag; recipientPriv is returned as hex so the
// test can decrypt.
func encryptForTest(t *testing.T, plaintext []byte, from, recipientDid string) (map[string]any, string) {
	t.Helper()
	curve := ecdh.X25519()
	recipientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	shared, err := ephPriv.ECDH(recipientPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	key, err := hkdf.Key(sha256.New, shared, []byte("ink/0.1"), "ink/0.1/encrypt", 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ephKeyStr := base64.RawURLEncoding.EncodeToString(ephPriv.PublicKey().Bytes())
	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
	recipientKey := base64.RawURLEncoding.EncodeToString(recipientPriv.PublicKey().Bytes())
	const messageType = "network.ink.encrypted"
	const timestamp = "2026-07-11T12:00:00.000Z"
	const messageNonce = "0123456789abcdef0123456789abcdef"
	aadObject := map[string]any{
		"protocol":     "ink/0.1",
		"type":         messageType,
		"from":         from,
		"recipientKey": recipientKey,
		"ephemeralKey": ephKeyStr,
		"nonce":        nonceStr,
		"timestamp":    timestamp,
		"messageNonce": messageNonce,
	}
	canonical, err := canonicalizeJSON(aadObject)
	if err != nil {
		t.Fatalf("canonicalize aad: %v", err)
	}
	aad := []byte("ink/0.1:envelope\n" + canonical)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	envelope := map[string]any{
		"protocol":     "ink/0.1",
		"type":         messageType,
		"from":         from,
		"ephemeralKey": ephKeyStr,
		"nonce":        nonceStr,
		"ciphertext":   base64.RawURLEncoding.EncodeToString(ciphertext),
		"timestamp":    timestamp,
		"messageNonce": messageNonce,
	}
	return envelope, hex.EncodeToString(recipientPriv.Bytes())
}

func TestDecryptInkPayloadRoundTrip(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	inner := map[string]any{"from": from, "to": to, "body": "hello"}
	plaintext, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	envelope, privHex := encryptForTest(t, plaintext, from, to)
	got, err := DecryptInkPayload(envelope, privHex, to)
	if err != nil {
		t.Fatalf("round-trip decrypt rejected: %v", err)
	}
	if got["body"] != "hello" {
		t.Errorf("decrypted body = %v, want hello", got["body"])
	}
}

// TestDecryptInkPayloadRejectsOversizedCiphertext pins the step-9 ciphertext
// encoded-length cap: a ciphertext string over 1,400,000 UTF-16 code units is
// rejected before base64url decode. The envelope reuses a real round-trip
// fixture so steps 1 through 8 pass, then its ciphertext is overwritten with an
// overlong string so rejection lands on the step-9 cap. This cap is what bounds
// the decoded plaintext size, so the decrypt path carries no separate plaintext
// byte cap.
func TestDecryptInkPayloadRejectsOversizedCiphertext(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	inner := map[string]any{"from": from, "to": to, "body": "hello"}
	plaintext, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	envelope, privHex := encryptForTest(t, plaintext, from, to)
	envelope["ciphertext"] = strings.Repeat("A", 1_400_001)
	if _, err := DecryptInkPayload(envelope, privHex, to); err == nil {
		t.Error("oversized ciphertext accepted")
	}
}

// TestDecryptInkPayloadAcceptsDeepPlaintext pins parity with the reference: the
// TypeScript decryptInkPayload in src/crypto/ink.ts applies no structural walk to
// the authenticated plaintext, so a plaintext that nests past the signed-body
// depth cap still decrypts once the AES-GCM tag verifies. The step-9 ciphertext
// cap bounds decode cost and Go's encoding/json hard nesting limit (~10000) is
// the stack backstop, so the decrypt path adds no depth guard of its own.
func TestDecryptInkPayloadAcceptsDeepPlaintext(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	deep := strings.Repeat(`{"a":`, maxBodyDepth+2) + "1" + strings.Repeat(`}`, maxBodyDepth+2)
	plaintext := []byte(`{"from":"` + from + `","to":"` + to + `","x":` + deep + `}`)
	envelope, privHex := encryptForTest(t, plaintext, from, to)
	got, err := DecryptInkPayload(envelope, privHex, to)
	if err != nil {
		t.Fatalf("deep plaintext rejected: %v", err)
	}
	if got["from"] != from || got["to"] != to {
		t.Errorf("decrypted inner from/to = %v/%v, want %v/%v", got["from"], got["to"], from, to)
	}
}

// recipientKeypair returns a fresh X25519 recipient keypair as the public key
// hex the sealer accepts and the private key hex the decrypter accepts.
func recipientKeypair(t *testing.T) (pubHex, privHex string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), hex.EncodeToString(priv.Bytes())
}

func cloneEnvelope(env map[string]any) map[string]any {
	out := make(map[string]any, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}

// TestEncryptInkPayloadRoundTrip seals with the Go sealer and recovers the exact
// inner plaintext with the Go decrypter, proving the encryption envelope is now
// exercised in both directions by the Go implementation.
func TestEncryptInkPayloadRoundTrip(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	pubHex, privHex := recipientKeypair(t)

	inner := map[string]any{"from": from, "to": to, "body": "hello", "count": 7}
	env, err := EncryptInkPayload(inner, from, pubHex, "2026-07-11T12:00:00.000Z", "0123456789abcdef0123456789abcdef", &InkEncryptOptions{MessageType: "network.ink.encrypted"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := DecryptInkPayload(env, privHex, to)
	if err != nil {
		t.Fatalf("round-trip decrypt rejected: %v", err)
	}
	if got["body"] != "hello" {
		t.Errorf("decrypted body = %v, want hello", got["body"])
	}
	// JSON numbers decode to float64 on the decrypt side.
	if got["count"] != float64(7) {
		t.Errorf("decrypted count = %v, want 7", got["count"])
	}
}

// TestEncryptInkPayloadDefaultsToLegacyType pins the default wire namespace: an
// unset MessageType emits network.tulpa.encrypted, the legacy spelling, and the
// envelope still round-trips.
func TestEncryptInkPayloadDefaultsToLegacyType(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	pubHex, privHex := recipientKeypair(t)
	env, err := EncryptInkPayload(map[string]any{"from": from, "to": to}, from, pubHex, "2026-07-11T12:00:00.000Z", "0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env["type"] != "network.tulpa.encrypted" {
		t.Errorf("default type = %v, want network.tulpa.encrypted", env["type"])
	}
	if _, err := DecryptInkPayload(env, privHex, to); err != nil {
		t.Fatalf("default-type envelope rejected: %v", err)
	}
}

// TestEncryptInkPayloadTamperFailsTag tampers each AAD-bound outer field and the
// ciphertext, one at a time, and confirms the Go decrypter rejects: an AAD field
// mutation reconstructs a different AAD (or a different ECDH/key) so the AES-GCM
// tag no longer verifies.
func TestEncryptInkPayloadTamperFailsTag(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	pubHex, privHex := recipientKeypair(t)
	env, err := EncryptInkPayload(map[string]any{"from": from, "to": to, "body": "hello"}, from, pubHex, "2026-07-11T12:00:00.000Z", "0123456789abcdef0123456789abcdef", &InkEncryptOptions{MessageType: "network.ink.encrypted"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Sanity: the untouched envelope decrypts.
	if _, err := DecryptInkPayload(env, privHex, to); err != nil {
		t.Fatalf("baseline decrypt rejected: %v", err)
	}

	// A fresh 32-byte X25519 public key and a fresh 12-byte nonce, valid in
	// shape so the tamper reaches the tag check rather than an early length
	// reject.
	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other eph: %v", err)
	}
	otherEphB64 := base64.RawURLEncoding.EncodeToString(otherEph.PublicKey().Bytes())
	otherNonceB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 12))

	tampers := []struct {
		name  string
		field string
		value any
	}{
		{"type", "type", "network.tulpa.encrypted"},
		{"from", "from", "did:web:attacker.example"},
		{"ephemeralKey", "ephemeralKey", otherEphB64},
		{"nonce", "nonce", otherNonceB64},
		{"timestamp", "timestamp", "2026-07-11T12:00:01.000Z"},
		{"messageNonce", "messageNonce", "ffffffffffffffffffffffffffffffff"},
	}
	for _, tc := range tampers {
		t.Run(tc.name, func(t *testing.T) {
			bad := cloneEnvelope(env)
			bad[tc.field] = tc.value
			if _, err := DecryptInkPayload(bad, privHex, to); err == nil {
				t.Errorf("tampered %s accepted", tc.field)
			}
		})
	}

	t.Run("ciphertext", func(t *testing.T) {
		bad := cloneEnvelope(env)
		ct, err := base64.RawURLEncoding.DecodeString(env["ciphertext"].(string))
		if err != nil {
			t.Fatalf("decode ciphertext: %v", err)
		}
		ct[0] ^= 0x01
		bad["ciphertext"] = base64.RawURLEncoding.EncodeToString(ct)
		if _, err := DecryptInkPayload(bad, privHex, to); err == nil {
			t.Error("tampered ciphertext accepted")
		}
	})
}

// TestEncryptInkPayloadWrongRecipientFails confirms a Go-sealed envelope does not
// decrypt under a different recipient static key: the AAD recipientKey is
// recomputed from the local private key and the ECDH secret differs, so the tag
// fails.
func TestEncryptInkPayloadWrongRecipientFails(t *testing.T) {
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	pubHex, _ := recipientKeypair(t)
	_, wrongPrivHex := recipientKeypair(t)
	env, err := EncryptInkPayload(map[string]any{"from": from, "to": to, "body": "hello"}, from, pubHex, "2026-07-11T12:00:00.000Z", "0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := DecryptInkPayload(env, wrongPrivHex, to); err == nil {
		t.Error("envelope decrypted under the wrong recipient key")
	}
}

// TestEncryptInkPayloadRejectsBadInput pins the sealer's input guards.
func TestEncryptInkPayloadRejectsBadInput(t *testing.T) {
	pubHex, _ := recipientKeypair(t)
	base := func() (map[string]any, string, string, string) {
		return map[string]any{"from": "a", "to": "b"}, "did:web:s", "2026-07-11T12:00:00.000Z", "0123456789abcdef0123456789abcdef"
	}
	if _, err := EncryptInkPayload(nil, "did:web:s", pubHex, "2026-07-11T12:00:00.000Z", "n", nil); err == nil {
		t.Error("nil plaintext accepted")
	}
	pt, sender, ts, mn := base()
	if _, err := EncryptInkPayload(pt, "", pubHex, ts, mn, nil); err == nil {
		t.Error("empty senderDid accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, pubHex, "", mn, nil); err == nil {
		t.Error("empty timestamp accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, pubHex, ts, "", nil); err == nil {
		t.Error("empty messageNonce accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, "zz", ts, mn, nil); err == nil {
		t.Error("non-hex recipient key accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, pubHex, ts, mn, &InkEncryptOptions{MessageType: "network.other.encrypted"}); err == nil {
		t.Error("unknown messageType accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, pubHex, ts, mn, &InkEncryptOptions{EphemeralPrivateKey: make([]byte, 31)}); err == nil {
		t.Error("short ephemeral key accepted")
	}
	if _, err := EncryptInkPayload(pt, sender, pubHex, ts, mn, &InkEncryptOptions{AESNonce: make([]byte, 11)}); err == nil {
		t.Error("short AES nonce accepted")
	}
	// Plaintext preflight parity with the reference: a non-JCS-safe number in
	// the plaintext is refused before sealing, mirroring encryptInkPayload's
	// isWithinCanonicalizeBounds guard.
	if _, err := EncryptInkPayload(map[string]any{"from": "a", "to": "b", "x": 1.5}, sender, pubHex, ts, mn, nil); err == nil {
		t.Error("fractional plaintext number accepted")
	}
	// A native Go integer past the JS safe-integer range would seal a value a
	// reference decoder reads with precision loss, so the preflight rejects it.
	if _, err := EncryptInkPayload(map[string]any{"from": "a", "to": "b", "x": int64(1) << 60}, sender, pubHex, ts, mn, nil); err == nil {
		t.Error("out-of-range native integer accepted")
	}
	// A native integer within the safe range still seals.
	if _, err := EncryptInkPayload(map[string]any{"from": "a", "to": "b", "x": int64(1234)}, sender, pubHex, ts, mn, nil); err != nil {
		t.Errorf("safe native integer rejected: %v", err)
	}
	// A non-JSON in-memory type in the plaintext is refused before marshal, so
	// the seal cannot mint plaintext a reference producer would never emit.
	type notJSON struct{ A int }
	if _, err := EncryptInkPayload(map[string]any{"from": "a", "to": "b", "x": notJSON{A: 1}}, sender, pubHex, ts, mn, nil); err == nil {
		t.Error("struct-valued plaintext accepted")
	}
}

// TestEncryptInkPayloadAADPin cross-impl-pins the AAD member set and ordering and
// the derived AES key. With a fixed ephemeral private key and a fixed AES nonce
// (the determinism seam), the sealer's AAD bytes and the HKDF-derived key are
// reproducible, so the exact bytes are asserted here and mirrored in the TypeScript
// reference (test/go-encryption-sealing-interop.test.ts). The full ciphertext is
// not pinned because AES-GCM output is still nonce/key-derived, but the AAD member
// set, its JCS ordering, and the key schedule are the cross-implementation contract.
func TestEncryptInkPayloadAADPin(t *testing.T) {
	// RFC 7748 §6.1 test vectors: recipient is Alice, ephemeral is Bob.
	// These hex constants are published RFC 7748 §6.1 fixtures (public standard
	// test vectors, not secrets) and are allowlisted for gitleaks' generic-api-key
	// rule in .gitleaks.toml.
	const recipientPrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	const recipientPubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	const ephemeralPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	const from = "did:web:sender.example"
	const to = "did:web:recipient.example"
	const timestamp = "2026-07-11T12:00:00.000Z"
	const messageNonce = "0123456789abcdef0123456789abcdef"

	ephPriv, err := hex.DecodeString(ephemeralPrivHex)
	if err != nil {
		t.Fatalf("eph hex: %v", err)
	}
	aesNonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	env, err := EncryptInkPayload(
		map[string]any{"from": from, "to": to, "body": "hello", "n": 42},
		from, recipientPubHex, timestamp, messageNonce,
		&InkEncryptOptions{EphemeralPrivateKey: ephPriv, AESNonce: aesNonce, MessageType: "network.ink.encrypted"},
	)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	const wantEphemeralKey = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
	const wantNonce = "AQIDBAUGBwgJCgsM"
	const wantRecipientKey = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
	if env["ephemeralKey"] != wantEphemeralKey {
		t.Errorf("ephemeralKey = %v, want %v", env["ephemeralKey"], wantEphemeralKey)
	}
	if env["nonce"] != wantNonce {
		t.Errorf("nonce = %v, want %v", env["nonce"], wantNonce)
	}

	// Pin the exact AAD bytes the sealer binds. inkEncryptAAD is the single AAD
	// builder both seal and decrypt call, so this pins the bytes both directions
	// authenticate over.
	wantAAD := "ink/0.1:envelope\n" +
		`{"ephemeralKey":"` + wantEphemeralKey + `",` +
		`"from":"` + from + `",` +
		`"messageNonce":"` + messageNonce + `",` +
		`"nonce":"` + wantNonce + `",` +
		`"protocol":"ink/0.1",` +
		`"recipientKey":"` + wantRecipientKey + `",` +
		`"timestamp":"` + timestamp + `",` +
		`"type":"network.ink.encrypted"}`
	gotAAD, err := inkEncryptAAD("network.ink.encrypted", from, wantRecipientKey, wantEphemeralKey, wantNonce, timestamp, messageNonce)
	if err != nil {
		t.Fatalf("aad: %v", err)
	}
	if string(gotAAD) != wantAAD {
		t.Errorf("AAD mismatch\n got: %q\nwant: %q", string(gotAAD), wantAAD)
	}

	// Pin the HKDF-derived AES-256 key for the fixed ECDH inputs.
	recipPriv, err := hex.DecodeString(recipientPrivHex)
	if err != nil {
		t.Fatalf("recip hex: %v", err)
	}
	curve := ecdh.X25519()
	rp, err := curve.NewPrivateKey(recipPriv)
	if err != nil {
		t.Fatalf("recip key: %v", err)
	}
	ep, err := curve.NewPrivateKey(ephPriv)
	if err != nil {
		t.Fatalf("eph key: %v", err)
	}
	shared, err := ep.ECDH(rp.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	key, err := inkEncryptKey(shared)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	const wantKeyHex = "ab2bd1b7028e959bed6cb15c7228e4f8ea4c3a3fa86719d9eb26c3f56881215e"
	if hex.EncodeToString(key) != wantKeyHex {
		t.Errorf("derived key = %s, want %s", hex.EncodeToString(key), wantKeyHex)
	}

	// The sealed envelope round-trips, proving EncryptInkPayload actually used
	// the pinned AAD and key (a mismatch would fail the tag).
	got, err := DecryptInkPayload(env, recipientPrivHex, to)
	if err != nil {
		t.Fatalf("pinned envelope decrypt rejected: %v", err)
	}
	if got["body"] != "hello" {
		t.Errorf("decrypted body = %v, want hello", got["body"])
	}
}
