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
