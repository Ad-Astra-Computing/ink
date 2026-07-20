package ink

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// A fixed request used across the signer tests. Its body has members out of
// canonical order so a passing signature also proves the signer canonicalizes
// (JCS) the body before signing.
func fixedSignInput() InkSignInput {
	return InkSignInput{
		Method:       "POST",
		Path:         "/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent",
		RecipientDid: "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
		Body: map[string]interface{}{
			"protocol": "ink/0.1",
			"intent":   "ping",
			"payload":  map[string]interface{}{"note": "hello", "scope": "deep"},
		},
		Timestamp: "2026-06-11T00:00:00.000Z",
	}
}

// TestSignInkMessageRoundTrip signs a request and confirms the Go verifier
// accepts the freshly minted signature: the producing and verifying halves of
// §3.3 agree on the signed bytes.
func TestSignInkMessageRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	in := fixedSignInput()
	sig, err := SignInkMessage(in, priv)
	if err != nil {
		t.Fatalf("SignInkMessage: %v", err)
	}
	if !signatureRe.MatchString(sig) {
		t.Fatalf("signature is not 86 base64url chars: %q", sig)
	}
	if !VerifyInkSignature(in, sig, pub) {
		t.Fatal("Go verifier rejected a Go-signed request")
	}
}

// TestSignInkMessageTamperRejected pins that a signature is bound to every part
// of the base: mutating the body, path, timestamp, or recipient makes the Go
// verifier reject the original signature.
func TestSignInkMessageTamperRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	in := fixedSignInput()
	sig, err := SignInkMessage(in, priv)
	if err != nil {
		t.Fatalf("SignInkMessage: %v", err)
	}
	tampers := map[string]func(*InkSignInput){
		"body":      func(x *InkSignInput) { x.Body = map[string]interface{}{"intent": "pong"} },
		"path":      func(x *InkSignInput) { x.Path = "/ink/v1/other/intent" },
		"timestamp": func(x *InkSignInput) { x.Timestamp = "2026-06-11T00:00:01.000Z" },
		"recipient": func(x *InkSignInput) { x.RecipientDid = "tulpa:zAttacker" },
		"method":    func(x *InkSignInput) { x.Method = "GET" },
	}
	for name, mut := range tampers {
		tampered := fixedSignInput()
		mut(&tampered)
		if VerifyInkSignature(tampered, sig, pub) {
			t.Errorf("verifier accepted a signature after tampering with %s", name)
		}
	}
}

// TestSignInkMessageRejectsBadInput pins that the signer refuses inputs the
// verifier would refuse: a wrong-size private key and a base BuildSignatureBase
// cannot build (a CR/LF-bearing scalar).
func TestSignInkMessageRejectsBadInput(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := SignInkMessage(fixedSignInput(), ed25519.PrivateKey(make([]byte, 10))); err == nil {
		t.Error("SignInkMessage accepted a wrong-size private key")
	}
	bad := fixedSignInput()
	bad.Path = "/a\n/b"
	if _, err := SignInkMessage(bad, priv); err == nil {
		t.Error("SignInkMessage accepted a scalar containing a newline")
	}
}

// TestSignatureBaseBytesPinned is the cross-impl byte-exact pin: a fixed seed
// and a fixed request produce an exact signature base and Ed25519 signature.
// Any drift in the base construction (field order, separators, JCS, the fixed
// ink/0.1 domain line) or the encoding changes these bytes. The same seed,
// request, expected base, and expected signature are asserted on the TypeScript
// side (test/go-request-signing-interop.test.ts) so both implementations are
// pinned to one wire value.
func TestSignatureBaseBytesPinned(t *testing.T) {
	seed, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	const wantPubHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	if got := hex.EncodeToString(pub); got != wantPubHex {
		t.Fatalf("public key = %s, want %s", got, wantPubHex)
	}

	in := fixedSignInput()

	wantBase := "ink/0.1\nPOST\n/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent\n" +
		"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX\n" +
		"{\"intent\":\"ping\",\"payload\":{\"note\":\"hello\",\"scope\":\"deep\"},\"protocol\":\"ink/0.1\"}\n" +
		"2026-06-11T00:00:00.000Z"
	gotBase, err := BuildSignatureBase(in)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	if gotBase != wantBase {
		t.Fatalf("signature base bytes drifted\n got: %q\nwant: %q", gotBase, wantBase)
	}

	const wantSig = "4coNdBbBjKh6blEoMVuKMb7-emCrKNFPhbuuj6UGtZkK_xCN53_06hWqo4u1oFCf7lUo9XUuBHi6Z2tRZxwlBA"
	gotSig, err := SignInkMessage(in, priv)
	if err != nil {
		t.Fatalf("SignInkMessage: %v", err)
	}
	if gotSig != wantSig {
		t.Fatalf("signature drifted\n got: %s\nwant: %s", gotSig, wantSig)
	}
	if !VerifyInkSignature(in, gotSig, pub) {
		t.Fatal("pinned signature does not verify under the Go verifier")
	}
}

// TestBuildAuthHeader pins the §3.3 Authorization-header grammar in both forms
// and the validation the reference builder enforces.
func TestBuildAuthHeader(t *testing.T) {
	sig := "4coNdBbBjKh6blEoMVuKMb7-emCrKNFPhbuuj6UGtZkK_xCN53_06hWqo4u1oFCf7lUo9XUuBHi6Z2tRZxwlBA"

	got, err := BuildAuthHeader(sig, "")
	if err != nil {
		t.Fatalf("BuildAuthHeader without keyId: %v", err)
	}
	if want := "INK-Ed25519 " + sig; got != want {
		t.Errorf("header = %q, want %q", got, want)
	}

	got, err = BuildAuthHeader(sig, "key-2026")
	if err != nil {
		t.Fatalf("BuildAuthHeader with keyId: %v", err)
	}
	if want := "INK-Ed25519 " + sig + " keyId=key-2026"; got != want {
		t.Errorf("header = %q, want %q", got, want)
	}

	if _, err := BuildAuthHeader("too-short", ""); err == nil {
		t.Error("BuildAuthHeader accepted a signature that is not 86 base64url chars")
	}
	if _, err := BuildAuthHeader(sig, "bad key"); err == nil {
		t.Error("BuildAuthHeader accepted a keyId with a space")
	}
	if _, err := BuildAuthHeader(sig, "bad\nkey"); err == nil {
		t.Error("BuildAuthHeader accepted a keyId with a newline")
	}
}

// TestSignInkRequest pins the one-shot: it returns a signature the Go verifier
// accepts and the matching Authorization header.
func TestSignInkRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	in := fixedSignInput()
	sig, hdr, err := SignInkRequest(in, priv, "key-2026")
	if err != nil {
		t.Fatalf("SignInkRequest: %v", err)
	}
	if !VerifyInkSignature(in, sig, pub) {
		t.Fatal("Go verifier rejected a SignInkRequest signature")
	}
	if want := "INK-Ed25519 " + sig + " keyId=key-2026"; hdr != want {
		t.Errorf("header = %q, want %q", hdr, want)
	}
}
