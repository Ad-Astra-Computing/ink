package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// conformanceWitnessKey derives the fixed witness key the conformance generator
// uses: seed = SHA-256("ink-conformance-v1-test-key"). Signing with this key
// reproduces the frozen vectors' signatures byte for byte.
func conformanceWitnessKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("ink-conformance-v1-test-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// TestSignReceiptCoreReproducesFrozenVector pins that the Go receipt signer emits
// the exact serviceSignature the frozen inclusion-receipt corpus carries, not
// merely a signature the verifier happens to accept.
func TestSignReceiptCoreReproducesFrozenVector(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	vf := loadVectors(t, "inclusion-receipt")
	found := false
	for _, c := range vf.Cases {
		if c.CaseID != "valid-signature-only-accepts" {
			continue
		}
		found = true
		var in struct {
			Receipt struct {
				EventID          string `json:"eventId"`
				LeafIndex        int    `json:"leafIndex"`
				TreeSize         int    `json:"treeSize"`
				RootHash         string `json:"rootHash"`
				Timestamp        string `json:"timestamp"`
				ServiceSignature string `json:"serviceSignature"`
			} `json:"receipt"`
			WitnessPublicKeyHex string `json:"witnessPublicKeyHex"`
		}
		mustUnmarshalCase(t, c, &in)
		if hex.EncodeToString(pub) != in.WitnessPublicKeyHex {
			t.Fatalf("witness key mismatch: derived %s, vector %s", hex.EncodeToString(pub), in.WitnessPublicKeyHex)
		}
		sig, err := signReceiptCore(in.Receipt.EventID, in.Receipt.LeafIndex, in.Receipt.TreeSize, in.Receipt.RootHash, in.Receipt.Timestamp, priv)
		if err != nil {
			t.Fatalf("signReceiptCore: %v", err)
		}
		if sig != in.Receipt.ServiceSignature {
			t.Errorf("serviceSignature = %s, want %s", sig, in.Receipt.ServiceSignature)
		}
	}
	if !found {
		t.Fatal("valid-signature-only-accepts vector not found")
	}
}

// TestSignReceiptCoreRefusesOversizedCore pins the emitter-side canonical
// ceiling: the Go witness refuses to sign a receipt core whose canonical form
// exceeds maxCanonicalBodyBytes UTF-16 code units, mirroring the reference
// jcsCanonicalize post-canonicalize check that the TS receipt-signing path runs
// through. The reference caps result.length, a JS string length in UTF-16 code
// units, so Go measures the same units (utf16Len), not bytes, despite the
// byte-named constant. Without this bound a Go witness could mint a receipt its
// own ParseInclusionReceipt/MaxInclusionReceiptBytes boundary rejects, and the
// MaxInclusionReceiptBytes derivation comment would be false.
func TestSignReceiptCoreRefusesOversizedCore(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const ts = "2026-06-15T12:00:00.000Z"

	// An eventId over the code-unit cap. The core is {eventId, leafIndex,
	// treeSize, rootHash, timestamp}; a plain-ASCII eventId of
	// maxCanonicalBodyBytes+1 code units alone exceeds the cap once the other
	// members are added.
	huge := strings.Repeat("x", maxCanonicalBodyBytes)
	if _, err := signReceiptCore(huge, 0, 1, root, ts, priv); err == nil {
		t.Error("signReceiptCore signed an oversized core")
	}
	if _, err := SignInclusionReceipt([]string{"leaf"}, 0, huge, ts, priv); err == nil {
		t.Error("SignInclusionReceipt signed an oversized core")
	}

	// A core comfortably under the cap still signs.
	if _, err := signReceiptCore("evt", 0, 1, root, ts, priv); err != nil {
		t.Errorf("signReceiptCore rejected a well-formed core: %v", err)
	}
}

// TestSignReceiptCoreNonASCIIUnderCodeUnitCap is the parity pin for the round-4
// finding: the reference caps the canonical string length in UTF-16 code units,
// not UTF-8 bytes. A non-ASCII eventId can sit under the code-unit ceiling while
// its UTF-8 encoding runs well over maxCanonicalBodyBytes bytes (a BMP character
// like U+00E9 is 1 code unit that JCS emits unescaped as 2 UTF-8 bytes). TS
// signs such a core and both object verifiers accept it, so the Go emitter must
// sign it too. A byte-measured Go guard would refuse it, reintroducing the
// issuer-side parity regression.
func TestSignReceiptCoreNonASCIIUnderCodeUnitCap(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const ts = "2026-06-15T12:00:00.000Z"

	// U+00E9 is 1 UTF-16 code unit that the canonicalizer emits unescaped as 2
	// UTF-8 bytes per code unit, not the 6-byte-per-code-unit worst case of
	// non-canonical wire escaping. 700_000 code units is under the 1_048_576
	// code-unit cap but at 2 bytes per unit its canonical byte length exceeds
	// maxCanonicalBodyBytes, so a byte-measured guard would wrongly refuse it.
	eventID := strings.Repeat("é", 700_000)
	if utf16Len(eventID) > maxCanonicalBodyBytes {
		t.Fatalf("test eventId over the code-unit cap: %d", utf16Len(eventID))
	}
	sig, err := signReceiptCore(eventID, 0, 1, root, ts, priv)
	if err != nil {
		t.Fatalf("signReceiptCore refused a core under the code-unit cap: %v", err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}

	r, err := SignInclusionReceipt(buildLeaves("receipt-leaf", 1), 0, eventID, ts, priv)
	if err != nil {
		t.Fatalf("SignInclusionReceipt refused a core under the code-unit cap: %v", err)
	}
	// The object verifier must accept what the emitter signed.
	if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{}) {
		t.Error("object verifier rejected a receipt the emitter signed under the code-unit cap")
	}
}

func TestSignInclusionReceiptRoundTrip(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	_, otherPub := func() (ed25519.PrivateKey, ed25519.PublicKey) {
		seed := sha256.Sum256([]byte("other-witness"))
		p := ed25519.NewKeyFromSeed(seed[:])
		return p, p.Public().(ed25519.PublicKey)
	}()
	ts := "2026-07-09T00:00:00.000Z"
	for _, size := range []int{1, 4, 5, 8} {
		leaves := buildLeaves("receipt-leaf", size)
		for i := 0; i < size; i++ {
			r, err := SignInclusionReceipt(leaves, i, "evt-1", ts, priv)
			if err != nil {
				t.Fatalf("size %d idx %d: SignInclusionReceipt: %v", size, i, err)
			}
			// Structure and signature only.
			if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{}) {
				t.Errorf("size %d idx %d: signature-only verify failed", size, i)
			}
			// Proof walk: the leaf hash at this index must reconstruct rootHash.
			if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{EventHash: leaves[i]}) {
				t.Errorf("size %d idx %d: proof-walk verify failed", size, i)
			}
			// A newer checkpoint at a larger size is consistent.
			if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{LaterCheckpoint: &CheckpointRef{TreeSize: size + 4, RootHash: r.RootHash}}) {
				t.Errorf("size %d idx %d: later-checkpoint verify failed", size, i)
			}
			// Wrong witness key must fail.
			if VerifyInclusionReceipt(r, otherPub, ReceiptVerifyOptions{}) {
				t.Errorf("size %d idx %d: verified against the wrong witness key", size, i)
			}
		}
	}
	if _, err := SignInclusionReceipt(buildLeaves("x", 3), 3, "e", ts, priv); err == nil {
		t.Error("out-of-range index accepted")
	}
	if _, err := SignInclusionReceipt(buildLeaves("x", 3), 0, "", ts, priv); err == nil {
		t.Error("empty eventId accepted")
	}
	if _, err := SignInclusionReceipt(buildLeaves("x", 3), 0, "evt\xff", ts, priv); err == nil {
		t.Error("invalid-UTF-8 eventId accepted")
	}
}

func TestSignCheckpointRoundTrip(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	origin := "example.com/witness"
	root, err := MerkleTreeHead(buildLeaves("cp", 5))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignCheckpoint(origin, 5, root, priv)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	data, ok := VerifyCheckpoint(signed, pub, origin)
	if !ok {
		t.Fatal("round-trip verify failed")
	}
	if data.Origin != origin || data.TreeSize != 5 || data.RootHash != root {
		t.Errorf("parsed data = %+v", data)
	}
	// The empty tree signs and verifies with the empty-tree root.
	emptyRoot, _ := MerkleTreeHead(nil)
	if s, err := SignCheckpoint(origin, 0, emptyRoot, priv); err != nil {
		t.Fatalf("empty checkpoint: %v", err)
	} else if _, ok := VerifyCheckpoint(s, pub, origin); !ok {
		t.Error("empty-tree checkpoint did not verify")
	}
	// Negatives.
	if _, ok := VerifyCheckpoint(signed, pub, "other.example/log"); ok {
		t.Error("verified against the wrong origin")
	}
	_, otherPub := func() (ed25519.PrivateKey, ed25519.PublicKey) {
		seed := sha256.Sum256([]byte("cp-other"))
		p := ed25519.NewKeyFromSeed(seed[:])
		return p, p.Public().(ed25519.PublicKey)
	}()
	if _, ok := VerifyCheckpoint(signed, otherPub, origin); ok {
		t.Error("verified against the wrong witness key")
	}
	tampered := []byte(signed)
	tampered[0] ^= 0x01 // flip a byte of the origin line inside the signed body
	if _, ok := VerifyCheckpoint(string(tampered), pub, origin); ok {
		t.Error("verified a tampered body")
	}
}

func TestSignCheckpointValidation(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	root, _ := MerkleTreeHead(buildLeaves("v", 2))
	if _, err := SignCheckpoint("", 2, root, priv); err == nil {
		t.Error("empty origin accepted")
	}
	if _, err := SignCheckpoint("has\nnewline", 2, root, priv); err == nil {
		t.Error("origin with newline accepted")
	}
	if _, err := SignCheckpoint("o", -1, root, priv); err == nil {
		t.Error("negative tree size accepted")
	}
	if _, err := SignCheckpoint("o", 2, "not-hex", priv); err == nil {
		t.Error("non-hex root accepted")
	}
	if _, err := SignCheckpoint("bad\xfforigin", 2, root, priv); err == nil {
		t.Error("invalid-UTF-8 origin accepted")
	}
	if _, err := SignCheckpoint("origin with space", 2, root, priv); err == nil {
		t.Error("origin with a space accepted; it would not round-trip")
	}
}

func TestVerifyCheckpointRejectsMalformed(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	origin := "example.com/witness"
	root, _ := MerkleTreeHead(buildLeaves("m", 3))
	signed, _ := SignCheckpoint(origin, 3, root, priv)

	reject := map[string]string{
		"empty":            "",
		"no separator":     origin + "\n3\n" + root + "\n",
		"body only":        origin + "\n3\n" + root,
		"missing sig line": origin + "\n3\n" + root + "\n\n",
		"bad sig line":     origin + "\n3\n" + root + "\n\n-- " + origin + " not-base64!!",
	}
	for name, s := range reject {
		if _, ok := VerifyCheckpoint(s, pub, origin); ok {
			t.Errorf("%s: verified but should reject", name)
		}
	}
	// A short public key rejects.
	if _, ok := VerifyCheckpoint(signed, pub[:16], origin); ok {
		t.Error("short public key accepted")
	}
	// An empty expected origin rejects.
	if _, ok := VerifyCheckpoint(signed, pub, ""); ok {
		t.Error("empty expected origin accepted")
	}
	// Invalid UTF-8 in the signed note rejects.
	if _, ok := VerifyCheckpoint(signed+"\xff", pub, origin); ok {
		t.Error("invalid-UTF-8 signed note accepted")
	}
}
