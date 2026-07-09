package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
