package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func signReceipt(t *testing.T, priv ed25519.PrivateKey, eventID string, leafIndex, treeSize int, rootHash, ts string) string {
	t.Helper()
	core := map[string]interface{}{
		"eventId":   eventID,
		"leafIndex": float64(leafIndex),
		"treeSize":  float64(treeSize),
		"rootHash":  rootHash,
		"timestamp": ts,
	}
	canonical, err := canonicalizeJSON(core)
	if err != nil {
		t.Fatalf("canonicalize core: %v", err)
	}
	sig := ed25519.Sign(priv, []byte("ink/audit-inclusion/v1\n"+canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func TestParseInclusionReceipt(t *testing.T) {
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	// An integer leafIndex/treeSize written with a decimal or exponent is the
	// same integer, matching the reference's Number.isInteger.
	for _, spelling := range []string{`1`, `1.0`, `1e0`} {
		raw := []byte(`{"eventId":"e","leafIndex":` + spelling + `,"treeSize":4,"rootHash":"` + root + `","inclusionProof":[],"timestamp":"t","serviceSignature":"s"}`)
		r, ok := ParseInclusionReceipt(raw)
		if !ok || r.LeafIndex != 1 {
			t.Errorf("leafIndex spelling %q: parsed=%v ok=%v, want 1", spelling, r.LeafIndex, ok)
		}
	}
	// A fractional index is not an integer.
	if _, ok := ParseInclusionReceipt([]byte(`{"eventId":"e","leafIndex":1.5,"treeSize":4,"rootHash":"` + root + `","inclusionProof":[],"timestamp":"t","serviceSignature":"s"}`)); ok {
		t.Error("fractional leafIndex parsed")
	}
	// A lone surrogate escape in a signed field is rejected before unmarshal.
	if _, ok := ParseInclusionReceipt([]byte(`{"eventId":"\ud800","leafIndex":1,"treeSize":4,"rootHash":"` + root + `","inclusionProof":[],"timestamp":"t","serviceSignature":"s"}`)); ok {
		t.Error("lone-surrogate eventId parsed")
	}
	// A non-object is rejected.
	if _, ok := ParseInclusionReceipt([]byte(`"not-a-receipt"`)); ok {
		t.Error("non-object receipt parsed")
	}
}

func TestVerifyInclusionReceipt(t *testing.T) {
	seed := sha256.Sum256([]byte("go-receipt-unit-test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	// Single-leaf tree: the root is the one leaf and the proof is empty.
	event := map[string]interface{}{"id": "evt-x", "type": "connection_request"}
	leaf, ok := ComputeAuditMerkleLeafHash(event)
	if !ok {
		t.Fatal("leaf hash failed")
	}
	other, _ := ComputeAuditMerkleLeafHash(map[string]interface{}{"id": "evt-y"})
	const ts = "2026-06-15T12:00:00.000Z"
	sig := signReceipt(t, priv, "evt-x", 0, 1, leaf, ts)
	receipt := InclusionReceipt{
		EventID: "evt-x", LeafIndex: 0, TreeSize: 1, RootHash: leaf,
		InclusionProof: []string{}, Timestamp: ts, ServiceSignature: sig,
	}

	// Accept across all three optional modes.
	if !VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{}) {
		t.Error("signature-only valid receipt rejected")
	}
	if !VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{Event: event}) {
		t.Error("event-bound valid receipt rejected")
	}
	if !VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{EventHash: leaf}) {
		t.Error("eventHash valid receipt rejected")
	}
	if !VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{LaterCheckpoint: &CheckpointRef{TreeSize: 5, RootHash: other}}) {
		t.Error("newer-checkpoint receipt rejected")
	}

	// Tampered signed field breaks the signature.
	tampered := receipt
	tampered.Timestamp = "2026-01-01T00:00:00.000Z"
	if VerifyInclusionReceipt(tampered, pub, ReceiptVerifyOptions{}) {
		t.Error("tampered timestamp accepted")
	}

	// Wrong witness key.
	otherSeed := sha256.Sum256([]byte("other-witness"))
	otherPub := ed25519.NewKeyFromSeed(otherSeed[:]).Public().(ed25519.PublicKey)
	if VerifyInclusionReceipt(receipt, otherPub, ReceiptVerifyOptions{}) {
		t.Error("wrong witness key accepted")
	}

	// Structural rejections.
	bad := receipt
	bad.TreeSize = 0
	if VerifyInclusionReceipt(bad, pub, ReceiptVerifyOptions{}) {
		t.Error("treeSize 0 accepted")
	}

	// Event id mismatch and out-of-tree event.
	if VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{Event: map[string]interface{}{"id": "evt-z"}}) {
		t.Error("event id mismatch accepted")
	}
	if VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{EventHash: other}) {
		t.Error("out-of-tree eventHash accepted")
	}

	// Checkpoint rollback and fork.
	if VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{LaterCheckpoint: &CheckpointRef{TreeSize: 0, RootHash: leaf}}) {
		t.Error("rolled-back checkpoint accepted")
	}
	if VerifyInclusionReceipt(receipt, pub, ReceiptVerifyOptions{LaterCheckpoint: &CheckpointRef{TreeSize: 1, RootHash: other}}) {
		t.Error("forked checkpoint accepted")
	}
}
