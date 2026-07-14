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
	// Raw invalid UTF-8 in a signed field is rejected before unmarshal, so
	// encoding/json cannot normalize it to U+FFFD and verify a signature over
	// bytes that differ from the wire.
	if _, ok := ParseInclusionReceipt([]byte("{\"eventId\":\"e\xff\",\"leafIndex\":1,\"treeSize\":4,\"rootHash\":\"" + root + "\",\"inclusionProof\":[],\"timestamp\":\"t\",\"serviceSignature\":\"s\"}")); ok {
		t.Error("raw invalid utf-8 eventId parsed")
	}
	// A non-object is rejected.
	if _, ok := ParseInclusionReceipt([]byte(`"not-a-receipt"`)); ok {
		t.Error("non-object receipt parsed")
	}
}

// TestParseInclusionReceiptRejectsOversizedBody pins the byte-length cap the Go
// parser applies before json.Unmarshal, so a pathological blob is never decoded
// into the receipt struct.
func TestParseInclusionReceiptRejectsOversizedBody(t *testing.T) {
	if MaxInclusionReceiptBytes != 8*1024*1024 {
		t.Errorf("MaxInclusionReceiptBytes: got %d, want %d", MaxInclusionReceiptBytes, 8*1024*1024)
	}
	raw := make([]byte, MaxInclusionReceiptBytes+1)
	for i := range raw {
		raw[i] = 'x'
	}
	if _, ok := ParseInclusionReceipt(raw); ok {
		t.Error("oversized receipt body parsed")
	}
}

// TestParseInclusionReceiptAcceptsBodyUnderCap pins that a well-formed receipt
// under the cap still parses, so the cap only rejects pathological input.
func TestParseInclusionReceiptAcceptsBodyUnderCap(t *testing.T) {
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	raw := []byte(`{"eventId":"e","leafIndex":1,"treeSize":4,"rootHash":"` + root + `","inclusionProof":[],"timestamp":"t","serviceSignature":"s"}`)
	if len(raw) > MaxInclusionReceiptBytes {
		t.Fatalf("fixture receipt %d bytes exceeds cap %d", len(raw), MaxInclusionReceiptBytes)
	}
	if _, ok := ParseInclusionReceipt(raw); !ok {
		t.Error("well-formed receipt under cap did not parse")
	}
}

// TestVerifyReceiptSignatureRejectsOverCapCore pins that the receipt signature
// verifier rejects a receipt whose canonical signed core exceeds the
// maxCanonicalBodyBytes (1,048,576 UTF-16 code units) ceiling, mirroring the
// reference jcsCanonicalize post-canonicalize check in
// src/audit/inclusion-receipt.ts (which caps result.length in code units). The
// oversized eventId keeps the raw receipt under MaxInclusionReceiptBytes (8 MiB)
// and passes checkReceiptShape, so without the verify-side cap a Go receiver
// would accept a receipt the TS verifier refuses. The signature is a genuine
// witness signature over the over-cap core, so only the cap can reject it.
func TestVerifyReceiptSignatureRejectsOverCapCore(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const ts = "2026-06-11T00:00:00.000Z"
	// An eventId of ~1.1M ASCII chars makes the canonical core exceed 1,048,576
	// code units while the raw receipt stays well under the 8 MiB parser cap.
	bigEventID := ""
	{
		b := make([]byte, maxCanonicalBodyBytes+50_000)
		for i := range b {
			b[i] = 'a'
		}
		bigEventID = string(b)
	}
	sig := signReceipt(t, priv, bigEventID, 1, 4, root, ts)
	r := InclusionReceipt{
		EventID:          bigEventID,
		LeafIndex:        1,
		TreeSize:         4,
		RootHash:         root,
		InclusionProof:   []string{},
		Timestamp:        ts,
		ServiceSignature: sig,
	}
	if !checkReceiptShape(r) {
		t.Fatal("fixture receipt should pass shape check")
	}
	if verifyReceiptSignature(r, pub) {
		t.Error("verifier accepted a receipt whose canonical core exceeds the cap")
	}
}

// TestVerifyReceiptSignatureAcceptsUnderCapCore pins that a genuine receipt whose
// canonical core stays under the cap still verifies, so the added cap is
// reject-only and does not change any accepted-within-bounds input.
func TestVerifyReceiptSignatureAcceptsUnderCapCore(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	const ts = "2026-06-11T00:00:00.000Z"
	sig := signReceipt(t, priv, "event-1", 1, 4, root, ts)
	r := InclusionReceipt{
		EventID:          "event-1",
		LeafIndex:        1,
		TreeSize:         4,
		RootHash:         root,
		InclusionProof:   []string{},
		Timestamp:        ts,
		ServiceSignature: sig,
	}
	if !verifyReceiptSignature(r, pub) {
		t.Error("verifier rejected a genuine under-cap receipt")
	}
}

// TestParseCheckpointRefRejectsOversizedBody pins the byte-length cap on the
// checkpoint reference parser.
func TestParseCheckpointRefRejectsOversizedBody(t *testing.T) {
	if MaxCheckpointRefBytes != 64*1024 {
		t.Errorf("MaxCheckpointRefBytes: got %d, want %d", MaxCheckpointRefBytes, 64*1024)
	}
	raw := make([]byte, MaxCheckpointRefBytes+1)
	for i := range raw {
		raw[i] = 'x'
	}
	if _, ok := ParseCheckpointRef(raw); ok {
		t.Error("oversized checkpoint ref parsed")
	}
}

// TestParseCheckpointRefAcceptsBodyUnderCap pins that a well-formed checkpoint
// reference under the cap still parses.
func TestParseCheckpointRefAcceptsBodyUnderCap(t *testing.T) {
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	raw := []byte(`{"treeSize":4,"rootHash":"` + root + `"}`)
	if len(raw) > MaxCheckpointRefBytes {
		t.Fatalf("fixture checkpoint %d bytes exceeds cap %d", len(raw), MaxCheckpointRefBytes)
	}
	if _, ok := ParseCheckpointRef(raw); !ok {
		t.Error("well-formed checkpoint ref under cap did not parse")
	}
}

// TestParseInclusionReceiptToleratesExtraMembers pins that an unknown extra
// member is ignored structurally, matching the reference shape check, so the byte
// cap is the only thing that bounds a receipt carrying extra fields. The headroom
// in MaxInclusionReceiptBytes exists because both implementations tolerate such
// members structurally. Parity is only structural: the raw-layer UTF-8 and
// lone-surrogate scans this parser runs before unmarshal span the whole body
// including unknown members, a byte-edge behavior the decoded-object reference
// API never sees because it receives an already-parsed receipt with no raw
// unknown members.
func TestParseInclusionReceiptToleratesExtraMembers(t *testing.T) {
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	raw := []byte(`{"eventId":"e","leafIndex":1,"treeSize":4,"rootHash":"` + root + `","inclusionProof":[],"timestamp":"t","serviceSignature":"s","extra":"ignored"}`)
	if _, ok := ParseInclusionReceipt(raw); !ok {
		t.Error("receipt with an extra member did not parse")
	}
}

// TestParseCheckpointRefToleratesExtraMembers pins that both the Go parser and
// the reference shape check ignore an unknown extra member on a checkpoint
// reference, which is why MaxCheckpointRefBytes carries headroom far above a
// well-formed ref.
func TestParseCheckpointRefToleratesExtraMembers(t *testing.T) {
	const root = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	raw := []byte(`{"treeSize":4,"rootHash":"` + root + `","extra":"ignored"}`)
	if _, ok := ParseCheckpointRef(raw); !ok {
		t.Error("checkpoint ref with an extra member did not parse")
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
