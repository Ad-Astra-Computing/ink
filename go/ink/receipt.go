package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"unicode/utf8"
)

// parseReceiptInt converts a JSON number token to an int under the reference's
// Number.isInteger rule: any integer-valued finite number in [min, 2^53-1],
// regardless of spelling (so 1, 1.0, and 1e0 are all the integer 1, while 1.5
// is rejected). It matches the reference, which parses the token to a JS number
// and checks Number.isInteger, so a receipt a witness wrote with an exponent or
// trailing-zero integer is not rejected by one implementation and accepted by
// the other.
func parseReceiptInt(n json.Number, min int) (int, bool) {
	f, err := n.Float64()
	if err != nil {
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) {
		return 0, false
	}
	if f < float64(min) || f > maxSafeInteger {
		return 0, false
	}
	return int(f), true
}

// ParseInclusionReceipt parses a raw JSON receipt at the receiver boundary. It
// rejects a body carrying raw invalid UTF-8 or a lone UTF-16 surrogate escape
// before unmarshaling, because encoding/json would rewrite either to U+FFFD and
// the verifier would then canonicalize different signed bytes than the
// reference, and it parses leafIndex and treeSize as integer-valued JSON numbers
// rather than requiring a specific spelling. A receiver MUST verify a receipt
// through this parse, the way the signed-body path goes through ParseSignedBody.
func ParseInclusionReceipt(raw []byte) (InclusionReceipt, bool) {
	if !utf8.Valid(raw) {
		return InclusionReceipt{}, false
	}
	if ContainsLoneSurrogateEscape(raw) {
		return InclusionReceipt{}, false
	}
	var rr struct {
		EventID          string      `json:"eventId"`
		LeafIndex        json.Number `json:"leafIndex"`
		TreeSize         json.Number `json:"treeSize"`
		RootHash         string      `json:"rootHash"`
		InclusionProof   []string    `json:"inclusionProof"`
		Timestamp        string      `json:"timestamp"`
		ServiceSignature string      `json:"serviceSignature"`
	}
	if err := json.Unmarshal(raw, &rr); err != nil {
		return InclusionReceipt{}, false
	}
	leafIndex, ok := parseReceiptInt(rr.LeafIndex, 0)
	if !ok {
		return InclusionReceipt{}, false
	}
	treeSize, ok := parseReceiptInt(rr.TreeSize, 0)
	if !ok {
		return InclusionReceipt{}, false
	}
	return InclusionReceipt{
		EventID:          rr.EventID,
		LeafIndex:        leafIndex,
		TreeSize:         treeSize,
		RootHash:         rr.RootHash,
		InclusionProof:   rr.InclusionProof,
		Timestamp:        rr.Timestamp,
		ServiceSignature: rr.ServiceSignature,
	}, true
}

// ParseCheckpointRef parses a raw JSON later-checkpoint reference, applying the
// same integer-valued-number rule to treeSize as ParseInclusionReceipt, and the
// same raw-invalid-UTF-8 rejection so the cross-checked rootHash is byte-
// identical to the wire. It returns ok=false for a malformed reference, which
// the caller treats as a failed cross-check.
func ParseCheckpointRef(raw []byte) (CheckpointRef, bool) {
	if !utf8.Valid(raw) {
		return CheckpointRef{}, false
	}
	var rc struct {
		TreeSize json.Number `json:"treeSize"`
		RootHash string      `json:"rootHash"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		return CheckpointRef{}, false
	}
	treeSize, ok := parseReceiptInt(rc.TreeSize, 0)
	if !ok {
		return CheckpointRef{}, false
	}
	return CheckpointRef{TreeSize: treeSize, RootHash: rc.RootHash}, true
}

// InclusionReceipt is a witness's signed commitment that a submitted audit
// event sits at (LeafIndex, TreeSize, RootHash) in its transparency log
// (INK Auditability §7). ServiceSignature is the witness Ed25519 signature,
// base64url without padding, over the canonical bytes built in
// verifyReceiptSignature.
type InclusionReceipt struct {
	EventID          string   `json:"eventId"`
	LeafIndex        int      `json:"leafIndex"`
	TreeSize         int      `json:"treeSize"`
	RootHash         string   `json:"rootHash"`
	InclusionProof   []string `json:"inclusionProof"`
	Timestamp        string   `json:"timestamp"`
	ServiceSignature string   `json:"serviceSignature"`
}

// CheckpointRef is the (treeSize, rootHash) a verifier has already authenticated
// from a later signed checkpoint, used for the anti-rollback and fork
// cross-check. It MUST come from a checkpoint whose witness signature and origin
// were verified first; an unverified checkpoint provides no security here.
type CheckpointRef struct {
	TreeSize int    `json:"treeSize"`
	RootHash string `json:"rootHash"`
}

// ReceiptVerifyOptions carries the optional inputs to VerifyInclusionReceipt.
// A nil Event, an empty EventHash, and a nil LaterCheckpoint each mean the
// corresponding step is skipped, matching the reference.
type ReceiptVerifyOptions struct {
	// Event, when set, recomputes the leaf hash with ComputeAuditMerkleLeafHash
	// and binds Event["id"] to the receipt's EventID, so the proof attests the
	// named event's inclusion. Preferred over EventHash.
	Event map[string]interface{}
	// EventHash is a pre-computed leaf hash (lowercase hex). Lower assurance than
	// Event because it is not bound to EventID. Ignored when Event is set.
	EventHash string
	// LaterCheckpoint, when set, cross-checks the receipt against an authenticated
	// later checkpoint: the tree only grew, and at an equal size the root matches.
	LaterCheckpoint *CheckpointRef
}

// checkReceiptShape mirrors the reference structural validation. It rejects a
// receipt whose fields are out of range or malformed before any cryptography
// runs. A nil InclusionProof (an absent or null array) is rejected, but an empty
// proof is valid for a single-leaf tree.
func checkReceiptShape(r InclusionReceipt) bool {
	if r.EventID == "" {
		return false
	}
	if r.LeafIndex < 0 {
		return false
	}
	if r.TreeSize < 1 {
		return false
	}
	if r.LeafIndex >= r.TreeSize {
		return false
	}
	if !isMerkleHashHex(r.RootHash) {
		return false
	}
	if r.InclusionProof == nil {
		return false
	}
	if len(r.InclusionProof) > maxProofLength {
		return false
	}
	for _, p := range r.InclusionProof {
		if !isMerkleHashHex(p) {
			return false
		}
	}
	if r.Timestamp == "" {
		return false
	}
	if r.ServiceSignature == "" {
		return false
	}
	return true
}

// verifyReceiptSignature checks the witness Ed25519 signature over
// "ink/audit-inclusion/v1\n" + JCS({eventId, leafIndex, treeSize, rootHash,
// timestamp}). The key must pass the same strong-key check the reference's
// zip215:false verification applies.
func verifyReceiptSignature(r InclusionReceipt, witnessPublicKey []byte) bool {
	payload := map[string]interface{}{
		"eventId":   r.EventID,
		"leafIndex": float64(r.LeafIndex),
		"treeSize":  float64(r.TreeSize),
		"rootHash":  r.RootHash,
		"timestamp": r.Timestamp,
	}
	canonical, err := canonicalizeJSON(payload)
	if err != nil {
		return false
	}
	sigBase := "ink/audit-inclusion/v1\n" + canonical
	sig, err := base64.RawURLEncoding.DecodeString(r.ServiceSignature)
	if err != nil {
		return false
	}
	if len(witnessPublicKey) != ed25519.PublicKeySize {
		return false
	}
	if !isStrongEd25519PublicKey(witnessPublicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(witnessPublicKey), []byte(sigBase), sig)
}

// VerifyInclusionReceipt verifies an INK inclusion receipt (INK Auditability §7).
// It always validates the receipt shape and the witness service signature, then
// optionally walks the inclusion proof (when Event or EventHash is given) and
// cross-checks a later checkpoint (when LaterCheckpoint is given). It returns
// false, never panics, on any failed step.
func VerifyInclusionReceipt(receipt InclusionReceipt, witnessPublicKey []byte, opts ReceiptVerifyOptions) bool {
	if !checkReceiptShape(receipt) {
		return false
	}
	if !verifyReceiptSignature(receipt, witnessPublicKey) {
		return false
	}

	var leafHash string
	hasLeaf := false
	if opts.Event != nil {
		id, ok := opts.Event["id"].(string)
		if !ok || id != receipt.EventID {
			return false
		}
		h, ok := ComputeAuditMerkleLeafHash(opts.Event)
		if !ok {
			return false
		}
		leafHash, hasLeaf = h, true
	} else if opts.EventHash != "" {
		if !isMerkleHashHex(opts.EventHash) {
			return false
		}
		leafHash, hasLeaf = opts.EventHash, true
	}
	if hasLeaf && !VerifyInclusionProof(leafHash, receipt.InclusionProof, receipt.LeafIndex, receipt.TreeSize, receipt.RootHash) {
		return false
	}

	if cp := opts.LaterCheckpoint; cp != nil {
		if cp.TreeSize < 0 || !isMerkleHashHex(cp.RootHash) {
			return false
		}
		if cp.TreeSize < receipt.TreeSize {
			return false
		}
		if cp.TreeSize == receipt.TreeSize && cp.RootHash != receipt.RootHash {
			return false
		}
	}
	return true
}
