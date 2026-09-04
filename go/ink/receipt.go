package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"unicode/utf8"
)

// MaxInclusionReceiptBytes is a raw-bytes edge guard applied at the layer that
// receives receipt bytes: an oversized blob is rejected by a len check before
// json.Unmarshal decodes it into the struct. The decoded-object reference in
// src/audit/inclusion-receipt.ts defines no byte bound, so this cap has no
// counterpart there; it only bounds decode allocation on the raw-bytes boundary.
// There is no structural walk here because the receipt decodes into a fixed
// struct with no open-ended map, and the one array field (inclusionProof) is
// length-bounded by checkReceiptShape.
//
// The cap is set comfortably above the ceiling a conforming witness can emit,
// after accounting for wire escape expansion. A receipt's signed core {eventId,
// leafIndex, treeSize, rootHash, timestamp} flows through JCS canonicalization on
// the emitter (signReceiptCore), which enforces maxCanonicalBodyBytes (1,048,576)
// UTF-16 code units of canonical output before signing, mirroring the reference
// jcsCanonicalize post-canonicalize check on result.length (a JS string length in
// code units). So no witness can sign a receipt whose signed core exceeds
// 1,048,576 code units of canonical output. The eventId carries no schema length
// bound of its own but is bounded by that canonicalize ceiling.
//
// That bound is on canonical code units, but the receipt on the wire is not
// canonical JSON: a sender may escape any character, and the signature verifies
// against the re-canonicalized core, not the raw bytes. Worst-case wire escape is
// 6 raw bytes per code unit: an ASCII character is 1 code unit written as \uXXXX
// (6 bytes), and a surrogate pair is 2 code units written as \uXXXX\uXXXX (12
// bytes, still 6 per unit). So a validly signed core at the 1,048,576 code-unit
// ceiling can legitimately occupy up to about 6 MiB of raw wire bytes. The
// unsigned members (inclusionProof up to 64 hashes, serviceSignature, timestamp)
// are all small and add only tens of KiB even fully escaped. 8 MiB clears the
// ~6 MiB signed-core worst case plus that unsigned overhead with headroom, while
// still rejecting a blob far past anything a conforming witness can emit.
const MaxInclusionReceiptBytes = 8 * 1024 * 1024

// MaxCheckpointRefBytes is a raw-bytes edge guard on a checkpoint reference
// before it is parsed. A checkpoint reference carries only a treeSize integer and
// a 64-char rootHash, so a well-formed ref is under 200 bytes. Both the Go parser
// and the reference shape check ignore unknown extra members, so a valid ref can
// legitimately carry additional fields; the headroom to 64 KiB exists only
// because that tolerance is shared, not because the two known fields need it. As
// with the receipt, the fixed struct means no structural walk is needed.
const MaxCheckpointRefBytes = 64 * 1024

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
// through this parse, the way the signed-body path goes through ParseSignedBody:
// it applies the same four text-level rules (invalid UTF-8, lone surrogate
// escape, out-of-range number literal, escaped member name) before unmarshaling.
func ParseInclusionReceipt(raw []byte) (InclusionReceipt, bool) {
	if len(raw) > MaxInclusionReceiptBytes {
		return InclusionReceipt{}, false
	}
	// The receipt is a signed artifact, so every text-level rule of
	// ink-signed-string-safety.md applies. It unmarshals into a typed struct
	// rather than a map, so the rules run here directly instead of through
	// ParseSignedObject; keep this list in step with ParseSignedBody.
	if !utf8.Valid(raw) {
		return InclusionReceipt{}, false
	}
	if ContainsLoneSurrogateEscape(raw) {
		return InclusionReceipt{}, false
	}
	if ContainsOutOfRangeNumberLiteral(raw) {
		return InclusionReceipt{}, false
	}
	if ContainsEscapedMemberName(raw) {
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
	if len(raw) > MaxCheckpointRefBytes {
		return CheckpointRef{}, false
	}
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
	return verifyReceiptSignatureWith(r, fixedKey(witnessPublicKey), 0).Verified
}

// verifyReceiptSignatureWith builds the receipt's signed payload and
// canonical bytes once and hands the signature check to the strategy.
// artifactMs is the receipt's own clock, already parsed by the caller when
// the strategy needs one.
func verifyReceiptSignatureWith(r InclusionReceipt, s signerStrategy, artifactMs int64) MultiKeyResult {
	payload := map[string]interface{}{
		"eventId":   r.EventID,
		"leafIndex": float64(r.LeafIndex),
		"treeSize":  float64(r.TreeSize),
		"rootHash":  r.RootHash,
		"timestamp": r.Timestamp,
	}
	canonical, err := canonicalizeJSON(payload)
	if err != nil {
		return MultiKeyResult{}
	}
	// Post-canonicalize output cap, mirroring the reference verify path in
	// src/audit/inclusion-receipt.ts: it builds the signature base with
	// jcsCanonicalize, which rejects a canonical result whose result.length (a JS
	// string length in UTF-16 code units) exceeds MAX_SIGBASE_BODY_BYTES
	// (1,048,576). The receipt's signed core carries a free-form eventId, so its
	// canonical form can exceed that ceiling while the raw receipt still fits the
	// 8 MiB MaxInclusionReceiptBytes parser cap. Without this a Go receiver would
	// verify a receipt the reference refuses. Measured in code units (utf16Len),
	// the same measurement signReceiptCore applies on the issue side, not bytes,
	// so a receipt with a large non-ASCII eventId under the code-unit ceiling is
	// treated identically by both sides. Checked over the canonical output, not
	// the version prefix, matching where the reference caps.
	if utf16Len(canonical) > maxCanonicalBodyBytes {
		return MultiKeyResult{}
	}
	sigBase := "ink/audit-inclusion/v1\n" + canonical
	sig, err := base64.RawURLEncoding.DecodeString(r.ServiceSignature)
	if err != nil {
		return MultiKeyResult{}
	}
	return s.verify(func(pub []byte) bool {
		return ed25519.Verify(ed25519.PublicKey(pub), []byte(sigBase), sig)
	}, artifactMs)
}

// VerifyInclusionReceipt verifies an INK inclusion receipt (INK Auditability §7).
// It always validates the receipt shape and the witness service signature, then
// optionally walks the inclusion proof (when Event or EventHash is given) and
// cross-checks a later checkpoint (when LaterCheckpoint is given). It returns
// false, never panics, on any failed step.
func VerifyInclusionReceipt(receipt InclusionReceipt, witnessPublicKey []byte, opts ReceiptVerifyOptions) bool {
	return verifyInclusionReceiptWith(receipt, fixedKey(witnessPublicKey), opts).Verified
}

// VerifyInclusionReceiptWithKeys verifies an INK inclusion receipt (INK
// Auditability §7) against a rotation-aware candidate witness key set (spec
// §6.2/§12.1/§12.3: a witness service MUST be able to verify submissions,
// and by the same rule the receipts it issues for them, against a retired
// key still inside its validity window; a revoked key never verifies, even
// for a receipt predating its revocation).
//
// The artifact clock is the receipt's own Timestamp field (the moment the
// witness committed the leaf), parsed with the shared strict RFC 3339
// grammar; a missing or unparseable timestamp fails closed before any
// candidate key is tried. Structure, the optional proof walk, and the
// optional later-checkpoint cross-check are the same code path as
// VerifyInclusionReceipt; only the signature step is rotation-aware. The
// returned MultiKeyResult.Verified is the overall verdict: a false result
// from any step (not just the signature) yields the zero MultiKeyResult,
// matching the "no key attribution for a rejection" rule
// VerifyInkSignatureForLiveAuth documents elsewhere in this package.
func VerifyInclusionReceiptWithKeys(receipt InclusionReceipt, keys []CandidateKey, hintKeyID string, opts ReceiptVerifyOptions) MultiKeyResult {
	return verifyInclusionReceiptWith(receipt, candidateKeys(keys, hintKeyID), opts)
}

func verifyInclusionReceiptWith(receipt InclusionReceipt, s signerStrategy, opts ReceiptVerifyOptions) MultiKeyResult {
	if !checkReceiptShape(receipt) {
		return MultiKeyResult{}
	}
	var artifactMs int64
	if s.needsClock {
		ms, ok := ParseInkTimestampMs(receipt.Timestamp)
		if !ok {
			return MultiKeyResult{}
		}
		artifactMs = ms
	}
	result := verifyReceiptSignatureWith(receipt, s, artifactMs)
	if !result.Verified {
		return MultiKeyResult{}
	}

	var leafHash string
	hasLeaf := false
	if opts.Event != nil {
		id, ok := opts.Event["id"].(string)
		if !ok || id != receipt.EventID {
			return MultiKeyResult{}
		}
		h, ok := ComputeAuditMerkleLeafHash(opts.Event)
		if !ok {
			return MultiKeyResult{}
		}
		leafHash, hasLeaf = h, true
	} else if opts.EventHash != "" {
		if !isMerkleHashHex(opts.EventHash) {
			return MultiKeyResult{}
		}
		leafHash, hasLeaf = opts.EventHash, true
	}
	if hasLeaf && !VerifyInclusionProof(leafHash, receipt.InclusionProof, receipt.LeafIndex, receipt.TreeSize, receipt.RootHash) {
		return MultiKeyResult{}
	}

	if cp := opts.LaterCheckpoint; cp != nil {
		if cp.TreeSize < 0 || !isMerkleHashHex(cp.RootHash) {
			return MultiKeyResult{}
		}
		if cp.TreeSize < receipt.TreeSize {
			return MultiKeyResult{}
		}
		if cp.TreeSize == receipt.TreeSize && cp.RootHash != receipt.RootHash {
			return MultiKeyResult{}
		}
	}
	return result
}
