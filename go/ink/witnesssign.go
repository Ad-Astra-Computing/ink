package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The issuing side of the witness: given a tree state and a witness Ed25519 key,
// produce a signed inclusion receipt and a signed checkpoint that the existing
// verifiers accept. These are pure functions over a supplied tree state; they
// own no storage, sequencing, or transport.

// signReceiptCore signs the receipt core with the witness key. It mirrors the
// reference signReceiptCore and the Go verifyReceiptSignature: the signature is
// Ed25519 over "ink/audit-inclusion/v1\n" + JCS({eventId, leafIndex, treeSize,
// rootHash, timestamp}), base64url without padding.
func signReceiptCore(eventID string, leafIndex, treeSize int, rootHash, timestamp string, witnessPrivateKey ed25519.PrivateKey) (string, error) {
	payload := map[string]interface{}{
		"eventId":   eventID,
		"leafIndex": float64(leafIndex),
		"treeSize":  float64(treeSize),
		"rootHash":  rootHash,
		"timestamp": timestamp,
	}
	canonical, err := canonicalizeJSON(payload)
	if err != nil {
		return "", err
	}
	// Enforce the canonical ceiling on the emit side, mirroring the reference
	// jcsCanonicalize post-canonicalize check the TS receipt-signing path runs
	// through. The reference caps result.length, a JS string length in UTF-16
	// code units, against MAX_SIGBASE_BODY_BYTES; the constant is byte-named but
	// on this path it bounds a string length, so Go mirrors the applied semantics
	// (utf16Len) not the name. Measuring bytes here would refuse a core with a
	// large non-ASCII eventId that stays under the code-unit ceiling but exceeds
	// it in UTF-8 bytes, which TS signs and both object verifiers accept.
	// Without any bound a Go witness could mint a receipt whose signed core
	// exceeds the parser's MaxInclusionReceiptBytes boundary, and its own
	// ParseInclusionReceipt would reject it. Checked over the canonical output
	// (not the version prefix), matching where the reference caps.
	if utf16Len(canonical) > maxCanonicalBodyBytes {
		return "", errors.New("inclusion-receipt core exceeds maximum allowed size")
	}
	sig := ed25519.Sign(witnessPrivateKey, []byte("ink/audit-inclusion/v1\n"+canonical))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignInclusionReceipt issues a witness-signed inclusion receipt for the leaf at
// index in the tree over leaves, committing to the current Merkle Tree Head. The
// result verifies with VerifyInclusionReceipt against the witness public key. It
// errors on an out-of-range index, a malformed leaf, an empty eventId or
// timestamp, or a private key of the wrong size.
func SignInclusionReceipt(leaves []string, index int, eventID, timestamp string, witnessPrivateKey ed25519.PrivateKey) (InclusionReceipt, error) {
	if len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return InclusionReceipt{}, errors.New("witness private key must be an ed25519 private key")
	}
	if eventID == "" || timestamp == "" {
		return InclusionReceipt{}, errors.New("eventId and timestamp must not be empty")
	}
	// Signed string fields must be valid UTF-8 so the signed bytes are portable:
	// a byte sequence a JSON parser would rewrite is not identical across
	// implementations. Invalid UTF-8 also covers an encoded lone surrogate.
	if !utf8.Valid([]byte(eventID)) || !utf8.Valid([]byte(timestamp)) {
		return InclusionReceipt{}, errors.New("eventId and timestamp must be valid UTF-8")
	}
	root, err := MerkleTreeHead(leaves)
	if err != nil {
		return InclusionReceipt{}, err
	}
	proof, err := InclusionProof(leaves, index)
	if err != nil {
		return InclusionReceipt{}, err
	}
	treeSize := len(leaves)
	signature, err := signReceiptCore(eventID, index, treeSize, root, timestamp, witnessPrivateKey)
	if err != nil {
		return InclusionReceipt{}, err
	}
	return InclusionReceipt{
		EventID:          eventID,
		LeafIndex:        index,
		TreeSize:         treeSize,
		RootHash:         root,
		InclusionProof:   proof,
		Timestamp:        timestamp,
		ServiceSignature: signature,
	}, nil
}

// checkpointSep separates the signed checkpoint body from its cosignature
// block: two newlines then the "-- " that begins the first signature line.
const checkpointSep = "\n\n-- "

// SignCheckpoint issues a signed C2SP-style checkpoint note committing to
// (origin, treeSize, rootHash):
//
//	<origin>\n<treeSize>\n<rootHash>\n\n-- <origin> <base64url(sig)>\n
//
// The Ed25519 signature covers the body bytes "<origin>\n<treeSize>\n<rootHash>"
// with no trailing newline, so the origin first line binds the signature to this
// log. The result verifies with VerifyCheckpoint against the witness key and the
// same origin.
func SignCheckpoint(origin string, treeSize int64, rootHash string, witnessPrivateKey ed25519.PrivateKey) (string, error) {
	if len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("witness private key must be an ed25519 private key")
	}
	// The origin appears in both the body first line and the cosignature line
	// "-- <origin> <sig>", which the verifier splits at the first space, so an
	// origin containing ASCII whitespace would not round-trip.
	if origin == "" || strings.ContainsAny(origin, " \t\r\n\v\f") || utf16Len(origin) > maxCheckpointLine || !utf8.Valid([]byte(origin)) {
		return "", errors.New("invalid checkpoint origin")
	}
	if treeSize < 0 || treeSize > maxSafeInteger {
		return "", errors.New("checkpoint tree size out of range")
	}
	if !isMerkleHashHex(rootHash) {
		return "", errors.New("checkpoint root hash must be 64 lowercase hex")
	}
	body := origin + "\n" + strconv.FormatInt(treeSize, 10) + "\n" + rootHash
	sig := ed25519.Sign(witnessPrivateKey, []byte(body))
	return body + checkpointSep + origin + " " + base64.RawURLEncoding.EncodeToString(sig) + "\n", nil
}

// Bounds on a signed checkpoint, mirroring the reference verifyCheckpoint.
const (
	maxSignedCheckpointBody = 4096
	maxCheckpointSignatures = 8
)

// VerifyCheckpoint verifies a signed checkpoint note and returns its parsed body
// on success. It mirrors the reference verifyCheckpoint: the body grammar is
// parsed by ParseCheckpoint, the body origin and a matching cosignature-line
// origin must equal expectedOrigin, and the Ed25519 signature over the body
// bytes (no trailing newline) is verified in RFC 8032 strict mode (small-order
// and non-canonically encoded keys rejected). It returns ok=false, never panics,
// on any malformed input or failed check.
func VerifyCheckpoint(signed string, witnessPublicKey []byte, expectedOrigin string) (CheckpointData, bool) {
	data, result := verifyCheckpointWith(signed, fixedKey(witnessPublicKey), expectedOrigin, 0)
	return data, result.Verified
}

// VerifyCheckpointWithKeys verifies a signed checkpoint note against a
// rotation-aware candidate witness key set (spec §6.2/§12.1/§12.3) and
// returns its parsed body plus the key that verified it. A checkpoint note
// carries no intrinsic timestamp of its own, since it commits only to
// (origin, treeSize, rootHash), so the caller MUST supply artifactMs
// explicitly: typically the time the checkpoint was fetched, or a timestamp
// pinned out of band.
//
// Every other behavior is the same code path as VerifyCheckpoint, including
// the origin-matching rule: the checkpoint body's own origin, and the origin
// on the one signature line tried, must both equal expectedOrigin. Only that
// origin-matching signature line's candidates are tried; a matching-origin
// line that no candidate key verifies is fatal, with no fallback to a later
// line.
func VerifyCheckpointWithKeys(signed string, keys []CandidateKey, expectedOrigin string, artifactMs int64, hintKeyID string) (CheckpointData, MultiKeyResult) {
	return verifyCheckpointWith(signed, candidateKeys(keys, hintKeyID), expectedOrigin, artifactMs)
}

func verifyCheckpointWith(signed string, s signerStrategy, expectedOrigin string, artifactMs int64) (CheckpointData, MultiKeyResult) {
	// Reject invalid UTF-8 up front: a TS caller receives the checkpoint as a
	// decoded string, so bytes a decoder would rewrite never reach its verifier.
	// The size bound counts UTF-16 code units to match the reference (String
	// length), not bytes.
	if !utf8.Valid([]byte(signed)) {
		return CheckpointData{}, MultiKeyResult{}
	}
	if n := utf16Len(signed); n == 0 || n > maxSignedCheckpointBody {
		return CheckpointData{}, MultiKeyResult{}
	}
	if !s.keyOK() {
		return CheckpointData{}, MultiKeyResult{}
	}
	if expectedOrigin == "" || utf16Len(expectedOrigin) > maxCheckpointLine {
		return CheckpointData{}, MultiKeyResult{}
	}
	idx := strings.Index(signed, checkpointSep)
	if idx == -1 {
		return CheckpointData{}, MultiKeyResult{}
	}
	body := signed[:idx]
	data, ok := ParseCheckpoint(body + "\n")
	if !ok {
		return CheckpointData{}, MultiKeyResult{}
	}
	if data.Origin != expectedOrigin {
		return CheckpointData{}, MultiKeyResult{}
	}
	// The signature block starts at the "-- " that began the separator.
	sigBlock := signed[idx+2:]
	var sigLines []string
	for _, l := range strings.Split(sigBlock, "\n") {
		if l != "" {
			sigLines = append(sigLines, l)
		}
	}
	if len(sigLines) == 0 || len(sigLines) > maxCheckpointSignatures {
		return CheckpointData{}, MultiKeyResult{}
	}
	bodyBytes := []byte(body)
	for _, line := range sigLines {
		if !strings.HasPrefix(line, "-- ") {
			return CheckpointData{}, MultiKeyResult{}
		}
		rest := line[3:]
		sp := strings.IndexByte(rest, ' ')
		if sp == -1 {
			return CheckpointData{}, MultiKeyResult{}
		}
		lineOrigin := rest[:sp]
		sigB64 := rest[sp+1:]
		if lineOrigin != expectedOrigin {
			continue
		}
		sig, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return CheckpointData{}, MultiKeyResult{}
		}
		result := s.verify(func(pub []byte) bool {
			return ed25519.Verify(ed25519.PublicKey(pub), bodyBytes, sig)
		}, artifactMs)
		if !result.Verified {
			// A matching-origin signature that no key verifies is fatal.
			return CheckpointData{}, MultiKeyResult{}
		}
		return data, result
	}
	return CheckpointData{}, MultiKeyResult{}
}
