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
	// Reject invalid UTF-8 up front: a TS caller receives the checkpoint as a
	// decoded string, so bytes a decoder would rewrite never reach its verifier.
	// The size bound counts UTF-16 code units to match the reference (String
	// length), not bytes.
	if !utf8.Valid([]byte(signed)) {
		return CheckpointData{}, false
	}
	if n := utf16Len(signed); n == 0 || n > maxSignedCheckpointBody {
		return CheckpointData{}, false
	}
	if len(witnessPublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(witnessPublicKey) {
		return CheckpointData{}, false
	}
	if expectedOrigin == "" || utf16Len(expectedOrigin) > maxCheckpointLine {
		return CheckpointData{}, false
	}
	idx := strings.Index(signed, checkpointSep)
	if idx == -1 {
		return CheckpointData{}, false
	}
	body := signed[:idx]
	data, ok := ParseCheckpoint(body + "\n")
	if !ok {
		return CheckpointData{}, false
	}
	if data.Origin != expectedOrigin {
		return CheckpointData{}, false
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
		return CheckpointData{}, false
	}
	bodyBytes := []byte(body)
	for _, line := range sigLines {
		if !strings.HasPrefix(line, "-- ") {
			return CheckpointData{}, false
		}
		rest := line[3:]
		sp := strings.IndexByte(rest, ' ')
		if sp == -1 {
			return CheckpointData{}, false
		}
		lineOrigin := rest[:sp]
		sigB64 := rest[sp+1:]
		if lineOrigin != expectedOrigin {
			continue
		}
		sig, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return CheckpointData{}, false
		}
		if ed25519.Verify(ed25519.PublicKey(witnessPublicKey), bodyBytes, sig) {
			return data, true
		}
		return CheckpointData{}, false
	}
	return CheckpointData{}, false
}
