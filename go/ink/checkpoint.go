package ink

import (
	"regexp"
	"strconv"
	"strings"
)

// A C2SP tlog-checkpoint body is three lines plus a trailing newline:
//
//	<origin>\n<treeSize>\n<rootHash>\n
//
// maxCheckpointBody bounds the whole body and maxCheckpointLine each line, both
// measured in UTF-16 code units to match the reference, so an attacker-supplied
// blob cannot drive a large split/regex/parse scan before the parser rejects it.
const (
	maxCheckpointBody = 1024
	maxCheckpointLine = 256
)

var checkpointDigitsRe = regexp.MustCompile(`^[0-9]+$`)

// CheckpointData is a parsed checkpoint body. It mirrors the reference
// CheckpointData (origin, treeSize, rootHash).
type CheckpointData struct {
	Origin   string
	TreeSize int64
	RootHash string
}

// ParseCheckpoint parses a C2SP tlog-checkpoint body (INK Auditability §7.7),
// returning the parsed data and true, or a zero value and false when the body is
// not a well-formed checkpoint. It is the grammar half of checkpoint handling;
// VerifyCheckpoint-style signature verification is a separate, caller-side step.
// The decision boundary is pinned by the merkle-checkpoint conformance vectors so
// the reference and this implementation reject the same malformed bodies and a
// parser differential cannot let a forged checkpoint through one but not the
// other.
func ParseCheckpoint(body string) (CheckpointData, bool) {
	// Reject oversized input before Split allocates a partition slice.
	if n := utf16Len(body); n == 0 || n > maxCheckpointBody {
		return CheckpointData{}, false
	}
	lines := strings.Split(body, "\n")
	// Exactly origin, treeSize, rootHash, and the empty string after the final
	// newline. Strict equality rejects extra trailing lines or junk, matching
	// stricter C2SP reference verifiers.
	if len(lines) != 4 {
		return CheckpointData{}, false
	}
	if lines[3] != "" {
		return CheckpointData{}, false
	}

	origin := lines[0]
	treeSizeLine := lines[1]
	rootHash := lines[2]

	// Per-line caps before each regex or integer scan.
	if utf16Len(origin) > maxCheckpointLine || utf16Len(treeSizeLine) > maxCheckpointLine || utf16Len(rootHash) > maxCheckpointLine {
		return CheckpointData{}, false
	}
	if origin == "" {
		return CheckpointData{}, false
	}

	// Tree size: non-negative decimal with no sign, leading +, or trailing junk,
	// within the safe-integer range so the value round-trips through a JSON
	// number. A digit string too large for int64 fails to parse and rejects,
	// matching the reference's MAX_SAFE_INTEGER ceiling.
	if !checkpointDigitsRe.MatchString(treeSizeLine) {
		return CheckpointData{}, false
	}
	treeSize, err := strconv.ParseInt(treeSizeLine, 10, 64)
	if err != nil || treeSize < 0 || treeSize > maxSafeInteger {
		return CheckpointData{}, false
	}

	// Root hash: exactly 64 lowercase hex characters.
	if !isMerkleHashHex(rootHash) {
		return CheckpointData{}, false
	}

	return CheckpointData{Origin: origin, TreeSize: treeSize, RootHash: rootHash}, true
}

// FormatCheckpoint serializes a checkpoint body, the inverse of ParseCheckpoint
// and byte-for-byte equal to the reference formatCheckpoint output.
func FormatCheckpoint(d CheckpointData) string {
	return d.Origin + "\n" + strconv.FormatInt(d.TreeSize, 10) + "\n" + d.RootHash + "\n"
}
