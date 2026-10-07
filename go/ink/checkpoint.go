package ink

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A checkpoint body is three lines plus a trailing newline:
//
//	<origin>\n<treeSize>\n<rootHash>\n
//
// C2SP-shaped but not wire-compatible with it; no existing C2SP tool reads
// this format. maxCheckpointBody and maxCheckpointLine are measured in
// UTF-16 code units to match the reference.
const (
	maxCheckpointBody = 1024
	maxCheckpointLine = 256
	// MaxCheckpointWireBytes bounds a checkpoint response in bytes, the unit
	// a network fetch actually reads, unlike the UTF-16 caps above. Not
	// enforced here; a consumer applies it at its own fetch site.
	MaxCheckpointWireBytes = 4096
)

var checkpointDigitsRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// isValidCheckpointOrigin reports whether origin is valid UTF-8, non-empty,
// at most maxCheckpointLine UTF-16 code units, and free of C0/C1 control
// characters, DEL, '+', and Unicode whitespace. NewWitnessLog, below,
// applies it to a witness's own configured origin too.
func isValidCheckpointOrigin(origin string) bool {
	if origin == "" || utf16LenExceeds(origin, maxCheckpointLine) {
		return false
	}
	// A Go string is not guaranteed valid UTF-8. Ranging over an invalid
	// byte sequence silently decodes each bad byte to U+FFFD, which would
	// pass every check below, so this must run first.
	if !utf8.ValidString(origin) {
		return false
	}
	for _, r := range origin {
		if r == '+' {
			return false
		}
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return false
		}
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// CheckpointData is a parsed checkpoint body. It mirrors the reference
// CheckpointData (origin, treeSize, rootHash).
type CheckpointData struct {
	Origin   string
	TreeSize int64
	RootHash string
}

// ParseCheckpoint parses a checkpoint body (INK Auditability §7.7),
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
	if utf16Len(treeSizeLine) > maxCheckpointLine || utf16Len(rootHash) > maxCheckpointLine {
		return CheckpointData{}, false
	}
	if !isValidCheckpointOrigin(origin) {
		return CheckpointData{}, false
	}

	// Tree size: non-negative decimal with no sign, leading +, leading zero,
	// or trailing junk, within the safe-integer range so the value round-trips
	// through a JSON number. "007" and "7" are different byte strings; a
	// leading zero is rejected rather than normalized so an accepted body's
	// serialization is unambiguous. A digit string too large for int64 fails
	// to parse and rejects, matching the reference's MAX_SAFE_INTEGER ceiling.
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
