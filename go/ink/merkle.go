package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
)

// maxProofLength caps the inclusion-proof length a verifier will walk. A real
// proof is ceil(log2(treeSize)) entries, so a tree beyond 2^64 leaves is
// implausible; capping at 64 bounds verifier work against a hostile receipt
// whose signed payload commits to treeSize but not to the proof array.
const maxProofLength = 64

var merkleHashHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isMerkleHashHex(s string) bool { return merkleHashHexRe.MatchString(s) }

// merkleNodeHash hashes an internal Merkle node as SHA-256(0x01 || left ||
// right) over the raw 32-byte child hashes, the RFC 6962 §2.1 construction. The
// 0x01 prefix (distinct from the 0x00 leaf prefix) is second-preimage
// protection. Both arguments are 64 lowercase hex characters.
func merkleNodeHash(left, right string) (string, error) {
	l, err := hex.DecodeString(left)
	if err != nil {
		return "", err
	}
	r, err := hex.DecodeString(right)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 1+len(l)+len(r))
	buf[0] = 0x01
	copy(buf[1:], l)
	copy(buf[1+len(l):], r)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// largestPowerOf2LessThan returns the largest power of two strictly less than n,
// the RFC 6962 left/right split point for a subtree of n leaves. n <= 1 has no
// split and returns 0. The loop condition is written as p <= (n-1)/2 rather than
// p*2 < n so doubling never overflows a near-MaxInt n into a non-terminating
// loop; VerifyInclusionProof additionally caps treeSize at maxSafeInteger.
func largestPowerOf2LessThan(n int) int {
	if n <= 1 {
		return 0
	}
	p := 1
	for p <= (n-1)/2 {
		p *= 2
	}
	return p
}

// recomputeRoot walks the tree's index space from the subtree [start, start+size)
// down to the leaf, combining the running hash with one proof sibling per level.
// proofIdx advances as each level consumes its sibling; the index that remains
// after the walk must equal len(proof) (no unused entries), and the walk must
// not run past the proof (too short). Mirrors the reference walker so both
// implementations reconstruct the identical root from the identical proof.
func recomputeRoot(current string, proof []string, proofIdx *int, leafIndex, start, size int) (string, error) {
	if size == 1 {
		if *proofIdx != len(proof) {
			return "", errors.New("inclusion proof has unused entries")
		}
		return current, nil
	}
	if *proofIdx >= len(proof) {
		return "", errors.New("inclusion proof too short for declared treeSize")
	}
	split := largestPowerOf2LessThan(size)
	sibling := proof[*proofIdx]
	*proofIdx++
	if leafIndex-start < split {
		left, err := recomputeRoot(current, proof, proofIdx, leafIndex, start, split)
		if err != nil {
			return "", err
		}
		return merkleNodeHash(left, sibling)
	}
	right, err := recomputeRoot(current, proof, proofIdx, leafIndex, start+split, size-split)
	if err != nil {
		return "", err
	}
	return merkleNodeHash(sibling, right)
}

// VerifyInclusionProof verifies an RFC 6962 §2.1.1 inclusion proof: that
// leafHash sits at leafIndex in a tree of treeSize leaves whose Merkle root is
// expectedRootHash. proof is the ordered list of sibling hashes, top-down (the
// sibling nearest the root first, the sibling adjacent to the leaf last).
// Returns false (never panics) for an out-of-range index, a malformed proof
// element, a proof that is too short, or one padded with unused entries. See
// specs/ink-merkle-inclusion.md.
//
// This is a low-level primitive: it attests only that leafHash walks to
// expectedRootHash. It does not authenticate the witness signature, bind the
// leaf hash to an audit event, or check the root against a signed checkpoint.
// Those checks belong to the caller.
func VerifyInclusionProof(leafHash string, proof []string, leafIndex, treeSize int, expectedRootHash string) bool {
	if !isMerkleHashHex(leafHash) || !isMerkleHashHex(expectedRootHash) {
		return false
	}
	if len(proof) > maxProofLength {
		return false
	}
	for _, p := range proof {
		if !isMerkleHashHex(p) {
			return false
		}
	}
	// Reject a treeSize past the JS safe-integer range to match the TS
	// reference: a JSON number above it loses precision, and the overflow-safe
	// split loop relies on this bound. leafIndex is implicitly bounded because
	// it must be < treeSize.
	if treeSize < 1 || treeSize > maxSafeInteger {
		return false
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return false
	}
	idx := 0
	root, err := recomputeRoot(leafHash, proof, &idx, leafIndex, 0, treeSize)
	if err != nil {
		return false
	}
	return root == expectedRootHash
}
