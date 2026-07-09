package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// merkleEmptyRoot is the RFC 6962 Merkle Tree Head of the empty tree: SHA-256 of
// the empty string. A witness whose log has no entries publishes this root.
var merkleEmptyRoot = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// The issuing dual of merkle.go. These functions build the RFC 6962 §2.1 Merkle
// Tree Head and the inclusion and consistency proofs a witness serves. They
// share merkleNodeHash and largestPowerOf2LessThan with the verifier, so an
// issued proof reconstructs to the same root the verifier recomputes. They are
// pure and stateless: leaves are the ordered list of 64-hex leaf hashes, and no
// key, storage, or transport is involved.

// subtreeRoot returns the Merkle Tree Head of leaves[start:start+size]. size
// must be at least 1; callers never pass an empty range.
func subtreeRoot(leaves []string, start, size int) (string, error) {
	if size == 1 {
		return leaves[start], nil
	}
	k := largestPowerOf2LessThan(size)
	left, err := subtreeRoot(leaves, start, k)
	if err != nil {
		return "", err
	}
	right, err := subtreeRoot(leaves, start+k, size-k)
	if err != nil {
		return "", err
	}
	return merkleNodeHash(left, right)
}

// MerkleTreeHead returns the RFC 6962 Merkle Tree Head (root hash, 64 lowercase
// hex) over leaves, the ordered list of leaf hashes. An empty list yields the
// empty-tree root. It errors on a leaf that is not a 64-hex hash.
func MerkleTreeHead(leaves []string) (string, error) {
	if len(leaves) > maxSafeInteger {
		return "", errors.New("tree size exceeds the safe-integer range")
	}
	for _, leaf := range leaves {
		if !isMerkleHashHex(leaf) {
			return "", errors.New("leaf is not a 64-hex hash")
		}
	}
	if len(leaves) == 0 {
		return merkleEmptyRoot, nil
	}
	return subtreeRoot(leaves, 0, len(leaves))
}

// inclusionProofRec builds the top-down sibling list for the leaf at absolute
// index m within the subtree [start, start+size), the order VerifyInclusionProof
// consumes (the sibling nearest the root first, adjacent to the leaf last).
func inclusionProofRec(leaves []string, m, start, size int) ([]string, error) {
	if size == 1 {
		return []string{}, nil
	}
	k := largestPowerOf2LessThan(size)
	if m-start < k {
		sibling, err := subtreeRoot(leaves, start+k, size-k)
		if err != nil {
			return nil, err
		}
		rest, err := inclusionProofRec(leaves, m, start, k)
		if err != nil {
			return nil, err
		}
		return append([]string{sibling}, rest...), nil
	}
	sibling, err := subtreeRoot(leaves, start, k)
	if err != nil {
		return nil, err
	}
	rest, err := inclusionProofRec(leaves, m, start+k, size-k)
	if err != nil {
		return nil, err
	}
	return append([]string{sibling}, rest...), nil
}

// InclusionProof returns the RFC 6962 §2.1.1 inclusion proof that the leaf at
// index sits in the tree over leaves. The result verifies with
// VerifyInclusionProof(leaves[index], proof, index, len(leaves), root). It
// errors on an empty list, a malformed leaf, or an out-of-range index.
func InclusionProof(leaves []string, index int) ([]string, error) {
	if len(leaves) > maxSafeInteger {
		return nil, errors.New("tree size exceeds the safe-integer range")
	}
	if err := validateLeaves(leaves); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("leaf index out of range")
	}
	return inclusionProofRec(leaves, index, 0, len(leaves))
}

// consistencySubproof is the recursive RFC 6962 §2.1.2 SUBPROOF(m,
// D[start:start+size], b).
func consistencySubproof(leaves []string, m, start, size int, b bool) ([]string, error) {
	if m == size {
		if b {
			return []string{}, nil
		}
		root, err := subtreeRoot(leaves, start, size)
		if err != nil {
			return nil, err
		}
		return []string{root}, nil
	}
	k := largestPowerOf2LessThan(size)
	if m <= k {
		sub, err := consistencySubproof(leaves, m, start, k, b)
		if err != nil {
			return nil, err
		}
		right, err := subtreeRoot(leaves, start+k, size-k)
		if err != nil {
			return nil, err
		}
		return append(sub, right), nil
	}
	sub, err := consistencySubproof(leaves, m-k, start+k, size-k, false)
	if err != nil {
		return nil, err
	}
	left, err := subtreeRoot(leaves, start, k)
	if err != nil {
		return nil, err
	}
	return append(sub, left), nil
}

// ConsistencyProof returns the RFC 6962 §2.1.2 consistency proof that the tree
// of the first `first` leaves is a prefix of the tree of the first `second`
// leaves. The result verifies with VerifyConsistencyProof(first,
// MerkleTreeHead(leaves[:first]), second, MerkleTreeHead(leaves[:second]),
// proof). It errors unless 0 <= first <= second <= len(leaves). A proof from the
// empty tree or to an unchanged size is empty, matching the reference.
func ConsistencyProof(leaves []string, first, second int) ([]string, error) {
	if first < 0 || second < first || second > len(leaves) || second > maxSafeInteger {
		return nil, errors.New("consistency bounds out of range")
	}
	// A proof from the empty tree or between equal sizes is empty and touches no
	// leaf, so the degenerate empty-to-empty case is valid without any leaves.
	if first == 0 || first == second {
		return []string{}, nil
	}
	if err := validateLeaves(leaves[:second]); err != nil {
		return nil, err
	}
	return consistencySubproof(leaves, first, 0, second, true)
}

// validateLeaves rejects an empty list or any leaf that is not a 64-hex hash, so
// the issuing functions never build a root over ill-formed input.
func validateLeaves(leaves []string) error {
	if len(leaves) == 0 {
		return errors.New("no leaves")
	}
	for _, leaf := range leaves {
		if !isMerkleHashHex(leaf) {
			return errors.New("leaf is not a 64-hex hash")
		}
	}
	return nil
}
