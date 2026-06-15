package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// goLeafHash mirrors the RFC 6962 leaf-hash rule (0x00 prefix) for a synthetic
// leaf, so the test can build trees independently of the conformance corpus.
func goLeafHash(label string) string {
	data := []byte(label)
	buf := make([]byte, 1+len(data))
	buf[0] = 0x00
	copy(buf[1:], data)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func goMerkleRoot(t *testing.T, leaves []string) string {
	t.Helper()
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestPowerOf2LessThan(len(leaves))
	h, err := merkleNodeHash(goMerkleRoot(t, leaves[:k]), goMerkleRoot(t, leaves[k:]))
	if err != nil {
		t.Fatalf("merkleNodeHash: %v", err)
	}
	return h
}

// goInclusionProof builds the top-down proof the verifier expects: the sibling
// nearest the root first, the sibling adjacent to the leaf last.
func goInclusionProof(t *testing.T, m int, leaves []string) []string {
	t.Helper()
	if len(leaves) == 1 {
		return nil
	}
	k := largestPowerOf2LessThan(len(leaves))
	if m < k {
		return append([]string{goMerkleRoot(t, leaves[k:])}, goInclusionProof(t, m, leaves[:k])...)
	}
	return append([]string{goMerkleRoot(t, leaves[:k])}, goInclusionProof(t, m-k, leaves[k:])...)
}

// TestVerifyInclusionProofRoundTrip walks every leaf of every tree size 1..9 and
// asserts a freshly built proof verifies, exercising both power-of-two and
// non-power-of-two splits.
func TestVerifyInclusionProofRoundTrip(t *testing.T) {
	for n := 1; n <= 9; n++ {
		leaves := make([]string, n)
		for i := range leaves {
			leaves[i] = goLeafHash(fmt.Sprintf("leaf-%d-of-%d", i, n))
		}
		root := goMerkleRoot(t, leaves)
		for m := 0; m < n; m++ {
			proof := goInclusionProof(t, m, leaves)
			if !VerifyInclusionProof(leaves[m], proof, m, n, root) {
				t.Errorf("n=%d m=%d: valid proof rejected", n, m)
			}
		}
	}
}

// TestVerifyInclusionProofRejects pins every rejection branch on a four-leaf
// tree so a regression in the strictness checks is caught.
func TestVerifyInclusionProofRejects(t *testing.T) {
	leaves := []string{
		goLeafHash("a"), goLeafHash("b"), goLeafHash("c"), goLeafHash("d"),
	}
	root := goMerkleRoot(t, leaves)
	proof0 := goInclusionProof(t, 0, leaves)

	flip := func(h string) string {
		last := h[len(h)-1]
		if last == '0' {
			return h[:len(h)-1] + "1"
		}
		return h[:len(h)-1] + "0"
	}

	cases := []struct {
		name      string
		leafHash  string
		proof     []string
		leafIndex int
		treeSize  int
		root      string
	}{
		{"tampered-root", leaves[0], proof0, 0, 4, flip(root)},
		{"wrong-leaf", flip(leaves[0]), proof0, 0, 4, root},
		{"index-out-of-range", leaves[0], proof0, 4, 4, root},
		{"negative-index", leaves[0], proof0, -1, 4, root},
		{"tree-size-zero", leaves[0], proof0, 0, 0, root},
		{"proof-too-short", leaves[0], proof0[:len(proof0)-1], 0, 4, root},
		{"proof-extra-entry", leaves[0], append(append([]string{}, proof0...), goLeafHash("x")), 0, 4, root},
		{"malformed-element", leaves[0], []string{proof0[0], "zz"}, 0, 4, root},
		{"malformed-leaf", "not-hex", proof0, 0, 4, root},
		{"malformed-root", leaves[0], proof0, 0, 4, "not-hex"},
		{"treesize-above-safe-integer", leaves[0], nil, 0, maxSafeInteger + 1, leaves[0]},
	}
	for _, c := range cases {
		if VerifyInclusionProof(c.leafHash, c.proof, c.leafIndex, c.treeSize, c.root) {
			t.Errorf("%s: expected reject, got accept", c.name)
		}
	}
}

// TestVerifyInclusionProofOverlongRejected ensures a proof longer than the depth
// cap is rejected before any hashing work.
func TestVerifyInclusionProofOverlongRejected(t *testing.T) {
	proof := make([]string, maxProofLength+1)
	for i := range proof {
		proof[i] = goLeafHash(fmt.Sprintf("p-%d", i))
	}
	if VerifyInclusionProof(goLeafHash("leaf"), proof, 0, 2, goLeafHash("root")) {
		t.Errorf("expected reject for proof longer than maxProofLength")
	}
}
