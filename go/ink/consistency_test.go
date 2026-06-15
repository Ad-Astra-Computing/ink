package ink

import (
	"fmt"
	"testing"
)

// The helpers below are an independent recursive RFC 6962 consistency-proof
// generator, deliberately not the imperative production verifier in
// consistency.go. Agreement between the recursive SUBPROOF generator and the
// imperative walk across the exhaustive small matrix is what makes a round-trip
// pass meaningful: an off-by-one in one would have to be mirrored in the other
// to go unnoticed. goLeafHash and merkleNodeHash are shared with merkle_test.go.

func goConsistencyMth(t *testing.T, leaves []string, start, size int) string {
	t.Helper()
	if size == 0 {
		return emptyTreeRoot
	}
	if size == 1 {
		return leaves[start]
	}
	k := largestPowerOf2LessThan(size)
	h, err := merkleNodeHash(goConsistencyMth(t, leaves, start, k), goConsistencyMth(t, leaves, start+k, size-k))
	if err != nil {
		t.Fatalf("merkleNodeHash: %v", err)
	}
	return h
}

func goConsistencySubproof(t *testing.T, leaves []string, m, start, size int, b bool) []string {
	t.Helper()
	if m == size {
		if b {
			return nil
		}
		return []string{goConsistencyMth(t, leaves, start, size)}
	}
	k := largestPowerOf2LessThan(size)
	if m <= k {
		return append(goConsistencySubproof(t, leaves, m, start, k, b), goConsistencyMth(t, leaves, start+k, size-k))
	}
	return append(goConsistencySubproof(t, leaves, m-k, start+k, size-k, false), goConsistencyMth(t, leaves, start, k))
}

func goConsistencyProof(t *testing.T, leaves []string, m, n int) []string {
	t.Helper()
	if m == 0 || m == n {
		return nil
	}
	return goConsistencySubproof(t, leaves, m, 0, n, true)
}

// TestVerifyConsistencyProofRoundTrip verifies every 1 <= m <= n <= 24, the
// exhaustive small matrix, so any power-of-two or off-by-one split error is
// caught against an independently generated proof.
func TestVerifyConsistencyProofRoundTrip(t *testing.T) {
	const N = 24
	leaves := make([]string, N)
	for i := range leaves {
		leaves[i] = goLeafHash(fmt.Sprintf("leaf-%d", i))
	}
	roots := make([]string, N+1)
	for s := 0; s <= N; s++ {
		roots[s] = goConsistencyMth(t, leaves, 0, s)
	}
	for n := 1; n <= N; n++ {
		for m := 1; m <= n; m++ {
			proof := goConsistencyProof(t, leaves, m, n)
			if !VerifyConsistencyProof(m, roots[m], n, roots[n], proof) {
				t.Errorf("m=%d n=%d: valid consistency proof rejected", m, n)
			}
		}
	}
}

// TestVerifyConsistencyProofEmptyPrefix pins the first = 0 edge: the empty tree
// is a prefix of every tree, carries the fixed empty-tree root, and an empty
// proof; any other first root is rejected.
func TestVerifyConsistencyProofEmptyPrefix(t *testing.T) {
	leaves := make([]string, 4)
	for i := range leaves {
		leaves[i] = goLeafHash(fmt.Sprintf("leaf-%d", i))
	}
	second := goConsistencyMth(t, leaves, 0, 4)
	if !VerifyConsistencyProof(0, emptyTreeRoot, 4, second, nil) {
		t.Errorf("empty prefix with empty-tree root rejected")
	}
	if VerifyConsistencyProof(0, goConsistencyMth(t, leaves, 0, 3), 4, second, nil) {
		t.Errorf("empty prefix with a non-empty root accepted")
	}
}

// TestVerifyConsistencyProofRejects pins every rejection branch on a 5 -> 8
// proof so a regression in the strictness checks is caught.
func TestVerifyConsistencyProofRejects(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = goLeafHash(fmt.Sprintf("leaf-%d", i))
	}
	first := goConsistencyMth(t, leaves, 0, 5)
	second := goConsistencyMth(t, leaves, 0, 8)
	proof := goConsistencyProof(t, leaves, 5, 8)

	flip := func(h string) string {
		last := h[len(h)-1]
		if last == '0' {
			return h[:len(h)-1] + "1"
		}
		return h[:len(h)-1] + "0"
	}

	cases := []struct {
		name   string
		first  int
		fRoot  string
		second int
		sRoot  string
		proof  []string
	}{
		{"tampered-second-root", 5, first, 8, flip(second), proof},
		{"tampered-first-root", 5, flip(first), 8, second, proof},
		{"wrong-proof-element", 5, first, 8, second, append([]string{flip(proof[0])}, proof[1:]...)},
		{"proof-too-short", 5, first, 8, second, proof[:len(proof)-1]},
		{"proof-extra-entry", 5, first, 8, second, append(append([]string{}, proof...), leaves[0])},
		{"first-greater-than-second", 8, second, 4, goConsistencyMth(t, leaves, 0, 4), nil},
		{"equal-size-root-mismatch", 4, goConsistencyMth(t, leaves, 0, 4), 4, flip(goConsistencyMth(t, leaves, 0, 4)), nil},
		{"malformed-proof-element", 5, first, 8, second, append([]string{"zz"}, proof[1:]...)},
		{"malformed-first-root", 5, "not-hex", 8, second, proof},
		{"negative-first", -1, first, 8, second, proof},
		{"second-above-safe-integer", 1, leaves[0], maxSafeInteger + 1, leaves[1], nil},
	}
	for _, c := range cases {
		if VerifyConsistencyProof(c.first, c.fRoot, c.second, c.sRoot, c.proof) {
			t.Errorf("%s: expected reject, got accept", c.name)
		}
	}
}
