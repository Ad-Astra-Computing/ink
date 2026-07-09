package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// leafHashOf reproduces the conformance generator's merkleLeafHash: the leaf
// hash is SHA-256(0x00 || utf8(label)). Reconstructing the exact frozen leaves
// lets the tests assert the Go issuer emits byte-identical roots and proofs.
func leafHashOf(label string) string {
	sum := sha256.Sum256(append([]byte{0x00}, []byte(label)...))
	return hex.EncodeToString(sum[:])
}

func buildLeaves(prefix string, n int) []string {
	leaves := make([]string, n)
	for i := 0; i < n; i++ {
		leaves[i] = leafHashOf(fmt.Sprintf("%s-%d", prefix, i))
	}
	return leaves
}

func equalHex(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMerkleIssueReproducesInclusionVectors pins that the Go issuer emits the
// exact roots and inclusion proofs the frozen merkle-inclusion corpus expects,
// not merely a proof that round-trips (issuer and verifier could share a bug).
func TestMerkleIssueReproducesInclusionVectors(t *testing.T) {
	leaves := buildLeaves("ink-conformance-merkle-leaf", 5)
	vf := loadVectors(t, "merkle-inclusion")
	seen := 0
	for _, c := range vf.Cases {
		if c.Expect.Result != "accept" {
			continue
		}
		var in struct {
			LeafHash       string   `json:"leafHash"`
			InclusionProof []string `json:"inclusionProof"`
			LeafIndex      int      `json:"leafIndex"`
			TreeSize       int      `json:"treeSize"`
			RootHash       string   `json:"rootHash"`
		}
		mustUnmarshalCase(t, c, &in)
		sub := leaves[:in.TreeSize]
		root, err := MerkleTreeHead(sub)
		if err != nil {
			t.Fatalf("%s: MerkleTreeHead: %v", c.CaseID, err)
		}
		if root != in.RootHash {
			t.Errorf("%s: root = %s, want %s", c.CaseID, root, in.RootHash)
		}
		if sub[in.LeafIndex] != in.LeafHash {
			t.Errorf("%s: leaf mismatch", c.CaseID)
		}
		proof, err := InclusionProof(sub, in.LeafIndex)
		if err != nil {
			t.Fatalf("%s: InclusionProof: %v", c.CaseID, err)
		}
		if !equalHex(proof, in.InclusionProof) {
			t.Errorf("%s: proof = %v, want %v", c.CaseID, proof, in.InclusionProof)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no accept inclusion vectors exercised")
	}
}

func TestMerkleIssueReproducesConsistencyVectors(t *testing.T) {
	leaves := buildLeaves("ink-conformance-consistency-leaf", 8)
	vf := loadVectors(t, "merkle-consistency")
	seen := 0
	for _, c := range vf.Cases {
		if c.Expect.Result != "accept" {
			continue
		}
		var in struct {
			First      int      `json:"first"`
			FirstRoot  string   `json:"firstRoot"`
			Second     int      `json:"second"`
			SecondRoot string   `json:"secondRoot"`
			Proof      []string `json:"proof"`
		}
		mustUnmarshalCase(t, c, &in)
		firstRoot, err := MerkleTreeHead(leaves[:in.First])
		if err != nil {
			t.Fatalf("%s: firstRoot: %v", c.CaseID, err)
		}
		if firstRoot != in.FirstRoot {
			t.Errorf("%s: firstRoot = %s, want %s", c.CaseID, firstRoot, in.FirstRoot)
		}
		secondRoot, err := MerkleTreeHead(leaves[:in.Second])
		if err != nil {
			t.Fatalf("%s: secondRoot: %v", c.CaseID, err)
		}
		if secondRoot != in.SecondRoot {
			t.Errorf("%s: secondRoot = %s, want %s", c.CaseID, secondRoot, in.SecondRoot)
		}
		proof, err := ConsistencyProof(leaves, in.First, in.Second)
		if err != nil {
			t.Fatalf("%s: ConsistencyProof: %v", c.CaseID, err)
		}
		if !equalHex(proof, in.Proof) {
			t.Errorf("%s: proof = %v, want %v", c.CaseID, proof, in.Proof)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no accept consistency vectors exercised")
	}
}

// TestIssuedProofsRoundTripThroughVerifiers issues a proof for every leaf and
// every (first, second) pair across a range of tree sizes and confirms the
// existing verifiers accept them.
func TestIssuedProofsRoundTripThroughVerifiers(t *testing.T) {
	sizes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 31, 32, 33, 34}
	for _, size := range sizes {
		leaves := buildLeaves("roundtrip-leaf", size)
		root, err := MerkleTreeHead(leaves)
		if err != nil {
			t.Fatalf("size %d: MerkleTreeHead: %v", size, err)
		}
		for i := 0; i < size; i++ {
			proof, err := InclusionProof(leaves, i)
			if err != nil {
				t.Fatalf("size %d idx %d: InclusionProof: %v", size, i, err)
			}
			if !VerifyInclusionProof(leaves[i], proof, i, size, root) {
				t.Errorf("size %d idx %d: issued inclusion proof did not verify", size, i)
			}
		}
		for first := 1; first <= size; first++ {
			for second := first; second <= size; second++ {
				firstRoot, err := MerkleTreeHead(leaves[:first])
				if err != nil {
					t.Fatal(err)
				}
				secondRoot, err := MerkleTreeHead(leaves[:second])
				if err != nil {
					t.Fatal(err)
				}
				proof, err := ConsistencyProof(leaves, first, second)
				if err != nil {
					t.Fatalf("size %d %d->%d: ConsistencyProof: %v", size, first, second, err)
				}
				if !VerifyConsistencyProof(first, firstRoot, second, secondRoot, proof) {
					t.Errorf("size %d: issued consistency proof %d->%d did not verify", size, first, second)
				}
			}
		}
	}
}

func TestMerkleIssueValidation(t *testing.T) {
	leaves := buildLeaves("v", 3)
	if root, err := MerkleTreeHead(nil); err != nil || root != merkleEmptyRoot {
		t.Error("empty tree should yield the empty-tree root")
	}
	if _, err := MerkleTreeHead([]string{"not-hex"}); err == nil {
		t.Error("non-hex leaf accepted")
	}
	if _, err := InclusionProof(leaves, 3); err == nil {
		t.Error("out-of-range index accepted")
	}
	if _, err := InclusionProof(leaves, -1); err == nil {
		t.Error("negative index accepted")
	}
	if _, err := ConsistencyProof(leaves, 2, 4); err == nil {
		t.Error("second past length accepted")
	}
	if _, err := ConsistencyProof(leaves, 3, 2); err == nil {
		t.Error("first > second accepted")
	}
	if p, err := ConsistencyProof(leaves, 0, 2); err != nil || len(p) != 0 {
		t.Error("empty-tree consistency should be an empty proof")
	}
	if p, err := ConsistencyProof(nil, 0, 0); err != nil || len(p) != 0 {
		t.Error("empty-to-empty consistency should be an empty proof without leaves")
	}
	if p, err := ConsistencyProof(leaves, 2, 2); err != nil || len(p) != 0 {
		t.Error("equal-size consistency should be an empty proof")
	}
}

func mustUnmarshalCase(t *testing.T, c conformanceCase, v interface{}) {
	t.Helper()
	raw, err := json.Marshal(c.Input)
	if err != nil {
		t.Fatalf("%s: remarshal input: %v", c.CaseID, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: unmarshal input: %v", c.CaseID, err)
	}
}
