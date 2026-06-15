package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// leafOf recomputes the RFC 6962 leaf hash from a known-canonical body string,
// independently of ComputeAuditMerkleLeafHash, so the assertions pin the rule
// rather than the implementation.
func leafOf(canonical string) string {
	sum := sha256.Sum256(append([]byte{0x00}, []byte(canonical)...))
	return hex.EncodeToString(sum[:])
}

func TestComputeAuditMerkleLeafHashKnown(t *testing.T) {
	// {"id":"evt-1","type":"connection_request"} is already in JCS member order.
	want := leafOf(`{"id":"evt-1","type":"connection_request"}`)
	got, ok := ComputeAuditMerkleLeafHash(map[string]interface{}{
		"id":   "evt-1",
		"type": "connection_request",
	})
	if !ok || got != want {
		t.Errorf("leaf = %q ok=%v, want %q", got, ok, want)
	}
}

func TestComputeAuditMerkleLeafHashStripsSignatureAndOrder(t *testing.T) {
	base, baseOK := ComputeAuditMerkleLeafHash(map[string]interface{}{
		"id":   "evt-1",
		"type": "connection_request",
	})
	withSig, sigOK := ComputeAuditMerkleLeafHash(map[string]interface{}{
		"type":           "connection_request",
		"id":             "evt-1",
		"agentSignature": "z3kmY29udGVudA",
	})
	if !baseOK || !sigOK || withSig != base {
		t.Errorf("agentSignature or member order changed the leaf: base=%q withSig=%q", base, withSig)
	}
}

func TestComputeAuditMerkleLeafHashEmptyObject(t *testing.T) {
	want := leafOf("{}")
	got, ok := ComputeAuditMerkleLeafHash(map[string]interface{}{})
	if !ok || got != want {
		t.Errorf("empty-object leaf = %q ok=%v, want %q", got, ok, want)
	}
}

func TestComputeAuditMerkleLeafHashBounds(t *testing.T) {
	// Depth past the bound (32): a 40-deep nest rejects before canonicalization.
	deep := interface{}("leaf")
	for i := 0; i < 40; i++ {
		deep = map[string]interface{}{"a": deep}
	}
	if _, ok := ComputeAuditMerkleLeafHash(map[string]interface{}{"a": deep}); ok {
		t.Errorf("excessive depth: expected reject, got accept")
	}

	// Node count past the bound (10000): an array of 10001 elements rejects.
	big := make([]interface{}, 10001)
	for i := range big {
		big[i] = float64(0)
	}
	if _, ok := ComputeAuditMerkleLeafHash(map[string]interface{}{"a": big}); ok {
		t.Errorf("excessive node count: expected reject, got accept")
	}

	// Canonical body past the 1 MiB cap rejects after canonicalization, while a
	// value just under the cap is accepted, so the boundary is exact.
	underCap := map[string]interface{}{"d": strings.Repeat("x", maxCanonicalBodyBytes-16)}
	if _, ok := ComputeAuditMerkleLeafHash(underCap); !ok {
		t.Errorf("just under the byte cap: expected accept, got reject")
	}
	overCap := map[string]interface{}{"d": strings.Repeat("x", maxCanonicalBodyBytes)}
	if _, ok := ComputeAuditMerkleLeafHash(overCap); ok {
		t.Errorf("over the byte cap: expected reject, got accept")
	}
}

func TestComputeAuditMerkleLeafHashRejects(t *testing.T) {
	cases := []struct {
		name  string
		event interface{}
	}{
		{"array", []interface{}{1.0, 2.0, 3.0}},
		{"string", "hello"},
		{"null", nil},
		{"number", float64(42)},
		{"unsafe-integer", map[string]interface{}{"n": float64(9007199254740992)}},
	}
	for _, c := range cases {
		if _, ok := ComputeAuditMerkleLeafHash(c.event); ok {
			t.Errorf("%s: expected reject, got accept", c.name)
		}
	}
}
