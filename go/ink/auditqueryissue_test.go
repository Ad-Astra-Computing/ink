package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// loadAQCase parses one audit-query-response vector case into the witness key
// hex, the resolved agent keys, the response object, and the expected bindings.
func loadAQCase(t *testing.T, caseID string) (resp map[string]interface{}, witnessHex, expectedRequester, expectedMessageID string, agentKeys map[string][]byte) {
	t.Helper()
	vf := loadVectors(t, "audit-query-response")
	for _, c := range vf.Cases {
		if c.CaseID != caseID {
			continue
		}
		decodeJSON(t, c.Input["witnessPublicKeyHex"], &witnessHex)
		decodeJSON(t, c.Input["expectedRequester"], &expectedRequester)
		decodeJSON(t, c.Input["expectedMessageId"], &expectedMessageID)
		var keysHex map[string]string
		if raw, ok := c.Input["agentKeysHex"]; ok {
			decodeJSON(t, raw, &keysHex)
		}
		agentKeys = make(map[string][]byte, len(keysHex))
		for k, v := range keysHex {
			b, err := hex.DecodeString(v)
			if err != nil {
				t.Fatalf("%s: bad agent key hex: %v", caseID, err)
			}
			agentKeys[k] = b
		}
		decodeJSON(t, c.Input["response"], &resp)
		return
	}
	t.Fatalf("audit-query-response case %q not found", caseID)
	return
}

func decodeJSON(t *testing.T, raw json.RawMessage, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// withoutServiceSignature returns a shallow copy of the response without the
// serviceSignature key, the payload the signer canonicalizes over.
func withoutServiceSignature(resp map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(resp))
	for k, v := range resp {
		if k == "serviceSignature" {
			continue
		}
		out[k] = v
	}
	return out
}

// TestSignAuditQueryResponseReproducesFrozenVector pins that the Go issuer emits
// the exact serviceSignature the frozen corpus carries, across the legacy and
// vendor-neutral namespaces and the empty tree, not merely a signature the
// verifier happens to accept.
func TestSignAuditQueryResponseReproducesFrozenVector(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	for _, caseID := range []string{"valid-accepts", "ink-namespace-accepts", "empty-tree-accepts"} {
		resp, witnessHex, _, _, _ := loadAQCase(t, caseID)
		if hex.EncodeToString(pub) != witnessHex {
			t.Fatalf("%s: witness key mismatch: derived %s, vector %s", caseID, hex.EncodeToString(pub), witnessHex)
		}
		want, _ := resp["serviceSignature"].(string)
		if want == "" {
			t.Fatalf("%s: vector has no serviceSignature", caseID)
		}
		got, err := SignAuditQueryResponse(withoutServiceSignature(resp), priv)
		if err != nil {
			t.Fatalf("%s: SignAuditQueryResponse: %v", caseID, err)
		}
		if got != want {
			t.Errorf("%s: serviceSignature = %s, want %s", caseID, got, want)
		}
	}
}

// TestSignAuditQueryResponseRoundTrip signs the payload and checks the full
// verifier accepts it, resolving each event's agent key from the vector.
func TestSignAuditQueryResponseRoundTrip(t *testing.T) {
	priv, pub := conformanceWitnessKey()
	resp, _, expReq, expMsg, agentKeys := loadAQCase(t, "valid-accepts")
	payload := withoutServiceSignature(resp)
	sig, err := SignAuditQueryResponse(payload, priv)
	if err != nil {
		t.Fatalf("SignAuditQueryResponse: %v", err)
	}
	payload["serviceSignature"] = sig

	opts := AuditQueryVerifyOptions{
		ExpectedRequester: expReq,
		ExpectedMessageID: expMsg,
		VerifyEventSignature: func(ev map[string]interface{}) bool {
			agentID, _ := ev["agentId"].(string)
			key, ok := agentKeys[agentID]
			if !ok {
				return false
			}
			return VerifyAuditEventSignature(ev, key)
		},
	}
	if !VerifyInkAuditQueryResponse(payload, pub, opts) {
		t.Error("signed response did not verify end to end")
	}
	// A signature checked against a different witness key must fail.
	_, otherPub := aqOtherKey()
	if VerifyInkAuditQueryResponse(payload, otherPub, opts) {
		t.Error("verified against the wrong witness key")
	}
}

func TestSignAuditQueryResponseScopeEnforcement(t *testing.T) {
	priv, _ := conformanceWitnessKey()

	// A clean payload signs without error.
	base, _, _, _, _ := loadAQCase(t, "valid-accepts")
	if _, err := SignAuditQueryResponse(withoutServiceSignature(base), priv); err != nil {
		t.Fatalf("clean payload: %v", err)
	}

	// Each mutation reloads the case so the change is isolated.
	firstEvent := func(p map[string]interface{}) map[string]interface{} {
		return p["events"].([]interface{})[0].(map[string]interface{})
	}
	cases := []struct {
		name   string
		mutate func(p map[string]interface{})
	}{
		{"event messageId mismatch", func(p map[string]interface{}) { firstEvent(p)["messageId"] = "other" }},
		{"requester not a party", func(p map[string]interface{}) { p["requester"] = "did:web:stranger.example" }},
		{"missing agentSignature", func(p map[string]interface{}) { delete(firstEvent(p), "agentSignature") }},
		{"empty agentSignature", func(p map[string]interface{}) { firstEvent(p)["agentSignature"] = "" }},
		{"empty envelope messageId", func(p map[string]interface{}) { p["messageId"] = "" }},
		{"non-object event", func(p map[string]interface{}) { p["events"].([]interface{})[0] = "not-an-object" }},
	}
	for _, c := range cases {
		resp, _, _, _, _ := loadAQCase(t, "valid-accepts")
		payload := withoutServiceSignature(resp)
		c.mutate(payload)
		if _, err := SignAuditQueryResponse(payload, priv); err == nil {
			t.Errorf("%s: signed a scope-violating response", c.name)
		}
	}
}

func TestSignAuditQueryResponseInputValidation(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	resp, _, _, _, _ := loadAQCase(t, "valid-accepts")

	if _, err := SignAuditQueryResponse(nil, priv); err == nil {
		t.Error("nil response accepted")
	}
	if _, err := SignAuditQueryResponse(withoutServiceSignature(resp), make([]byte, 5)); err == nil {
		t.Error("bad private key length accepted")
	}
	// A payload that still carries a serviceSignature is rejected: the signer must
	// canonicalize over the response minus its signature.
	if _, err := SignAuditQueryResponse(resp, priv); err == nil {
		t.Error("payload with serviceSignature accepted")
	}
}

// TestSignAuditQueryResponsePortability covers the non-portable and non-JSON
// payload rejections: invalid UTF-8 in a string canonicalizes to U+FFFD, and a
// native Go integer would canonicalize but the float64-only verifier would then
// reject the same in-memory map.
func TestSignAuditQueryResponsePortability(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	cases := []struct {
		name   string
		mutate func(p map[string]interface{})
	}{
		{"invalid utf8 string value", func(p map[string]interface{}) { p["serviceDid"] = "did:web:\xff.example" }},
		{"native int treeSize", func(p map[string]interface{}) { p["treeSize"] = 3 }},
		{"native int leafIndex", func(p map[string]interface{}) {
			p["proofs"].([]interface{})[0].(map[string]interface{})["leafIndex"] = 0
		}},
		{"float32 value", func(p map[string]interface{}) { p["treeSize"] = float32(3) }},
	}
	for _, c := range cases {
		resp, _, _, _, _ := loadAQCase(t, "valid-accepts")
		payload := withoutServiceSignature(resp)
		c.mutate(payload)
		if _, err := SignAuditQueryResponse(payload, priv); err == nil {
			t.Errorf("%s: signed a non-portable payload", c.name)
		}
	}
}

func aqOtherKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("aq-other-witness"))
	p := ed25519.NewKeyFromSeed(seed[:])
	return p, p.Public().(ed25519.PublicKey)
}
