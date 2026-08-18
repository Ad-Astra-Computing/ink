package ink

import (
	"encoding/json"
	"testing"
)

// Step 9 of the discovery fetch contract (owner anti-substitution). A host that
// legitimately publishes a card for one DID must not be able to serve it in
// answer to resolution of another. The comparison is byte for byte, and both
// "card carries no ownerDid" and "fetch names no DID" pass unchanged.
func TestEvaluateAgentCardFetchOwnerAntiSubstitution(t *testing.T) {
	const agentID = "did:web:a.example"
	const ownerDID = "did:web:owner.example"

	body := func(extra map[string]interface{}) string {
		card := map[string]interface{}{
			"protocol":           "ink/0.1",
			"agentId":            agentID,
			"handle":             "alice",
			"displayName":        "Alice",
			"endpoint":           "https://a.example/ink/inbox",
			"publicKeyMultibase": "z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
			"capabilities": map[string]interface{}{
				"intentsAccepted": []interface{}{"ask"},
				"intentsSent":     []interface{}{"ask"},
			},
			"availability": map[string]interface{}{"timezone": "UTC"},
		}
		for k, v := range extra {
			card[k] = v
		}
		b, err := json.Marshal(card)
		if err != nil {
			t.Fatalf("marshal card: %v", err)
		}
		return string(b)
	}

	ct := "application/json"
	str := func(s string) *string { return &s }

	cases := []struct {
		name          string
		bodyRaw       string
		resolutionDID *string
		want          bool
	}{
		{"mismatch rejects", body(map[string]interface{}{"ownerDid": ownerDID}), str("did:web:someone-else.example"), false},
		{"match accepts", body(map[string]interface{}{"ownerDid": ownerDID}), str(ownerDID), true},
		{"no case folding", body(map[string]interface{}{"ownerDid": ownerDID}), str("did:web:Owner.example"), false},
		{"card without ownerDid accepts", body(nil), str(ownerDID), true},
		{"fetch without resolutionDid accepts", body(map[string]interface{}{"ownerDid": ownerDID}), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateAgentCardFetch(200, &ct, nil, c.bodyRaw, agentID, c.resolutionDID)
			if got != c.want {
				t.Errorf("EvaluateAgentCardFetch = %v, want %v", got, c.want)
			}
		})
	}

	// Step 9 runs after step 8: a mismatched agentId rejects regardless.
	if EvaluateAgentCardFetch(200, &ct, nil,
		body(map[string]interface{}{"agentId": "did:web:other.example", "ownerDid": ownerDID}),
		agentID, str(ownerDID)) {
		t.Error("identity mismatch must still reject")
	}
}
