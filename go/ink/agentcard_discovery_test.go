package ink

import "testing"

// baseDiscoveryCard returns a minimal valid Agent Card map. Tests add or
// mutate the optional discovery descriptor on top of it.
func baseDiscoveryCard() map[string]interface{} {
	return map[string]interface{}{
		"protocol":           "ink/0.1",
		"agentId":            "did:web:a.example",
		"handle":             "alice",
		"displayName":        "Alice",
		"endpoint":           "https://a.example/ink/inbox",
		"publicKeyMultibase": "z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
		"capabilities": map[string]interface{}{
			"intentsAccepted": []interface{}{"ask", "ping"},
			"intentsSent":     []interface{}{"ask"},
		},
		"availability": map[string]interface{}{"timezone": "America/Los_Angeles"},
	}
}

func TestValidateAgentCardDiscoveryDescriptor(t *testing.T) {
	cases := []struct {
		name string
		mut  func(m map[string]interface{})
		want bool
	}{
		{"no descriptor accepts", func(m map[string]interface{}) {}, true},
		{"enabled false accepts", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": false, "scope": "public"}
		}, true},
		{"enabled at visibility accepts", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{
				"enabled":   true,
				"scope":     "public",
				"tags":      []interface{}{"hiring", "ai"},
				"queryable": true,
				"updatedAt": "2026-06-26T00:00:00.000Z",
			}
		}, true},
		{"narrowing below visibility accepts", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "network_only"}
		}, true},
		{"absent visibility treated as public upper bound", func(m map[string]interface{}) {
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public"}
		}, true},
		{"private scope under private visibility accepts", func(m map[string]interface{}) {
			m["visibility"] = "private"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "private"}
		}, true},
		{"scope wider than visibility rejects", func(m map[string]interface{}) {
			m["visibility"] = "network_only"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public"}
		}, false},
		{"network_only scope under private rejects", func(m map[string]interface{}) {
			m["visibility"] = "private"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "network_only"}
		}, false},
		{"public scope under capability_gated rejects", func(m map[string]interface{}) {
			m["visibility"] = "capability_gated"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public"}
		}, false},
		{"missing enabled rejects", func(m map[string]interface{}) {
			m["discovery"] = map[string]interface{}{"scope": "public"}
		}, false},
		{"missing scope rejects", func(m map[string]interface{}) {
			m["discovery"] = map[string]interface{}{"enabled": true}
		}, false},
		{"unknown scope enum rejects", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "everyone"}
		}, false},
		{"non-boolean enabled rejects", func(m map[string]interface{}) {
			m["discovery"] = map[string]interface{}{"enabled": "yes", "scope": "public"}
		}, false},
		{"over-cap tags rejects", func(m map[string]interface{}) {
			tags := make([]interface{}, 33)
			for i := range tags {
				tags[i] = "x"
			}
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public", "tags": tags}
		}, false},
		{"empty tag rejects", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public", "tags": []interface{}{""}}
		}, false},
		{"over-long tag rejects", func(m map[string]interface{}) {
			long := make([]byte, 65)
			for i := range long {
				long[i] = 'x'
			}
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public", "tags": []interface{}{string(long)}}
		}, false},
		{"non-strict updatedAt rejects", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public", "updatedAt": "2026-06-26"}
		}, false},
		{"unknown descriptor key ignored", func(m map[string]interface{}) {
			m["visibility"] = "public"
			m["discovery"] = map[string]interface{}{"enabled": true, "scope": "public", "rank": float64(5)}
		}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := baseDiscoveryCard()
			c.mut(m)
			if got := ValidateAgentCard(m); got != c.want {
				t.Errorf("ValidateAgentCard = %v, want %v", got, c.want)
			}
		})
	}
}
