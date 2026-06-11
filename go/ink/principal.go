package ink

import (
	"errors"
	"strings"
)

// agentIDKeyPrefixes are the scheme prefixes whose body is a key multibase.
// tulpa: and ink: are aliases for the same Ed25519 key.
var agentIDKeyPrefixes = []string{"tulpa:", "ink:"}

// CanonicalAgentPrincipal collapses an agentId to a prefix-independent
// principal that security state keys on. The tulpa: and ink: spellings of one
// key map to the same key: principal; a literal key: id is escaped to raw:key:
// so it cannot collide with a real key principal; other identifiers (DIDs) pass
// through; an empty or oversized id is rejected. A malformed key body is kept
// opaque (raw:) rather than throwing, so the function is total over valid input.
func CanonicalAgentPrincipal(agentID string) (string, error) {
	if n := utf16Len(agentID); n == 0 || n > 512 {
		return "", errors.New("invalid agent ID")
	}
	for _, prefix := range agentIDKeyPrefixes {
		if strings.HasPrefix(agentID, prefix) {
			key, err := DecodePublicKeyMultibase(agentID[len(prefix):])
			if err != nil {
				return "raw:" + agentID, nil
			}
			mb, err := EncodePublicKeyMultibase(key)
			if err != nil {
				return "raw:" + agentID, nil
			}
			return "key:" + mb, nil
		}
	}
	if strings.HasPrefix(agentID, "key:") {
		return "raw:" + agentID, nil
	}
	return agentID, nil
}
