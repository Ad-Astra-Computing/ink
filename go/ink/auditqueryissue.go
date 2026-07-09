package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"unicode/utf8"
)

// SignAuditQueryResponse signs a witness audit-query response and returns the
// base64url serviceSignature over "ink/audit-query-response/v1\n" + JCS(response
// without serviceSignature). It is the issuing counterpart of
// VerifyInkAuditQueryResponse and mirrors the reference signAuditQueryResponse:
// the caller assembles the response envelope (protocol, type, serviceDid,
// messageId, requester, timestamp, treeSize, rootHash, events, proofs) and
// attaches the returned value as serviceSignature.
//
// This is the low-level primitive. It signs the exact bytes it is given, so the
// caller is responsible for building an in-spec envelope; a signature over a
// malformed envelope will still be rejected by the verifier. The one thing it
// enforces at sign time is the §7.3/§7.4 per-event scope rule, mirroring the
// reference: a conformant witness must not mint a signature over a response whose
// events fall outside the envelope's (messageId, requester) scope or drop their
// per-event agentSignature. Enforcing it here makes the primitive self-defending
// rather than able to emit bytes the verifier would only later reject.
func SignAuditQueryResponse(responseWithoutSignature map[string]interface{}, witnessPrivateKey ed25519.PrivateKey) (string, error) {
	if len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("witness private key must be an ed25519 private key")
	}
	if responseWithoutSignature == nil {
		return "", errors.New("response must be a non-null object")
	}
	if _, present := responseWithoutSignature["serviceSignature"]; present {
		return "", errors.New("responseWithoutSignature must not carry a serviceSignature")
	}
	if err := enforceAuditQueryResponseSignScope(responseWithoutSignature); err != nil {
		return "", err
	}
	// Bound the payload first: isWithinCanonicalizeBounds is depth-limited, so it
	// rejects an over-deep or cyclic in-memory structure before the portability
	// walk below recurses over it.
	if !isWithinCanonicalizeBounds(responseWithoutSignature) {
		return "", errors.New("audit-query response exceeds maximum allowed complexity")
	}
	// Refuse to sign over a non-portable or non-JSON payload. Invalid UTF-8 in a
	// string canonicalizes to U+FFFD (the reference rejects it before signing), and
	// a native Go integer would canonicalize but be rejected by the float64-only
	// verifier shape checks, yielding a signature that fails on the same in-memory
	// map. Requiring exactly what encoding/json produces keeps the signed bytes
	// portable and self-consistent with the verifier. The bounds check above caps
	// depth, so this recursion is bounded.
	if !isJSONPortable(responseWithoutSignature) {
		return "", errors.New("audit-query response contains a non-portable or non-JSON value")
	}
	canonical, err := canonicalizeJSON(responseWithoutSignature)
	if err != nil {
		return "", err
	}
	prefixed := "ink/audit-query-response/v1\n" + canonical
	if len(prefixed) > maxCanonicalBodyBytes {
		return "", errors.New("audit-query response exceeds maximum allowed size")
	}
	sig := ed25519.Sign(witnessPrivateKey, []byte(prefixed))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// isJSONPortable reports whether a value is exactly what encoding/json produces
// for a decoded document and is portable across implementations: nil, bool,
// float64, a valid-UTF-8 string, a slice of such values, or a map with
// valid-UTF-8 keys and such values. Any other Go type (a native integer, a
// float32, a json.Number, invalid UTF-8) is rejected, because it would either
// fail to round-trip through the float64-only verifier or serialize to different
// bytes under another implementation.
func isJSONPortable(v interface{}) bool {
	switch t := v.(type) {
	case nil, bool, float64:
		return true
	case string:
		return utf8.ValidString(t)
	case []interface{}:
		for _, e := range t {
			if !isJSONPortable(e) {
				return false
			}
		}
		return true
	case map[string]interface{}:
		for k, val := range t {
			if !utf8.ValidString(k) || !isJSONPortable(val) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// enforceAuditQueryResponseSignScope mirrors the reference sign-side scope
// enforcement: when the response carries events, the envelope must have a
// non-empty messageId and requester, and every event must be an object whose
// messageId matches the envelope, whose requester is a party (agentId or
// counterpartyId), and which carries a non-empty agentSignature. An empty-tree
// response (no events) is unconstrained here and validated structurally by the
// verifier.
func enforceAuditQueryResponseSignScope(response map[string]interface{}) error {
	eventsRaw, ok := response["events"].([]interface{})
	if !ok || len(eventsRaw) == 0 {
		return nil
	}
	envMessageID, ok := response["messageId"].(string)
	if !ok || envMessageID == "" {
		return errors.New("audit-query response must include a non-empty messageId")
	}
	envRequester, ok := response["requester"].(string)
	if !ok || envRequester == "" {
		return errors.New("audit-query response must include a non-empty requester")
	}
	for _, e := range eventsRaw {
		ev, ok := e.(map[string]interface{})
		if !ok {
			return errors.New("every event must be a non-null object")
		}
		if mid, _ := ev["messageId"].(string); mid != envMessageID {
			return errors.New("per-event scope violation: event.messageId does not match envelope.messageId")
		}
		agentID, _ := ev["agentId"].(string)
		counterpartyID, _ := ev["counterpartyId"].(string)
		if agentID != envRequester && counterpartyID != envRequester {
			return errors.New("per-event scope violation: requester is not a party (agentId/counterpartyId)")
		}
		if sig, _ := ev["agentSignature"].(string); sig == "" {
			return errors.New("per-event scope violation: event.agentSignature is missing or empty")
		}
	}
	return nil
}
