package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func signAuditQueryEnvelope(t *testing.T, witnessPriv ed25519.PrivateKey, payload map[string]interface{}) string {
	t.Helper()
	canonical, err := canonicalizeJSON(payload)
	if err != nil {
		t.Fatalf("canonicalize envelope: %v", err)
	}
	sig := ed25519.Sign(witnessPriv, []byte("ink/audit-query-response/v1\n"+canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyInkAuditQueryResponse(t *testing.T) {
	wSeed := sha256.Sum256([]byte("aq-witness"))
	wPriv := ed25519.NewKeyFromSeed(wSeed[:])
	wPub := wPriv.Public().(ed25519.PublicKey)
	aSeed := sha256.Sum256([]byte("aq-agent"))
	aPriv := ed25519.NewKeyFromSeed(aSeed[:])
	aPub := aPriv.Public().(ed25519.PublicKey)

	event := map[string]interface{}{
		"id": "e0", "type": "connection_request", "messageId": "m1",
		"agentId": "did:web:a", "counterpartyId": "did:web:b", "seq": float64(0),
	}
	event["agentSignature"] = signAuditEvent(t, aPriv, event)
	leaf, ok := ComputeAuditMerkleLeafHash(event)
	if !ok {
		t.Fatal("leaf hash failed")
	}
	payload := map[string]interface{}{
		"protocol": "ink/0.1", "type": "network.tulpa.audit_query_response", "serviceDid": "did:web:w",
		"messageId": "m1", "requester": "did:web:a",
		"events":   []interface{}{event},
		"proofs":   []interface{}{map[string]interface{}{"eventId": "e0", "leafIndex": float64(0), "inclusionProof": []interface{}{}}},
		"treeSize": float64(1), "rootHash": leaf, "timestamp": "2026-06-15T12:00:00.000Z",
	}
	response := map[string]interface{}{}
	for k, v := range payload {
		response[k] = v
	}
	response["serviceSignature"] = signAuditQueryEnvelope(t, wPriv, payload)

	opts := AuditQueryVerifyOptions{
		ExpectedRequester: "did:web:a",
		ExpectedMessageID: "m1",
		VerifyEventSignature: func(e map[string]interface{}) bool {
			return VerifyAuditEventSignature(e, aPub)
		},
	}
	if !VerifyInkAuditQueryResponse(response, wPub, opts) {
		t.Error("valid response rejected")
	}

	// A panicking callback must be caught and treated as a failure, not crash.
	opts.VerifyEventSignature = func(e map[string]interface{}) bool {
		_ = e["agentId"].(int) // wrong type assertion panics
		return true
	}
	if VerifyInkAuditQueryResponse(response, wPub, opts) {
		t.Error("panicking callback accepted")
	}

	// A nil callback is rejected (provenance check is required).
	opts.VerifyEventSignature = nil
	if VerifyInkAuditQueryResponse(response, wPub, opts) {
		t.Error("nil callback accepted")
	}

	// Wrong witness key.
	oSeed := sha256.Sum256([]byte("other-witness"))
	oPub := ed25519.NewKeyFromSeed(oSeed[:]).Public().(ed25519.PublicKey)
	opts.VerifyEventSignature = func(e map[string]interface{}) bool { return VerifyAuditEventSignature(e, aPub) }
	if VerifyInkAuditQueryResponse(response, oPub, opts) {
		t.Error("wrong witness key accepted")
	}
}

// A small-order witness key makes [h]A constant, so R=basepoint, S=1 verifies
// for any body under Go's bare crypto/ed25519.Verify. This pins that both
// audit-query-response entry points reject it at the shared signerStrategy
// gate instead of falling through to the raw ed25519.Verify call.
func TestVerifyInkAuditQueryResponseRejectsSmallOrderWitnessKey(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 0x01
	basepoint, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	scalarOne := make([]byte, 32)
	scalarOne[0] = 0x01
	forgedSig := append(append([]byte{}, basepoint...), scalarOne...)
	forgedSigB64 := base64.RawURLEncoding.EncodeToString(forgedSig)

	aSeed := sha256.Sum256([]byte("aq-forgery-agent"))
	aPriv := ed25519.NewKeyFromSeed(aSeed[:])
	aPub := aPriv.Public().(ed25519.PublicKey)

	event := map[string]interface{}{
		"id": "e0", "type": "connection_request", "messageId": "m1",
		"agentId": "did:web:a", "counterpartyId": "did:web:b", "seq": float64(0),
	}
	event["agentSignature"] = signAuditEvent(t, aPriv, event)
	leaf, ok := ComputeAuditMerkleLeafHash(event)
	if !ok {
		t.Fatal("leaf hash failed")
	}
	response := map[string]interface{}{
		"protocol": "ink/0.1", "type": "network.tulpa.audit_query_response", "serviceDid": "did:web:w",
		"messageId": "m1", "requester": "did:web:a",
		"events":           []interface{}{event},
		"proofs":           []interface{}{map[string]interface{}{"eventId": "e0", "leafIndex": float64(0), "inclusionProof": []interface{}{}}},
		"treeSize":         float64(1),
		"rootHash":         leaf,
		"timestamp":        "2026-06-15T12:00:00.000Z",
		"serviceSignature": forgedSigB64,
	}

	opts := AuditQueryVerifyOptions{
		ExpectedRequester: "did:web:a",
		ExpectedMessageID: "m1",
		VerifyEventSignature: func(e map[string]interface{}) bool {
			return VerifyAuditEventSignature(e, aPub)
		},
	}
	if VerifyInkAuditQueryResponse(response, identity, opts) {
		t.Error("VerifyInkAuditQueryResponse accepted a small-order-A (identity) universal forgery")
	}
	if r := VerifyInkAuditQueryResponseWithKeys(response, []CandidateKey{{PublicKey: identity, Status: "active"}}, "", opts); r.Verified {
		t.Error("VerifyInkAuditQueryResponseWithKeys accepted a small-order-A (identity) universal forgery")
	}
}
