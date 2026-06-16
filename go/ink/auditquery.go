package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"math"
)

// emptyTreeRootHex is SHA-256(""), the RFC 6962 root of an empty log. A fresh
// witness reports treeSize 0 with this root and no events or proofs.
const emptyTreeRootHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// safeIntFromFloat converts a decoded JSON number to an int under the reference's
// Number.isInteger rule: an integer-valued finite number in [min, 2^53-1].
func safeIntFromFloat(f float64, min int) (int, bool) {
	if math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) {
		return 0, false
	}
	if f < float64(min) || f > maxSafeInteger {
		return 0, false
	}
	return int(f), true
}

func asString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}

// checkAuditQueryResponseShape mirrors the reference structural validation
// (INK Auditability §7.3). It returns false for any envelope, event, or proof
// field that is out of spec, before any cryptography runs.
func checkAuditQueryResponseShape(r map[string]interface{}) bool {
	if v, _ := asString(r, "protocol"); v != "ink/0.1" {
		return false
	}
	if v, _ := asString(r, "type"); v != "network.tulpa.audit_query_response" {
		return false
	}
	for _, k := range []string{"serviceDid", "messageId", "requester", "timestamp", "serviceSignature"} {
		if v, ok := asString(r, k); !ok || v == "" {
			return false
		}
	}
	treeSizeF, ok := r["treeSize"].(float64)
	if !ok {
		return false
	}
	treeSize, ok := safeIntFromFloat(treeSizeF, 0)
	if !ok {
		return false
	}
	if rh, ok := asString(r, "rootHash"); !ok || !isMerkleHashHex(rh) {
		return false
	}
	events, ok := r["events"].([]interface{})
	if !ok {
		return false
	}
	proofs, ok := r["proofs"].([]interface{})
	if !ok {
		return false
	}
	if treeSize == 0 {
		if len(events) != 0 || len(proofs) != 0 {
			return false
		}
		if rh, _ := asString(r, "rootHash"); rh != emptyTreeRootHex {
			return false
		}
	}
	for _, e := range events {
		ev, ok := e.(map[string]interface{})
		if !ok {
			return false
		}
		if id, ok := asString(ev, "id"); !ok || id == "" {
			return false
		}
		if sig, ok := asString(ev, "agentSignature"); !ok || sig == "" {
			return false
		}
	}
	for _, p := range proofs {
		pr, ok := p.(map[string]interface{})
		if !ok {
			return false
		}
		if eid, ok := asString(pr, "eventId"); !ok || eid == "" {
			return false
		}
		liF, ok := pr["leafIndex"].(float64)
		if !ok {
			return false
		}
		li, ok := safeIntFromFloat(liF, 0)
		if !ok || li >= treeSize {
			return false
		}
		ip, ok := pr["inclusionProof"].([]interface{})
		if !ok || len(ip) > maxProofLength {
			return false
		}
		for _, h := range ip {
			hs, ok := h.(string)
			if !ok || !isMerkleHashHex(hs) {
				return false
			}
		}
	}
	return true
}

// verifyAuditQueryResponseSignature checks the witness Ed25519 signature over
// "ink/audit-query-response/v1\n" + JCS(response without serviceSignature).
func verifyAuditQueryResponseSignature(response map[string]interface{}, witnessPublicKey []byte) bool {
	sig, ok := asString(response, "serviceSignature")
	if !ok || !signatureRe.MatchString(sig) {
		return false
	}
	payload := make(map[string]interface{}, len(response))
	for k, v := range response {
		if k == "serviceSignature" {
			continue
		}
		payload[k] = v
	}
	if !isWithinCanonicalizeBounds(payload) {
		return false
	}
	canonical, err := canonicalizeJSON(payload)
	if err != nil {
		return false
	}
	prefixed := "ink/audit-query-response/v1\n" + canonical
	if len(prefixed) > maxCanonicalBodyBytes {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if len(witnessPublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(witnessPublicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(witnessPublicKey), []byte(prefixed), sigBytes)
}

// AuditQueryVerifyOptions carries the verifier inputs the caller supplies out of
// band: the requester and messageId it asked about, an optional expected witness
// DID and later checkpoint, and the required per-event signature verifier.
type AuditQueryVerifyOptions struct {
	ExpectedRequester  string
	ExpectedMessageID  string
	ExpectedServiceDid string // "" = skip
	LaterCheckpoint    *CheckpointRef
	// VerifyEventSignature resolves the submitting agent's key and validates the
	// event's agentSignature. It is REQUIRED (Auditability §7.5): a nil verifier
	// makes the result false, because Merkle inclusion alone does not prove an
	// agent produced the event.
	VerifyEventSignature func(event map[string]interface{}) bool
}

// safeVerifyEventSignature invokes the caller-supplied per-event verifier and
// treats a panic as a verification failure, matching the reference, which
// catches a throwing callback and rejects. A brittle caller resolver that, say,
// type-asserts a missing agentId must not crash the whole verifier.
func safeVerifyEventSignature(cb func(map[string]interface{}) bool, event map[string]interface{}) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return cb(event)
}

// VerifyInkAuditQueryResponse verifies a witness audit-query response end to end
// (INK Auditability §7.3): structure, the requester/messageId bindings, the
// witness envelope signature, the per-event scope rule, the events-to-proofs
// one-to-one mapping, every Merkle proof walk, the required per-event agent
// signature, and an optional later-checkpoint cross-check. It returns false,
// never panics, on any failed step.
func VerifyInkAuditQueryResponse(response map[string]interface{}, witnessPublicKey []byte, opts AuditQueryVerifyOptions) bool {
	if !checkAuditQueryResponseShape(response) {
		return false
	}

	// binding
	if mid, _ := asString(response, "messageId"); mid != opts.ExpectedMessageID {
		return false
	}
	if req, _ := asString(response, "requester"); req != opts.ExpectedRequester {
		return false
	}
	if opts.ExpectedServiceDid != "" {
		if sd, _ := asString(response, "serviceDid"); sd != opts.ExpectedServiceDid {
			return false
		}
	}

	// signature
	if !verifyAuditQueryResponseSignature(response, witnessPublicKey) {
		return false
	}

	events, _ := response["events"].([]interface{})
	proofs, _ := response["proofs"].([]interface{})
	envMessageID, _ := asString(response, "messageId")
	rootHash, _ := asString(response, "rootHash")
	treeSizeF, _ := response["treeSize"].(float64)
	treeSize, _ := safeIntFromFloat(treeSizeF, 0)

	// per-event scope
	for _, e := range events {
		ev := e.(map[string]interface{})
		if mid, ok := asString(ev, "messageId"); !ok || mid != envMessageID {
			return false
		}
		agentID, _ := asString(ev, "agentId")
		counterpartyID, _ := asString(ev, "counterpartyId")
		if agentID != opts.ExpectedRequester && counterpartyID != opts.ExpectedRequester {
			return false
		}
	}

	// events <-> proofs strict one-to-one by eventId
	if len(events) != len(proofs) {
		return false
	}
	eventIDs := make(map[string]bool, len(events))
	for _, e := range events {
		id, _ := asString(e.(map[string]interface{}), "id")
		if eventIDs[id] {
			return false
		}
		eventIDs[id] = true
	}
	proofByID := make(map[string]map[string]interface{}, len(proofs))
	for _, p := range proofs {
		pr := p.(map[string]interface{})
		eid, _ := asString(pr, "eventId")
		if _, dup := proofByID[eid]; dup {
			return false
		}
		if !eventIDs[eid] {
			return false
		}
		proofByID[eid] = pr
	}
	for id := range eventIDs {
		if _, ok := proofByID[id]; !ok {
			return false
		}
	}

	// proof walk
	for _, e := range events {
		ev := e.(map[string]interface{})
		id, _ := asString(ev, "id")
		pr := proofByID[id]
		leafHash, ok := ComputeAuditMerkleLeafHash(ev)
		if !ok {
			return false
		}
		liF, _ := pr["leafIndex"].(float64)
		leafIndex, ok := safeIntFromFloat(liF, 0)
		if !ok {
			return false
		}
		proof := make([]string, 0)
		ipRaw, _ := pr["inclusionProof"].([]interface{})
		for _, h := range ipRaw {
			proof = append(proof, h.(string))
		}
		if !VerifyInclusionProof(leafHash, proof, leafIndex, treeSize, rootHash) {
			return false
		}
	}

	// required per-event agent signature
	if opts.VerifyEventSignature == nil {
		return false
	}
	for _, e := range events {
		if !safeVerifyEventSignature(opts.VerifyEventSignature, e.(map[string]interface{})) {
			return false
		}
	}

	// optional later-checkpoint cross-check
	if cp := opts.LaterCheckpoint; cp != nil {
		if cp.TreeSize < 0 || !isMerkleHashHex(cp.RootHash) {
			return false
		}
		if cp.TreeSize < treeSize {
			return false
		}
		if cp.TreeSize == treeSize && cp.RootHash != rootHash {
			return false
		}
	}
	return true
}
