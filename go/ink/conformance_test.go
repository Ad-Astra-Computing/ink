package ink

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsDir is the shared conformance corpus, relative to this package.
const vectorsDir = "../../conformance/v1/vectors"

type vectorFile struct {
	Format   string            `json:"format"`
	Category string            `json:"category"`
	Cases    []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	CaseID      string                     `json:"caseId"`
	Description string                     `json:"description"`
	Input       map[string]json.RawMessage `json:"input"`
	Expect      struct {
		Result             string `json:"result"`
		CanonicalPrincipal string `json:"canonicalPrincipal"`
		KeyStatus          string `json:"keyStatus"`
		KeyID              string `json:"keyId"`
		EpochMs            *int64 `json:"epochMs"`
		CanonicalString    string `json:"canonicalString"`
		LeafHash           string `json:"leafHash"`
	} `json:"expect"`
}

func loadVectors(t *testing.T, category string) vectorFile {
	t.Helper()
	path := filepath.Join(vectorsDir, category+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if vf.Format != "ink.conformance.v1" {
		t.Fatalf("%s: unexpected format %q", path, vf.Format)
	}
	if len(vf.Cases) == 0 {
		t.Fatalf("%s: no cases", path)
	}
	return vf
}

func TestTimestampValidity(t *testing.T) {
	vf := loadVectors(t, "timestamp-validity")
	for _, c := range vf.Cases {
		var ts string
		if err := json.Unmarshal(c.Input["timestamp"], &ts); err != nil {
			t.Fatalf("%s: bad timestamp: %v", c.CaseID, err)
		}
		ms, ok := ParseInkTimestampMs(ts)
		if c.Expect.Result == "reject" {
			if ok {
				t.Errorf("%s: expected reject, got accept (ms=%d)", c.CaseID, ms)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: expected accept, got reject", c.CaseID)
			continue
		}
		if c.Expect.EpochMs != nil && ms != *c.Expect.EpochMs {
			t.Errorf("%s: epochMs = %d, want %d", c.CaseID, ms, *c.Expect.EpochMs)
		}
	}
}

func TestJCSStringSafety(t *testing.T) {
	vf := loadVectors(t, "jcs-string-safety")
	for _, c := range vf.Cases {
		var bodyRaw string
		if err := json.Unmarshal(c.Input["bodyRaw"], &bodyRaw); err != nil {
			t.Fatalf("%s: bad bodyRaw: %v", c.CaseID, err)
		}
		reject := ContainsLoneSurrogateEscape([]byte(bodyRaw))
		got := "accept"
		if reject {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s: got %s, want %s", c.CaseID, got, c.Expect.Result)
		}
	}
}

func TestJCSNumber(t *testing.T) {
	vf := loadVectors(t, "jcs-number")
	for _, c := range vf.Cases {
		var bodyRaw string
		if err := json.Unmarshal(c.Input["bodyRaw"], &bodyRaw); err != nil {
			t.Fatalf("%s: bad bodyRaw: %v", c.CaseID, err)
		}
		parsed, parseErr := ParseSignedBody([]byte(bodyRaw))
		canonical := ""
		var canonErr error
		if parseErr == nil {
			canonical, canonErr = canonicalizeJSON(parsed)
		}
		rejected := parseErr != nil || canonErr != nil
		if c.Expect.Result == "reject" {
			if !rejected {
				t.Errorf("%s: expected reject, got %q", c.CaseID, canonical)
			}
			continue
		}
		if rejected {
			t.Errorf("%s: expected accept, got error (parse=%v canon=%v)", c.CaseID, parseErr, canonErr)
			continue
		}
		if c.Expect.CanonicalString != "" && canonical != c.Expect.CanonicalString {
			t.Errorf("%s: canonical = %q, want %q", c.CaseID, canonical, c.Expect.CanonicalString)
		}
	}
}

func TestMerkleInclusion(t *testing.T) {
	vf := loadVectors(t, "merkle-inclusion")
	for _, c := range vf.Cases {
		var leafHash, rootHash string
		var proof []string
		var leafIndex, treeSize int
		if err := json.Unmarshal(c.Input["leafHash"], &leafHash); err != nil {
			t.Fatalf("%s: bad leafHash: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["rootHash"], &rootHash); err != nil {
			t.Fatalf("%s: bad rootHash: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["inclusionProof"], &proof); err != nil {
			t.Fatalf("%s: bad inclusionProof: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["leafIndex"], &leafIndex); err != nil {
			t.Fatalf("%s: bad leafIndex: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["treeSize"], &treeSize); err != nil {
			t.Fatalf("%s: bad treeSize: %v", c.CaseID, err)
		}
		ok := VerifyInclusionProof(leafHash, proof, leafIndex, treeSize, rootHash)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: VerifyInclusionProof = %v, want %v", c.CaseID, ok, want)
		}
	}
}

func TestMerkleConsistency(t *testing.T) {
	vf := loadVectors(t, "merkle-consistency")
	for _, c := range vf.Cases {
		var firstRoot, secondRoot string
		var proof []string
		var first, second int
		if err := json.Unmarshal(c.Input["firstRoot"], &firstRoot); err != nil {
			t.Fatalf("%s: bad firstRoot: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["secondRoot"], &secondRoot); err != nil {
			t.Fatalf("%s: bad secondRoot: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["proof"], &proof); err != nil {
			t.Fatalf("%s: bad proof: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["first"], &first); err != nil {
			t.Fatalf("%s: bad first: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["second"], &second); err != nil {
			t.Fatalf("%s: bad second: %v", c.CaseID, err)
		}
		ok := VerifyConsistencyProof(first, firstRoot, second, secondRoot, proof)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: VerifyConsistencyProof = %v, want %v", c.CaseID, ok, want)
		}
	}
}

func TestMerkleCheckpoint(t *testing.T) {
	vf := loadVectors(t, "merkle-checkpoint")
	for _, c := range vf.Cases {
		var body string
		if err := json.Unmarshal(c.Input["body"], &body); err != nil {
			t.Fatalf("%s: bad body: %v", c.CaseID, err)
		}
		parsed, ok := ParseCheckpoint(body)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: ParseCheckpoint ok = %v, want %v", c.CaseID, ok, want)
			continue
		}
		if ok && c.Expect.CanonicalString != "" {
			if got := FormatCheckpoint(parsed); got != c.Expect.CanonicalString {
				t.Errorf("%s: canonical = %q, want %q", c.CaseID, got, c.Expect.CanonicalString)
			}
		}
	}
}

func TestMerkleLeaf(t *testing.T) {
	vf := loadVectors(t, "merkle-leaf")
	for _, c := range vf.Cases {
		var eventRaw string
		if err := json.Unmarshal(c.Input["eventRaw"], &eventRaw); err != nil {
			t.Fatalf("%s: bad eventRaw: %v", c.CaseID, err)
		}
		want := c.Expect.Result == "accept"
		parsed, err := ParseSignedBody([]byte(eventRaw))
		if err != nil {
			if want {
				t.Errorf("%s: ParseSignedBody rejected an accept vector: %v", c.CaseID, err)
			}
			continue
		}
		got, ok := ComputeAuditMerkleLeafHash(parsed)
		if ok != want {
			t.Errorf("%s: ComputeAuditMerkleLeafHash ok = %v, want %v", c.CaseID, ok, want)
			continue
		}
		if ok && got != c.Expect.LeafHash {
			t.Errorf("%s: leafHash = %q, want %q", c.CaseID, got, c.Expect.LeafHash)
		}
	}
}

func TestAgentCard(t *testing.T) {
	vf := loadVectors(t, "agent-card")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"
		var card map[string]interface{}
		if err := json.Unmarshal(c.Input["card"], &card); err != nil {
			if want {
				t.Errorf("%s: card is not an object but vector expects accept", c.CaseID)
			}
			continue
		}
		if got := ValidateAgentCard(card); got != want {
			t.Errorf("%s: ValidateAgentCard = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestAgentCardFetch(t *testing.T) {
	vf := loadVectors(t, "agent-card-fetch")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"
		var status int
		if err := json.Unmarshal(c.Input["status"], &status); err != nil {
			t.Fatalf("%s: bad status: %v", c.CaseID, err)
		}
		var contentType, contentLength *string
		if raw, ok := c.Input["contentType"]; ok {
			_ = json.Unmarshal(raw, &contentType)
		}
		if raw, ok := c.Input["contentLength"]; ok {
			_ = json.Unmarshal(raw, &contentLength)
		}
		var bodyRaw, reqID string
		_ = json.Unmarshal(c.Input["bodyRaw"], &bodyRaw)
		_ = json.Unmarshal(c.Input["requestedAgentId"], &reqID)
		if got := EvaluateAgentCardFetch(status, contentType, contentLength, bodyRaw, reqID); got != want {
			t.Errorf("%s: EvaluateAgentCardFetch = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestPrivateHostname(t *testing.T) {
	vf := loadVectors(t, "private-hostname")
	for _, c := range vf.Cases {
		var hostname string
		if err := json.Unmarshal(c.Input["hostname"], &hostname); err != nil {
			t.Fatalf("%s: bad hostname: %v", c.CaseID, err)
		}
		// accept = public/safe (IsPrivateHostname false); reject = private/unsafe.
		got := "accept"
		if IsPrivateHostname(hostname) {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s (%q): got %s, want %s", c.CaseID, hostname, got, c.Expect.Result)
		}
	}
}

func TestConnectionPayload(t *testing.T) {
	vf := loadVectors(t, "connection-payload")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"
		var kind string
		if err := json.Unmarshal(c.Input["kind"], &kind); err != nil {
			t.Fatalf("%s: bad kind: %v", c.CaseID, err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(c.Input["payload"], &payload); err != nil {
			if want {
				t.Errorf("%s: payload is not an object but vector expects accept", c.CaseID)
			}
			continue
		}
		if got := ValidateConnectionPayload(kind, payload); got != want {
			t.Errorf("%s: ValidateConnectionPayload = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestHandshakeMessage(t *testing.T) {
	vf := loadVectors(t, "handshake-message")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"
		var message map[string]interface{}
		if err := json.Unmarshal(c.Input["message"], &message); err != nil {
			if want {
				t.Errorf("%s: message is not an object but vector expects accept", c.CaseID)
			}
			continue
		}
		if got := ValidateHandshakeMessage(message); got != want {
			t.Errorf("%s: ValidateHandshakeMessage = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestAuditQueryResponse(t *testing.T) {
	vf := loadVectors(t, "audit-query-response")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"

		var pubHex, expReq, expMsg string
		if err := json.Unmarshal(c.Input["witnessPublicKeyHex"], &pubHex); err != nil {
			t.Fatalf("%s: bad witnessPublicKeyHex: %v", c.CaseID, err)
		}
		_ = json.Unmarshal(c.Input["expectedRequester"], &expReq)
		_ = json.Unmarshal(c.Input["expectedMessageId"], &expMsg)
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("%s: witnessPublicKeyHex not hex: %v", c.CaseID, err)
		}

		opts := AuditQueryVerifyOptions{ExpectedRequester: expReq, ExpectedMessageID: expMsg}
		if raw, ok := c.Input["expectedServiceDid"]; ok {
			_ = json.Unmarshal(raw, &opts.ExpectedServiceDid)
		}
		agentKeys := map[string]string{}
		if raw, ok := c.Input["agentKeysHex"]; ok {
			_ = json.Unmarshal(raw, &agentKeys)
		}
		opts.VerifyEventSignature = func(event map[string]interface{}) bool {
			agentID, _ := event["agentId"].(string)
			keyHex, ok := agentKeys[agentID]
			if !ok {
				return false
			}
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				return false
			}
			return VerifyAuditEventSignature(event, key)
		}
		if raw, ok := c.Input["laterCheckpoint"]; ok {
			cp, cpOK := ParseCheckpointRef(raw)
			if !cpOK {
				if want {
					t.Errorf("%s: laterCheckpoint malformed but vector expects accept", c.CaseID)
				}
				continue
			}
			opts.LaterCheckpoint = &cp
		}

		// The response is the witness signed body; parse it surrogate-safe.
		body, err := ParseSignedBody(c.Input["response"])
		if err != nil {
			if want {
				t.Errorf("%s: response failed to parse but vector expects accept: %v", c.CaseID, err)
			}
			continue
		}
		resp, isObj := body.(map[string]interface{})
		if !isObj {
			if want {
				t.Errorf("%s: response is not an object but vector expects accept", c.CaseID)
			}
			continue
		}

		if got := VerifyInkAuditQueryResponse(resp, pub, opts); got != want {
			t.Errorf("%s: VerifyInkAuditQueryResponse = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestInclusionReceipt(t *testing.T) {
	vf := loadVectors(t, "inclusion-receipt")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"

		var pubHex string
		if err := json.Unmarshal(c.Input["witnessPublicKeyHex"], &pubHex); err != nil {
			t.Fatalf("%s: bad witnessPublicKeyHex: %v", c.CaseID, err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("%s: witnessPublicKeyHex not hex: %v", c.CaseID, err)
		}

		// The receipt is parsed at the receiver boundary: a lone surrogate, a
		// non-object, or an out-of-spec numeric field is a reject, matching the
		// reference's structural and signed-string checks.
		receipt, ok := ParseInclusionReceipt(c.Input["receipt"])
		if !ok {
			if want {
				t.Errorf("%s: receipt failed to parse but vector expects accept", c.CaseID)
			}
			continue
		}

		var opts ReceiptVerifyOptions
		// The event runs through ParseSignedBody so a lone surrogate is rejected
		// before hashing, the same as any signed body. A malformed event is a
		// reject, not a harness error.
		if raw, present := c.Input["event"]; present {
			body, err := ParseSignedBody(raw)
			if err != nil {
				if want {
					t.Errorf("%s: event failed to parse but vector expects accept: %v", c.CaseID, err)
				}
				continue
			}
			m, isObj := body.(map[string]interface{})
			if !isObj {
				if want {
					t.Errorf("%s: event is not an object but vector expects accept", c.CaseID)
				}
				continue
			}
			opts.Event = m
		}
		if raw, present := c.Input["eventHash"]; present {
			if err := json.Unmarshal(raw, &opts.EventHash); err != nil {
				if want {
					t.Errorf("%s: eventHash malformed but vector expects accept: %v", c.CaseID, err)
				}
				continue
			}
		}
		if raw, present := c.Input["laterCheckpoint"]; present {
			cp, cpOK := ParseCheckpointRef(raw)
			if !cpOK {
				if want {
					t.Errorf("%s: laterCheckpoint malformed but vector expects accept", c.CaseID)
				}
				continue
			}
			opts.LaterCheckpoint = &cp
		}

		if got := VerifyInclusionReceipt(receipt, pub, opts); got != want {
			t.Errorf("%s: VerifyInclusionReceipt = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestPrincipalNormalization(t *testing.T) {
	vf := loadVectors(t, "principal-normalization")
	for _, c := range vf.Cases {
		var agentID string
		if err := json.Unmarshal(c.Input["agentId"], &agentID); err != nil {
			t.Fatalf("%s: bad agentId: %v", c.CaseID, err)
		}
		got, err := CanonicalAgentPrincipal(agentID)
		if c.Expect.Result == "reject" {
			if err == nil {
				t.Errorf("%s: expected reject, got principal %q", c.CaseID, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: expected accept, got error: %v", c.CaseID, err)
			continue
		}
		if got != c.Expect.CanonicalPrincipal {
			t.Errorf("%s: principal = %q, want %q", c.CaseID, got, c.Expect.CanonicalPrincipal)
		}
	}
}

func TestSignatureBase(t *testing.T) {
	vf := loadVectors(t, "signature-base")
	for _, c := range vf.Cases {
		var in struct {
			SignInput struct {
				Method       string      `json:"method"`
				Path         string      `json:"path"`
				RecipientDid string      `json:"recipientDid"`
				Body         interface{} `json:"body"`
				Timestamp    string      `json:"timestamp"`
			} `json:"signInput"`
			Signature    string `json:"signature"`
			PublicKeyHex string `json:"publicKeyHex"`
		}
		if err := json.Unmarshal(mustJSON(t, c.Input, "signInput"), &in.SignInput); err != nil {
			t.Fatalf("%s: bad signInput: %v", c.CaseID, err)
		}
		_ = json.Unmarshal(c.Input["signature"], &in.Signature)
		_ = json.Unmarshal(c.Input["publicKeyHex"], &in.PublicKeyHex)
		pub, err := hex.DecodeString(in.PublicKeyHex)
		if err != nil {
			t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
		}
		ok := VerifyInkSignature(InkSignInput{
			Method:       in.SignInput.Method,
			Path:         in.SignInput.Path,
			RecipientDid: in.SignInput.RecipientDid,
			Body:         in.SignInput.Body,
			Timestamp:    in.SignInput.Timestamp,
		}, in.Signature, pub)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v, want %v", c.CaseID, ok, want)
		}
	}
}

func TestReplayFreshness(t *testing.T) {
	vf := loadVectors(t, "replay-freshness")
	for _, c := range vf.Cases {
		var r struct {
			MessageTimestamp     string   `json:"messageTimestamp"`
			ReceiverClock        string   `json:"receiverClock"`
			Nonce                string   `json:"nonce"`
			PreviouslySeenNonces []string `json:"previouslySeenNonces"`
		}
		if err := json.Unmarshal(mustJSON(t, c.Input, "replay"), &r); err != nil {
			t.Fatalf("%s: bad replay input: %v", c.CaseID, err)
		}
		ok := CheckReplay(r.MessageTimestamp, r.ReceiverClock, r.Nonce, r.PreviouslySeenNonces)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: checkReplay = %v, want %v", c.CaseID, ok, want)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	vf := loadVectors(t, "key-rotation")
	for _, c := range vf.Cases {
		var in struct {
			SignInput struct {
				Method       string      `json:"method"`
				Path         string      `json:"path"`
				RecipientDid string      `json:"recipientDid"`
				Body         interface{} `json:"body"`
				Timestamp    string      `json:"timestamp"`
			} `json:"signInput"`
			Signature string `json:"signature"`
			HintKeyID string `json:"hintKeyId"`
			Keys      []struct {
				KeyID        string            `json:"keyId"`
				PublicKeyHex string            `json:"publicKeyHex"`
				Status       string            `json:"status"`
				ValidFrom    OptionalTimestamp `json:"validFrom"`
				ValidUntil   OptionalTimestamp `json:"validUntil"`
				RevokedAt    OptionalTimestamp `json:"revokedAt"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(mustJSON(t, c.Input, "signInput"), &in.SignInput); err != nil {
			t.Fatalf("%s: bad signInput: %v", c.CaseID, err)
		}
		_ = json.Unmarshal(c.Input["signature"], &in.Signature)
		_ = json.Unmarshal(c.Input["hintKeyId"], &in.HintKeyID)
		if err := json.Unmarshal(c.Input["keys"], &in.Keys); err != nil {
			t.Fatalf("%s: bad keys: %v", c.CaseID, err)
		}
		keys := make([]CandidateKey, 0, len(in.Keys))
		for _, k := range in.Keys {
			pub, err := hex.DecodeString(k.PublicKeyHex)
			if err != nil {
				t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
			}
			keys = append(keys, CandidateKey{
				KeyID: k.KeyID, PublicKey: pub, Status: k.Status,
				ValidFrom: k.ValidFrom, ValidUntil: k.ValidUntil, RevokedAt: k.RevokedAt,
			})
		}
		r := VerifyInkSignatureWithKeys(InkSignInput{
			Method:       in.SignInput.Method,
			Path:         in.SignInput.Path,
			RecipientDid: in.SignInput.RecipientDid,
			Body:         in.SignInput.Body,
			Timestamp:    in.SignInput.Timestamp,
		}, in.Signature, keys, in.HintKeyID)
		want := c.Expect.Result == "accept"
		if r.Verified != want {
			t.Errorf("%s: verified = %v, want %v", c.CaseID, r.Verified, want)
		}
		if c.Expect.KeyStatus != "" && r.KeyStatus != c.Expect.KeyStatus {
			t.Errorf("%s: keyStatus = %q, want %q", c.CaseID, r.KeyStatus, c.Expect.KeyStatus)
		}
		if c.Expect.KeyID != "" && r.KeyID != c.Expect.KeyID {
			t.Errorf("%s: keyId = %q, want %q", c.CaseID, r.KeyID, c.Expect.KeyID)
		}
		// On a rejection the result must not attribute a key: a populated
		// keyId/keyStatus alongside Verified=false would hide an authority
		// bug in the fallback path.
		if !want {
			if r.KeyID != "" {
				t.Errorf("%s: rejected result leaked keyId %q", c.CaseID, r.KeyID)
			}
			if r.KeyStatus != "" {
				t.Errorf("%s: rejected result leaked keyStatus %q", c.CaseID, r.KeyStatus)
			}
		}
	}
}

func mustJSON(t *testing.T, m map[string]json.RawMessage, key string) json.RawMessage {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing input key %q", key)
	}
	return v
}
