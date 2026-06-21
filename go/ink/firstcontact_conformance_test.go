package ink

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestFirstContactTranscript verifies the composite stranger first-contact flow
// (discovery, version selection, signed connection_request, accepted
// connection_response) against the shared corpus. It composes the same pinned
// primitives the TypeScript reference does, so the two implementations must make
// the same accept/reject decision and select the same protocol version. See
// specs/ink-first-contact-transcript.md.
func TestFirstContactTranscript(t *testing.T) {
	vf := loadVectors(t, "first-contact-transcript")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"
		selected, ok := evalFirstContact(t, c)
		if ok != want {
			t.Errorf("%s: transcript accepted=%v, want %v", c.CaseID, ok, want)
			continue
		}
		if want && selected != c.Expect.CanonicalString {
			t.Errorf("%s: selected version = %q, want %q", c.CaseID, selected, c.Expect.CanonicalString)
		}
	}
}

type fcSignInput struct {
	Method       string      `json:"method"`
	Path         string      `json:"path"`
	RecipientDid string      `json:"recipientDid"`
	Body         interface{} `json:"body"`
	Timestamp    string      `json:"timestamp"`
}

type fcTranscript struct {
	CardFetch struct {
		Status           int     `json:"status"`
		ContentType      *string `json:"contentType"`
		ContentLength    *string `json:"contentLength"`
		BodyRaw          string  `json:"bodyRaw"`
		RequestedAgentID string  `json:"requestedAgentId"`
	} `json:"cardFetch"`
	ClientSupportedVersions []string `json:"clientSupportedVersions"`
	ReceiverClock           string   `json:"receiverClock"`
	SeenNonces              []string `json:"seenNonces"`
	Request                 struct {
		SignInput          fcSignInput `json:"signInput"`
		Signature          string      `json:"signature"`
		SenderPublicKeyHex string      `json:"senderPublicKeyHex"`
	} `json:"request"`
	Response struct {
		SignInput            fcSignInput `json:"signInput"`
		Signature            string      `json:"signature"`
		ReceiverPublicKeyHex string      `json:"receiverPublicKeyHex"`
	} `json:"response"`
}

// evalFirstContact runs the transcript through the pinned primitives in order
// and returns the selected protocol version and whether the whole flow accepts.
func evalFirstContact(t *testing.T, c conformanceCase) (string, bool) {
	t.Helper()
	raw, err := json.Marshal(c.Input)
	if err != nil {
		t.Fatalf("%s: re-marshal input: %v", c.CaseID, err)
	}
	var tr fcTranscript
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", false
	}

	// 1. discovery
	if !EvaluateAgentCardFetch(tr.CardFetch.Status, tr.CardFetch.ContentType, tr.CardFetch.ContentLength, tr.CardFetch.BodyRaw, tr.CardFetch.RequestedAgentID) {
		return "", false
	}

	// 2. version selection: first client version the card advertises. A found
	// flag (not an empty-string sentinel) so selection matches the reference
	// exactly even if an advertised version were the empty string.
	advertised := fcSupportedVersions(tr.CardFetch.BodyRaw)
	selected := ""
	found := false
	for _, v := range tr.ClientSupportedVersions {
		if fcContains(advertised, v) {
			selected = v
			found = true
			break
		}
	}
	if !found {
		return "", false
	}

	// 3. request agreement
	reqEnv, ok := tr.Request.SignInput.Body.(map[string]interface{})
	if !ok {
		return "", false
	}
	if s, _ := reqEnv["protocol"].(string); s != selected {
		return "", false
	}
	if s, _ := reqEnv["intent"].(string); s != "connection_request" {
		return "", false
	}
	reqPayload, ok := reqEnv["payload"].(map[string]interface{})
	if !ok || !ValidateConnectionPayload("connection_request", reqPayload) {
		return "", false
	}
	reqTs, _ := reqEnv["timestamp"].(string)
	if reqTs != tr.Request.SignInput.Timestamp {
		return "", false
	}

	// 4. request signature
	senderPub, err := hex.DecodeString(tr.Request.SenderPublicKeyHex)
	if err != nil {
		return "", false
	}
	if !VerifyInkSignature(toInkSignInput(tr.Request.SignInput), tr.Request.Signature, senderPub) {
		return "", false
	}

	// 5. replay / freshness
	reqNonce, _ := reqEnv["nonce"].(string)
	if !CheckReplay(reqTs, tr.ReceiverClock, reqNonce, tr.SeenNonces) {
		return "", false
	}

	// 6. response agreement
	respEnv, ok := tr.Response.SignInput.Body.(map[string]interface{})
	if !ok {
		return "", false
	}
	if s, _ := respEnv["protocol"].(string); s != selected {
		return "", false
	}
	if s, _ := respEnv["intent"].(string); s != "connection_response" {
		return "", false
	}
	respPayload, ok := respEnv["payload"].(map[string]interface{})
	if !ok || !ValidateConnectionPayload("connection_response", respPayload) {
		return "", false
	}
	if s, _ := respPayload["status"].(string); s != "accepted" {
		return "", false
	}
	respTs, _ := respEnv["timestamp"].(string)
	if respTs != tr.Response.SignInput.Timestamp {
		return "", false
	}

	// 7. response signature
	recvPub, err := hex.DecodeString(tr.Response.ReceiverPublicKeyHex)
	if err != nil {
		return "", false
	}
	if !VerifyInkSignature(toInkSignInput(tr.Response.SignInput), tr.Response.Signature, recvPub) {
		return "", false
	}

	return selected, true
}

func toInkSignInput(in fcSignInput) InkSignInput {
	return InkSignInput{
		Method:       in.Method,
		Path:         in.Path,
		RecipientDid: in.RecipientDid,
		Body:         in.Body,
		Timestamp:    in.Timestamp,
	}
}

// fcSupportedVersions reads supportedProtocolVersions from a card body, falling
// back to ink/0.1 when the field is absent or empty (matching
// agentSupportedProtocolVersions in the reference).
func fcSupportedVersions(bodyRaw string) []string {
	var card struct {
		SupportedProtocolVersions []string `json:"supportedProtocolVersions"`
	}
	if err := json.Unmarshal([]byte(bodyRaw), &card); err != nil || len(card.SupportedProtocolVersions) == 0 {
		return []string{"ink/0.1"}
	}
	return card.SupportedProtocolVersions
}

func fcContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
