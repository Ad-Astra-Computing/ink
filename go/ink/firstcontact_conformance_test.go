package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
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
		ResolutionDID    *string `json:"resolutionDid"`
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
	if !EvaluateAgentCardFetch(tr.CardFetch.Status, tr.CardFetch.ContentType, tr.CardFetch.ContentLength, tr.CardFetch.BodyRaw, tr.CardFetch.RequestedAgentID, tr.CardFetch.ResolutionDID) {
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
	// 3a. envelope structure (§3.1): protocol, id, correlationId, createdAt,
	// from, to, intent and signature are all MUSTs and the surface is strict, so
	// a receiver validates the envelope before it spends any signature work.
	if !ValidateMessageEnvelope(reqEnv) {
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

	// 3b. endpoint binding: the signed PATH is the path component of the card's
	// endpoint. INK reserves no fixed inbound path, so the card is the only
	// thing binding sender and receiver to one spelling.
	cardPath, ok := fcCardEndpointPath(tr.CardFetch.BodyRaw)
	if !ok || tr.Request.SignInput.Path != cardPath {
		return "", false
	}

	// 4. request signatures: the §3.3 transport signature over the delivered
	// body, and the §3.6 body signature the envelope carries, both under the
	// sender's key.
	senderPub, err := hex.DecodeString(tr.Request.SenderPublicKeyHex)
	if err != nil {
		return "", false
	}
	if !VerifyInkSignature(toInkSignInput(tr.Request.SignInput), tr.Request.Signature, senderPub) {
		return "", false
	}
	if !fcVerifyBodySignature(reqEnv, senderPub) {
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
	if !ValidateMessageEnvelope(respEnv) {
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

	// 7. response signatures, transport and body, under the receiver's key.
	recvPub, err := hex.DecodeString(tr.Response.ReceiverPublicKeyHex)
	if err != nil {
		return "", false
	}
	if !VerifyInkSignature(toInkSignInput(tr.Response.SignInput), tr.Response.Signature, recvPub) {
		return "", false
	}
	if !fcVerifyBodySignature(respEnv, recvPub) {
		return "", false
	}

	return selected, true
}

// fcVerifyBodySignature checks the §3.6 body signature an intent envelope
// carries: Ed25519 over the version-keyed domain prefix plus JCS of the envelope
// with `signature` removed. It composes the package-internal halves rather than
// an exported generic verifier, matching the deliberate omission recorded in
// signbody.go: this package still ships no generic envelope receiver, and the
// conformance runner composes primitives the same way it composes the rest of
// the transcript.
func fcVerifyBodySignature(env map[string]interface{}, publicKey []byte) bool {
	sig, ok := env["signature"].(string)
	if !ok || !signatureRe.MatchString(sig) {
		return false
	}
	unsigned := make(map[string]interface{}, len(env))
	for k, v := range env {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}
	canonical, err := JCSCanonicalize(unsigned)
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(publicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(bodySignatureDomain(unsigned)+canonical), sigBytes)
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

// fcCardEndpointPath returns the path component of the card's endpoint URL.
func fcCardEndpointPath(bodyRaw string) (string, bool) {
	var card struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(bodyRaw), &card); err != nil {
		return "", false
	}
	u, err := url.Parse(card.Endpoint)
	if err != nil || u.Path == "" {
		return "", false
	}
	return u.Path, true
}

func fcContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
