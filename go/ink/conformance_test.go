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

// optionalBehavior marks a case whose decision the spec it pins leaves to the
// implementation. `Expect` still carries the branch the reference takes;
// `Alternative` names the other outcome that is equally conforming.
type optionalBehavior struct {
	ID          string `json:"id"`
	Alternative string `json:"alternative"`
	Spec        string `json:"spec"`
	Rationale   string `json:"rationale"`
}

// goOptionalBehaviorPolicy declares which branch THIS implementation takes for
// every optional behavior in the corpus, the second-implementation half of
// OPTIONAL_BEHAVIOR_POLICY in test/conformance.test.ts. "pinned" means it makes
// the same decision the vector's `expect` records; "alternative" means it takes
// the other conformant branch and the runner asserts that instead. An id in the
// corpus with no entry here is a failure, so a new optional behavior cannot slip
// through undeclared.
var goOptionalBehaviorPolicy = map[string]string{
	"didweb-warm-resolver-unavailable": "pinned",
	"cold-chain-extension-residual":    "pinned",
}

// expectedOutcome returns the accept/reject decision this implementation must
// make for a case, and whether the reference's reason and audit-event
// expectations still apply (they do not when it takes the alternative branch).
func expectedOutcome(t *testing.T, c conformanceCase) (string, bool) {
	t.Helper()
	if c.OptionalBehavior == nil {
		return c.Expect.Result, true
	}
	branch, declared := goOptionalBehaviorPolicy[c.OptionalBehavior.ID]
	if !declared {
		t.Errorf("%s: undeclared optional behavior %q; add it to goOptionalBehaviorPolicy", c.CaseID, c.OptionalBehavior.ID)
		return c.Expect.Result, true
	}
	if c.OptionalBehavior.Alternative == c.Expect.Result {
		t.Errorf("%s: optional behavior %q names the pinned result as its alternative", c.CaseID, c.OptionalBehavior.ID)
	}
	if branch == "alternative" {
		return c.OptionalBehavior.Alternative, false
	}
	return c.Expect.Result, true
}

type conformanceCase struct {
	CaseID           string                     `json:"caseId"`
	Description      string                     `json:"description"`
	OptionalBehavior *optionalBehavior          `json:"optionalBehavior"`
	Input            map[string]json.RawMessage `json:"input"`
	Expect           struct {
		Result             string `json:"result"`
		Reason             string `json:"reason"`
		Step               string `json:"step"`
		AuditEvent         string `json:"auditEvent"`
		CanonicalPrincipal string `json:"canonicalPrincipal"`
		KeyStatus          string `json:"keyStatus"`
		KeyID              string `json:"keyId"`
		Signature          string `json:"signature"`
		EpochMs            *int64 `json:"epochMs"`
		CanonicalString    string `json:"canonicalString"`
		LeafHash           string `json:"leafHash"`
		DerivedGrantID     string `json:"derivedGrantId"`
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

func TestSignedBodyMemberName(t *testing.T) {
	vf := loadVectors(t, "signed-body-member-name")
	for _, c := range vf.Cases {
		var bodyRaw string
		if err := json.Unmarshal(c.Input["bodyRaw"], &bodyRaw); err != nil {
			t.Fatalf("%s: bad bodyRaw: %v", c.CaseID, err)
		}
		got := "accept"
		if ContainsEscapedMemberName([]byte(bodyRaw)) {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s: got %s, want %s", c.CaseID, got, c.Expect.Result)
		}
	}
}

func TestAuthorizationHeader(t *testing.T) {
	vf := loadVectors(t, "authorization-header")
	for _, c := range vf.Cases {
		var header string
		if err := json.Unmarshal(c.Input["header"], &header); err != nil {
			t.Fatalf("%s: bad header: %v", c.CaseID, err)
		}
		parsed := ParseInkAuthHeader(header)
		got := "accept"
		if !parsed.OK {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s: got %s, want %s (reason=%q)", c.CaseID, got, c.Expect.Result, parsed.Reason)
			continue
		}
		if !parsed.OK {
			if c.Expect.Reason != "" && parsed.Reason != c.Expect.Reason {
				t.Errorf("%s: reason = %q, want %q", c.CaseID, parsed.Reason, c.Expect.Reason)
			}
			continue
		}
		if c.Expect.Signature != "" && parsed.Signature != c.Expect.Signature {
			t.Errorf("%s: signature = %q, want %q", c.CaseID, parsed.Signature, c.Expect.Signature)
		}
		if c.Expect.KeyID != "" && parsed.KeyID != c.Expect.KeyID {
			t.Errorf("%s: keyId = %q, want %q", c.CaseID, parsed.KeyID, c.Expect.KeyID)
		}
	}
}

func TestSignedBodyUTF8(t *testing.T) {
	vf := loadVectors(t, "signed-body-utf8")
	for _, c := range vf.Cases {
		var bodyHex string
		if err := json.Unmarshal(c.Input["bodyHex"], &bodyHex); err != nil {
			t.Fatalf("%s: bad bodyHex: %v", c.CaseID, err)
		}
		raw, err := hex.DecodeString(bodyHex)
		if err != nil {
			t.Fatalf("%s: bodyHex not hex: %v", c.CaseID, err)
		}
		_, parseErr := ParseSignedBody(raw)
		got := "accept"
		if parseErr != nil {
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
		var resolutionDID *string
		if raw, ok := c.Input["resolutionDid"]; ok {
			_ = json.Unmarshal(raw, &resolutionDID)
		}
		if got := EvaluateAgentCardFetch(status, contentType, contentLength, bodyRaw, reqID, resolutionDID); got != want {
			t.Errorf("%s: EvaluateAgentCardFetch = %v, want %v", c.CaseID, got, want)
		}
	}
}

func TestAgentCardSignature(t *testing.T) {
	runAgentCardSignatureVectors(t, "agent-card-signature")
}

// TestAgentCardSignaturePhaseC runs the STAGED Phase C category. It is anchored
// in the manifest and verified for integrity on every run, but its accept/reject
// semantics are exercised only in the dedicated staged job, so a default
// `go test ./...` covers exactly the categories it covered before the staged
// category existed. At the flip the skip goes away with the `staged` profile.
func TestAgentCardSignaturePhaseC(t *testing.T) {
	if os.Getenv("INK_STAGED_CONFORMANCE") != "1" {
		t.Skip("staged conformance category; set INK_STAGED_CONFORMANCE=1 to run it")
	}
	runAgentCardSignatureVectors(t, "agent-card-signature-phase-c")
}

// runAgentCardSignatureVectors drives the card-signature verifier over one
// category. The base and the staged categories share a vector shape and a
// verifier entry point, so they share a runner: a divergence between the two
// runs would be a divergence in the flag, not in the harness.
func runAgentCardSignatureVectors(t *testing.T, category string) {
	t.Helper()
	vf := loadVectors(t, category)
	for _, c := range vf.Cases {
		var card map[string]interface{}
		if err := json.Unmarshal(c.Input["card"], &card); err != nil {
			t.Fatalf("%s: bad card: %v", c.CaseID, err)
		}
		var agentID string
		if err := json.Unmarshal(c.Input["agentId"], &agentID); err != nil {
			t.Fatalf("%s: bad agentId: %v", c.CaseID, err)
		}
		var opts struct {
			CachedCard          map[string]interface{} `json:"cachedCard"`
			DidVerificationKeys *struct {
				Status           string   `json:"status"`
				VerificationKeys []string `json:"verificationKeys"`
			} `json:"didVerificationKeys"`
			Profile       string `json:"profile"`
			EnforcePhaseC *bool  `json:"enforcePhaseC"`
		}
		if err := json.Unmarshal(c.Input["options"], &opts); err != nil {
			t.Fatalf("%s: bad options: %v", c.CaseID, err)
		}
		cardOpts := CardVerifyOptions{CachedCard: opts.CachedCard, Profile: opts.Profile, EnforcePhaseC: opts.EnforcePhaseC}
		if opts.DidVerificationKeys != nil {
			cardOpts.DidVerificationKeys = &DidResolution{
				Status:           opts.DidVerificationKeys.Status,
				VerificationKeys: opts.DidVerificationKeys.VerificationKeys,
			}
		}
		res := VerifyAgentCardSignature(card, agentID, cardOpts)
		got := "accept"
		if res.Rejected {
			got = "reject"
		}
		// A case tagged optionalBehavior pins a decision the spec leaves open;
		// the declared branch decides which outcome this implementation must
		// reach, and the reference's reason and audit marks apply only on the
		// pinned branch.
		wantResult, detailsApply := expectedOutcome(t, c)
		if got != wantResult {
			t.Errorf("%s: result = %s, want %s (reason %s)", c.CaseID, got, wantResult, res.Reason)
		}
		if !detailsApply {
			continue
		}
		if c.Expect.Reason != "" && string(res.Reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, res.Reason, c.Expect.Reason)
		}
		if c.Expect.AuditEvent != "" {
			found := false
			for _, e := range res.AuditEvents {
				if e == c.Expect.AuditEvent {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: auditEvents %v does not contain %q", c.CaseID, res.AuditEvents, c.Expect.AuditEvent)
			}
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

// boundaryReject records that the receiver's parser refused the input before the
// verifier ran. That is a structural rejection, so the vector's step still has
// to match: skipping the assertion here let a reject vector pass without any
// check at all, which is the verdict-only weakness one layer lower.
func expectBoundaryStep(t *testing.T, caseID, wantStep, what string) {
	t.Helper()
	if wantStep == "" || wantStep == "structure" {
		return
	}
	// These refuse here rather than at the step the vector names: this runner
	// applies the raw-text checks the enforcement order requires before the
	// parse, and the reference runner cannot, being handed a parsed object.
	// Listed by name so the set cannot widen silently.
	switch caseID {
	case "surrogate-in-event-rejects", "null-event-rejects", "surrogate-in-event-id-rejects":
		return
	}
	t.Errorf("%s: %s refused at the boundary (step structure), want step %q", caseID, what, wantStep)
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
			} else {
				expectBoundaryStep(t, c.CaseID, c.Expect.Step, "receipt")
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
				} else {
					expectBoundaryStep(t, c.CaseID, c.Expect.Step, "event")
				}
				continue
			}
			m, isObj := body.(map[string]interface{})
			if !isObj {
				if want {
					t.Errorf("%s: event is not an object but vector expects accept", c.CaseID)
				} else {
					expectBoundaryStep(t, c.CaseID, c.Expect.Step, "event")
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

		got, step := VerifyInclusionReceiptStep(receipt, pub, opts)
		if got != want {
			t.Errorf("%s: VerifyInclusionReceipt = %v, want %v (step %s)", c.CaseID, got, want, step)
		}
		// The step is the reason for this surface. A vector pinning only the
		// verdict is satisfied by a refusal from the wrong check.
		if c.Expect.Step != "" && string(step) != c.Expect.Step {
			t.Errorf("%s: step = %q, want %q", c.CaseID, step, c.Expect.Step)
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

func TestDiscoveryQueryEnvelope(t *testing.T) {
	vf := loadVectors(t, "discovery-query-envelope")
	for _, c := range vf.Cases {
		var pubHex string
		if err := json.Unmarshal(c.Input["publicKeyHex"], &pubHex); err != nil {
			t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
		}
		var now string
		if err := json.Unmarshal(c.Input["now"], &now); err != nil {
			t.Fatalf("%s: bad now: %v", c.CaseID, err)
		}
		// A directory states the spellings of itself it answers to. The vector
		// carries one string or a list of them; both decode to the same set.
		var audience []string
		var single string
		if err := json.Unmarshal(c.Input["audience"], &single); err == nil {
			audience = []string{single}
		} else if err := json.Unmarshal(c.Input["audience"], &audience); err != nil {
			t.Fatalf("%s: bad audience: %v", c.CaseID, err)
		}
		var seen []DiscoveryQueryKey
		if raw, present := c.Input["seenNonces"]; present {
			var list []struct {
				From  string `json:"from"`
				Nonce string `json:"nonce"`
			}
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatalf("%s: bad seenNonces: %v", c.CaseID, err)
			}
			for _, k := range list {
				seen = append(seen, DiscoveryQueryKey{From: k.From, Nonce: k.Nonce})
			}
		}
		ctx := DiscoveryQueryContext{Audience: audience, Now: now, SeenNonces: seen}
		// The verifier takes the raw body bytes. A case that exercises the
		// raw-body gate carries envelopeRaw, the exact wire text, because the
		// rule under test is about bytes a parsed value has already lost; every
		// other case carries the envelope as a value, whose vector bytes are the
		// wire form already.
		body := c.Input["envelope"]
		if raw, present := c.Input["envelopeRaw"]; present {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatalf("%s: bad envelopeRaw: %v", c.CaseID, err)
			}
			body = []byte(text)
		}
		ok, reason := VerifyDiscoveryQueryEnvelope(body, pub, ctx)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v (%s), want %v", c.CaseID, ok, reason, want)
		}
		if !ok && c.Expect.Reason != "" && string(reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
		}
	}
}

func TestAuthorizationGrant(t *testing.T) {
	vf := loadVectors(t, "authorization-grant")
	for _, c := range vf.Cases {
		var pubHex, audience, now string
		if err := json.Unmarshal(c.Input["issuerPublicKeyHex"], &pubHex); err != nil {
			t.Fatalf("%s: bad issuerPublicKeyHex: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["audience"], &audience); err != nil {
			t.Fatalf("%s: bad audience: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["now"], &now); err != nil {
			t.Fatalf("%s: bad now: %v", c.CaseID, err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("%s: issuerPublicKeyHex not hex: %v", c.CaseID, err)
		}
		var seen []GrantKey
		if raw, ok := c.Input["seenGrants"]; ok {
			var list []struct {
				Issuer  string `json:"issuer"`
				GrantID string `json:"grantId"`
			}
			_ = json.Unmarshal(raw, &list)
			for _, k := range list {
				seen = append(seen, GrantKey{Issuer: k.Issuer, GrantID: k.GrantID})
			}
		}
		revoked := map[GrantKey]bool{}
		if raw, ok := c.Input["revokedGrants"]; ok {
			var list []struct {
				Issuer  string `json:"issuer"`
				GrantID string `json:"grantId"`
			}
			_ = json.Unmarshal(raw, &list)
			for _, k := range list {
				revoked[GrantKey{Issuer: k.Issuer, GrantID: k.GrantID}] = true
			}
		}
		ownerStatus := ""
		if raw, ok := c.Input["verifiedOwner"]; ok {
			var vo struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(raw, &vo)
			ownerStatus = vo.Status
		}
		var maxLifetimeMs int64
		if raw, ok := c.Input["maxLifetimeMs"]; ok {
			_ = json.Unmarshal(raw, &maxLifetimeMs)
		}
		presenter := ""
		if raw, ok := c.Input["presenter"]; ok {
			_ = json.Unmarshal(raw, &presenter)
		}
		ctx := AuthorizationGrantContext{
			Audience:            audience,
			Now:                 now,
			Presenter:           presenter,
			SeenGrants:          seen,
			IsRevoked:           func(key GrantKey) bool { return revoked[key] },
			VerifiedOwnerStatus: ownerStatus,
			MaxLifetimeMs:       maxLifetimeMs,
		}
		// The verifier takes the raw body bytes. A case that exercises the
		// raw-body gate carries grantRaw, the exact wire text, because the rule
		// under test is about bytes a parsed value has already lost; every other
		// case carries the grant as a value, whose vector bytes are the wire form
		// already.
		grantBody := c.Input["grant"]
		if raw, present := c.Input["grantRaw"]; present {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatalf("%s: bad grantRaw: %v", c.CaseID, err)
			}
			grantBody = []byte(text)
		}
		ok, reason := VerifyAuthorizationGrant(grantBody, pub, ctx)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v, want %v", c.CaseID, ok, want)
		}
		if !ok && c.Expect.Reason != "" && string(reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
		}
	}
}

func TestAttestation(t *testing.T) {
	vf := loadVectors(t, "attestation")
	for _, c := range vf.Cases {
		var pubHex, now string
		if err := json.Unmarshal(c.Input["issuerPublicKeyHex"], &pubHex); err != nil {
			t.Fatalf("%s: bad issuerPublicKeyHex: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["now"], &now); err != nil {
			t.Fatalf("%s: bad now: %v", c.CaseID, err)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("%s: issuerPublicKeyHex not hex: %v", c.CaseID, err)
		}
		var body []byte
		if raw, present := c.Input["attestationRaw"]; present {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatalf("%s: bad attestationRaw: %v", c.CaseID, err)
			}
			body = []byte(text)
		} else {
			body = c.Input["attestation"]
		}
		ok, reason := VerifyAttestation(body, pub, now)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v, want %v", c.CaseID, ok, want)
		}
		if !ok && c.Expect.Reason != "" && string(reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
		}
	}
}

// TestAgentCardEvidence drives the Agent Card evidence members. A case with an
// agentId exercises card-proof coverage of the members through the
// card-signature verifier; a case without one pins clockless shape validation
// of attestations and evidencePolicy, mirroring the TS runner branch for
// branch.
func TestAgentCardEvidence(t *testing.T) {
	vf := loadVectors(t, "agent-card-evidence")
	for _, c := range vf.Cases {
		var card map[string]interface{}
		if err := json.Unmarshal(c.Input["card"], &card); err != nil {
			t.Fatalf("%s: bad card: %v", c.CaseID, err)
		}
		if raw, present := c.Input["agentId"]; present {
			var agentID string
			if err := json.Unmarshal(raw, &agentID); err != nil {
				t.Fatalf("%s: bad agentId: %v", c.CaseID, err)
			}
			var opts struct {
				Profile string `json:"profile"`
			}
			if err := json.Unmarshal(c.Input["options"], &opts); err != nil {
				t.Fatalf("%s: bad options: %v", c.CaseID, err)
			}
			res := VerifyAgentCardSignature(card, agentID, CardVerifyOptions{Profile: opts.Profile})
			got := "accept"
			if res.Rejected {
				got = "reject"
			}
			if got != c.Expect.Result {
				t.Errorf("%s: result = %s, want %s (reason %s)", c.CaseID, got, c.Expect.Result, res.Reason)
			}
			if c.Expect.Reason != "" && string(res.Reason) != c.Expect.Reason {
				t.Errorf("%s: reason = %q, want %q", c.CaseID, res.Reason, c.Expect.Reason)
			}
			continue
		}
		got := "accept"
		if !ValidateAgentCard(card) {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s: ValidateAgentCard = %s, want %s", c.CaseID, got, c.Expect.Result)
		}
	}
}

// TestEvidenceRefusal drives the policy:evidence_required structured refusal
// body against ValidateEvidenceRefusal.
func TestEvidenceRefusal(t *testing.T) {
	vf := loadVectors(t, "evidence-refusal")
	for _, c := range vf.Cases {
		var refusal map[string]interface{}
		if err := json.Unmarshal(c.Input["refusal"], &refusal); err != nil {
			t.Fatalf("%s: bad refusal: %v", c.CaseID, err)
		}
		got := "accept"
		if !ValidateEvidenceRefusal(refusal) {
			got = "reject"
		}
		if got != c.Expect.Result {
			t.Errorf("%s: ValidateEvidenceRefusal = %s, want %s", c.CaseID, got, c.Expect.Result)
		}
	}
}

func TestAuthorizationChain(t *testing.T) {
	vf := loadVectors(t, "authorization-chain")
	for _, c := range vf.Cases {
		var audience, now string
		if err := json.Unmarshal(c.Input["audience"], &audience); err != nil {
			t.Fatalf("%s: bad audience: %v", c.CaseID, err)
		}
		if err := json.Unmarshal(c.Input["now"], &now); err != nil {
			t.Fatalf("%s: bad now: %v", c.CaseID, err)
		}
		var rawKeys []struct {
			PublicKeyHex string `json:"publicKeyHex"`
			Status       string `json:"status"`
		}
		if err := json.Unmarshal(c.Input["issuerKeys"], &rawKeys); err != nil {
			t.Fatalf("%s: bad issuerKeys: %v", c.CaseID, err)
		}
		keys := make([]ChainIssuerKey, 0, len(rawKeys))
		for _, k := range rawKeys {
			pub, err := hex.DecodeString(k.PublicKeyHex)
			if err != nil {
				t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
			}
			keys = append(keys, ChainIssuerKey{PublicKey: pub, Status: k.Status})
		}
		var seen []GrantKey
		if raw, ok := c.Input["seenGrants"]; ok {
			var list []struct {
				Issuer  string `json:"issuer"`
				GrantID string `json:"grantId"`
			}
			_ = json.Unmarshal(raw, &list)
			for _, k := range list {
				seen = append(seen, GrantKey{Issuer: k.Issuer, GrantID: k.GrantID})
			}
		}
		revoked := map[GrantKey]bool{}
		if raw, ok := c.Input["revokedGrants"]; ok {
			var list []struct {
				Issuer  string `json:"issuer"`
				GrantID string `json:"grantId"`
			}
			_ = json.Unmarshal(raw, &list)
			for _, k := range list {
				revoked[GrantKey{Issuer: k.Issuer, GrantID: k.GrantID}] = true
			}
		}
		ownerStatus := ""
		if raw, ok := c.Input["verifiedOwner"]; ok {
			var vo struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(raw, &vo)
			ownerStatus = vo.Status
		}
		presenter := ""
		if raw, ok := c.Input["presenter"]; ok {
			_ = json.Unmarshal(raw, &presenter)
		}
		ctx := AuthorizationChainContext{
			Audience:            audience,
			Now:                 now,
			IssuerKeys:          keys,
			Presenter:           presenter,
			SeenGrants:          seen,
			IsRevoked:           func(key GrantKey) bool { return revoked[key] },
			VerifiedOwnerStatus: ownerStatus,
		}
		// The verifier takes the raw body bytes; a case that exercises the
		// raw-body gate carries chainRaw, the exact wire text.
		chainBody := c.Input["chain"]
		if raw, present := c.Input["chainRaw"]; present {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatalf("%s: bad chainRaw: %v", c.CaseID, err)
			}
			chainBody = []byte(text)
		}
		ok, reason := VerifyAuthorizationChain(chainBody, ctx)
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v, want %v (reason %q)", c.CaseID, ok, want, reason)
		}
		if !ok && c.Expect.Reason != "" && string(reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
		}
	}
}

func TestAgentAuthorization(t *testing.T) {
	vf := loadVectors(t, "agent-authorization")
	for _, c := range vf.Cases {
		// Extract the four binding fields from the challenge for the derived id.
		var ch struct {
			RP        string `json:"rp"`
			Nonce     string `json:"nonce"`
			IssuedAt  string `json:"issuedAt"`
			ExpiresAt string `json:"expiresAt"`
		}
		// The verifier takes the raw body bytes; a case that exercises the
		// raw-body gate carries challengeRaw, the exact wire text, and carries no
		// parsed `challenge` because no serializer could produce those bytes.
		challengeBody := c.Input["challenge"]
		if raw, present := c.Input["challengeRaw"]; present {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatalf("%s: bad challengeRaw: %v", c.CaseID, err)
			}
			challengeBody = []byte(text)
		} else if err := json.Unmarshal(c.Input["challenge"], &ch); err != nil {
			t.Fatalf("%s: bad challenge: %v", c.CaseID, err)
		}

		// A case with no keys is a derive-only case: it pins the exact
		// challenge-derived grantId for fixed inputs, independent of signature.
		if _, hasKeys := c.Input["keys"]; !hasKeys {
			id := DeriveChallengeGrantID(ch.RP, ch.Nonce, ch.IssuedAt, ch.ExpiresAt)
			if c.Expect.Result != "accept" {
				t.Errorf("%s: derive-only case must expect accept", c.CaseID)
			}
			if c.Expect.DerivedGrantID != "" && id != c.Expect.DerivedGrantID {
				t.Errorf("%s: derivedGrantId = %q, want %q", c.CaseID, id, c.Expect.DerivedGrantID)
			}
			continue
		}

		var now string
		if err := json.Unmarshal(c.Input["now"], &now); err != nil {
			t.Fatalf("%s: bad now: %v", c.CaseID, err)
		}
		var rawKeys []struct {
			KeyID        string            `json:"keyId"`
			PublicKeyHex string            `json:"publicKeyHex"`
			Status       string            `json:"status"`
			ValidFrom    OptionalTimestamp `json:"validFrom"`
			ValidUntil   OptionalTimestamp `json:"validUntil"`
			RevokedAt    OptionalTimestamp `json:"revokedAt"`
		}
		if err := json.Unmarshal(c.Input["keys"], &rawKeys); err != nil {
			t.Fatalf("%s: bad keys: %v", c.CaseID, err)
		}
		keys := make([]CandidateKey, 0, len(rawKeys))
		for _, k := range rawKeys {
			pub, err := hex.DecodeString(k.PublicKeyHex)
			if err != nil {
				t.Fatalf("%s: bad publicKeyHex: %v", c.CaseID, err)
			}
			keys = append(keys, CandidateKey{
				KeyID: k.KeyID, PublicKey: pub, Status: k.Status,
				ValidFrom: k.ValidFrom, ValidUntil: k.ValidUntil, RevokedAt: k.RevokedAt,
			})
		}
		ok, reason := VerifyAuthorizationChallenge(challengeBody, keys, AuthorizationChallengeContext{Now: now})
		want := c.Expect.Result == "accept"
		if ok != want {
			t.Errorf("%s: verify = %v, want %v (reason %q)", c.CaseID, ok, want, reason)
		}
		if !ok && c.Expect.Reason != "" && string(reason) != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
		}
		// An accept case pins the derived grantId the answering assertion adopts.
		if ok && c.Expect.DerivedGrantID != "" {
			id := DeriveChallengeGrantID(ch.RP, ch.Nonce, ch.IssuedAt, ch.ExpiresAt)
			if id != c.Expect.DerivedGrantID {
				t.Errorf("%s: derivedGrantId = %q, want %q", c.CaseID, id, c.Expect.DerivedGrantID)
			}
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
			// liveAuth selects the live transport authentication layer instead
			// of the bare multi-key primitive, and liveAuthAllowRetired opts
			// into the bounded rotation grace window. See
			// VerifyInkSignatureForLiveAuth.
			LiveAuth             bool `json:"liveAuth"`
			LiveAuthAllowRetired bool `json:"liveAuthAllowRetired"`
			Keys                 []struct {
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
		_ = json.Unmarshal(c.Input["liveAuth"], &in.LiveAuth)
		_ = json.Unmarshal(c.Input["liveAuthAllowRetired"], &in.LiveAuthAllowRetired)
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
		si := InkSignInput{
			Method:       in.SignInput.Method,
			Path:         in.SignInput.Path,
			RecipientDid: in.SignInput.RecipientDid,
			Body:         in.SignInput.Body,
			Timestamp:    in.SignInput.Timestamp,
		}
		var r MultiKeyResult
		var reason string
		if in.LiveAuth {
			// Live transport auth: the primitive answers first, then the
			// retired-key default of Protocol §3.3 narrows what may
			// authenticate a request arriving now.
			la := VerifyInkSignatureForLiveAuth(si, in.Signature, keys, in.HintKeyID, in.LiveAuthAllowRetired)
			r = MultiKeyResult{Verified: la.Verified, KeyID: la.KeyID, KeyStatus: la.KeyStatus}
			reason = la.Error
		} else {
			r = VerifyInkSignatureWithKeys(si, in.Signature, keys, in.HintKeyID)
		}
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
		if c.Expect.Reason != "" && reason != c.Expect.Reason {
			t.Errorf("%s: reason = %q, want %q", c.CaseID, reason, c.Expect.Reason)
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

func TestPayloadEncryption(t *testing.T) {
	vf := loadVectors(t, "payload-encryption")
	for _, c := range vf.Cases {
		want := c.Expect.Result == "accept"

		var envelope map[string]any
		if err := json.Unmarshal(mustJSON(t, c.Input, "envelope"), &envelope); err != nil {
			if want {
				t.Errorf("%s: envelope is not an object but vector expects accept: %v", c.CaseID, err)
			}
			continue
		}
		var privHex string
		if err := json.Unmarshal(c.Input["recipientPrivateKeyHex"], &privHex); err != nil {
			t.Fatalf("%s: bad recipientPrivateKeyHex: %v", c.CaseID, err)
		}
		// recipientDid is mandatory; a vector that omits it leaves the empty
		// string, which DecryptInkPayload rejects (matches the TS reference).
		var recipientDid string
		if raw, ok := c.Input["recipientDid"]; ok {
			_ = json.Unmarshal(raw, &recipientDid)
		}

		got, err := DecryptInkPayload(envelope, privHex, recipientDid)
		if (err == nil) != want {
			t.Errorf("%s: DecryptInkPayload accepted=%v, want %v (err=%v)", c.CaseID, err == nil, want, err)
			continue
		}
		if !want {
			continue
		}
		// An accept case pins the exact decrypted plaintext as canonical
		// bytes (the same canonicalString the TS reference compares), so a
		// verifier that decrypts to different bytes diverges.
		gotCanon, gerr := canonicalizeJSON(got)
		if gerr != nil {
			t.Errorf("%s: canonicalize failed: %v", c.CaseID, gerr)
			continue
		}
		if c.Expect.CanonicalString != "" && gotCanon != c.Expect.CanonicalString {
			t.Errorf("%s: plaintext canonical = %s, want %s", c.CaseID, gotCanon, c.Expect.CanonicalString)
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
