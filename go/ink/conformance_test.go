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
				KeyID        string `json:"keyId"`
				PublicKeyHex string `json:"publicKeyHex"`
				Status       string `json:"status"`
				ValidFrom    string `json:"validFrom"`
				ValidUntil   string `json:"validUntil"`
				RevokedAt    string `json:"revokedAt"`
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
