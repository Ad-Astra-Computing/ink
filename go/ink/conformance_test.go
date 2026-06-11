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

func mustJSON(t *testing.T, m map[string]json.RawMessage, key string) json.RawMessage {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing input key %q", key)
	}
	return v
}
