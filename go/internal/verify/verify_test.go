package verify

import (
	"encoding/hex"
	"testing"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

const validCard = `{"protocol":"ink/0.1","agentId":"did:web:a.example","handle":"alice","displayName":"Alice","endpoint":"https://a.example/ink/inbox","publicKeyMultibase":"z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","capabilities":{"intentsAccepted":["ask"],"intentsSent":["ask"]},"availability":{"timezone":"UTC"}}`

func TestCard(t *testing.T) {
	r, err := Card([]byte(validCard))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "agent-card" {
		t.Errorf("valid card: got %+v", r)
	}

	r, err = Card([]byte(`{"protocol":"ink/0.2","agentId":"x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("invalid card accepted: %+v", r)
	}

	if _, err := Card([]byte(`{not json`)); err == nil {
		t.Errorf("malformed JSON did not error")
	}
}

func TestInclusion(t *testing.T) {
	// A single-leaf tree: the root is the leaf hash and the proof is empty.
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	accept := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `"}`
	r, err := Inclusion([]byte(accept))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "merkle-inclusion" {
		t.Errorf("valid inclusion proof: got %+v", r)
	}

	// A mismatched root rejects.
	reject := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"00"}`
	r, err = Inclusion([]byte(reject))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("bad inclusion proof accepted: %+v", r)
	}

	if _, err := Inclusion([]byte(`{`)); err == nil {
		t.Errorf("malformed JSON did not error")
	}
}

func TestConsistency(t *testing.T) {
	const accept = `{"first":1,"firstRoot":"bb15072bf1d8bf0791f48964ef8511973fa01f0b8307c36576ea2e2486386795","second":2,"secondRoot":"f53ae60398fe1ad1a266cd62229393fd8cc0e6e7dc52df6714ee2fe0dede66ec","proof":["7c335acabf2f6e37cef0988b4c52e007d466f8f87782ce50e1dafa30d881ec29"]}`
	r, err := Consistency([]byte(accept))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "merkle-consistency" {
		t.Errorf("valid consistency proof: got %+v", r)
	}

	reject := `{"first":1,"firstRoot":"00","second":2,"secondRoot":"11","proof":[]}`
	r, err = Consistency([]byte(reject))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("bad consistency proof accepted: %+v", r)
	}

	if _, err := Consistency([]byte(`nope`)); err == nil {
		t.Errorf("malformed JSON did not error")
	}
}

// The signature inputs below mirror the accept case in
// conformance/v1/vectors/signature-base.json: the same signing key, signed
// request, and detached signature the Go conformance runner verifies.
const sigPubHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
const sigValue = "ifHGTDmRgl6H_XZIyCgkaxmE2AVSNvgQG_dybsZvsVobod0qzYcBe8bEsf1srDvmdbyeD6-jnQTFb0xTmCeaCA"
const sigSignInput = `{"method":"POST","path":"/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent","recipientDid":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","timestamp":"2026-06-11T00:00:00.000Z","body":{"correlationId":"22222222-2222-4222-8222-222222222222","createdAt":"2026-06-11T00:00:00.000Z","from":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","id":"11111111-1111-4111-8111-111111111111","intent":"ping","nonce":"33333333-3333-4333-8333-333333333333","payload":{"note":"conformance","scope":"deep"},"protocol":"ink/0.1","timestamp":"2026-06-11T00:00:00.000Z","to":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX"}}`

func sigInput(keyField string) string {
	return `{` + keyField + `,"signInput":` + sigSignInput + `,"signature":"` + sigValue + `"}`
}

func TestSignatureHex(t *testing.T) {
	r, err := Signature([]byte(sigInput(`"publicKeyHex":"` + sigPubHex + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "signature" {
		t.Errorf("valid signature: got %+v", r)
	}
}

func TestSignatureMultibase(t *testing.T) {
	raw, err := hex.DecodeString(sigPubHex)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := ink.EncodePublicKeyMultibase(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Signature([]byte(sigInput(`"publicKeyMultibase":"` + mb + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "signature" {
		t.Errorf("multibase key did not verify: %+v", r)
	}
}

func TestSignatureWrongKeyRejects(t *testing.T) {
	// A different but well-formed key: the signature is well-formed, it just
	// does not verify, so this is a clean rejection, not bad input.
	const other = "32fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	r, err := Signature([]byte(sigInput(`"publicKeyHex":"` + other + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("wrong key verified: %+v", r)
	}
}

func TestSignatureBothKeysBadInput(t *testing.T) {
	in := `{"publicKeyHex":"` + sigPubHex + `","publicKeyMultibase":"z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","signInput":` + sigSignInput + `,"signature":"` + sigValue + `"}`
	if _, err := Signature([]byte(in)); err == nil {
		t.Errorf("supplying both key forms did not error")
	}
}

func TestSignatureNoKeyBadInput(t *testing.T) {
	in := `{"signInput":` + sigSignInput + `,"signature":"` + sigValue + `"}`
	if _, err := Signature([]byte(in)); err == nil {
		t.Errorf("missing key did not error")
	}
}

func TestSignatureMissingSignInputFieldBadInput(t *testing.T) {
	// signInput without timestamp is a malformed request, not a rejection.
	bad := `{"publicKeyHex":"` + sigPubHex + `","signInput":{"method":"POST","path":"/x","recipientDid":"d","body":{}},"signature":"` + sigValue + `"}`
	if _, err := Signature([]byte(bad)); err == nil {
		t.Errorf("missing timestamp did not error")
	}
}

func TestSignatureUnknownFieldBadInput(t *testing.T) {
	in := `{"publicKeyHex":"` + sigPubHex + `","signInput":` + sigSignInput + `,"signature":"` + sigValue + `","extra":1}`
	if _, err := Signature([]byte(in)); err == nil {
		t.Errorf("unknown field did not error")
	}
}

func TestSignatureBadKeyEncodingBadInput(t *testing.T) {
	if _, err := Signature([]byte(sigInput(`"publicKeyHex":"zzzz"`))); err == nil {
		t.Errorf("non-hex key did not error")
	}
}

func TestSignatureShortHexKeyBadInput(t *testing.T) {
	// A well-formed but wrong-length key is bad input, not a verification
	// rejection, matching how a bad multibase key is handled.
	if _, err := Signature([]byte(sigInput(`"publicKeyHex":"abcd"`))); err == nil {
		t.Errorf("short hex key did not error")
	}
}

func TestSignatureScalarSurrogateBadInput(t *testing.T) {
	// A lone surrogate escape in a signed scalar (not the body) must be rejected
	// before encoding/json rewrites it to U+FFFD.
	si := `{"method":"POST\uD800","path":"/x","recipientDid":"d","body":{},"timestamp":"2026-06-11T00:00:00.000Z"}`
	in := `{"publicKeyHex":"` + sigPubHex + `","signInput":` + si + `,"signature":"` + sigValue + `"}`
	if _, err := Signature([]byte(in)); err == nil {
		t.Errorf("lone surrogate in a signed scalar did not error")
	}
}

func TestSignatureInvalidUTF8BadInput(t *testing.T) {
	// Raw invalid UTF-8 in a signed scalar is the same parser-loss class: reject
	// it before json.Unmarshal substitutes U+FFFD.
	si := "{\"method\":\"POST\xed\xa0\x80\",\"path\":\"/x\",\"recipientDid\":\"d\",\"body\":{},\"timestamp\":\"2026-06-11T00:00:00.000Z\"}"
	in := `{"publicKeyHex":"` + sigPubHex + `","signInput":` + si + `,"signature":"` + sigValue + `"}`
	if _, err := Signature([]byte(in)); err == nil {
		t.Errorf("invalid UTF-8 in a signed scalar did not error")
	}
}
