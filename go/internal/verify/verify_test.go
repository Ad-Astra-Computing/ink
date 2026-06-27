package verify

import "testing"

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
