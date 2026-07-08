package verify

import (
	"encoding/hex"
	"encoding/json"
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

// The receipt inputs below mirror the valid-signature-only-accepts case in
// conformance/v1/vectors/inclusion-receipt.json: the witness key and a receipt
// whose service signature verifies, with no event binding or later checkpoint.
const receiptWitnessHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
const receiptValue = `{"eventId":"evt-1","leafIndex":1,"treeSize":4,"rootHash":"af29b338fe8fb49e6dfccfb826b605d9fc4db9fb6b1b5f65d4b8717af8cde32f","timestamp":"2026-06-15T12:00:00.000Z","inclusionProof":["03f7a68e23dc6ec76d76e4c345fa64fedffb6f26ddd0233f952a02005cf62749","1a01d742673069afdd4ae9b6643939e94935869dcfb605bc71624469c2a54dd0"],"serviceSignature":"_10wmxv3DiY1Xg7dn7aiyASpaNn9goteTliq_gcen4YzcMXypHmTQrFpK7cMUIqYIcpMbeMMgXpmYWecySeWCQ"}`

func receiptInputJSON(keyField string) string {
	return `{` + keyField + `,"receipt":` + receiptValue + `}`
}

func TestReceiptHex(t *testing.T) {
	r, err := Receipt([]byte(receiptInputJSON(`"witnessPublicKeyHex":"` + receiptWitnessHex + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "inclusion-receipt" {
		t.Errorf("valid receipt: got %+v", r)
	}
}

func TestReceiptMultibase(t *testing.T) {
	raw, err := hex.DecodeString(receiptWitnessHex)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := ink.EncodePublicKeyMultibase(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Receipt([]byte(receiptInputJSON(`"witnessPublicKeyMultibase":"` + mb + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK {
		t.Errorf("multibase witness key did not verify: %+v", r)
	}
}

func TestReceiptWrongKeyRejects(t *testing.T) {
	const other = "32fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	r, err := Receipt([]byte(receiptInputJSON(`"witnessPublicKeyHex":"` + other + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("wrong witness key verified: %+v", r)
	}
}

func TestReceiptMalformedReceiptRejects(t *testing.T) {
	// A receipt with a non-integer leafIndex fails the receiver-boundary parse.
	// Per the conformance contract a malformed receipt is a rejection, not bad
	// input, so this returns OK:false with no error (exit 1, not 2).
	bad := `{"eventId":"evt-1","leafIndex":1.5,"treeSize":4,"rootHash":"af29b338fe8fb49e6dfccfb826b605d9fc4db9fb6b1b5f65d4b8717af8cde32f","timestamp":"2026-06-15T12:00:00.000Z","inclusionProof":[],"serviceSignature":"_10wmxv3DiY1Xg7dn7aiyASpaNn9goteTliq_gcen4YzcMXypHmTQrFpK7cMUIqYIcpMbeMMgXpmYWecySeWCQ"}`
	in := `{"witnessPublicKeyHex":"` + receiptWitnessHex + `","receipt":` + bad + `}`
	r, err := Receipt([]byte(in))
	if err != nil {
		t.Fatalf("malformed receipt should reject, not error: %v", err)
	}
	if r.OK {
		t.Errorf("malformed receipt verified: %+v", r)
	}
}

func TestReceiptMissingReceiptBadInput(t *testing.T) {
	if _, err := Receipt([]byte(`{"witnessPublicKeyHex":"` + receiptWitnessHex + `"}`)); err == nil {
		t.Errorf("missing receipt did not error")
	}
}

func TestReceiptNoKeyBadInput(t *testing.T) {
	if _, err := Receipt([]byte(`{"receipt":` + receiptValue + `}`)); err == nil {
		t.Errorf("missing witness key did not error")
	}
}

func TestReceiptBothKeysBadInput(t *testing.T) {
	in := `{"witnessPublicKeyHex":"` + receiptWitnessHex + `","witnessPublicKeyMultibase":"z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","receipt":` + receiptValue + `}`
	if _, err := Receipt([]byte(in)); err == nil {
		t.Errorf("supplying both witness key forms did not error")
	}
}

func TestReceiptUnknownFieldBadInput(t *testing.T) {
	in := `{"witnessPublicKeyHex":"` + receiptWitnessHex + `","receipt":` + receiptValue + `,"extra":1}`
	if _, err := Receipt([]byte(in)); err == nil {
		t.Errorf("unknown field did not error")
	}
}

func TestReceiptMalformedEventHashRejects(t *testing.T) {
	// A non-string eventHash is a malformed binding, which the reference treats
	// as a verification rejection (exit 1), not a CLI usage error.
	in := `{"witnessPublicKeyHex":"` + receiptWitnessHex + `","receipt":` + receiptValue + `,"eventHash":123}`
	r, err := Receipt([]byte(in))
	if err != nil {
		t.Fatalf("malformed eventHash should reject, not error: %v", err)
	}
	if r.OK {
		t.Errorf("malformed eventHash verified: %+v", r)
	}
}

func TestReceiptDuplicateKeyBadInput(t *testing.T) {
	// The envelope is the CLI's own schema, so a duplicate top-level key is
	// ambiguous input, even though a duplicate key inside the raw receipt is left
	// to the library parser's last-wins tolerance.
	in := `{"witnessPublicKeyHex":"` + receiptWitnessHex + `","receipt":` + receiptValue + `,"receipt":` + receiptValue + `}`
	if _, err := Receipt([]byte(in)); err == nil {
		t.Errorf("duplicate top-level key did not error")
	}
}

// The audit-response inputs below mirror the valid-accepts case in
// conformance/v1/vectors/audit-query-response.json: the witness key, a signed
// response carrying three agent events with inclusion proofs, and the per-agent
// key the events' agentSignature is checked against.
const audrWitnessHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
const audrRequester = "did:web:agent-a.example"
const audrMessageID = "msg-001"
const audrAgentKeys = `{"did:web:agent-a.example":"b8d0e8e9c703c25b661ccbde06420da4ecde22d3291c3fe00f0e53a2fddff297"}`
const audrResponse = `{"protocol":"ink/0.1","type":"network.tulpa.audit_query_response","serviceDid":"did:web:witness.example","messageId":"msg-001","requester":"did:web:agent-a.example","events":[{"id":"evt-0","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":0,"agentSignature":"XHcBOVegyakSEzI8vT5QiuVB2fGU-h3aqx7bLv51d_f8-YJFYouoB0yYTIJqA0CY0dE4u-PlLdIhmRBtVKj0Bw"},{"id":"evt-1","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":1,"agentSignature":"GPB347fu-T6qi5V6xqGEJcoq7sVtk5pmM-pxBRqf_HszySZrqvuOlkpyZDPxEQMGXm-zJO6NlPITNsBp_lzRAw"},{"id":"evt-2","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":2,"agentSignature":"26eSzfRJO4CtHlwzL1X9O6pY5g4vXnVf5GP87CFsvMtOGHdIAO_qfGoJclF5JfGysp7bb-3pQWkrOJ2ISFheAA"}],"proofs":[{"eventId":"evt-0","leafIndex":0,"inclusionProof":["cf1d4d7971e05e58ebb9f4f8e2384ba1982b1c072958b7297e7ceabf96b6acce","64637effd60a4f8b1a74d8737406e91dec34d87f8575f5335e295b561fddcb9d"]},{"eventId":"evt-1","leafIndex":1,"inclusionProof":["cf1d4d7971e05e58ebb9f4f8e2384ba1982b1c072958b7297e7ceabf96b6acce","b455954693e797074af9281352a4f8b336dc01330c3c9047c859aea4a705b2ca"]},{"eventId":"evt-2","leafIndex":2,"inclusionProof":["3f1a6b57827d594230355a70560f6f601f58b1a2acf4bd8a1bad5564d8f658a1"]}],"treeSize":3,"rootHash":"66cc105579a2cb38c58b4279d773623e50ead1568f1ce34fa225f2c55525c435","timestamp":"2026-06-15T12:00:00.000Z","serviceSignature":"Fe4zi76c_NiJ249LskVA0mkIqJF7DmdC0o3LfwcaBxq5FMO7A2ckvabocjLUvT8H5gNWe-EUAGSxJYMYg_jyAw"}`

func audrInput(keyField string) string {
	return `{` + keyField + `,"response":` + audrResponse + `,"expectedRequester":"` + audrRequester + `","expectedMessageId":"` + audrMessageID + `","agentKeysHex":` + audrAgentKeys + `}`
}

func TestAuditResponseHex(t *testing.T) {
	r, err := AuditResponse([]byte(audrInput(`"witnessPublicKeyHex":"` + audrWitnessHex + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "audit-query-response" {
		t.Errorf("valid audit response: got %+v", r)
	}
}

func TestAuditResponseMultibase(t *testing.T) {
	raw, err := hex.DecodeString(audrWitnessHex)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := ink.EncodePublicKeyMultibase(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := AuditResponse([]byte(audrInput(`"witnessPublicKeyMultibase":"` + mb + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK {
		t.Errorf("multibase witness key did not verify: %+v", r)
	}
}

func TestAuditResponseWrongWitnessRejects(t *testing.T) {
	const other = "32fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	r, err := AuditResponse([]byte(audrInput(`"witnessPublicKeyHex":"` + other + `"`)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("wrong witness key verified: %+v", r)
	}
}

func TestAuditResponseBadAgentKeyRejects(t *testing.T) {
	// An undecodable per-agent key makes the event-signature callback fail, so
	// the required per-event agent signature is unmet: a rejection, not an error.
	in := `{"witnessPublicKeyHex":"` + audrWitnessHex + `","response":` + audrResponse + `,"expectedRequester":"` + audrRequester + `","expectedMessageId":"` + audrMessageID + `","agentKeysHex":{"did:web:agent-a.example":"zz"}}`
	r, err := AuditResponse([]byte(in))
	if err != nil {
		t.Fatalf("bad agent key should reject, not error: %v", err)
	}
	if r.OK {
		t.Errorf("response with an undecodable agent key verified: %+v", r)
	}
}

func TestAuditResponseMissingResponseBadInput(t *testing.T) {
	in := `{"witnessPublicKeyHex":"` + audrWitnessHex + `","expectedRequester":"` + audrRequester + `","expectedMessageId":"` + audrMessageID + `","agentKeysHex":` + audrAgentKeys + `}`
	if _, err := AuditResponse([]byte(in)); err == nil {
		t.Errorf("missing response did not error")
	}
}

func TestAuditResponseMissingRequesterBadInput(t *testing.T) {
	in := `{"witnessPublicKeyHex":"` + audrWitnessHex + `","response":` + audrResponse + `,"expectedMessageId":"` + audrMessageID + `","agentKeysHex":` + audrAgentKeys + `}`
	if _, err := AuditResponse([]byte(in)); err == nil {
		t.Errorf("missing expectedRequester did not error")
	}
}

func TestAuditResponseNoKeyBadInput(t *testing.T) {
	in := `{"response":` + audrResponse + `,"expectedRequester":"` + audrRequester + `","expectedMessageId":"` + audrMessageID + `","agentKeysHex":` + audrAgentKeys + `}`
	if _, err := AuditResponse([]byte(in)); err == nil {
		t.Errorf("missing witness key did not error")
	}
}

func TestAuditResponseUnknownFieldBadInput(t *testing.T) {
	in := audrInput(`"witnessPublicKeyHex":"` + audrWitnessHex + `"`)
	in = in[:len(in)-1] + `,"extra":1}`
	if _, err := AuditResponse([]byte(in)); err == nil {
		t.Errorf("unknown field did not error")
	}
}

// The handshake and connection inputs below mirror the first accept case in
// conformance/v1/vectors/handshake-message.json and connection-payload.json.
const handshakeMessage = `{"protocol":"ink/0.1","type":"network.tulpa.challenge","intentRef":"intent-1","challengeType":"availability_query","nonce":"n1","timestamp":"2026-06-16T12:00:00.000Z"}`
const connectionPayload = `{"method":"discovery","context":"met at the conference","profileSnapshot":{"headline":"Staff engineer","skills":["go","typescript"],"interests":["agents"],"openTo":["roles","advising"],"availability":{"timezone":"America/Los_Angeles","meetingHours":"9-5 PT weekdays"}}}`

func TestHandshakeAccept(t *testing.T) {
	r, err := Handshake([]byte(handshakeMessage))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "handshake-message" {
		t.Errorf("valid handshake: got %+v", r)
	}
}

func TestHandshakeInvalidRejects(t *testing.T) {
	// A non-literal type fails the schema: a rejection, not an error.
	bad := `{"protocol":"ink/0.1","type":"network.tulpa.bogus","intentRef":"intent-1","challengeType":"availability_query","nonce":"n1","timestamp":"2026-06-16T12:00:00.000Z"}`
	r, err := Handshake([]byte(bad))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("invalid handshake accepted: %+v", r)
	}
}

func TestHandshakeNonObjectRejects(t *testing.T) {
	// Well-formed JSON of the wrong shape is a rejection (exit 1), not bad input.
	r, err := Handshake([]byte(`[1,2,3]`))
	if err != nil {
		t.Fatalf("non-object should reject, not error: %v", err)
	}
	if r.OK {
		t.Errorf("array accepted as a handshake message: %+v", r)
	}
}

func TestHandshakeMalformedBadInput(t *testing.T) {
	if _, err := Handshake([]byte(`{not json`)); err == nil {
		t.Errorf("malformed JSON did not error")
	}
}

// Raw invalid UTF-8 is bad input, not a normalized rejection: encoding/json
// would rewrite the byte to U+FFFD, so a request with an invalid byte must map
// to the bad-input exit code rather than reach schema validation as U+FFFD.
func TestInvalidUTF8IsBadInput(t *testing.T) {
	bad := []byte("{\"displayName\":\"a\xffb\"}")
	verifiers := map[string]func([]byte) (Result, error){
		"Card":        Card,
		"Handshake":   Handshake,
		"Connection":  Connection,
		"Inclusion":   Inclusion,
		"Consistency": Consistency,
		"Checkpoint":  Checkpoint,
	}
	for name, fn := range verifiers {
		if _, err := fn(bad); err == nil {
			t.Errorf("%s accepted raw invalid UTF-8 instead of returning bad input", name)
		}
	}
}

func TestConnectionAccept(t *testing.T) {
	in := `{"kind":"connection_request","payload":` + connectionPayload + `}`
	r, err := Connection([]byte(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "connection-payload" {
		t.Errorf("valid connection payload: got %+v", r)
	}
}

func TestConnectionWrongKindRejects(t *testing.T) {
	in := `{"kind":"bogus_kind","payload":` + connectionPayload + `}`
	r, err := Connection([]byte(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.OK {
		t.Errorf("unknown kind accepted: %+v", r)
	}
}

func TestConnectionNonObjectPayloadRejects(t *testing.T) {
	in := `{"kind":"connection_request","payload":[1,2,3]}`
	r, err := Connection([]byte(in))
	if err != nil {
		t.Fatalf("non-object payload should reject, not error: %v", err)
	}
	if r.OK {
		t.Errorf("array payload accepted: %+v", r)
	}
}

func TestConnectionMissingKindBadInput(t *testing.T) {
	if _, err := Connection([]byte(`{"payload":` + connectionPayload + `}`)); err == nil {
		t.Errorf("missing kind did not error")
	}
}

func TestConnectionMissingPayloadBadInput(t *testing.T) {
	if _, err := Connection([]byte(`{"kind":"connection_request"}`)); err == nil {
		t.Errorf("missing payload did not error")
	}
}

func TestConnectionUnknownFieldBadInput(t *testing.T) {
	in := `{"kind":"connection_request","payload":` + connectionPayload + `,"extra":1}`
	if _, err := Connection([]byte(in)); err == nil {
		t.Errorf("unknown field did not error")
	}
}

func TestEventSignatureVerifierFailsClosed(t *testing.T) {
	// A 32-byte key so only the agentId/key-resolution guards, not the key
	// length, decide these cases.
	const key = "b8d0e8e9c703c25b661ccbde06420da4ecde22d3291c3fe00f0e53a2fddff297"
	v := eventSignatureVerifier(map[string]string{
		"":                      key,
		"did:web:bad.example":   "zz",   // not valid hex
		"did:web:short.example": "abcd", // valid hex, wrong length
	})
	cases := []struct {
		name  string
		event map[string]interface{}
	}{
		{"missing agentId", map[string]interface{}{}},
		{"empty agentId cannot borrow the empty-string map entry", map[string]interface{}{"agentId": ""}},
		{"non-string agentId", map[string]interface{}{"agentId": 123}},
		{"undecodable key", map[string]interface{}{"agentId": "did:web:bad.example"}},
		{"wrong-length key", map[string]interface{}{"agentId": "did:web:short.example"}},
		{"absent key", map[string]interface{}{"agentId": "did:web:absent.example"}},
	}
	for _, c := range cases {
		if v(c.event) {
			t.Errorf("%s: event verified but should fail closed", c.name)
		}
	}
}

// A canonical checkpoint body from the merkle-checkpoint vectors: origin, a tree
// size, and a 32-byte hex root, each on its own line with a trailing newline.
const validCheckpointBody = "example.com/ink-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271\n"

func TestCheckpointAccept(t *testing.T) {
	r, err := Checkpoint([]byte(`{"body":` + jsonString(validCheckpointBody) + `}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.OK || r.Kind != "merkle-checkpoint" {
		t.Errorf("valid checkpoint: got %+v", r)
	}
	// On accept the canonical re-serialization is surfaced; for a body already in
	// canonical form it round-trips to itself.
	if r.Canonical != validCheckpointBody {
		t.Errorf("canonical = %q, want %q", r.Canonical, validCheckpointBody)
	}
}

func TestCheckpointMalformedRejects(t *testing.T) {
	// Present but malformed bodies are a clean rejection, not bad input: an empty
	// body, a missing trailing newline, and trailing junk all fail ParseCheckpoint.
	for _, body := range []string{
		"",
		"example.com/ink-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271",
		"example.com/ink-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271\nx",
	} {
		r, err := Checkpoint([]byte(`{"body":` + jsonString(body) + `}`))
		if err != nil {
			t.Fatalf("body %q: unexpected error: %v", body, err)
		}
		if r.OK {
			t.Errorf("body %q accepted, want reject", body)
		}
		if r.Canonical != "" {
			t.Errorf("body %q: canonical set on reject: %q", body, r.Canonical)
		}
	}
}

func TestCheckpointMissingBodyBadInput(t *testing.T) {
	if _, err := Checkpoint([]byte(`{}`)); err == nil {
		t.Errorf("missing body did not error")
	}
	if _, err := Checkpoint([]byte(`{"body":null}`)); err == nil {
		t.Errorf("null body did not error")
	}
}

// A lone UTF-16 surrogate escape in the signed body must be bad input, not an
// accept: encoding/json would otherwise rewrite it to U+FFFD and lose the
// byte-identity the witness signature is over.
func TestCheckpointLoneSurrogateBadInput(t *testing.T) {
	if _, err := Checkpoint([]byte(`{"body":"example.com/\ud800-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271\n"}`)); err == nil {
		t.Errorf("lone surrogate body did not error")
	}
}

func TestCheckpointUnknownFieldBadInput(t *testing.T) {
	in := `{"body":` + jsonString(validCheckpointBody) + `,"extra":1}`
	if _, err := Checkpoint([]byte(in)); err == nil {
		t.Errorf("unknown field did not error")
	}
}

// jsonString encodes s as a JSON string literal for embedding in test fixtures.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
