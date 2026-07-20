package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCard = `{"protocol":"ink/0.1","agentId":"did:web:a.example","handle":"alice","displayName":"Alice","endpoint":"https://a.example/ink/inbox","publicKeyMultibase":"z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","capabilities":{"intentsAccepted":["ask"],"intentsSent":["ask"]},"availability":{"timezone":"UTC"}}`

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestVerifyCardStdin(t *testing.T) {
	code, out, _ := run(t, validCard, "verify-card")
	if code != 0 {
		t.Fatalf("valid card exit = %d, want 0", code)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("output not JSON: %v (%q)", err, out)
	}
	if res["ok"] != true || res["kind"] != "agent-card" {
		t.Errorf("unexpected result: %v", res)
	}
}

func TestVerifyCardRejectExits1(t *testing.T) {
	code, out, _ := run(t, `{"protocol":"ink/0.2"}`, "verify-card")
	if code != 1 {
		t.Fatalf("rejected card exit = %d, want 1", code)
	}
	if !strings.Contains(out, `"ok":false`) {
		t.Errorf("expected ok:false, got %q", out)
	}
}

func TestMalformedJSONExits2(t *testing.T) {
	code, _, errOut := run(t, `{not json`, "verify-card")
	if code != 2 {
		t.Fatalf("malformed JSON exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "bad_input") {
		t.Errorf("expected bad_input on stderr, got %q", errOut)
	}
}

func TestMissingFileExits2(t *testing.T) {
	code, _, errOut := run(t, "", "verify-card", "--file", "/no/such/file.json")
	if code != 2 {
		t.Fatalf("missing file exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "bad_input") {
		t.Errorf("expected bad_input, got %q", errOut)
	}
}

func TestVerifyCardFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.json")
	if err := os.WriteFile(path, []byte(validCard), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ := run(t, "", "verify-card", "--file", path)
	if code != 0 {
		t.Fatalf("valid card from file exit = %d, want 0", code)
	}
}

func TestVerifyInclusion(t *testing.T) {
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	accept := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `"}`
	if code, _, _ := run(t, accept, "verify-inclusion"); code != 0 {
		t.Fatalf("valid inclusion exit = %d, want 0", code)
	}
	reject := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"00"}`
	if code, _, _ := run(t, reject, "verify-inclusion"); code != 1 {
		t.Fatalf("bad inclusion exit = %d, want 1", code)
	}
}

func TestVerifySignature(t *testing.T) {
	const pubHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	const sig = "ifHGTDmRgl6H_XZIyCgkaxmE2AVSNvgQG_dybsZvsVobod0qzYcBe8bEsf1srDvmdbyeD6-jnQTFb0xTmCeaCA"
	const signInput = `{"method":"POST","path":"/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent","recipientDid":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","timestamp":"2026-06-11T00:00:00.000Z","body":{"correlationId":"22222222-2222-4222-8222-222222222222","createdAt":"2026-06-11T00:00:00.000Z","from":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","id":"11111111-1111-4111-8111-111111111111","intent":"ping","nonce":"33333333-3333-4333-8333-333333333333","payload":{"note":"conformance","scope":"deep"},"protocol":"ink/0.1","timestamp":"2026-06-11T00:00:00.000Z","to":"tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX"}}`
	accept := `{"publicKeyHex":"` + pubHex + `","signInput":` + signInput + `,"signature":"` + sig + `"}`
	if code, out, _ := run(t, accept, "verify-signature"); code != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("valid signature exit = %d out = %q, want 0 ok:true", code, out)
	}
	noKey := `{"signInput":` + signInput + `,"signature":"` + sig + `"}`
	if code, _, errOut := run(t, noKey, "verify-signature"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing key exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestSignRequestRoundTripsThroughVerify(t *testing.T) {
	const seedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	const signInput = `{"method":"POST","path":"/ink/v1/tulpa:z/intent","recipientDid":"tulpa:z","body":{"protocol":"ink/0.1","intent":"ping"},"timestamp":"2026-06-11T00:00:00.000Z"}`
	signReq := `{"privateKeyHex":"` + seedHex + `","signInput":` + signInput + `,"keyId":"key-2026"}`

	code, out, errOut := run(t, signReq, "sign-request")
	if code != 0 {
		t.Fatalf("sign-request exit = %d (err %q), want 0", code, errOut)
	}
	var signed struct {
		Signature    string          `json:"signature"`
		AuthHeader   string          `json:"authHeader"`
		PublicKeyHex string          `json:"publicKeyHex"`
		SignInput    json.RawMessage `json:"signInput"`
	}
	if err := json.Unmarshal([]byte(out), &signed); err != nil {
		t.Fatalf("sign-request output not JSON: %v (%q)", err, out)
	}
	if !strings.HasPrefix(signed.AuthHeader, "INK-Ed25519 ") || !strings.HasSuffix(signed.AuthHeader, " keyId=key-2026") {
		t.Errorf("unexpected auth header %q", signed.AuthHeader)
	}

	// Feed the Go-signed output straight back into the Go verifier command.
	verifyReq := `{"publicKeyHex":"` + signed.PublicKeyHex + `","signInput":` + string(signed.SignInput) + `,"signature":"` + signed.Signature + `"}`
	if vc, vout, verr := run(t, verifyReq, "verify-signature"); vc != 0 || !strings.Contains(vout, `"ok":true`) {
		t.Fatalf("verify-signature of a signed request exit = %d out = %q (err %q), want 0 ok:true", vc, vout, verr)
	}

	// A malformed sign request is bad input (exit 2), not a silent signature.
	if bc, _, berr := run(t, `{"signInput":{}}`, "sign-request"); bc != 2 || !strings.Contains(berr, "bad_input") {
		t.Fatalf("bad sign-request exit = %d (err %q), want 2 bad_input", bc, berr)
	}
}

func TestVerifyReceipt(t *testing.T) {
	const witnessHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	const receipt = `{"eventId":"evt-1","leafIndex":1,"treeSize":4,"rootHash":"af29b338fe8fb49e6dfccfb826b605d9fc4db9fb6b1b5f65d4b8717af8cde32f","timestamp":"2026-06-15T12:00:00.000Z","inclusionProof":["03f7a68e23dc6ec76d76e4c345fa64fedffb6f26ddd0233f952a02005cf62749","1a01d742673069afdd4ae9b6643939e94935869dcfb605bc71624469c2a54dd0"],"serviceSignature":"_10wmxv3DiY1Xg7dn7aiyASpaNn9goteTliq_gcen4YzcMXypHmTQrFpK7cMUIqYIcpMbeMMgXpmYWecySeWCQ"}`
	accept := `{"witnessPublicKeyHex":"` + witnessHex + `","receipt":` + receipt + `}`
	if code, out, _ := run(t, accept, "verify-receipt"); code != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("valid receipt exit = %d out = %q, want 0 ok:true", code, out)
	}
	noKey := `{"receipt":` + receipt + `}`
	if code, _, errOut := run(t, noKey, "verify-receipt"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing key exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestVerifyAuditResponse(t *testing.T) {
	const witnessHex = "22fec375ea0fe9d1b05996aac2485c17fafda30b7b6718c76e3169fa16c419c4"
	const agentKeys = `{"did:web:agent-a.example":"b8d0e8e9c703c25b661ccbde06420da4ecde22d3291c3fe00f0e53a2fddff297"}`
	const response = `{"protocol":"ink/0.1","type":"network.tulpa.audit_query_response","serviceDid":"did:web:witness.example","messageId":"msg-001","requester":"did:web:agent-a.example","events":[{"id":"evt-0","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":0,"agentSignature":"XHcBOVegyakSEzI8vT5QiuVB2fGU-h3aqx7bLv51d_f8-YJFYouoB0yYTIJqA0CY0dE4u-PlLdIhmRBtVKj0Bw"},{"id":"evt-1","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":1,"agentSignature":"GPB347fu-T6qi5V6xqGEJcoq7sVtk5pmM-pxBRqf_HszySZrqvuOlkpyZDPxEQMGXm-zJO6NlPITNsBp_lzRAw"},{"id":"evt-2","type":"connection_request","messageId":"msg-001","agentId":"did:web:agent-a.example","counterpartyId":"did:web:agent-b.example","seq":2,"agentSignature":"26eSzfRJO4CtHlwzL1X9O6pY5g4vXnVf5GP87CFsvMtOGHdIAO_qfGoJclF5JfGysp7bb-3pQWkrOJ2ISFheAA"}],"proofs":[{"eventId":"evt-0","leafIndex":0,"inclusionProof":["cf1d4d7971e05e58ebb9f4f8e2384ba1982b1c072958b7297e7ceabf96b6acce","64637effd60a4f8b1a74d8737406e91dec34d87f8575f5335e295b561fddcb9d"]},{"eventId":"evt-1","leafIndex":1,"inclusionProof":["cf1d4d7971e05e58ebb9f4f8e2384ba1982b1c072958b7297e7ceabf96b6acce","b455954693e797074af9281352a4f8b336dc01330c3c9047c859aea4a705b2ca"]},{"eventId":"evt-2","leafIndex":2,"inclusionProof":["3f1a6b57827d594230355a70560f6f601f58b1a2acf4bd8a1bad5564d8f658a1"]}],"treeSize":3,"rootHash":"66cc105579a2cb38c58b4279d773623e50ead1568f1ce34fa225f2c55525c435","timestamp":"2026-06-15T12:00:00.000Z","serviceSignature":"Fe4zi76c_NiJ249LskVA0mkIqJF7DmdC0o3LfwcaBxq5FMO7A2ckvabocjLUvT8H5gNWe-EUAGSxJYMYg_jyAw"}`
	accept := `{"witnessPublicKeyHex":"` + witnessHex + `","response":` + response + `,"expectedRequester":"did:web:agent-a.example","expectedMessageId":"msg-001","agentKeysHex":` + agentKeys + `}`
	if code, out, _ := run(t, accept, "verify-audit-response"); code != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("valid audit response exit = %d out = %q, want 0 ok:true", code, out)
	}
	noKey := `{"response":` + response + `,"expectedRequester":"did:web:agent-a.example","expectedMessageId":"msg-001","agentKeysHex":` + agentKeys + `}`
	if code, _, errOut := run(t, noKey, "verify-audit-response"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing key exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestVerifyHandshake(t *testing.T) {
	const msg = `{"protocol":"ink/0.1","type":"network.tulpa.challenge","intentRef":"intent-1","challengeType":"availability_query","nonce":"n1","timestamp":"2026-06-16T12:00:00.000Z"}`
	if code, out, _ := run(t, msg, "verify-handshake"); code != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("valid handshake exit = %d out = %q, want 0 ok:true", code, out)
	}
	if code, _, _ := run(t, `[1,2,3]`, "verify-handshake"); code != 1 {
		t.Fatalf("non-object handshake exit = %d, want 1", code)
	}
}

func TestVerifyConnection(t *testing.T) {
	const payload = `{"method":"discovery","context":"met at the conference","profileSnapshot":{"headline":"Staff engineer","skills":["go","typescript"],"interests":["agents"],"openTo":["roles","advising"],"availability":{"timezone":"America/Los_Angeles","meetingHours":"9-5 PT weekdays"}}}`
	accept := `{"kind":"connection_request","payload":` + payload + `}`
	if code, out, _ := run(t, accept, "verify-connection"); code != 0 || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("valid connection exit = %d out = %q, want 0 ok:true", code, out)
	}
	noKind := `{"payload":` + payload + `}`
	if code, _, errOut := run(t, noKind, "verify-connection"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing kind exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	const accept = `{"body":"example.com/ink-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271\n"}`
	if code, out, _ := run(t, accept, "verify-checkpoint"); code != 0 || !strings.Contains(out, `"canonical":`) {
		t.Fatalf("valid checkpoint exit = %d out = %q, want 0 with canonical", code, out)
	}
	// A present-but-malformed body (missing trailing newline) is a rejection.
	malformed := `{"body":"example.com/ink-log\n5\n6b7afabb949cf3b283bb350a4dacecdc109cf7dcd3824156511958cddfb61271"}`
	if code, _, _ := run(t, malformed, "verify-checkpoint"); code != 1 {
		t.Fatalf("malformed checkpoint exit = %d, want 1", code)
	}
	if code, _, errOut := run(t, `{}`, "verify-checkpoint"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing body exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestVerifyConsistency(t *testing.T) {
	const accept = `{"first":1,"firstRoot":"bb15072bf1d8bf0791f48964ef8511973fa01f0b8307c36576ea2e2486386795","second":2,"secondRoot":"f53ae60398fe1ad1a266cd62229393fd8cc0e6e7dc52df6714ee2fe0dede66ec","proof":["7c335acabf2f6e37cef0988b4c52e007d466f8f87782ce50e1dafa30d881ec29"]}`
	if code, _, _ := run(t, accept, "verify-consistency"); code != 0 {
		t.Fatalf("valid consistency exit = %d, want 0", code)
	}
}

func TestInclusionMissingFieldExits2(t *testing.T) {
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	// inclusionProof omitted: a missing required field must be bad input, not a
	// zero-value that happens to verify a single-leaf tree.
	missing := `{"leafHash":"` + leaf + `","leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `"}`
	if code, _, errOut := run(t, missing, "verify-inclusion"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("missing field exit = %d (err %q), want 2 bad_input", code, errOut)
	}
	// null required field is also bad input.
	null := `{"leafHash":"` + leaf + `","inclusionProof":null,"leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `"}`
	if code, _, _ := run(t, null, "verify-inclusion"); code != 2 {
		t.Fatalf("null field exit = %d, want 2", code)
	}
}

func TestInclusionUnknownFieldExits2(t *testing.T) {
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	extra := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `","extra":1}`
	if code, _, _ := run(t, extra, "verify-inclusion"); code != 2 {
		t.Fatalf("unknown field exit = %d, want 2", code)
	}
}

func TestInclusionDuplicateKeyExits2(t *testing.T) {
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	dup := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"treeSize":99,"rootHash":"` + leaf + `"}`
	if code, _, _ := run(t, dup, "verify-inclusion"); code != 2 {
		t.Fatalf("duplicate key exit = %d, want 2", code)
	}
}

func TestInclusionTrailingDataExits2(t *testing.T) {
	const leaf = "413d26d603ca86b447ee3e0ca9ac075a412cf0b6d38976743d8a4c58d7a08596"
	trailing := `{"leafHash":"` + leaf + `","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"` + leaf + `"} {}`
	if code, _, _ := run(t, trailing, "verify-inclusion"); code != 2 {
		t.Fatalf("trailing data exit = %d, want 2", code)
	}
}

func TestOversizedInputExits2(t *testing.T) {
	big := strings.Repeat("x", (4<<20)+1)
	if code, _, errOut := run(t, big, "verify-card"); code != 2 || !strings.Contains(errOut, "bad_input") {
		t.Fatalf("oversized input exit = %d (err %q), want 2 bad_input", code, errOut)
	}
}

func TestVersionRejectsUnexpectedArg(t *testing.T) {
	if code, _, _ := run(t, "", "version", "--file", "x"); code != 2 {
		t.Fatalf("version with bad arg exit = %d, want 2", code)
	}
}

func TestUnknownCommandExits2(t *testing.T) {
	code, _, errOut := run(t, "", "frobnicate")
	if code != 2 {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "bad_input") {
		t.Errorf("expected bad_input, got %q", errOut)
	}
}

func TestNoArgsExits2(t *testing.T) {
	if code, _, _ := run(t, ""); code != 2 {
		t.Fatalf("no args exit = %d, want 2", code)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "", "version")
	if code != 0 {
		t.Fatalf("version exit = %d, want 0", code)
	}
	if !strings.Contains(out, Version) {
		t.Errorf("version output %q missing %q", out, Version)
	}
}
