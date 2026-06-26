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
