package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validCard = `{"protocol":"ink/0.1","agentId":"did:web:a.example","handle":"alice","displayName":"Alice","endpoint":"https://a.example/ink/inbox","publicKeyMultibase":"z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX","capabilities":{"intentsAccepted":["ask"],"intentsSent":["ask"]},"availability":{"timezone":"UTC"}}`

func do(t *testing.T, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	var res map[string]any
	if b := rec.Body.Bytes(); len(b) > 0 {
		_ = json.Unmarshal(b, &res)
	}
	return rec, res
}

func TestVerifyCardAccept(t *testing.T) {
	rec, res := do(t, http.MethodPost, "/verify/card", validCard)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if res["ok"] != true || res["kind"] != "agent-card" {
		t.Errorf("unexpected verdict: %v", res)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestVerifyCardReject(t *testing.T) {
	rec, res := do(t, http.MethodPost, "/verify/card", `{"protocol":"ink/0.2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a well-formed-but-rejected artifact", rec.Code)
	}
	if res["ok"] != false || res["kind"] != "agent-card" {
		t.Errorf("unexpected verdict: %v", res)
	}
}

func TestVerifyBadJSONIs400(t *testing.T) {
	rec, res := do(t, http.MethodPost, "/verify/card", `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if res["ok"] != false || res["error"] != "bad_input" {
		t.Errorf("unexpected error body: %v", res)
	}
}

// Every verify route must be reachable and must map to its verifier. Sending an
// empty object exercises each verifier's own input handling: schema validators
// return a 200 verdict (kind set), strict-envelope verifiers return 400.
func TestAllRoutesWired(t *testing.T) {
	cases := []struct {
		path     string
		wantKind string // "" means the route rejects {} as bad input (400)
	}{
		{"/verify/card", "agent-card"},
		{"/verify/handshake", "handshake-message"},
		{"/verify/signature", ""},
		{"/verify/receipt", ""},
		{"/verify/audit-response", ""},
		{"/verify/connection", ""},
		{"/verify/checkpoint", ""},
		{"/verify/inclusion", ""},
		{"/verify/consistency", ""},
	}
	for _, c := range cases {
		rec, res := do(t, http.MethodPost, c.path, `{}`)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s not wired: status %d", c.path, rec.Code)
			continue
		}
		if c.wantKind == "" {
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s with {} status = %d, want 400", c.path, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusOK || res["kind"] != c.wantKind {
			t.Errorf("%s with {} = status %d kind %v, want 200 kind %q", c.path, rec.Code, res["kind"], c.wantKind)
		}
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	rec, res := do(t, http.MethodPost, "/verify/bogus", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if res["error"] != "not_found" {
		t.Errorf("unexpected body: %v", res)
	}
}

func TestWrongMethodIs405(t *testing.T) {
	rec, _ := do(t, http.MethodGet, "/verify/card", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestOversizeBodyIs413(t *testing.T) {
	big := strings.Repeat("a", (4<<20)+1)
	rec, _ := do(t, http.MethodPost, "/verify/card", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	rec, res := do(t, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK || res["ok"] != true {
		t.Errorf("healthz = status %d body %v", rec.Code, res)
	}
}
