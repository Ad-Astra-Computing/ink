package ink

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The assembled §3.3 receiver. These tests mirror the reference verifyInkAuth
// cases in test/ink-auth.test.ts, test/security-round25.test.ts and the
// atomic-store cases of test/security-review-2026-06.test.ts, so the two
// receivers reject the same request with the same code.

var authTestNow = time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)

const (
	authTestTimestamp = "2026-06-11T00:00:00.000Z"
	authTestRecipient = "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX"
	authTestPath      = "/ink/v1/inbound"
	authTestNonce     = "nonce-0123456789abcdef"
)

func authTestClock() time.Time { return authTestNow }

// signedAuthRequest builds a request body carrying from/timestamp/nonce, signs
// it with signer under the §3.3 base, and returns an input ready for
// VerifyInkAuth with the bootstrap path (no resolvers) and nonce handling
// deferred. Tests override fields from there.
func signedAuthRequest(t *testing.T, from string, signer kp, keyID string, mutate func(body map[string]interface{})) InkAuthInput {
	t.Helper()
	body := map[string]interface{}{
		"from":      from,
		"timestamp": authTestTimestamp,
		"nonce":     authTestNonce,
		"intent":    "ping",
	}
	if mutate != nil {
		mutate(body)
	}
	ts, _ := body["timestamp"].(string)
	_, header, err := SignInkRequest(InkSignInput{
		Method:       "POST",
		Path:         authTestPath,
		RecipientDid: authTestRecipient,
		Body:         body,
		Timestamp:    ts,
	}, signer.priv, keyID)
	if err != nil {
		t.Fatalf("SignInkRequest: %v", err)
	}
	return InkAuthInput{
		AuthHeader:         header,
		Method:             "POST",
		Path:               authTestPath,
		RecipientAgentID:   authTestRecipient,
		Body:               body,
		DeferNonceHandling: true,
		Now:                authTestClock,
	}
}

func expectAuthError(t *testing.T, r InkAuthResult, code string) {
	t.Helper()
	if r.Valid || r.Error != code {
		t.Fatalf("got %+v, want error %q", r, code)
	}
	if r.SenderAgentID != "" || r.Principal != "" || r.KeyID != "" || r.KeyStatus != "" {
		t.Fatalf("rejection carries attribution: %+v", r)
	}
}

// fakeNonceStore is a scripted has/add store; fakeAtomicNonceStore adds the
// optional atomic method.
type fakeNonceStore struct {
	seen     map[string]bool
	hasErr   error
	addErr   error
	hasCalls int
	addCalls int
	panicOn  string
}

func newFakeNonceStore() *fakeNonceStore { return &fakeNonceStore{seen: map[string]bool{}} }

func (s *fakeNonceStore) Has(nonce string) (bool, error) {
	s.hasCalls++
	if s.panicOn == "has" {
		panic("store down")
	}
	if s.hasErr != nil {
		return false, s.hasErr
	}
	return s.seen[nonce], nil
}

func (s *fakeNonceStore) Add(nonce string) error {
	s.addCalls++
	if s.panicOn == "add" {
		panic("store down")
	}
	if s.addErr != nil {
		return s.addErr
	}
	s.seen[nonce] = true
	return nil
}

type fakeAtomicNonceStore struct {
	fakeNonceStore
	aiaErr   error
	aiaCalls int
}

func (s *fakeAtomicNonceStore) AddIfAbsent(nonce string) (bool, error) {
	s.aiaCalls++
	if s.aiaErr != nil {
		return false, s.aiaErr
	}
	if s.seen[nonce] {
		return false, nil
	}
	s.seen[nonce] = true
	return true, nil
}

func TestVerifyInkAuthAcceptsSignedRequestOnBootstrapPath(t *testing.T) {
	k := fixedKeypair(t, 0x41)
	in := signedAuthRequest(t, deriveAgentID(k), k, "", nil)
	r := VerifyInkAuth(in)
	if !r.Valid || r.Error != "" {
		t.Fatalf("got %+v", r)
	}
	if r.SenderAgentID != deriveAgentID(k) {
		t.Fatalf("senderAgentId = %q", r.SenderAgentID)
	}
	if r.Principal != "key:"+k.multibase {
		t.Fatalf("principal = %q", r.Principal)
	}
	if r.KeyID != "" || r.KeyStatus != "" {
		t.Fatalf("bootstrap path attributed a key: %+v", r)
	}
}

func TestVerifyInkAuthUsesWallClockWhenNowIsNil(t *testing.T) {
	k := fixedKeypair(t, 0x42)
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	in := signedAuthRequest(t, deriveAgentID(k), k, "", func(b map[string]interface{}) { b["timestamp"] = ts })
	in.Now = nil
	if r := VerifyInkAuth(in); !r.Valid {
		t.Fatalf("got %+v", r)
	}
}

func TestVerifyInkAuthPrincipalIsPrefixIndependent(t *testing.T) {
	k := fixedKeypair(t, 0x43)
	a := VerifyInkAuth(signedAuthRequest(t, "tulpa:"+k.multibase, k, "", nil))
	b := VerifyInkAuth(signedAuthRequest(t, "ink:"+k.multibase, k, "", nil))
	if !a.Valid || !b.Valid {
		t.Fatalf("got %+v / %+v", a, b)
	}
	if a.Principal != b.Principal {
		t.Fatalf("principals differ: %q vs %q", a.Principal, b.Principal)
	}
	if a.SenderAgentID == b.SenderAgentID {
		t.Fatal("raw spelling collapsed")
	}
}

func TestVerifyInkAuthHeaderAndBodyShapeErrors(t *testing.T) {
	k := fixedKeypair(t, 0x44)
	from := deriveAgentID(k)
	cases := []struct {
		name string
		edit func(in *InkAuthInput)
		want string
	}{
		{"empty header", func(in *InkAuthInput) { in.AuthHeader = "" }, "missing_authorization"},
		{"wrong scheme", func(in *InkAuthInput) { in.AuthHeader = "Bearer " + in.AuthHeader[12:] }, "invalid_auth_scheme"},
		{"header with trailing junk", func(in *InkAuthInput) { in.AuthHeader += " x=y" }, "invalid_auth_scheme"},
		{"nil body", func(in *InkAuthInput) { in.Body = nil }, "missing_sender"},
		{"missing from", func(in *InkAuthInput) { delete(in.Body, "from") }, "missing_sender"},
		{"empty from", func(in *InkAuthInput) { in.Body["from"] = "" }, "missing_sender"},
		{"non-string from", func(in *InkAuthInput) { in.Body["from"] = 7 }, "invalid_from_field"},
		{"over-long from", func(in *InkAuthInput) { in.Body["from"] = "tulpa:" + strings.Repeat("z", 251) }, "invalid_from_field"},
		{"missing timestamp", func(in *InkAuthInput) { delete(in.Body, "timestamp") }, "missing_timestamp"},
		{"empty timestamp", func(in *InkAuthInput) { in.Body["timestamp"] = "" }, "missing_timestamp"},
		{"non-string timestamp", func(in *InkAuthInput) { in.Body["timestamp"] = 1783296000000 }, "missing_timestamp"},
		{"lenient timestamp", func(in *InkAuthInput) { in.Body["timestamp"] = "2026-06-11 00:00:00Z" }, "invalid_timestamp"},
		{"date-only timestamp", func(in *InkAuthInput) { in.Body["timestamp"] = "2026-06-11" }, "invalid_timestamp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedAuthRequest(t, from, k, "", nil)
			tc.edit(&in)
			expectAuthError(t, VerifyInkAuth(in), tc.want)
		})
	}
}

// The length caps on from and nonce are judged in UTF-16 code units like the
// reference, but a value far past the cap is rejected from its byte length
// alone, without transcoding an attacker-sized string first.
func TestUTF16LenExceedsBoundsWorkByByteLength(t *testing.T) {
	cases := []struct {
		name string
		s    string
		max  int
		want bool
	}{
		{"ascii at cap", strings.Repeat("a", 256), 256, false},
		{"ascii past cap", strings.Repeat("a", 257), 256, true},
		{"three-byte runes at cap", strings.Repeat("€", 256), 256, false},
		{"three-byte runes past cap", strings.Repeat("€", 257), 256, true},
		{"surrogate pairs at cap", strings.Repeat("\U0001F600", 128), 256, false},
		{"surrogate pairs past cap", strings.Repeat("\U0001F600", 129), 256, true},
		{"megabyte value", strings.Repeat("a", 1<<20), 256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := utf16LenExceeds(tc.s, tc.max); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyInkAuthRejectsOversizedFromAndNonceEarly(t *testing.T) {
	k := fixedKeypair(t, 0x56)
	huge := strings.Repeat("\U0001F600", 1<<18)
	in := signedAuthRequest(t, deriveAgentID(k), k, "", nil)
	in.Body["from"] = huge
	expectAuthError(t, VerifyInkAuth(in), "invalid_from_field")

	store := newFakeNonceStore()
	in = signedAuthRequest(t, deriveAgentID(k), k, "", nil)
	in.Body["nonce"] = huge
	in.DeferNonceHandling = false
	in.NonceStore = store
	expectAuthError(t, VerifyInkAuth(in), "missing_nonce")
	if store.hasCalls != 0 || store.addCalls != 0 {
		t.Fatal("store touched on an oversized nonce")
	}
}

// The shape checks run before any signature work, so the same codes come back
// for a request that was never signed at all.
func TestVerifyInkAuthShapeErrorsPrecedeSignatureWork(t *testing.T) {
	k := fixedKeypair(t, 0x45)
	in := signedAuthRequest(t, deriveAgentID(k), k, "", nil)
	in.AuthHeader = "INK-Ed25519 " + strings.Repeat("A", 86)
	delete(in.Body, "timestamp")
	expectAuthError(t, VerifyInkAuth(in), "missing_timestamp")
}

func TestVerifyInkAuthFreshnessWindow(t *testing.T) {
	k := fixedKeypair(t, 0x46)
	from := deriveAgentID(k)
	cases := []struct {
		name string
		ts   string
		want string
	}{
		{"exactly five minutes old", "2026-06-10T23:55:00.000Z", ""},
		{"one ms past five minutes", "2026-06-10T23:54:59.999Z", "timestamp_expired"},
		{"exactly thirty seconds ahead", "2026-06-11T00:00:30.000Z", ""},
		{"one ms past thirty seconds", "2026-06-11T00:00:30.001Z", "timestamp_too_far_future"},
		{"offset form inside window", "2026-06-11T01:00:00.000+01:00", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedAuthRequest(t, from, k, "", func(b map[string]interface{}) { b["timestamp"] = tc.ts })
			r := VerifyInkAuth(in)
			if tc.want == "" {
				if !r.Valid {
					t.Fatalf("got %+v", r)
				}
				return
			}
			expectAuthError(t, r, tc.want)
		})
	}
}

func TestVerifyInkAuthSignatureBinding(t *testing.T) {
	k := fixedKeypair(t, 0x47)
	other := fixedKeypair(t, 0x48)
	from := deriveAgentID(k)
	cases := []struct {
		name string
		edit func(in *InkAuthInput)
	}{
		{"signed by another key", func(in *InkAuthInput) {
			*in = signedAuthRequest(t, from, other, "", nil)
		}},
		{"tampered body", func(in *InkAuthInput) { in.Body["intent"] = "pong" }},
		{"tampered path", func(in *InkAuthInput) { in.Path = "/ink/v1/other" }},
		{"tampered method", func(in *InkAuthInput) { in.Method = "GET" }},
		{"tampered recipient", func(in *InkAuthInput) { in.RecipientAgentID = "tulpa:" + other.multibase }},
		{"path with CRLF", func(in *InkAuthInput) { in.Path = "/ink\n/v1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedAuthRequest(t, from, k, "", nil)
			tc.edit(&in)
			expectAuthError(t, VerifyInkAuth(in), "invalid_signature")
		})
	}
}

func TestVerifyInkAuthUnresolvableSender(t *testing.T) {
	k := fixedKeypair(t, 0x49)
	in := signedAuthRequest(t, "did:web:example.com", k, "", nil)
	expectAuthError(t, VerifyInkAuth(in), "unresolvable_sender_key")
	in = signedAuthRequest(t, "tulpa:not-a-multibase", k, "", nil)
	expectAuthError(t, VerifyInkAuth(in), "unresolvable_sender_key")
}

func TestVerifyInkAuthResolvePublicKeyPrecedesBootstrap(t *testing.T) {
	identity := fixedKeypair(t, 0x4a)
	signer := fixedKeypair(t, 0x4b)
	from := deriveAgentID(identity)

	in := signedAuthRequest(t, from, signer, "", nil)
	in.ResolvePublicKey = func(agentID string) []byte {
		if agentID != from {
			t.Fatalf("resolver asked for %q", agentID)
		}
		return signer.pub
	}
	if r := VerifyInkAuth(in); !r.Valid || r.Principal != "key:"+identity.multibase {
		t.Fatalf("got %+v", r)
	}

	// A resolver with no record falls through to the key embedded in the id.
	in = signedAuthRequest(t, from, identity, "", nil)
	in.ResolvePublicKey = func(string) []byte { return nil }
	if r := VerifyInkAuth(in); !r.Valid {
		t.Fatalf("got %+v", r)
	}

	// A resolved key that does not verify is invalid_signature, never a
	// fallback to the bootstrap key.
	in = signedAuthRequest(t, from, identity, "", nil)
	in.ResolvePublicKey = func(string) []byte { return signer.pub }
	expectAuthError(t, VerifyInkAuth(in), "invalid_signature")
}

func TestVerifyInkAuthNoncePolicyFailsClosed(t *testing.T) {
	k := fixedKeypair(t, 0x4c)
	in := signedAuthRequest(t, deriveAgentID(k), k, "", nil)
	in.DeferNonceHandling = false
	expectAuthError(t, VerifyInkAuth(in), "nonce_handling_required")

	in = signedAuthRequest(t, deriveAgentID(k), k, "", func(b map[string]interface{}) { delete(b, "nonce") })
	if r := VerifyInkAuth(in); !r.Valid {
		t.Fatalf("deferred handling rejected a request without a nonce: %+v", r)
	}
}

func TestVerifyInkAuthNonceShapeWithStore(t *testing.T) {
	k := fixedKeypair(t, 0x4d)
	from := deriveAgentID(k)
	cases := []struct {
		name  string
		nonce interface{}
		del   bool
	}{
		{"missing", nil, true},
		{"non-string", 42, false},
		{"fifteen chars", strings.Repeat("a", 15), false},
		{"257 chars", strings.Repeat("a", 257), false},
		{"bad charset", "nonce-0123456789abcde!", false},
		{"embedded space", "nonce 0123456789abcdef", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedAuthRequest(t, from, k, "", func(b map[string]interface{}) {
				if tc.del {
					delete(b, "nonce")
				} else {
					b["nonce"] = tc.nonce
				}
			})
			store := newFakeNonceStore()
			in.DeferNonceHandling = false
			in.NonceStore = store
			expectAuthError(t, VerifyInkAuth(in), "missing_nonce")
			if store.hasCalls != 0 || store.addCalls != 0 {
				t.Fatalf("store touched on a malformed nonce")
			}
		})
	}
	for _, n := range []string{strings.Repeat("a", 16), strings.Repeat("_-", 128)} {
		in := signedAuthRequest(t, from, k, "", func(b map[string]interface{}) { b["nonce"] = n })
		in.DeferNonceHandling = false
		in.NonceStore = newFakeNonceStore()
		if r := VerifyInkAuth(in); !r.Valid {
			t.Fatalf("boundary nonce of %d chars rejected: %+v", len(n), r)
		}
	}
}

func TestVerifyInkAuthReplayRejectedAndForgeryNeverRecorded(t *testing.T) {
	k := fixedKeypair(t, 0x4e)
	other := fixedKeypair(t, 0x4f)
	from := deriveAgentID(k)
	store := newFakeNonceStore()

	in := signedAuthRequest(t, from, k, "", nil)
	in.DeferNonceHandling = false
	in.NonceStore = store
	if r := VerifyInkAuth(in); !r.Valid {
		t.Fatalf("first presentation rejected: %+v", r)
	}
	if !store.seen[authTestNonce] {
		t.Fatal("nonce not recorded after a verified request")
	}
	expectAuthError(t, VerifyInkAuth(in), "nonce_replay")

	forged := signedAuthRequest(t, from, other, "", func(b map[string]interface{}) { b["nonce"] = "forged-0123456789abcdef" })
	forged.DeferNonceHandling = false
	forged.NonceStore = store
	expectAuthError(t, VerifyInkAuth(forged), "invalid_signature")
	if store.seen["forged-0123456789abcdef"] || store.addCalls != 1 || store.hasCalls != 2 {
		t.Fatalf("forged request touched the store: %+v", store)
	}
}

func TestVerifyInkAuthNonceStoreErrorsFailClosed(t *testing.T) {
	k := fixedKeypair(t, 0x50)
	from := deriveAgentID(k)
	boom := errors.New("backend down")
	cases := []struct {
		name  string
		store NonceStore
	}{
		{"has error", &fakeNonceStore{seen: map[string]bool{}, hasErr: boom}},
		{"add error", &fakeNonceStore{seen: map[string]bool{}, addErr: boom}},
		{"has panic", &fakeNonceStore{seen: map[string]bool{}, panicOn: "has"}},
		{"add panic", &fakeNonceStore{seen: map[string]bool{}, panicOn: "add"}},
		{"addIfAbsent error", &fakeAtomicNonceStore{fakeNonceStore: fakeNonceStore{seen: map[string]bool{}}, aiaErr: boom}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedAuthRequest(t, from, k, "", nil)
			in.DeferNonceHandling = false
			in.NonceStore = tc.store
			expectAuthError(t, VerifyInkAuth(in), "nonce_store_error")
		})
	}
}

func TestVerifyInkAuthPrefersAtomicAddIfAbsent(t *testing.T) {
	k := fixedKeypair(t, 0x51)
	from := deriveAgentID(k)
	store := &fakeAtomicNonceStore{fakeNonceStore: fakeNonceStore{seen: map[string]bool{}}}
	in := signedAuthRequest(t, from, k, "", nil)
	in.DeferNonceHandling = false
	in.NonceStore = store
	if r := VerifyInkAuth(in); !r.Valid {
		t.Fatalf("got %+v", r)
	}
	expectAuthError(t, VerifyInkAuth(in), "nonce_replay")
	if store.aiaCalls != 2 || store.hasCalls != 0 || store.addCalls != 0 {
		t.Fatalf("atomic store not used exclusively: aia=%d has=%d add=%d", store.aiaCalls, store.hasCalls, store.addCalls)
	}
}

func TestVerifyInkAuthKeySetIsAuthoritative(t *testing.T) {
	k := fixedKeypair(t, 0x52)
	rotated := fixedKeypair(t, 0x53)
	from := deriveAgentID(k)
	active := func(id string, key kp, status string) CandidateKey {
		return CandidateKey{KeyID: id, PublicKey: key.pub, Status: status, ValidFrom: Timestamp(testValidFrom)}
	}

	t.Run("published empty set rejects even the bootstrap key", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) { return []CandidateKey{}, true }
		in.ResolvePublicKey = func(string) []byte { t.Fatal("fell through to the single-key resolver"); return nil }
		expectAuthError(t, VerifyInkAuth(in), "signature_verification_failed")
	})

	t.Run("rotated set rejects the bootstrap key with no fallback", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) {
			return []CandidateKey{active("k2", rotated, "active")}, true
		}
		in.ResolvePublicKey = func(string) []byte { t.Fatal("fell through to the single-key resolver"); return nil }
		expectAuthError(t, VerifyInkAuth(in), "signature_verification_failed")
	})

	t.Run("verified entry is attributed", func(t *testing.T) {
		in := signedAuthRequest(t, from, rotated, "k2", nil)
		in.ResolveKeySet = func(agentID string) ([]CandidateKey, bool) {
			if agentID != from {
				t.Fatalf("resolver asked for %q", agentID)
			}
			return []CandidateKey{active("k1", k, "retired"), active("k2", rotated, "active")}, true
		}
		r := VerifyInkAuth(in)
		if !r.Valid || r.KeyID != "k2" || r.KeyStatus != "active" || r.Principal != "key:"+k.multibase {
			t.Fatalf("got %+v", r)
		}
	})

	t.Run("hint names the entry that verified", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "k1", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) {
			return []CandidateKey{active("k1", k, "active"), active("k2", rotated, "active")}, true
		}
		if r := VerifyInkAuth(in); !r.Valid || r.KeyID != "k1" {
			t.Fatalf("got %+v", r)
		}
	})

	t.Run("retired-only verification is refused by default", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) {
			return []CandidateKey{active("k1", k, "retired"), active("k2", rotated, "active")}, true
		}
		expectAuthError(t, VerifyInkAuth(in), "retired_key_for_live_auth")
		in.AllowRetiredKey = true
		if r := VerifyInkAuth(in); !r.Valid || r.KeyID != "k1" || r.KeyStatus != "retired" {
			t.Fatalf("grace window: got %+v", r)
		}
	})

	t.Run("revoked entry never verifies", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) {
			e := active("k1", k, "revoked")
			e.RevokedAt = Timestamp(testValidFrom)
			return []CandidateKey{e}, true
		}
		expectAuthError(t, VerifyInkAuth(in), "signature_verification_failed")
	})

	t.Run("retired refusal is not a nonce record", func(t *testing.T) {
		store := newFakeNonceStore()
		in := signedAuthRequest(t, from, k, "", nil)
		in.DeferNonceHandling = false
		in.NonceStore = store
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) {
			return []CandidateKey{active("k1", k, "retired")}, true
		}
		expectAuthError(t, VerifyInkAuth(in), "retired_key_for_live_auth")
		if store.addCalls != 0 || store.hasCalls != 0 {
			t.Fatal("store touched on a refused key")
		}
	})

	t.Run("unpublished set falls through to bootstrap", func(t *testing.T) {
		in := signedAuthRequest(t, from, k, "", nil)
		in.ResolveKeySet = func(string) ([]CandidateKey, bool) { return nil, false }
		if r := VerifyInkAuth(in); !r.Valid || r.KeyID != "" {
			t.Fatalf("got %+v", r)
		}
	})
}

func TestMemoryNonceStoreSingleUseAndEviction(t *testing.T) {
	s := NewMemoryNonceStore(10)
	if s.capacity != 64 {
		t.Fatalf("capacity floor not applied: %d", s.capacity)
	}
	ok, err := s.AddIfAbsent("n1")
	if err != nil || !ok {
		t.Fatalf("first add: %v %v", ok, err)
	}
	ok, err = s.AddIfAbsent("n1")
	if err != nil || ok {
		t.Fatalf("second add: %v %v", ok, err)
	}
	has, err := s.Has("n1")
	if err != nil || !has {
		t.Fatalf("has: %v %v", has, err)
	}
	if err := s.Add("n1"); err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	for i := 0; i < 64; i++ {
		if err := s.Add(fmt.Sprintf("fill-%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if has, _ := s.Has("n1"); has {
		t.Fatal("oldest entry survived past capacity")
	}
	if s.Len() != 64 {
		t.Fatalf("len = %d", s.Len())
	}
}

func TestMemoryNonceStoreAddIfAbsentIsAtomic(t *testing.T) {
	s := NewMemoryNonceStore(1024)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.AddIfAbsent("shared-nonce-0123456789")
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines recorded one nonce", wins)
	}
}
