package witnessserver

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Ad-Astra-Computing/ink/go/ink"
	"github.com/Ad-Astra-Computing/ink/go/internal/witnessstore"
)

// durableConfig fills a Config for a durable server rooted at dataDir, reusing
// the shared test key, origin, serviceDid and fixed clock so a receipt or
// checkpoint is deterministic across a restart.
func durableConfig(t *testing.T, dataDir string) Config {
	t.Helper()
	priv, _ := testKey(t)
	return Config{
		Origin:               testOrigin,
		PrivateKey:           priv,
		ServiceDid:           testServiceDid,
		AllowUnauthenticated: true,
		Now:                  fixedClock(),
		DataDir:              dataDir,
	}
}

// newDurable builds a durable server and returns its handler, closer and the
// witness public key. The caller closes the returned closer to release the
// record file before restarting.
func newDurable(t *testing.T, cfg Config) (http.Handler, closerFunc, ed25519.PublicKey) {
	t.Helper()
	_, pub := testKey(t)
	h, closer, err := NewWithCloser(cfg)
	if err != nil {
		t.Fatalf("NewWithCloser: %v", err)
	}
	return h, func() { _ = closer.Close() }, pub
}

type closerFunc func()

// submitAllow submits event i to a server that runs with unauthenticated submit.
func submitAllow(t *testing.T, h http.Handler, i int) ink.InclusionReceipt {
	t.Helper()
	raw, _ := event(i)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(string(raw)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit %d status %d (%s)", i, rec.Code, rec.Body.String())
	}
	var r ink.InclusionReceipt
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode receipt %d: %v", i, err)
	}
	return r
}

// TestDurableRestartContinuity submits events, drops the server, restarts it
// against the same data dir, and checks that the restarted log rebuilds the same
// root at the old size, that an old receipt still verifies against a fresh
// checkpoint via a consistency proof, and that new submissions continue the same
// tree from the recovered size.
func TestDurableRestartContinuity(t *testing.T) {
	dir := t.TempDir()

	h1, close1, pub := newDurable(t, durableConfig(t, dir))
	const preRestart = 3
	receipts := make([]ink.InclusionReceipt, preRestart)
	for i := 0; i < preRestart; i++ {
		receipts[i] = submitAllow(t, h1, i)
	}
	before := checkpoint(t, h1, pub)
	if before.TreeSize != preRestart {
		t.Fatalf("pre-restart size = %d, want %d", before.TreeSize, preRestart)
	}
	close1()

	// Restart against the same data dir: the record file is replayed.
	h2, close2, _ := newDurable(t, durableConfig(t, dir))
	defer close2()

	after := checkpoint(t, h2, pub)
	if after.TreeSize != before.TreeSize {
		t.Fatalf("restarted size = %d, want %d", after.TreeSize, before.TreeSize)
	}
	if after.RootHash != before.RootHash {
		t.Fatalf("restarted root = %q, want %q (rebuild must be byte-identical)", after.RootHash, before.RootHash)
	}

	// Each pre-restart receipt still verifies against the restarted checkpoint of
	// the same size, so an old receipt is honoured after recovery.
	for i, r := range receipts {
		_, ev := event(i)
		if !ink.VerifyInclusionReceipt(r, pub, ink.ReceiptVerifyOptions{Event: ev}) {
			t.Errorf("pre-restart receipt %d did not verify after restart", i)
		}
	}

	// New submissions continue the same tree from the recovered size, and a
	// consistency proof binds the old head to the new one.
	for i := preRestart; i < preRestart+2; i++ {
		r := submitAllow(t, h2, i)
		if r.LeafIndex != i {
			t.Errorf("post-restart submit %d got leafIndex %d, want %d (tree did not continue)", i, r.LeafIndex, i)
		}
	}
	grown := checkpoint(t, h2, pub)

	rec, res := do(h2, http.MethodGet, "/consistency?first="+itoa(after.TreeSize)+"&second="+itoa(grown.TreeSize), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("consistency status %d (%s)", rec.Code, rec.Body.String())
	}
	proof := toStrings(res["proof"])
	if !ink.VerifyConsistencyProof(int(after.TreeSize), after.RootHash, int(grown.TreeSize), grown.RootHash, proof) {
		t.Error("consistency proof from the recovered head to the grown head did not verify")
	}
}

// TestDurableTornFinalLineDiscardedThenContinues writes a torn final record onto
// a real record file after a clean submission, then restarts: the torn tail is
// dropped, the recovered tree is the one good leaf, and new submissions continue.
func TestDurableTornFinalLineDiscardedThenContinues(t *testing.T) {
	dir := t.TempDir()

	h1, close1, pub := newDurable(t, durableConfig(t, dir))
	submitAllow(t, h1, 0)
	before := checkpoint(t, h1, pub)
	close1()

	// Append a torn final record: a valid-looking line with no trailing newline,
	// exactly what a crash between write and fsync would leave.
	path := filepath.Join(dir, recordFileName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open record file: %v", err)
	}
	if _, err := f.WriteString(`{"v":1,"event":"eyJpZCI6InRvcm4ifQ==","timestamp":"ts-torn"`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	_ = f.Close()

	h2, close2, _ := newDurable(t, durableConfig(t, dir))

	after := checkpoint(t, h2, pub)
	if after.TreeSize != before.TreeSize || after.RootHash != before.RootHash {
		t.Fatalf("after torn recovery size/root = %d/%q, want %d/%q (torn tail must be discarded)", after.TreeSize, after.RootHash, before.TreeSize, before.RootHash)
	}
	// Submissions continue from the recovered size.
	r := submitAllow(t, h2, 1)
	if r.LeafIndex != 1 {
		t.Errorf("post-recovery submit leafIndex = %d, want 1", r.LeafIndex)
	}
	grown := checkpoint(t, h2, pub)
	close2()

	// A second restart must still replay cleanly: the torn bytes were physically
	// truncated at the first recovery, so the post-recovery record is not glued to
	// them into a corrupt line. The tree must come back at the grown size.
	h3, close3, _ := newDurable(t, durableConfig(t, dir))
	defer close3()
	replayed := checkpoint(t, h3, pub)
	if replayed.TreeSize != grown.TreeSize || replayed.RootHash != grown.RootHash {
		t.Fatalf("second restart size/root = %d/%q, want %d/%q (torn tail must be truncated, not left glued to the next record)", replayed.TreeSize, replayed.RootHash, grown.TreeSize, grown.RootHash)
	}
}

// TestDurableCorruptMiddleLineRefusesStart writes a corrupt record before the
// final line and asserts the server refuses to start with ErrCorruptLog.
func TestDurableCorruptMiddleLineRefusesStart(t *testing.T) {
	dir := t.TempDir()

	h1, close1, _ := newDurable(t, durableConfig(t, dir))
	submitAllow(t, h1, 0)
	submitAllow(t, h1, 1)
	close1()

	// Rewrite the record file with a corrupt middle line between two good ones.
	path := filepath.Join(dir, recordFileName)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	lines := strings.SplitAfter(string(orig), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least two records, got %q", orig)
	}
	corrupt := lines[0] + `{not json}` + "\n" + lines[1]
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, closer, err := NewWithCloser(durableConfig(t, dir))
	if closer != nil {
		_ = closer.Close()
	}
	if !errors.Is(err, witnessstore.ErrCorruptLog) {
		t.Fatalf("start with a corrupt middle line err = %v, want ErrCorruptLog", err)
	}
}

// TestDurableSyncBeforeReceipt asserts, through the injectable sync hook, that
// the record's fsync completes before the receipt is signed and returned: when
// the hook runs the record bytes are already on disk, and if the hook fails the
// submission fails closed and does not grow the durable tree.
func TestDurableSyncBeforeReceipt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, recordFileName)

	synced := 0
	cfg := durableConfig(t, dir)
	cfg.syncForTest = func() error {
		// When the sync hook runs the whole record line is already written; the
		// receipt is only signed after Append (hence this hook) returns.
		b, _ := os.ReadFile(path)
		if len(b) == 0 {
			t.Error("sync hook ran before the record was written")
		}
		synced++
		return nil
	}
	h, closer, err := NewWithCloser(cfg)
	if err != nil {
		t.Fatalf("NewWithCloser: %v", err)
	}
	defer closer.Close()

	submitAllow(t, h, 0)
	if synced != 1 {
		t.Errorf("sync hook ran %d times, want 1 (one fsync per accepted leaf)", synced)
	}

	// A failing fsync must fail the submission closed: the in-memory tree is rolled
	// back and does not grow, so no receipt is issued for a leaf the fsync could not
	// confirm durable.
	pub := mustPub(t)
	cfg2 := durableConfig(t, dir)
	cfg2.syncForTest = func() error { return errors.New("disk full") }
	h2, closer2, err := NewWithCloser(cfg2)
	if err != nil {
		t.Fatalf("NewWithCloser (fail): %v", err)
	}
	defer closer2.Close()

	before := checkpoint(t, h2, pub)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(`{"id":"never-durable"}`))
	h2.ServeHTTP(rec, req)
	// A durability failure is a server-side storage error, not client bad input.
	// The always-failing sync also fails the rollback fsync, poisoning the store,
	// so the mapped status is 503.
	if rec.Code < 500 {
		t.Fatalf("submit with a failing fsync got status %d; want a 5xx storage error", rec.Code)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("poisoned-store submit status = %d, want 503", rec.Code)
	}
	after := checkpoint(t, h2, pub)
	if after.TreeSize != before.TreeSize || after.RootHash != before.RootHash {
		t.Errorf("failed fsync grew the tree from %d/%q to %d/%q; want no growth (fail closed)", before.TreeSize, before.RootHash, after.TreeSize, after.RootHash)
	}
}

// TestDurableStorageFailureMapsTo500 asserts that a durability failure whose
// rollback succeeds (so the store is not poisoned) maps to a 500, distinguishing
// a storage outage from client bad input, and that the tree does not grow.
func TestDurableStorageFailureMapsTo500(t *testing.T) {
	dir := t.TempDir()
	pub := mustPub(t)
	cfg := durableConfig(t, dir)
	// The record fsync fails once; the following rollback fsync succeeds, so the
	// store is not poisoned and the mapped status is 500, not 503.
	failNext := false
	cfg.syncForTest = func() error {
		if failNext {
			failNext = false
			return errors.New("disk full")
		}
		return nil
	}
	h, closer, err := NewWithCloser(cfg)
	if err != nil {
		t.Fatalf("NewWithCloser: %v", err)
	}
	defer closer.Close()

	before := checkpoint(t, h, pub)
	failNext = true
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(`{"id":"transient"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("transient storage failure status = %d, want 500", rec.Code)
	}
	after := checkpoint(t, h, pub)
	if after.TreeSize != before.TreeSize {
		t.Errorf("storage failure grew the tree from %d to %d", before.TreeSize, after.TreeSize)
	}
	// After a clean rollback the store keeps serving: a later good submit succeeds.
	if r := submitAllow(t, h, 0); r.LeafIndex != int(before.TreeSize) {
		t.Errorf("post-failure submit leafIndex = %d, want %d", r.LeafIndex, int(before.TreeSize))
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
