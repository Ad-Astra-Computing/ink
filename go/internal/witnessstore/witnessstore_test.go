package witnessstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// collected replays a store file into an ordered list of (event,timestamp) pairs.
func collected(t *testing.T, path string) [][2]string {
	t.Helper()
	var got [][2]string
	if err := Replay(path, func(raw []byte, ts string) error {
		got = append(got, [2]string{string(raw), ts})
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

func TestAppendThenReplayRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := [][2]string{
		{`{"id":"evt-0"}`, "2026-07-09T00:00:00.000Z"},
		{`{"id":"evt-1","note":"café"}`, "2026-07-09T00:00:01.000Z"},
	}
	for _, w := range want {
		if err := s.Append([]byte(w[0]), w[1]); err != nil {
			t.Fatalf("Append %q: %v", w[0], err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := collected(t, path)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("replay = %v, want %v", got, want)
	}
}

// TestOpenTruncatesTornTail pins that Open physically removes a torn final record
// (a trailing chunk with no newline) so a record appended afterwards is not glued
// to the torn bytes into one corrupt line the next replay would reject.
func TestOpenTruncatesTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	good := mustJSON(t, record{V: recordVersion, Event: base64.StdEncoding.EncodeToString([]byte(`{"id":"evt-0"}`)), Timestamp: "ts0"})
	// One complete record followed by a torn tail with no newline.
	torn := good + "\n" + `{"v":1,"event":"partial`
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Append([]byte(`{"id":"evt-1"}`), "ts1"); err != nil {
		t.Fatalf("Append after recovery: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay must see exactly the good record and the appended one, with no corrupt
	// line formed from the torn bytes.
	got := collected(t, path)
	want := [][2]string{{`{"id":"evt-0"}`, "ts0"}, {`{"id":"evt-1"}`, "ts1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("replay after torn-tail recovery = %v, want %v", got, want)
	}
}

// TestOpenLeavesCleanFileUntouched pins that Open does not alter a file that
// already ends in a newline: no spurious truncation of a clean log.
func TestOpenLeavesCleanFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Append([]byte(`{"id":"a"}`), "ts0"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	before, _ := os.ReadFile(path)

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("Open altered a clean file: before %q after %q", before, after)
	}
}

func TestReplayMissingFileIsEmpty(t *testing.T) {
	got := collected(t, filepath.Join(t.TempDir(), "does-not-exist"))
	if len(got) != 0 {
		t.Errorf("missing file replayed %d records, want 0", len(got))
	}
}

func TestAppendFsyncsBeforeReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	synced := false
	s.SetSyncForTest(func() error {
		// When the injected sync runs, the record bytes are already written; the
		// return of Append after this proves the fsync happened before the caller
		// could sign a receipt.
		b, _ := os.ReadFile(path)
		if len(b) == 0 {
			t.Error("fsync ran before the record was written")
		}
		synced = true
		return nil
	})
	if err := s.Append([]byte(`{"id":"e"}`), "ts"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !synced {
		t.Error("Append returned without calling fsync")
	}
}

func TestAppendFsyncFailurePropagates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.SetSyncForTest(func() error { return errors.New("disk full") })
	if err := s.Append([]byte(`{"id":"e"}`), "ts"); err == nil {
		t.Fatal("Append with a failing fsync returned nil")
	}
}

// TestAppendFsyncFailureLeavesNoBytes pins that a failed record fsync is rolled
// back on disk, not just reported: when the record fsync fails but the rollback
// truncation and its fsync succeed, the failed record leaves no bytes and later
// appends continue cleanly. Without the truncate, the newline-terminated record
// would remain in the file and a later replay would resurrect a submission that
// failed closed and never got a receipt.
func TestAppendFsyncFailureLeavesNoBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The injected sync fails exactly once, on the record fsync of the second
	// append; the rollback fsync that follows succeeds, so the rollback is durable
	// and the store is not poisoned.
	failNext := false
	s.SetSyncForTest(func() error {
		if failNext {
			failNext = false
			return errors.New("disk full")
		}
		return nil
	})
	if err := s.Append([]byte(`{"id":"good"}`), "ts0"); err != nil {
		t.Fatalf("Append good: %v", err)
	}
	failNext = true
	if err := s.Append([]byte(`{"id":"lost"}`), "ts1"); err == nil {
		t.Fatal("Append with a failing fsync returned nil")
	}
	// A subsequent append must follow directly after the good record, with no
	// orphaned "lost" record between them.
	if err := s.Append([]byte(`{"id":"next"}`), "ts2"); err != nil {
		t.Fatalf("Append next: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := collected(t, path)
	want := [][2]string{{`{"id":"good"}`, "ts0"}, {`{"id":"next"}`, "ts2"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("replay after a rolled-back append = %v, want %v (the failed record must leave no bytes)", got, want)
	}
}

// TestAppendPoisonsStoreWhenRollbackUndurable pins that if the record fsync and
// the rollback fsync both fail, the store poisons itself and refuses every later
// append, so no receipt can be issued against a file whose rollback a crash might
// not have persisted.
func TestAppendPoisonsStoreWhenRollbackUndurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Append([]byte(`{"id":"good"}`), "ts0"); err != nil {
		t.Fatalf("Append good: %v", err)
	}
	// Every sync now fails, so the record fsync fails and the rollback fsync also
	// fails, leaving the on-disk state unknown.
	s.SetSyncForTest(func() error { return errors.New("disk full") })
	if err := s.Append([]byte(`{"id":"lost"}`), "ts1"); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("undurable rollback err = %v, want ErrStorePoisoned", err)
	}
	// Even with sync restored, the poisoned store refuses further appends.
	s.SetSyncForTest(func() error { return nil })
	if err := s.Append([]byte(`{"id":"after"}`), "ts2"); !errors.Is(err, ErrStorePoisoned) {
		t.Errorf("post-poison append err = %v, want ErrStorePoisoned", err)
	}
}

// TestReplayDiscardsTornFinalLine covers the only tail replay discards now that
// Append truncates a failed record away: a trailing chunk with no newline. The
// newline is the commit marker, so an unterminated tail was never committed and
// replay discards it, keeping the preceding complete records.
func TestReplayDiscardsTornFinalLine(t *testing.T) {
	good := record{V: recordVersion, Event: base64.StdEncoding.EncodeToString([]byte(`{"id":"evt-0"}`)), Timestamp: "ts0"}
	goodLine := mustJSON(t, good) + "\n"

	cases := map[string]string{
		"no trailing newline": goodLine + `{"v":1,"event":"` + base64.StdEncoding.EncodeToString([]byte(`{"id":"evt-1"}`)) + `","timestamp":"ts1"`,
		"partial json no nl":  goodLine + `{"v":1,"eve`,
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		got := collected(t, path)
		// Only the first complete record survives; the torn tail is dropped.
		if len(got) != 1 || got[0][1] != "ts0" {
			t.Errorf("%s: replay = %v, want the one good record only", name, got)
		}
	}
}

// TestReplayRefusesMalformedRecord fails closed on a newline-terminated record
// that fails to decode, wherever it sits, including as the last record. Append
// never leaves a newline-terminated record it did not fully write, so such a
// record is a complete record that came out corrupt: dropping it could silently
// discard a real leaf, so replay refuses to start instead.
func TestReplayRefusesMalformedRecord(t *testing.T) {
	good0 := mustJSON(t, record{V: recordVersion, Event: base64.StdEncoding.EncodeToString([]byte(`{"id":"evt-0"}`)), Timestamp: "ts0"})
	good1 := mustJSON(t, record{V: recordVersion, Event: base64.StdEncoding.EncodeToString([]byte(`{"id":"evt-1"}`)), Timestamp: "ts1"})

	cases := map[string]string{
		"invalid json middle":   good0 + "\n" + `{not json}` + "\n" + good1 + "\n",
		"bad base64 middle":     good0 + "\n" + `{"v":1,"event":"!!!","timestamp":"x"}` + "\n" + good1 + "\n",
		"wrong version middle":  good0 + "\n" + `{"v":2,"event":"","timestamp":"x"}` + "\n" + good1 + "\n",
		"invalid json final":    good0 + "\n" + `{not json}` + "\n",
		"bad base64 final":      good0 + "\n" + `{"v":1,"event":"!!!not-base64!!!","timestamp":"ts1"}` + "\n",
		"empty timestamp final": good0 + "\n" + `{"v":1,"event":"","timestamp":""}` + "\n",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		err := Replay(path, func(raw []byte, ts string) error { return nil })
		if !errors.Is(err, ErrCorruptLog) {
			t.Errorf("%s: Replay err = %v, want ErrCorruptLog", name, err)
		}
	}
}

func TestReplayPropagatesApplyError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Append([]byte(`{"id":"e0"}`), "ts0"); err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]byte(`{"id":"e1"}`), "ts1"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// An apply error on a non-final record (for example a capacity refusal during
	// rebuild) is fatal and fail-closed.
	err = Replay(path, func(raw []byte, ts string) error {
		return errors.New("capacity")
	})
	if !errors.Is(err, ErrCorruptLog) {
		t.Errorf("apply error err = %v, want ErrCorruptLog", err)
	}
}

func mustJSON(t *testing.T, r record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
