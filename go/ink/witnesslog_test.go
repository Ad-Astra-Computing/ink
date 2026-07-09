package ink

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

const testLogOrigin = "example.com/ink-log"
const testLogTimestamp = "2026-07-09T00:00:00.000Z"

// makeEvent returns a raw audit event and its parsed form. Fields are strings so
// the parsed map matches the JSON round-trip exactly for leaf-hash comparisons.
func makeEvent(i int) ([]byte, map[string]interface{}) {
	m := map[string]interface{}{
		"id":   fmt.Sprintf("evt-%d", i),
		"type": "connection_request",
		"note": fmt.Sprintf("note-%d", i),
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		panic(err)
	}
	return b, parsed
}

func newTestLog(t *testing.T) (*WitnessLog, []byte) {
	t.Helper()
	priv, pub := conformanceWitnessKey()
	log, err := NewWitnessLog(testLogOrigin, priv)
	if err != nil {
		t.Fatalf("NewWitnessLog: %v", err)
	}
	return log, pub
}

func TestWitnessLogSubmitSequencingAndReceipts(t *testing.T) {
	log, pub := newTestLog(t)
	const n = 6
	for i := 0; i < n; i++ {
		raw, event := makeEvent(i)
		r, err := log.Submit(raw, testLogTimestamp)
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if r.LeafIndex != i {
			t.Errorf("submit %d: LeafIndex = %d, want %d", i, r.LeafIndex, i)
		}
		if r.TreeSize != i+1 {
			t.Errorf("submit %d: TreeSize = %d, want %d", i, r.TreeSize, i+1)
		}
		if r.EventID != event["id"] {
			t.Errorf("submit %d: EventID = %q, want %q", i, r.EventID, event["id"])
		}
		// The receipt binds the event, recomputes its leaf, walks the proof to the
		// signed root, and checks the witness signature.
		if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{Event: event}) {
			t.Errorf("submit %d: receipt did not verify", i)
		}
	}
	if got := log.Size(); got != n {
		t.Errorf("Size = %d, want %d", got, n)
	}
}

func TestWitnessLogCheckpointRoundTrip(t *testing.T) {
	log, pub := newTestLog(t)
	// The empty log has a verifiable checkpoint at the empty-tree root.
	signed, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("empty checkpoint: %v", err)
	}
	if data, ok := VerifyCheckpoint(signed, pub, testLogOrigin); !ok || data.TreeSize != 0 {
		t.Errorf("empty checkpoint did not verify at size 0: ok=%v data=%+v", ok, data)
	}
	for i := 0; i < 4; i++ {
		raw, _ := makeEvent(i)
		if _, err := log.Submit(raw, testLogTimestamp); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	signed, err = log.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	data, ok := VerifyCheckpoint(signed, pub, testLogOrigin)
	if !ok {
		t.Fatal("checkpoint did not verify")
	}
	if int(data.TreeSize) != log.Size() {
		t.Errorf("checkpoint treeSize = %d, want %d", data.TreeSize, log.Size())
	}
}

func TestWitnessLogInclusionProofAgainstCheckpoint(t *testing.T) {
	log, pub := newTestLog(t)
	const n = 5
	events := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		raw, event := makeEvent(i)
		events[i] = event
		if _, err := log.Submit(raw, testLogTimestamp); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	signed, err := log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	cp, ok := VerifyCheckpoint(signed, pub, testLogOrigin)
	if !ok {
		t.Fatal("checkpoint did not verify")
	}
	for i := 0; i < n; i++ {
		proof, size, err := log.InclusionProof(i)
		if err != nil {
			t.Fatalf("inclusion proof %d: %v", i, err)
		}
		if size != int(cp.TreeSize) {
			t.Errorf("proof %d: size %d, want %d", i, size, cp.TreeSize)
		}
		leaf, ok := ComputeAuditMerkleLeafHash(events[i])
		if !ok {
			t.Fatalf("leaf hash %d failed", i)
		}
		if !VerifyInclusionProof(leaf, proof, i, size, cp.RootHash) {
			t.Errorf("leaf %d did not verify against the checkpoint root", i)
		}
	}
	if _, _, err := log.InclusionProof(n); err == nil {
		t.Error("out-of-range inclusion proof accepted")
	}
}

func TestWitnessLogConsistencyBetweenCheckpoints(t *testing.T) {
	log, pub := newTestLog(t)
	submit := func(from, to int) {
		for i := from; i < to; i++ {
			raw, _ := makeEvent(i)
			if _, err := log.Submit(raw, testLogTimestamp); err != nil {
				t.Fatalf("submit %d: %v", i, err)
			}
		}
	}
	checkpointRoot := func() (int, string) {
		signed, err := log.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		data, ok := VerifyCheckpoint(signed, pub, testLogOrigin)
		if !ok {
			t.Fatal("checkpoint did not verify")
		}
		return int(data.TreeSize), data.RootHash
	}

	submit(0, 3)
	first, firstRoot := checkpointRoot()
	submit(3, 8)
	second, secondRoot := checkpointRoot()

	proof, err := log.ConsistencyProof(first, second)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if !VerifyConsistencyProof(first, firstRoot, second, secondRoot, proof) {
		t.Errorf("consistency proof %d->%d did not verify", first, second)
	}
}

func TestWitnessLogRejects(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	if _, err := NewWitnessLog("", priv); err == nil {
		t.Error("empty origin accepted")
	}
	if _, err := NewWitnessLog("has space", priv); err == nil {
		t.Error("origin with a space accepted")
	}
	if _, err := NewWitnessLog(testLogOrigin, make([]byte, 5)); err == nil {
		t.Error("bad private key accepted")
	}
	log, _ := newTestLog(t)
	if _, err := log.Submit([]byte(`"not-an-object"`), testLogTimestamp); err == nil {
		t.Error("non-object event accepted")
	}
	if _, err := log.Submit([]byte(`{"type":"x"}`), testLogTimestamp); err == nil {
		t.Error("event without id accepted")
	}
	if _, err := log.Submit([]byte(`{"id":"","type":"x"}`), testLogTimestamp); err == nil {
		t.Error("event with empty id accepted")
	}
	if _, err := log.Submit([]byte("{\"id\":\"e\xff\"}"), testLogTimestamp); err == nil {
		t.Error("invalid-UTF-8 event accepted")
	}
	// A rejected timestamp must not grow the log (atomicity): the receipt input is
	// validated before the append.
	if _, err := log.Submit([]byte(`{"id":"evt-x"}`), ""); err == nil {
		t.Error("empty timestamp accepted")
	}
	if _, err := log.Submit([]byte(`{"id":"evt-x"}`), "ts\xff"); err == nil {
		t.Error("invalid-UTF-8 timestamp accepted")
	}
	if log.Size() != 0 {
		t.Errorf("rejected submits mutated the log: size %d", log.Size())
	}
}

func TestWitnessLogConcurrentSubmit(t *testing.T) {
	log, pub := newTestLog(t)
	const n = 40
	receipts := make([]InclusionReceipt, n)
	events := make([]map[string]interface{}, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, event := makeEvent(i)
			events[i] = event
			r, err := log.Submit(raw, testLogTimestamp)
			if err != nil {
				t.Errorf("submit %d: %v", i, err)
				return
			}
			receipts[i] = r
		}(i)
	}
	wg.Wait()

	if got := log.Size(); got != n {
		t.Fatalf("Size = %d, want %d", got, n)
	}
	// Every event got a distinct leaf index in [0, n), so sequencing held under
	// concurrency, and every receipt verifies against its own event.
	seenIndex := make(map[int]bool, n)
	for i := 0; i < n; i++ {
		r := receipts[i]
		if r.LeafIndex < 0 || r.LeafIndex >= n {
			t.Errorf("event %d: leaf index %d out of range", i, r.LeafIndex)
		}
		if seenIndex[r.LeafIndex] {
			t.Errorf("event %d: duplicate leaf index %d", i, r.LeafIndex)
		}
		seenIndex[r.LeafIndex] = true
		if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{Event: events[i]}) {
			t.Errorf("event %d: receipt did not verify", i)
		}
	}
}
