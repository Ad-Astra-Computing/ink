package ink

import (
	"encoding/json"
	"errors"
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

// makeAuditEvent returns a raw audit event shaped for audit-query scope: it
// carries a messageId, an agentId and counterpartyId, and a non-empty
// agentSignature. index selects the agent so events for two requesters can be
// interleaved in one log.
func makeAuditEvent(i int, messageID, agentID, counterpartyID string) ([]byte, map[string]interface{}) {
	m := map[string]interface{}{
		"id":             fmt.Sprintf("evt-%d", i),
		"type":           "connection_request",
		"messageId":      messageID,
		"agentId":        agentID,
		"counterpartyId": counterpartyID,
		"seq":            i,
		"agentSignature": fmt.Sprintf("sig-%d", i),
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

func TestWitnessLogAuditQueryResponse(t *testing.T) {
	log, pub := newTestLog(t)
	const serviceDid = "did:web:witness.example"
	const messageID = "msg-1"
	const alice = "did:web:alice.example"
	const bob = "did:web:bob.example"
	const carol = "did:web:carol.example"

	// Three events for the (msg-1, alice<->bob) thread and one unrelated event.
	for i := 0; i < 3; i++ {
		raw, _ := makeAuditEvent(i, messageID, alice, bob)
		if _, err := log.Submit(raw, testLogTimestamp); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	rawOther, _ := makeAuditEvent(99, "msg-2", carol, bob)
	if _, err := log.Submit(rawOther, testLogTimestamp); err != nil {
		t.Fatalf("submit other: %v", err)
	}

	response, err := log.AuditQueryResponse(serviceDid, alice, messageID, testLogTimestamp)
	if err != nil {
		t.Fatalf("AuditQueryResponse: %v", err)
	}
	// Every returned event is agent-signed here with a fixed value, so the
	// verifier's per-event signature callback just asserts the field is present.
	opts := AuditQueryVerifyOptions{
		ExpectedRequester:  alice,
		ExpectedMessageID:  messageID,
		ExpectedServiceDid: serviceDid,
		VerifyEventSignature: func(ev map[string]interface{}) bool {
			sig, _ := ev["agentSignature"].(string)
			return sig != ""
		},
	}
	if !VerifyInkAuditQueryResponse(response, pub, opts) {
		t.Fatal("audit-query response did not verify end to end")
	}
	events, _ := response["events"].([]interface{})
	if len(events) != 3 {
		t.Errorf("returned %d events, want 3 (the in-scope thread only)", len(events))
	}
	if ts := int(response["treeSize"].(float64)); ts != 4 {
		t.Errorf("treeSize = %d, want 4 (the full tree)", ts)
	}

	// A requester who is not a party to any event gets an empty but valid response
	// over the current tree.
	const stranger = "did:web:stranger.example"
	empty, err := log.AuditQueryResponse(serviceDid, stranger, messageID, testLogTimestamp)
	if err != nil {
		t.Fatalf("empty AuditQueryResponse: %v", err)
	}
	if evs, _ := empty["events"].([]interface{}); len(evs) != 0 {
		t.Errorf("out-of-scope query returned %d events, want 0", len(evs))
	}
	emptyOpts := opts
	emptyOpts.ExpectedRequester = stranger
	if !VerifyInkAuditQueryResponse(empty, pub, emptyOpts) {
		t.Error("empty audit-query response did not verify")
	}
}

// TestWitnessLogAuditQueryResponseRobustness proves a malformed or duplicate
// retained event in scope does not fail the whole query: an event without an
// agentSignature and a duplicate event id are skipped, and the valid events
// still verify.
func TestWitnessLogAuditQueryResponseRobustness(t *testing.T) {
	log, pub := newTestLog(t)
	const serviceDid = "did:web:witness.example"
	const messageID = "msg-1"
	const alice = "did:web:alice.example"

	submitRaw := func(raw string) {
		if _, err := log.Submit([]byte(raw), testLogTimestamp); err != nil {
			t.Fatalf("submit %s: %v", raw, err)
		}
	}
	// evt-a: valid and in scope.
	submitRaw(`{"id":"evt-a","messageId":"msg-1","agentId":"did:web:alice.example","counterpartyId":"did:web:bob.example","agentSignature":"sig-a"}`)
	// in scope but no agentSignature: must be skipped, not fatal.
	submitRaw(`{"id":"evt-b","messageId":"msg-1","agentId":"did:web:alice.example","counterpartyId":"did:web:bob.example"}`)
	// duplicate id of evt-a, in scope: must be skipped, not duplicated.
	submitRaw(`{"id":"evt-a","messageId":"msg-1","agentId":"did:web:alice.example","counterpartyId":"did:web:bob.example","agentSignature":"sig-a2"}`)

	response, err := log.AuditQueryResponse(serviceDid, alice, messageID, testLogTimestamp)
	if err != nil {
		t.Fatalf("AuditQueryResponse: %v", err)
	}
	opts := AuditQueryVerifyOptions{
		ExpectedRequester:  alice,
		ExpectedMessageID:  messageID,
		ExpectedServiceDid: serviceDid,
		VerifyEventSignature: func(ev map[string]interface{}) bool {
			sig, _ := ev["agentSignature"].(string)
			return sig != ""
		},
	}
	if !VerifyInkAuditQueryResponse(response, pub, opts) {
		t.Fatal("response with a malformed and a duplicate in-scope event did not verify")
	}
	if evs, _ := response["events"].([]interface{}); len(evs) != 1 {
		t.Errorf("returned %d events, want 1 (evt-a once, skipping the unsigned and the duplicate)", len(evs))
	}
}

func TestWitnessLogAuditQueryResponseValidation(t *testing.T) {
	log, _ := newTestLog(t)
	const sd = "did:web:witness.example"
	for _, bad := range []struct{ serviceDid, requester, messageID, ts string }{
		{"", "r", "m", testLogTimestamp},
		{sd, "", "m", testLogTimestamp},
		{sd, "r", "", testLogTimestamp},
		{sd, "r", "m", ""},
	} {
		if _, err := log.AuditQueryResponse(bad.serviceDid, bad.requester, bad.messageID, bad.ts); err == nil {
			t.Errorf("AuditQueryResponse(%q,%q,%q,%q) accepted empty argument", bad.serviceDid, bad.requester, bad.messageID, bad.ts)
		}
	}
}

func TestWitnessLogSubmitWithCapacity(t *testing.T) {
	log, _ := newTestLog(t)
	const cap = 3
	for i := 0; i < cap; i++ {
		raw, _ := makeEvent(i)
		if _, err := log.SubmitWithCapacity(raw, testLogTimestamp, cap); err != nil {
			t.Fatalf("submit %d under capacity: %v", i, err)
		}
	}
	raw, _ := makeEvent(cap)
	_, err := log.SubmitWithCapacity(raw, testLogTimestamp, cap)
	if !errors.Is(err, ErrCapacity) {
		t.Errorf("at-capacity submit err = %v, want ErrCapacity", err)
	}
	if log.Size() != cap {
		t.Errorf("capacity-rejected submit grew the log to %d", log.Size())
	}
	// A non-positive bound applies no extra limit beyond the hard ceiling.
	if _, err := log.SubmitWithCapacity(raw, testLogTimestamp, 0); err != nil {
		t.Errorf("submit with no bound: %v", err)
	}
}

// TestWitnessLogConcurrentSubmitRespectsCapacity fires many concurrent bounded
// submits and asserts the tree never exceeds the bound: the check-and-append is
// atomic, so a burst cannot overshoot the way a check-then-append would.
func TestWitnessLogConcurrentSubmitRespectsCapacity(t *testing.T) {
	log, _ := newTestLog(t)
	const cap = 5
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, _ := makeEvent(i)
			_, _ = log.SubmitWithCapacity(raw, testLogTimestamp, cap)
		}(i)
	}
	wg.Wait()
	if log.Size() != cap {
		t.Errorf("Size = %d, want exactly %d (no overshoot)", log.Size(), cap)
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

// TestWitnessLogPersistOrderingBeforeSign proves the durability sink runs before
// the receipt is signed, and in tree order. The sink records the index it saw for
// each call; because SetPersist runs it inside the append critical section before
// SignInclusionReceipt, a returned receipt can only exist for an index the sink
// already committed, and the recorded order equals the leaf order.
func TestWitnessLogPersistOrderingBeforeSign(t *testing.T) {
	log, pub := newTestLog(t)
	var persisted []int
	log.SetPersist(func(raw []byte, ts string, index int) error {
		// The sink sees the raw submitted bytes and the assigned index; recording
		// them here lets the test assert order and pre-sign timing.
		persisted = append(persisted, index)
		return nil
	})
	const n = 4
	for i := 0; i < n; i++ {
		raw, event := makeEvent(i)
		r, err := log.Submit(raw, testLogTimestamp)
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		// The sink must have recorded this leaf before the receipt for it existed.
		if len(persisted) != i+1 || persisted[i] != i {
			t.Fatalf("submit %d: sink saw %v, want the leaf committed in order before the receipt", i, persisted)
		}
		if !VerifyInclusionReceipt(r, pub, ReceiptVerifyOptions{Event: event}) {
			t.Errorf("submit %d: receipt did not verify", i)
		}
	}
}

// TestWitnessLogPersistFailureRollsBack proves a sink error fails the submission
// closed and leaves the tree unchanged: no leaf, no receipt, and later submits
// keep contiguous indices.
func TestWitnessLogPersistFailureRollsBack(t *testing.T) {
	log, _ := newTestLog(t)
	failNext := false
	log.SetPersist(func(raw []byte, ts string, index int) error {
		if failNext {
			return errors.New("disk full")
		}
		return nil
	})
	raw0, _ := makeEvent(0)
	if _, err := log.Submit(raw0, testLogTimestamp); err != nil {
		t.Fatalf("submit 0: %v", err)
	}
	failNext = true
	raw1, _ := makeEvent(1)
	if _, err := log.Submit(raw1, testLogTimestamp); err == nil {
		t.Fatal("submit with a failing sink returned a receipt")
	}
	if log.Size() != 1 {
		t.Fatalf("failed submit grew the tree to %d, want 1", log.Size())
	}
	failNext = false
	// The next accepted event takes index 1, proving the failed append left no gap.
	r, err := log.Submit(raw1, testLogTimestamp)
	if err != nil {
		t.Fatalf("submit after recovery: %v", err)
	}
	if r.LeafIndex != 1 {
		t.Errorf("post-failure leaf index = %d, want 1 (no gap)", r.LeafIndex)
	}
}

// TestWitnessLogReplayRebuildsIdenticalTree proves ReplayAppend rebuilds a tree
// whose root at any size equals the root the live submissions produced, without
// signing or re-persisting.
func TestWitnessLogReplayRebuildsIdenticalTree(t *testing.T) {
	live, pub := newTestLog(t)
	const n = 7
	raws := make([][]byte, n)
	for i := 0; i < n; i++ {
		raw, _ := makeEvent(i)
		raws[i] = raw
		if _, err := live.Submit(raw, testLogTimestamp); err != nil {
			t.Fatalf("live submit %d: %v", i, err)
		}
	}
	liveCP, err := live.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	liveData, ok := VerifyCheckpoint(liveCP, pub, testLogOrigin)
	if !ok {
		t.Fatal("live checkpoint did not verify")
	}

	priv, _ := conformanceWitnessKey()
	rebuilt, err := NewWitnessLog(testLogOrigin, priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := rebuilt.ReplayAppend(raws[i], testLogTimestamp, 0); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	rebuiltCP, err := rebuilt.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	rebuiltData, ok := VerifyCheckpoint(rebuiltCP, pub, testLogOrigin)
	if !ok {
		t.Fatal("rebuilt checkpoint did not verify")
	}
	if rebuiltData.TreeSize != liveData.TreeSize || rebuiltData.RootHash != liveData.RootHash {
		t.Errorf("rebuilt tree (%d,%s) != live tree (%d,%s)", rebuiltData.TreeSize, rebuiltData.RootHash, liveData.TreeSize, liveData.RootHash)
	}
}

// TestWitnessLogReplayHonoursCapacity proves replay refuses to exceed the bound.
func TestWitnessLogReplayHonoursCapacity(t *testing.T) {
	priv, _ := conformanceWitnessKey()
	log, err := NewWitnessLog(testLogOrigin, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw0, _ := makeEvent(0)
	if err := log.ReplayAppend(raw0, testLogTimestamp, 1); err != nil {
		t.Fatalf("replay 0: %v", err)
	}
	raw1, _ := makeEvent(1)
	if err := log.ReplayAppend(raw1, testLogTimestamp, 1); !errors.Is(err, ErrCapacity) {
		t.Errorf("replay past bound err = %v, want ErrCapacity", err)
	}
}
