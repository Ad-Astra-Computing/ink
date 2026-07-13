package ink

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"
)

// WitnessLog is an in-memory, append-only INK transparency log. It owns the
// sequencing and state a witness needs: it assigns each submitted audit event
// the next leaf index, holds the ordered leaf hashes, and issues signed
// inclusion receipts and signed checkpoints over its current tree. It builds on
// the pure issuing Merkle core and the signer; it adds no transport and performs
// no file IO itself, so by default a process restart starts an empty log. A
// caller that needs durability injects a storage sink with SetPersist and rebuilds
// the tree with ReplayAppend; the ordering guarantee that keeps a receipt from
// attesting to an unpersisted leaf lives here, but the storage does not.
//
// A WitnessLog is safe for concurrent use. Submit serializes appends, and the
// proof and checkpoint reads take a snapshot of the append-only leaf slice, so a
// read never observes a partially appended tree and never blocks on the length
// of a proof walk.
type WitnessLog struct {
	origin string
	priv   ed25519.PrivateKey

	mu sync.Mutex
	// leaves and events are appended together and stay index-aligned: events[i]
	// is the raw audit event whose leaf hash is leaves[i]. The events are retained
	// so the log can answer an audit query with the events themselves plus their
	// inclusion proofs, not only a Merkle proof over an opaque leaf.
	leaves []string
	events []map[string]interface{}
	// persist is an optional durability sink. When set, it runs inside the append
	// critical section, after the in-memory append but before the receipt is
	// signed, so the record for a leaf is committed to durable storage in tree
	// order before any receipt can attest to that leaf. It receives the raw
	// submitted event bytes, the receipt timestamp and the assigned leaf index. If
	// it returns an error the append is rolled back and Submit fails, so a leaf the
	// sink could not durably record is never issued a receipt and never grows the
	// tree. The library itself performs no file IO: the sink is injected by the
	// caller, and the nil case is the original in-memory path with no added cost.
	persist func(rawEvent []byte, timestamp string, index int) error
}

// SetPersist installs a durability sink that is invoked for every accepted leaf
// inside the append critical section, after the in-memory append and before the
// inclusion receipt is signed. It exists so a caller can make the log durable
// without adding storage code to this pure library: the sink owns the file, and
// the log owns only ordering. It must be called before the log accepts any
// submission (for example right after NewWitnessLog, or after the ReplayAppend
// pass that rebuilds a durable log) and not concurrently with Submit. A sink error
// fails the submission closed and rolls
// back the append, so the durable record and the tree never diverge.
func (w *WitnessLog) SetPersist(persist func(rawEvent []byte, timestamp string, index int) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.persist = persist
}

// NewWitnessLog creates an empty log that signs as origin with the witness key.
// origin is the log identity bound into every checkpoint, so it must be a
// non-empty single line with no ASCII whitespace, valid UTF-8, within the
// checkpoint line bound.
func NewWitnessLog(origin string, witnessPrivateKey ed25519.PrivateKey) (*WitnessLog, error) {
	if len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("witness private key must be an ed25519 private key")
	}
	if origin == "" || strings.ContainsAny(origin, " \t\r\n\v\f") || utf16Len(origin) > maxCheckpointLine || !utf8.Valid([]byte(origin)) {
		return nil, errors.New("invalid witness origin")
	}
	// Own the key: copy it so a caller mutating its slice later cannot alter or
	// race the log's signing.
	priv := make(ed25519.PrivateKey, len(witnessPrivateKey))
	copy(priv, witnessPrivateKey)
	return &WitnessLog{origin: origin, priv: priv}, nil
}

// ErrCapacity is returned by Submit and SubmitWithCapacity when the log cannot
// accept another leaf, either because it reached a caller-supplied capacity or
// its own hard ceiling. It lets a caller map an at-capacity submission to a
// distinct outcome (for example an HTTP 507) instead of treating it as a
// malformed event.
var ErrCapacity = errors.New("witness log is at capacity")

// Submit appends the leaf hash of a raw audit event and returns a signed
// inclusion receipt committing to the tree as it stands after the append. The
// raw event is parsed through ParseSignedBody, so invalid UTF-8 or a lone
// surrogate is rejected before hashing. The event must be a JSON object with a
// non-empty string id; timestamp is the witness's receipt timestamp.
func (w *WitnessLog) Submit(rawEvent []byte, timestamp string) (InclusionReceipt, error) {
	return w.SubmitWithCapacity(rawEvent, timestamp, 0)
}

// SubmitWithCapacity behaves like Submit but also rejects the append with
// ErrCapacity once the tree has reached maxLeaves leaves. The bound is checked
// inside the same critical section as the append, so a burst of concurrent
// submits cannot overshoot it. A non-positive maxLeaves applies no bound beyond
// the log's own hard ceiling.
func (w *WitnessLog) SubmitWithCapacity(rawEvent []byte, timestamp string, maxLeaves int) (InclusionReceipt, error) {
	// Validate every receipt input before the append so a rejected Submit never
	// mutates the log: the append-only tree only grows on success.
	if timestamp == "" || !utf8.Valid([]byte(timestamp)) {
		return InclusionReceipt{}, errors.New("timestamp must be a non-empty valid UTF-8 string")
	}
	parsed, err := ParseSignedBody(rawEvent)
	if err != nil {
		return InclusionReceipt{}, err
	}
	obj, ok := parsed.(map[string]interface{})
	if !ok {
		return InclusionReceipt{}, errors.New("event must be a JSON object")
	}
	eventID, ok := obj["id"].(string)
	if !ok || eventID == "" {
		return InclusionReceipt{}, errors.New("event id must be a non-empty string")
	}
	leafHash, ok := ComputeAuditMerkleLeafHash(obj)
	if !ok {
		return InclusionReceipt{}, errors.New("event could not be hashed into a leaf")
	}

	w.mu.Lock()
	if len(w.leaves) >= maxSafeInteger || (maxLeaves > 0 && len(w.leaves) >= maxLeaves) {
		w.mu.Unlock()
		return InclusionReceipt{}, ErrCapacity
	}
	index := len(w.leaves)
	w.leaves = append(w.leaves, leafHash)
	w.events = append(w.events, obj)
	// Commit the durable record for this leaf inside the critical section, before
	// the receipt is signed and before the lock is released. This is the security
	// ordering: the record for leaf index is on stable storage in the same order
	// as the tree, so a receipt can never attest to a leaf a crash could lose. On a
	// sink failure the append is rolled back and the submission fails closed, so
	// the durable log and the in-memory tree never diverge.
	if w.persist != nil {
		if err := w.persist(rawEvent, timestamp, index); err != nil {
			w.leaves = w.leaves[:index]
			w.events = w.events[:index]
			w.mu.Unlock()
			return InclusionReceipt{}, err
		}
	}
	// A three-index slice caps len and cap at the tree size at this append, so a
	// later append that reallocates or writes past this size cannot alias it.
	snapshot := w.leaves[: index+1 : index+1]
	w.mu.Unlock()

	// Inputs are prevalidated and leaves are always 64-hex, so signing cannot
	// fail after the append. The durable record was committed under the lock
	// above, so this receipt can only attest to an already-persisted leaf.
	return SignInclusionReceipt(snapshot, index, eventID, timestamp, w.priv)
}

// ReplayAppend re-appends a previously accepted event during startup replay. It
// runs the raw event through the exact same validation and leaf-hash path as
// Submit, so the rebuilt tree is byte-identical to the tree the events first
// produced, but it neither signs a receipt nor invokes the durability sink: the
// record being replayed is already on stable storage. The maxLeaves bound is
// enforced here too, so a durable log larger than the configured bound refuses to
// rebuild rather than silently exceeding it. ReplayAppend must be called before
// SetPersist and before the log serves any live submission.
func (w *WitnessLog) ReplayAppend(rawEvent []byte, timestamp string, maxLeaves int) error {
	if timestamp == "" || !utf8.Valid([]byte(timestamp)) {
		return errors.New("timestamp must be a non-empty valid UTF-8 string")
	}
	parsed, err := ParseSignedBody(rawEvent)
	if err != nil {
		return err
	}
	obj, ok := parsed.(map[string]interface{})
	if !ok {
		return errors.New("event must be a JSON object")
	}
	eventID, ok := obj["id"].(string)
	if !ok || eventID == "" {
		return errors.New("event id must be a non-empty string")
	}
	leafHash, ok := ComputeAuditMerkleLeafHash(obj)
	if !ok {
		return errors.New("event could not be hashed into a leaf")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.leaves) >= maxSafeInteger || (maxLeaves > 0 && len(w.leaves) >= maxLeaves) {
		return ErrCapacity
	}
	w.leaves = append(w.leaves, leafHash)
	w.events = append(w.events, obj)
	return nil
}

// Size returns the current number of leaves in the log.
func (w *WitnessLog) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.leaves)
}

// snapshot returns the current leaf slice, capped so the caller cannot alias the
// backing array, and the size at that moment.
func (w *WitnessLog) snapshot() ([]string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(w.leaves)
	return w.leaves[:n:n], n
}

// Checkpoint returns a signed checkpoint over the current tree head.
func (w *WitnessLog) Checkpoint() (string, error) {
	leaves, n := w.snapshot()
	root, err := MerkleTreeHead(leaves)
	if err != nil {
		return "", err
	}
	return SignCheckpoint(w.origin, int64(n), root, w.priv)
}

// InclusionProof returns the inclusion proof for the leaf at index in the tree
// as it stands at the time of the call, together with that tree size. It
// verifies with VerifyInclusionProof(leaf, proof, index, size, root) against the
// root of a checkpoint of the same size. Because a concurrent Submit can grow
// the tree between calls, the caller must pair this proof with the returned size
// and a checkpoint of that size, not assume a later Checkpoint has the same size.
func (w *WitnessLog) InclusionProof(index int) (proof []string, size int, err error) {
	leaves, n := w.snapshot()
	proof, err = InclusionProof(leaves, index)
	return proof, n, err
}

// ConsistencyProof returns a proof that the tree of the first `first` leaves is a
// prefix of the tree of the first `second` leaves, for two sizes this log has
// reached. It verifies with VerifyConsistencyProof against the roots of the two
// checkpoints.
func (w *WitnessLog) ConsistencyProof(first, second int) ([]string, error) {
	leaves, _ := w.snapshot()
	return ConsistencyProof(leaves, first, second)
}

// AuditQueryResponse builds and witness-signs an audit-query response over the
// current tree, returning each retained event within the (messageID, requester)
// scope, together with its inclusion proof, that can form a valid response. An
// in-scope event without a non-empty agentSignature, or a repeat of an id already
// returned, is skipped so a malformed or duplicate submission cannot fail the
// whole query. serviceDid is the witness identity bound into the response
// envelope; timestamp is the response timestamp. The result verifies with
// VerifyInkAuditQueryResponse against the witness public key, the same requester,
// and the same messageID. An empty result is a valid response over the current
// tree with no events.
func (w *WitnessLog) AuditQueryResponse(serviceDid, requester, messageID, timestamp string) (map[string]interface{}, error) {
	if serviceDid == "" || requester == "" || messageID == "" || timestamp == "" {
		return nil, errors.New("serviceDid, requester, messageId and timestamp must be non-empty")
	}
	// Snapshot the aligned leaves and events under one lock so the proofs, the
	// tree head and the selected events are all taken from the same tree state.
	w.mu.Lock()
	n := len(w.leaves)
	leaves := w.leaves[:n:n]
	events := w.events[:n:n]
	w.mu.Unlock()

	root, err := MerkleTreeHead(leaves)
	if err != nil {
		return nil, err
	}

	selectedEvents := []interface{}{}
	proofs := []interface{}{}
	seen := map[string]bool{}
	for i, ev := range events {
		if !eventInScope(ev, messageID, requester) {
			continue
		}
		// Only include an event that can be part of a valid signed response: a
		// non-empty id and agentSignature (the signer and verifier both require the
		// signature) and an id not already returned (the verifier rejects duplicate
		// event ids). Skipping a malformed or duplicate retained event returns the
		// valid events in scope instead of failing the whole query, so one bad or
		// repeated submission cannot deny an audit query for the scope.
		id, _ := ev["id"].(string)
		sig, _ := ev["agentSignature"].(string)
		if id == "" || sig == "" || seen[id] {
			continue
		}
		seen[id] = true
		proof, err := InclusionProof(leaves, i)
		if err != nil {
			return nil, err
		}
		proofHashes := make([]interface{}, len(proof))
		for j, h := range proof {
			proofHashes[j] = h
		}
		selectedEvents = append(selectedEvents, ev)
		proofs = append(proofs, map[string]interface{}{
			"eventId":        id,
			"leafIndex":      float64(i),
			"inclusionProof": proofHashes,
		})
	}

	response := map[string]interface{}{
		"protocol":   "ink/0.1",
		"type":       "network.tulpa.audit_query_response",
		"serviceDid": serviceDid,
		"messageId":  messageID,
		"requester":  requester,
		"events":     selectedEvents,
		"proofs":     proofs,
		"treeSize":   float64(n),
		"rootHash":   root,
		"timestamp":  timestamp,
	}
	signature, err := SignAuditQueryResponse(response, w.priv)
	if err != nil {
		return nil, err
	}
	response["serviceSignature"] = signature
	return response, nil
}

// eventInScope reports whether a retained event falls within an audit query's
// (messageID, requester) scope, matching the verifier's per-event rule: the
// event's messageId must equal the envelope messageId and the requester must be
// a party, its agentId or counterpartyId.
func eventInScope(ev map[string]interface{}, messageID, requester string) bool {
	if mid, _ := ev["messageId"].(string); mid != messageID {
		return false
	}
	agentID, _ := ev["agentId"].(string)
	counterpartyID, _ := ev["counterpartyId"].(string)
	return agentID == requester || counterpartyID == requester
}
