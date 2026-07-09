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
// the pure issuing Merkle core and the signer; it adds no transport and no
// durable storage, so a process restart starts an empty log.
//
// A WitnessLog is safe for concurrent use. Submit serializes appends, and the
// proof and checkpoint reads take a snapshot of the append-only leaf slice, so a
// read never observes a partially appended tree and never blocks on the length
// of a proof walk.
type WitnessLog struct {
	origin string
	priv   ed25519.PrivateKey

	mu     sync.Mutex
	leaves []string
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
	// A three-index slice caps len and cap at the tree size at this append, so a
	// later append that reallocates or writes past this size cannot alias it.
	snapshot := w.leaves[: index+1 : index+1]
	w.mu.Unlock()

	// Inputs are prevalidated and leaves are always 64-hex, so signing cannot
	// fail after the append.
	return SignInclusionReceipt(snapshot, index, eventID, timestamp, w.priv)
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
