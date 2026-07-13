// Package witnessstore is the durable-storage seam for the INK witness server.
// It persists the raw submitted audit events of a witness log to a single
// append-only file, one JSON record per line, and replays that file on startup to
// rebuild the log's tree byte-identically. It exists so the pure ink.WitnessLog
// stays free of file IO: the log owns tree ordering and the ordering guarantee,
// this package owns the bytes on disk.
//
// The durability contract is ordering. Append writes a record and fsyncs it
// before returning, and the log calls Append inside its append critical section
// before it signs an inclusion receipt, so a record for a leaf is on stable
// storage in tree order before any receipt can attest to that leaf. A crash after
// the tree grew in memory but before the fsync can therefore lose only a leaf that
// was never handed a receipt: if none or part of the record reached disk replay
// finds nothing or a torn tail, and if the whole record reached disk replay keeps
// it as a valid unreceipted leaf. A write or fsync that fails is rolled back by
// truncating the record away and fsyncing the
// truncation, so a failed append leaves no durable bytes behind; if that rollback
// cannot be confirmed durable the store poisons itself and refuses every later
// append. Open fsyncs the record file's directory so a freshly created file's
// directory entry is itself durable, not just its contents.
//
// The security invariant is one-directional and holds strictly: a receipt is
// signed only after Append returns, so no receipt ever attests to a leaf that is
// not durable. The converse is expected, not a fault: a crash between the record
// fsync and the receipt signing can leave a durable record for which no receipt
// was issued. Such a record is still a validated leaf, so replaying it rebuilds a
// consistent tree and never invalidates an existing receipt; a submitter whose
// call was interrupted may simply find its event present. This is the at-least-once
// semantics inherent to append-then-fsync, and it does not weaken the invariant
// above.
//
// The trailing newline is the commit marker for a fully written record. A crash
// can leave the tail in one of two shapes: a complete newline-terminated record
// (whose fsync may or may not have finished, and for which a receipt may or may
// not have been signed), or a partial record with no newline. The first is a
// valid leaf and replay keeps it; that is the at-least-once behavior above. The
// second was never a complete record, so replay discards the no-newline tail with
// a warning. Replay is fail-closed on everything else: a newline-terminated record
// that fails to decode is a fully written record that came out corrupt, so it is
// treated as corruption regardless of position and Replay refuses to start. There
// is no auto-repair.
package witnessstore

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// recordVersion is the on-disk record schema version. It is written into every
// record and checked on replay so a future format change is detected rather than
// silently misread.
const recordVersion = 1

// record is one persisted leaf. Event is the raw submitted event bytes, base64
// encoded so the exact bytes that were hashed into a leaf survive a JSON
// round-trip and rebuild the same leaf hash on replay. Timestamp is the receipt
// timestamp the witness stamped, kept so replay re-runs the identical Submit
// inputs. No other field is needed to rebuild the tree.
type record struct {
	V         int    `json:"v"`
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
}

// Store is an append-only record file. It is safe for concurrent Append calls,
// though the witness log already serializes them inside its append critical
// section.
type Store struct {
	mu sync.Mutex
	f  *os.File
	// sync is os.File.Sync in production; a test replaces it to observe the
	// fsync-before-receipt ordering or to inject a durability failure.
	sync func() error
	// poisoned records that an append failed and its on-disk rollback could not be
	// confirmed durable, so the file is in an unknown state. Once poisoned every
	// later Append fails closed rather than writing after a record that a crash
	// might still resurrect on replay.
	poisoned bool
}

// ErrStorePoisoned is returned by Append after a prior append failed and its
// rollback could not be confirmed durable, leaving the record file in an unknown
// state. The store refuses all further appends so no receipt can be issued
// against a file that a crash might replay inconsistently; the operator restarts
// the process, which replays the file fail-closed and reopens a clean handle.
var ErrStorePoisoned = errors.New("witness store is poisoned after an unrecoverable append failure")

// Open opens (creating if absent) the append-only record file at path for
// appending. Before returning it physically removes any torn tail: if the file
// does not end in a newline, the trailing partial record left by a crash is
// truncated away and the truncation is fsynced, so the append handle starts
// exactly after the last complete record. Without this an appended record would
// sit after the torn bytes, and a later replay would read the torn bytes glued to
// the next record as one corrupt line and refuse to start, stranding a leaf a
// post-recovery receipt already attested to. Open also fsyncs the containing
// directory so a freshly created record file's own entry is durable, not just its
// contents. The caller replays existing records with Replay before serving live
// submissions; Replay tolerates a torn tail too, so the order of Replay and Open
// does not matter.
func Open(path string) (*Store, error) {
	// O_RDWR, not O_WRONLY: recovery reads the file tail to find and truncate a
	// torn final record. O_APPEND still forces every write to the end, so the
	// append-only property holds regardless of the read position.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Store{f: f}
	s.sync = f.Sync
	if err := s.truncateTornTail(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot fsync record directory: %w", err)
	}
	return s, nil
}

// truncateTornTail removes a trailing partial record with no terminating newline
// so the append handle begins after the last complete record. A file that is
// empty or already ends in a newline is left untouched. The truncation is fsynced
// so the recovered prefix is itself durable before any new record is appended.
func (s *Store) truncateTornTail() error {
	size, err := s.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if size == 0 {
		return nil
	}
	last := make([]byte, 1)
	if _, err := s.f.ReadAt(last, size-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	// Walk back to the byte after the previous newline; that offset is the end of
	// the last complete record (0 if there is no earlier newline at all).
	keep, err := lastNewlineEnd(s.f, size)
	if err != nil {
		return err
	}
	if err := s.f.Truncate(keep); err != nil {
		return err
	}
	if _, err := s.f.Seek(keep, io.SeekStart); err != nil {
		return err
	}
	if err := s.sync(); err != nil {
		return err
	}
	log.Printf("witnessstore: truncated a torn final record (%d bytes) at open", size-keep)
	return nil
}

// lastNewlineEnd returns the offset just past the last newline in the file of the
// given size, or 0 if the file contains no newline. It reads backward in small
// chunks so it does not load the whole file.
func lastNewlineEnd(f *os.File, size int64) (int64, error) {
	const chunk = 4096
	buf := make([]byte, chunk)
	for end := size; end > 0; {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		n := int(end - start)
		if _, err := f.ReadAt(buf[:n], start); err != nil {
			return 0, err
		}
		for i := n - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				return start + int64(i) + 1, nil
			}
		}
		end = start
	}
	return 0, nil
}

// MkdirAllDurable creates dir and any missing parents, and fsyncs the parent of
// every directory it actually creates so each new directory entry is durable. A
// directory that already exists is left untouched and its parent is not fsynced,
// so the common already-provisioned path costs nothing extra. It exists so a
// caller can provision the data directory with the same directory-entry
// durability Open gives the record file.
func MkdirAllDurable(dir string, perm os.FileMode) error {
	dir = filepath.Clean(dir)
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := MkdirAllDurable(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// Fsync the parent so this directory's own entry survives a crash.
	return syncDir(parent)
}

// syncDir fsyncs a directory so an entry created or removed within it (here the
// record file's own directory entry) is durable. Opening a directory read-only
// and calling Sync is the portable way to flush its metadata on the platforms
// this witness targets.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// SetSyncForTest overrides the fsync used by Append. It exists only so a test can
// assert that the fsync happens before the receipt is signed, or inject a
// durability failure; production uses os.File.Sync.
func (s *Store) SetSyncForTest(sync func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sync = sync
}

// Append writes one record for a leaf and fsyncs it before returning. It is
// invoked by the witness log inside its append critical section, before the
// receipt is signed, so a successful return means the leaf is durable in tree
// order. Any write or fsync error is returned so the log rolls the append back
// and fails the submission closed.
func (s *Store) Append(rawEvent []byte, timestamp string) error {
	rec := record{
		V:         recordVersion,
		Event:     base64.StdEncoding.EncodeToString(rawEvent),
		Timestamp: timestamp,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	// Once poisoned the file is in an unknown durable state, so refuse to append
	// after it: a later record could sit past one a crash might still resurrect.
	if s.poisoned {
		return ErrStorePoisoned
	}
	// Capture the end-of-file offset before the write so a failed write or fsync
	// can be rolled back to it. Without this, a Write that succeeds but whose Sync
	// fails would leave a complete, newline-terminated record on disk that the next
	// replay would accept, resurrecting a submission that failed closed and never
	// got a receipt.
	offset, err := s.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	// A single Write of the whole line keeps the record atomic against a torn
	// write as far as the OS allows; the trailing newline is the commit marker
	// that replay uses to tell a complete record from a torn tail.
	if _, err := s.f.Write(line); err != nil {
		return s.rollbackTo(offset, err)
	}
	// fsync before returning is the durability point: the record is on stable
	// storage before the caller signs a receipt that would attest to it.
	if err := s.sync(); err != nil {
		return s.rollbackTo(offset, err)
	}
	return nil
}

// rollbackTo truncates the file back to offset and fsyncs, undoing a record whose
// write or fsync failed so a failed append leaves no bytes for replay to find. It
// returns cause, the original append error, on a clean rollback. If the truncate
// or its fsync cannot be confirmed durable it poisons the store instead, so every
// later Append fails closed rather than writing past a record a crash might still
// resurrect; the returned error joins that unrecoverable state to the cause.
func (s *Store) rollbackTo(offset int64, cause error) error {
	if err := s.f.Truncate(offset); err != nil {
		s.poisoned = true
		log.Printf("witnessstore: could not truncate after a failed append, store poisoned: %v", err)
		return errors.Join(cause, ErrStorePoisoned)
	}
	if _, err := s.f.Seek(offset, io.SeekStart); err != nil {
		s.poisoned = true
		log.Printf("witnessstore: could not reposition after a failed append, store poisoned: %v", err)
		return errors.Join(cause, ErrStorePoisoned)
	}
	// Make the truncation itself durable. If this fsync fails the pre-truncate
	// record may survive a crash, so the store is poisoned rather than trusted.
	if err := s.sync(); err != nil {
		s.poisoned = true
		log.Printf("witnessstore: could not fsync rollback truncation, store poisoned: %v", err)
		return errors.Join(cause, ErrStorePoisoned)
	}
	return cause
}

// Close closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// ErrCorruptLog is returned by Replay when a complete (newline-terminated) record
// at any position is malformed, or when replay cannot apply a record. It signals a
// corrupted durable log the operator must inspect, not the no-newline torn tail
// that replay discards.
var ErrCorruptLog = errors.New("witness log file is corrupt")

// ReplayFunc receives the raw event bytes and receipt timestamp of one persisted
// leaf, in order, so the caller can re-append it to the witness log through the
// same validation path.
type ReplayFunc func(rawEvent []byte, timestamp string) error

// Replay reads the record file at path line by line and calls apply for each
// complete record in order, so the caller rebuilds the tree. A trailing partial
// line with no newline is a torn tail: it is discarded with a warning, because
// Append truncates a failed record away, so a no-newline tail can only be a write
// a crash interrupted before the record was complete. Every other defect is fatal
// and returns an error wrapping ErrCorruptLog: a newline-terminated record that
// fails to decode (at any position, including the last), or an apply error on any
// record, refuses start rather than silently dropping a complete record. The log
// is fail-closed with no auto-repair. A missing file replays as an empty log.
func Replay(path string, apply ReplayFunc) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	lineNo := 0
	for {
		line, readErr := r.ReadBytes('\n')
		atEOF := errors.Is(readErr, io.EOF)
		if readErr != nil && !atEOF {
			return readErr
		}
		// A chunk with no terminating newline at EOF is a torn tail: the record was
		// never committed, so no receipt exists for it. Discard it with a warning.
		if atEOF && len(line) > 0 && line[len(line)-1] != '\n' {
			log.Printf("witnessstore: discarding torn final record (%d bytes, no newline) in %s", len(line), path)
			return nil
		}
		if atEOF && len(line) == 0 {
			return nil
		}
		lineNo++
		trimmed := line[:len(line)-1] // strip the newline
		rawEvent, timestamp, decErr := decodeRecord(trimmed)
		if decErr != nil {
			// The trailing newline is the commit marker: a record that carries it was
			// fully written, and Append truncates a record back to nothing when its
			// write or fsync fails, so a crash can only ever leave a partial record
			// with no newline. A newline-terminated record that fails to decode is
			// therefore not a torn tail; it is a fully written record that came out
			// corrupt, so it is corruption regardless of position and Replay fails
			// closed rather than dropping a complete record. Only the no-newline tail
			// handled above is discarded.
			return fmt.Errorf("%w: line %d: %v", ErrCorruptLog, lineNo, decErr)
		}
		if err := apply(rawEvent, timestamp); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrCorruptLog, lineNo, err)
		}
		if atEOF {
			return nil
		}
	}
}

// decodeRecord parses one trimmed record line into its raw event bytes and
// timestamp, rejecting an unknown version, a bad base64 event, or a missing
// field.
func decodeRecord(line []byte) (rawEvent []byte, timestamp string, err error) {
	var rec record
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, "", err
	}
	if rec.V != recordVersion {
		return nil, "", fmt.Errorf("unknown record version %d", rec.V)
	}
	if rec.Timestamp == "" {
		return nil, "", errors.New("record has an empty timestamp")
	}
	rawEvent, err = base64.StdEncoding.DecodeString(rec.Event)
	if err != nil {
		return nil, "", fmt.Errorf("record event is not valid base64: %v", err)
	}
	return rawEvent, rec.Timestamp, nil
}
