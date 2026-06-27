// Package verify orchestrates the INK protocol verifiers exposed by the
// reference Go library (github.com/Ad-Astra-Computing/ink/go/ink) behind a
// transport-neutral surface. The CLI calls these functions today; a later
// witness or inbound-verifier server can call the same functions without going
// through argv or stdin, so the verification logic lives here and not in the
// command layer.
package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

// Result is the outcome of verifying one INK artifact. OK reports whether the
// artifact is valid (accepted); Kind names the artifact so a caller does not
// have to track which verifier produced the result. A non-nil error from a
// verifier function means the input could not be parsed at all (bad input),
// which the caller maps to a distinct exit code from a clean rejection.
type Result struct {
	OK   bool   `json:"ok"`
	Kind string `json:"kind"`
}

// Card validates an Agent Card document against the reference schema. The card
// is a protocol artifact, so it is parsed with the same leniency as the
// TypeScript reference (unknown top-level keys are ignored, last value wins on a
// repeated key); required-field and shape enforcement is ValidateAgentCard's job.
func Card(data []byte) (Result, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return Result{}, fmt.Errorf("invalid JSON: %w", err)
	}
	return Result{OK: ink.ValidateAgentCard(m), Kind: "agent-card"}, nil
}

// The Merkle command inputs are this CLI's own request schemas (they mirror the
// merkle-inclusion / merkle-consistency vector shapes), not protocol wire
// objects, so they are parsed strictly: every field is required and present
// (pointer fields reject a missing or null field), unknown fields, duplicate
// keys, and trailing data are rejected. This keeps a malformed request a bad
// input (a distinct exit code) rather than letting an omitted field default to a
// Go zero value that happens to verify.

type inclusionInput struct {
	LeafHash       *string   `json:"leafHash"`
	InclusionProof *[]string `json:"inclusionProof"`
	LeafIndex      *int      `json:"leafIndex"`
	TreeSize       *int      `json:"treeSize"`
	RootHash       *string   `json:"rootHash"`
}

// Inclusion verifies a Merkle inclusion proof. The input shape matches the
// `merkle-inclusion` conformance vectors: leafHash, inclusionProof, leafIndex,
// treeSize, rootHash.
func Inclusion(data []byte) (Result, error) {
	var in inclusionInput
	if err := strictDecode(data, &in); err != nil {
		return Result{}, err
	}
	if in.LeafHash == nil || in.InclusionProof == nil || in.LeafIndex == nil || in.TreeSize == nil || in.RootHash == nil {
		return Result{}, fmt.Errorf("missing required field (leafHash, inclusionProof, leafIndex, treeSize, rootHash)")
	}
	ok := ink.VerifyInclusionProof(*in.LeafHash, *in.InclusionProof, *in.LeafIndex, *in.TreeSize, *in.RootHash)
	return Result{OK: ok, Kind: "merkle-inclusion"}, nil
}

type consistencyInput struct {
	First      *int      `json:"first"`
	FirstRoot  *string   `json:"firstRoot"`
	Second     *int      `json:"second"`
	SecondRoot *string   `json:"secondRoot"`
	Proof      *[]string `json:"proof"`
}

// Consistency verifies a Merkle consistency proof between two log states. The
// input shape matches the `merkle-consistency` conformance vectors: first,
// firstRoot, second, secondRoot, proof.
func Consistency(data []byte) (Result, error) {
	var in consistencyInput
	if err := strictDecode(data, &in); err != nil {
		return Result{}, err
	}
	if in.First == nil || in.FirstRoot == nil || in.Second == nil || in.SecondRoot == nil || in.Proof == nil {
		return Result{}, fmt.Errorf("missing required field (first, firstRoot, second, secondRoot, proof)")
	}
	ok := ink.VerifyConsistencyProof(*in.First, *in.FirstRoot, *in.Second, *in.SecondRoot, *in.Proof)
	return Result{OK: ok, Kind: "merkle-consistency"}, nil
}

// strictDecode decodes a single JSON object into v, rejecting unknown fields,
// duplicate object keys, and any trailing data. It returns a bad-input error
// (wrapped "invalid JSON") on any of those, so the caller maps it to the
// bad-input exit code rather than a clean rejection.
func strictDecode(data []byte, v any) error {
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	// dec.More() only reports a next element within the current array or object,
	// not a second top-level value, so check for EOF directly: anything other
	// than EOF means a trailing JSON value follows the artifact.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid JSON: unexpected trailing data")
	}
	return nil
}

// rejectDuplicateKeys walks one JSON value and errors on a repeated key within
// any object. encoding/json would otherwise silently keep the last value, which
// hides a malformed request and could diverge from another implementation.
func rejectDuplicateKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil // a scalar; nothing nested to check
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyTok.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err := rejectDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume '}'
		return err
	case '[':
		for dec.More() {
			if err := rejectDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // consume ']'
		return err
	}
	return nil
}
