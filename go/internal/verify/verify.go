// Package verify orchestrates the INK protocol verifiers exposed by the
// reference Go library (github.com/Ad-Astra-Computing/ink/go/ink) behind a
// transport-neutral surface. The CLI calls these functions today; a later
// witness or inbound-verifier server can call the same functions without going
// through argv or stdin, so the verification logic lives here and not in the
// command layer.
package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

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

// The signature input is this CLI's own request schema; it mirrors the
// `signature-base` conformance vector shape (signInput + signature +
// publicKeyHex) and additionally accepts publicKeyMultibase, the form an Agent
// Card carries. It is parsed strictly: the request scalars are pointer fields
// so a missing or null one is bad input, and unknown fields, duplicate keys, or
// trailing data are rejected. The signed body is kept raw and parsed through
// ParseSignedBody so a lone UTF-16 surrogate is rejected before verification,
// the receiver MUST the bare VerifyInkSignature cannot enforce on its own.

type signInputJSON struct {
	Method       *string         `json:"method"`
	Path         *string         `json:"path"`
	RecipientDid *string         `json:"recipientDid"`
	Body         json.RawMessage `json:"body"`
	Timestamp    *string         `json:"timestamp"`
}

type signatureInput struct {
	PublicKeyHex       *string         `json:"publicKeyHex"`
	PublicKeyMultibase *string         `json:"publicKeyMultibase"`
	SignInput          json.RawMessage `json:"signInput"`
	Signature          *string         `json:"signature"`
}

// Signature verifies a detached Ed25519 signature over an INK signature base.
// The input shape matches the `signature-base` conformance vectors plus an
// optional publicKeyMultibase alternative to publicKeyHex.
func Signature(data []byte) (Result, error) {
	var in signatureInput
	if err := strictDecode(data, &in); err != nil {
		return Result{}, err
	}
	if len(in.SignInput) == 0 || in.Signature == nil {
		return Result{}, fmt.Errorf("missing required field (signInput, signature)")
	}
	// Every field of signInput is part of the signature base, so the whole
	// signed request must be valid UTF-8 with no lone surrogate escape before
	// encoding/json sees it: Go silently rewrites either to U+FFFD, which would
	// let a signature over the rewritten bytes verify a request that is not
	// byte-identical to the one the signer signed. The body path enforces this
	// too; the scalars (method, path, recipientDid, timestamp) need it here.
	if !utf8.Valid(in.SignInput) {
		return Result{}, fmt.Errorf("invalid signInput: not valid UTF-8")
	}
	if ink.ContainsLoneSurrogateEscape(in.SignInput) {
		return Result{}, fmt.Errorf("invalid signInput: unpaired UTF-16 surrogate")
	}
	var si signInputJSON
	if err := strictDecode(in.SignInput, &si); err != nil {
		return Result{}, err
	}
	if si.Method == nil || si.Path == nil || si.RecipientDid == nil || si.Timestamp == nil || len(si.Body) == 0 {
		return Result{}, fmt.Errorf("missing required signInput field (method, path, recipientDid, body, timestamp)")
	}
	pub, err := resolvePublicKey(in.PublicKeyHex, in.PublicKeyMultibase)
	if err != nil {
		return Result{}, err
	}
	body, err := ink.ParseSignedBody(si.Body)
	if err != nil {
		return Result{}, fmt.Errorf("invalid signed body: %w", err)
	}
	ok := ink.VerifyInkSignature(ink.InkSignInput{
		Method:       *si.Method,
		Path:         *si.Path,
		RecipientDid: *si.RecipientDid,
		Body:         body,
		Timestamp:    *si.Timestamp,
	}, *in.Signature, pub)
	return Result{OK: ok, Kind: "signature"}, nil
}

// resolvePublicKey resolves an Ed25519 key from exactly one of the two accepted
// encodings, a hex string or a base58btc multibase string. Supplying both,
// neither, an undecodable value, or a wrong-length key is bad input rather than
// a verification failure, so the two encodings reject a malformed key with the
// same exit code.
func resolvePublicKey(hexKey, multibaseKey *string) ([]byte, error) {
	var b []byte
	switch {
	case hexKey != nil && multibaseKey != nil:
		return nil, fmt.Errorf("provide exactly one of the hex or multibase public key")
	case hexKey != nil:
		decoded, err := hex.DecodeString(*hexKey)
		if err != nil {
			return nil, fmt.Errorf("invalid hex public key: %w", err)
		}
		b = decoded
	case multibaseKey != nil:
		decoded, err := ink.DecodePublicKeyMultibase(*multibaseKey)
		if err != nil {
			return nil, fmt.Errorf("invalid multibase public key: %w", err)
		}
		b = decoded
	default:
		return nil, fmt.Errorf("missing required public key")
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return b, nil
}

// An inclusion receipt is a witness-signed artifact, so its envelope is parsed
// strictly (unknown CLI fields and trailing data are rejected) but the receipt,
// event, and checkpoint are passed raw to the library parsers below. Those
// parsers, not strictDecode, define the artifact's accepted shape: a malformed
// one is a verification rejection (exit 1), the same decision the conformance
// runner makes, not a CLI usage error.

type receiptInput struct {
	WitnessPublicKeyHex       *string         `json:"witnessPublicKeyHex"`
	WitnessPublicKeyMultibase *string         `json:"witnessPublicKeyMultibase"`
	Receipt                   json.RawMessage `json:"receipt"`
	Event                     json.RawMessage `json:"event"`
	EventHash                 json.RawMessage `json:"eventHash"`
	LaterCheckpoint           json.RawMessage `json:"laterCheckpoint"`
}

// Receipt verifies a witness inclusion receipt: its structure, the witness
// Ed25519 service signature, and, when supplied, the event-bound proof walk and
// a later-checkpoint cross-check. The input shape matches the
// `inclusion-receipt` conformance vectors plus an optional
// witnessPublicKeyMultibase alternative to witnessPublicKeyHex.
func Receipt(data []byte) (Result, error) {
	var in receiptInput
	if err := decodeEnvelope(data, &in); err != nil {
		return Result{}, err
	}
	if len(in.Receipt) == 0 {
		return Result{}, fmt.Errorf("missing required field (receipt)")
	}
	pub, err := resolvePublicKey(in.WitnessPublicKeyHex, in.WitnessPublicKeyMultibase)
	if err != nil {
		return Result{}, err
	}
	const kind = "inclusion-receipt"
	receipt, ok := ink.ParseInclusionReceipt(in.Receipt)
	if !ok {
		return Result{OK: false, Kind: kind}, nil
	}
	var opts ink.ReceiptVerifyOptions
	if len(in.Event) > 0 {
		body, err := ink.ParseSignedBody(in.Event)
		if err != nil {
			return Result{OK: false, Kind: kind}, nil
		}
		m, isObj := body.(map[string]interface{})
		if !isObj {
			return Result{OK: false, Kind: kind}, nil
		}
		opts.Event = m
	}
	if len(in.EventHash) > 0 {
		// eventHash is part of the signed artifact's binding, so a malformed one
		// is a rejection rather than a CLI usage error, matching the receipt and
		// event handling above. json.Unmarshal accepts a JSON null as the empty
		// string (no binding), the same as the reference.
		if err := json.Unmarshal(in.EventHash, &opts.EventHash); err != nil {
			return Result{OK: false, Kind: kind}, nil
		}
	}
	if len(in.LaterCheckpoint) > 0 {
		cp, cpOK := ink.ParseCheckpointRef(in.LaterCheckpoint)
		if !cpOK {
			return Result{OK: false, Kind: kind}, nil
		}
		opts.LaterCheckpoint = &cp
	}
	return Result{OK: ink.VerifyInclusionReceipt(receipt, pub, opts), Kind: kind}, nil
}

// An audit-query response is a witness-signed body, so the same envelope-strict
// but artifact-tolerant rule as the receipt applies: the response and the
// optional checkpoint are passed raw to the library parsers, and a malformed one
// is a rejection. The per-event agent keys are a CLI request map (agentId to hex
// key); an absent or undecodable key makes the event-signature callback fail,
// which the library treats as the required per-event agent signature being
// unmet, a rejection rather than a CLI usage error.

type auditResponseInput struct {
	WitnessPublicKeyHex       *string           `json:"witnessPublicKeyHex"`
	WitnessPublicKeyMultibase *string           `json:"witnessPublicKeyMultibase"`
	Response                  json.RawMessage   `json:"response"`
	ExpectedRequester         *string           `json:"expectedRequester"`
	ExpectedMessageID         *string           `json:"expectedMessageId"`
	ExpectedServiceDid        *string           `json:"expectedServiceDid"`
	AgentKeysHex              map[string]string `json:"agentKeysHex"`
	LaterCheckpoint           json.RawMessage   `json:"laterCheckpoint"`
}

// AuditResponse verifies a witness audit-query response: structure, the
// requester and messageId bindings, the witness envelope signature, the
// per-event scope and proof walks, and the required per-event agent signature,
// then an optional later-checkpoint cross-check. The input shape matches the
// `audit-query-response` conformance vectors plus an optional
// witnessPublicKeyMultibase alternative to witnessPublicKeyHex.
func AuditResponse(data []byte) (Result, error) {
	var in auditResponseInput
	if err := decodeEnvelope(data, &in); err != nil {
		return Result{}, err
	}
	if len(in.Response) == 0 {
		return Result{}, fmt.Errorf("missing required field (response)")
	}
	if in.ExpectedRequester == nil || in.ExpectedMessageID == nil {
		return Result{}, fmt.Errorf("missing required field (expectedRequester, expectedMessageId)")
	}
	pub, err := resolvePublicKey(in.WitnessPublicKeyHex, in.WitnessPublicKeyMultibase)
	if err != nil {
		return Result{}, err
	}
	const kind = "audit-query-response"

	opts := ink.AuditQueryVerifyOptions{
		ExpectedRequester: *in.ExpectedRequester,
		ExpectedMessageID: *in.ExpectedMessageID,
	}
	if in.ExpectedServiceDid != nil {
		opts.ExpectedServiceDid = *in.ExpectedServiceDid
	}
	// The verifier requires a per-event agent-signature check (Auditability
	// §7.5). The callback resolves the event's agent key from the request map and
	// fails closed when the key is absent, undecodable, or the wrong length, so a
	// missing or malformed key rejects the event rather than skipping the check.
	opts.VerifyEventSignature = eventSignatureVerifier(in.AgentKeysHex)

	if len(in.LaterCheckpoint) > 0 {
		cp, cpOK := ink.ParseCheckpointRef(in.LaterCheckpoint)
		if !cpOK {
			return Result{OK: false, Kind: kind}, nil
		}
		opts.LaterCheckpoint = &cp
	}

	body, err := ink.ParseSignedBody(in.Response)
	if err != nil {
		return Result{OK: false, Kind: kind}, nil
	}
	resp, isObj := body.(map[string]interface{})
	if !isObj {
		return Result{OK: false, Kind: kind}, nil
	}
	return Result{OK: ink.VerifyInkAuditQueryResponse(resp, pub, opts), Kind: kind}, nil
}

// eventSignatureVerifier builds the per-event agent-signature callback the audit
// verifier requires. It resolves the event's agent key from the request map and
// fails closed: an event with a missing, empty, or non-string agentId, or one
// whose key is absent, undecodable, or the wrong length, returns false so the
// required per-event signature is treated as unmet rather than skipped. An empty
// agentId is rejected explicitly so an agentKeysHex[""] entry cannot stand in for
// a real submitting-agent identity.
func eventSignatureVerifier(agentKeys map[string]string) func(map[string]interface{}) bool {
	return func(event map[string]interface{}) bool {
		agentID, ok := event["agentId"].(string)
		if !ok || agentID == "" {
			return false
		}
		keyHex, ok := agentKeys[agentID]
		if !ok {
			return false
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return false
		}
		return ink.VerifyAuditEventSignature(event, key)
	}
}

// decodeEnvelope decodes a CLI request envelope that wraps one or more raw
// protocol artifacts. It rejects unknown fields, a duplicate top-level key, and
// trailing data, but unlike strictDecode it does not walk into the raw
// sub-messages: the wrapped artifact is handed verbatim to its library parser,
// whose tolerance (number spellings, last-wins on a repeated key) defines what
// is accepted, so the CLI does not add a stricter rule that would diverge from
// the reference verifier. The duplicate-key check is therefore top-level only.
func decodeEnvelope(data []byte, v any) error {
	if err := rejectDuplicateTopLevelKeys(data); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid JSON: unexpected trailing data")
	}
	return nil
}

// rejectDuplicateTopLevelKeys errors on a repeated key in the outermost JSON
// object only. It skips the value after each key without inspecting nested
// objects, so a duplicate key inside a wrapped artifact is left to that
// artifact's own parser rather than rejected here.
func rejectDuplicateTopLevelKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil // not an object; the typed decode reports the shape error
	}
	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("invalid object key")
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		if err := skipValue(dec); err != nil {
			return err
		}
	}
	return nil
}

// skipValue consumes exactly one JSON value from dec, descending through any
// nested object or array so the caller resumes at the next sibling.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil // a scalar value is one token
	}
	depth := 1
	for depth > 0 {
		tt, err := dec.Token()
		if err != nil {
			return err
		}
		if dd, ok := tt.(json.Delim); ok {
			if dd == '{' || dd == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
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
