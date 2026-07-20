// Package sealcmd is the producing side of INK payload encryption (§3.4) behind
// a transport-neutral surface, the mirror of internal/verify and the encryption
// counterpart of internal/signcmd. The CLI's seal-payload command calls Seal
// today; a later sender component can call the same function without going
// through argv or stdin. The sealing itself lives in the reference Go library
// (github.com/Ad-Astra-Computing/ink/go/ink); this package only decodes a
// request, drives ink.EncryptInkPayload, and formats the resulting envelope.
package sealcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

// Result is the output of sealing one INK payload. Envelope is the outer ECIES
// envelope ready to marshal onto the wire; it decrypts with both the Go
// DecryptInkPayload and the TypeScript reference decryptInkPayload.
type Result struct {
	Envelope map[string]any `json:"envelope"`
}

type sealInput struct {
	RecipientPublicKeyHex *string         `json:"recipientPublicKeyHex"`
	SenderDid             *string         `json:"senderDid"`
	Timestamp             *string         `json:"timestamp"`
	MessageNonce          *string         `json:"messageNonce"`
	Plaintext             json.RawMessage `json:"plaintext"`
	MessageType           *string         `json:"messageType"`
}

// Seal encrypts an INK payload. The input is a JSON object with the recipient's
// static X25519 public key (recipientPublicKeyHex), the sender DID, the
// timestamp and messageNonce, a plaintext object, and an optional messageType.
// Each call draws a fresh ephemeral key and a random AES nonce: the CLI
// deliberately does NOT expose the library's deterministic ephemeral/nonce
// override, so it cannot be driven into an AES-GCM key/nonce reuse. A malformed
// request is an error (bad input), not a silently empty envelope.
func Seal(data []byte) (Result, error) {
	var in sealInput
	if err := strictDecode(data, &in); err != nil {
		return Result{}, err
	}

	// Every AAD-bound scalar (senderDid, timestamp, messageNonce) and the inner
	// plaintext are authenticated or emitted as given, so a lone UTF-16 surrogate
	// escape anywhere in the request must be rejected before encoding/json
	// rewrites it to U+FFFD. The reference jcsCanonicalize rejects unpaired
	// surrogates in AAD values, so accepting one here would seal an envelope the
	// reference producer refuses. strictDecode already checked utf8.Valid(data);
	// this scans the raw escapes the same way signcmd does for a signed request.
	if ink.ContainsLoneSurrogateEscape(data) {
		return Result{}, fmt.Errorf("invalid request: unpaired UTF-16 surrogate")
	}

	if in.RecipientPublicKeyHex == nil || in.SenderDid == nil || in.Timestamp == nil ||
		in.MessageNonce == nil || len(in.Plaintext) == 0 {
		return Result{}, fmt.Errorf("missing required field (recipientPublicKeyHex, senderDid, timestamp, messageNonce, plaintext)")
	}

	var plaintext map[string]any
	if err := json.Unmarshal(in.Plaintext, &plaintext); err != nil {
		return Result{}, fmt.Errorf("invalid plaintext: %w", err)
	}
	if plaintext == nil {
		return Result{}, fmt.Errorf("invalid plaintext: must be a JSON object")
	}

	var opts *ink.InkEncryptOptions
	if in.MessageType != nil {
		opts = &ink.InkEncryptOptions{MessageType: *in.MessageType}
	}

	envelope, err := ink.EncryptInkPayload(plaintext, *in.SenderDid, *in.RecipientPublicKeyHex, *in.Timestamp, *in.MessageNonce, opts)
	if err != nil {
		return Result{}, fmt.Errorf("cannot seal payload: %w", err)
	}

	return Result{Envelope: envelope}, nil
}

// strictDecode decodes a single JSON object into v, rejecting duplicate object
// keys and trailing data. Unknown top-level fields are rejected so a mistyped
// request surfaces as bad input rather than a silently dropped field. It mirrors
// signcmd.strictDecode.
func strictDecode(data []byte, v any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid JSON: not valid UTF-8")
	}
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
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

// rejectDuplicateKeys walks one JSON value and errors on a repeated key within
// any object, so a malformed request cannot hide a field behind a later
// duplicate. Mirrors signcmd.rejectDuplicateKeys.
func rejectDuplicateKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
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
		_, err := dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := rejectDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
