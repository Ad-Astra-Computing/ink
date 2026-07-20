package signcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// strictDecode decodes a single JSON object into v, rejecting unknown fields,
// duplicate object keys, and any trailing data. It returns a bad-input error
// (wrapped "invalid JSON") on any of those, matching the strict decode the
// verify package applies to its request envelopes so the sign and verify sides
// accept the same request shape.
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
// any object. encoding/json would otherwise silently keep the last value, which
// hides a malformed request and could diverge from another implementation.
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
