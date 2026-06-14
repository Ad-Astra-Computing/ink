// Package ink is an independent Go implementation of INK's security-relevant
// decisions, built to run the shared conformance vectors in conformance/v1.
// It deliberately does not port the TypeScript reference; agreement on the same
// vectors is what proves the wire spec is not accidentally TypeScript-shaped.
package ink

import (
	"errors"
	"math/big"
	"strings"
	"unicode/utf16"
)

// utf16Len returns the number of UTF-16 code units in s, matching JavaScript's
// String.length. INK's length caps are specified against that count, so the Go
// and TypeScript implementations must measure strings the same way or they will
// disagree on accept/reject for a multi-byte agentId.
func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ed25519Multicodec is the multicodec prefix for an Ed25519 public key (0xed 0x01).
var ed25519Multicodec = []byte{0xed, 0x01}

var big58 = big.NewInt(58)

// decodeBase58 decodes a base58btc string to bytes, preserving leading zero
// bytes encoded as leading '1' characters.
func decodeBase58(s string) ([]byte, error) {
	num := new(big.Int)
	for _, ch := range s {
		idx := strings.IndexRune(base58Alphabet, ch)
		if idx < 0 {
			return nil, errors.New("invalid base58 character")
		}
		num.Mul(num, big58)
		num.Add(num, big.NewInt(int64(idx)))
	}
	out := num.Bytes()
	for _, ch := range s {
		if ch != '1' {
			break
		}
		out = append([]byte{0}, out...)
	}
	return out, nil
}

// encodeBase58 encodes bytes to a base58btc string, emitting a leading '1' for
// each leading zero byte.
func encodeBase58(b []byte) string {
	num := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	zero := new(big.Int)
	var rev []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, big58, mod)
		rev = append(rev, base58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		rev = append(rev, '1')
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return string(rev)
}

// DecodePublicKeyMultibase decodes a multibase base58btc Ed25519 public key
// (z-prefixed, 0xed 0x01 multicodec) to its raw 32 bytes.
func DecodePublicKeyMultibase(multibase string) ([]byte, error) {
	if n := utf16Len(multibase); n == 0 || n > 1024 {
		return nil, errors.New("multibase must be a non-empty string under 1024 chars")
	}
	if !strings.HasPrefix(multibase, "z") {
		return nil, errors.New("expected multibase base58btc prefix 'z'")
	}
	decoded, err := decodeBase58(multibase[1:])
	if err != nil {
		return nil, err
	}
	if len(decoded) < 2 || decoded[0] != ed25519Multicodec[0] || decoded[1] != ed25519Multicodec[1] {
		return nil, errors.New("invalid Ed25519 multicodec prefix")
	}
	key := decoded[2:]
	if len(key) != 32 {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return key, nil
}

// EncodePublicKeyMultibase encodes a raw 32-byte Ed25519 public key as a
// z-prefixed multibase base58btc string with the 0xed 0x01 multicodec.
func EncodePublicKeyMultibase(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", errors.New("publicKey must be 32 bytes")
	}
	prefixed := make([]byte, 0, len(ed25519Multicodec)+len(publicKey))
	prefixed = append(prefixed, ed25519Multicodec...)
	prefixed = append(prefixed, publicKey...)
	return "z" + encodeBase58(prefixed), nil
}
