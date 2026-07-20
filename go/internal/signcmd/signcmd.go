// Package signcmd is the producing side of INK transport auth (§3.3) behind a
// transport-neutral surface, the mirror of internal/verify. The CLI's
// sign-request command calls Request today; a later sender component can call
// the same function without going through argv or stdin. The signing itself
// lives in the reference Go library (github.com/Ad-Astra-Computing/ink/go/ink);
// this package only decodes a request, resolves the key, and formats the result.
package signcmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

// Result is the output of signing one INK transport request. Base is the exact
// §3.3 signature base the signature covers, echoed so a cross-implementation
// test can pin the signed bytes; Signature is the base64url Ed25519 signature;
// AuthHeader is the ready-to-send Authorization header value; PublicKeyHex is
// the verifying key derived from the supplied seed; SignInput echoes the signed
// request so a verifier reconstructs the base from the same fields.
type Result struct {
	Base         string          `json:"base"`
	Signature    string          `json:"signature"`
	AuthHeader   string          `json:"authHeader"`
	PublicKeyHex string          `json:"publicKeyHex"`
	SignInput    json.RawMessage `json:"signInput"`
}

type signInputJSON struct {
	Method       *string         `json:"method"`
	Path         *string         `json:"path"`
	RecipientDid *string         `json:"recipientDid"`
	Body         json.RawMessage `json:"body"`
	Timestamp    *string         `json:"timestamp"`
}

type requestInput struct {
	PrivateKeyHex *string         `json:"privateKeyHex"`
	SignInput     json.RawMessage `json:"signInput"`
	KeyID         *string         `json:"keyId"`
}

// Request signs an INK transport request. The input is a JSON object with a
// 32-byte Ed25519 seed (privateKeyHex), a signInput of the same shape the
// signature-base conformance vectors use (method, path, recipientDid, body,
// timestamp), and an optional keyId. It parses the body through
// ink.ParseSignedBody so a lone UTF-16 surrogate is rejected before signing,
// signs with ink.SignInkMessage, and builds the Authorization header with
// ink.BuildAuthHeader. A malformed request is an error (bad input), not a
// silent zero-value signature.
func Request(data []byte) (Result, error) {
	var in requestInput
	if err := strictDecode(data, &in); err != nil {
		return Result{}, err
	}
	if in.PrivateKeyHex == nil || len(in.SignInput) == 0 {
		return Result{}, fmt.Errorf("missing required field (privateKeyHex, signInput)")
	}
	seed, err := hex.DecodeString(*in.PrivateKeyHex)
	if err != nil {
		return Result{}, fmt.Errorf("invalid hex private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return Result{}, fmt.Errorf("private key seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Every field of signInput is part of the signature base, so the whole
	// signed request must be valid UTF-8 with no lone surrogate escape before
	// encoding/json rewrites either to U+FFFD (which would sign bytes that are
	// not byte-identical to what a peer reconstructs). The body path enforces
	// this too; the scalars need it here. Mirrors verify.Signature.
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
	body, err := ink.ParseSignedBody(si.Body)
	if err != nil {
		return Result{}, fmt.Errorf("invalid signed body: %w", err)
	}
	// A present keyId must be a valid parameter, mirroring the TS reference
	// where `keyId !== undefined` is validated against the grammar. An omitted
	// keyId (JSON field absent) emits the bare two-token header, but a
	// present-empty `"keyId":""` is caller intent to set one and is rejected
	// rather than silently dropped.
	keyID := ""
	if in.KeyID != nil {
		if *in.KeyID == "" {
			return Result{}, fmt.Errorf("keyId must not be empty when present")
		}
		keyID = *in.KeyID
	}

	req := ink.InkSignInput{
		Method:       *si.Method,
		Path:         *si.Path,
		RecipientDid: *si.RecipientDid,
		Body:         body,
		Timestamp:    *si.Timestamp,
	}
	base, err := ink.BuildSignatureBase(req)
	if err != nil {
		return Result{}, fmt.Errorf("cannot build signature base: %w", err)
	}
	signature, err := ink.SignInkMessage(req, priv)
	if err != nil {
		return Result{}, fmt.Errorf("cannot sign request: %w", err)
	}
	authHeader, err := ink.BuildAuthHeader(signature, keyID)
	if err != nil {
		return Result{}, fmt.Errorf("cannot build authorization header: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	return Result{
		Base:         base,
		Signature:    signature,
		AuthHeader:   authHeader,
		PublicKeyHex: hex.EncodeToString(pub),
		SignInput:    append(json.RawMessage(nil), in.SignInput...),
	}, nil
}
