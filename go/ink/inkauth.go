package ink

import (
	"time"
)

// The assembled transport-auth receiver (Protocol §3.3 and §3.5). The
// primitives in this package each answer one question: ParseInkAuthHeader
// reads the header, ParseInkTimestampMs judges a timestamp, VerifyInkSignature
// checks one key, VerifyInkSignatureWithKeys applies the rotation rule, and
// CheckReplay applies the freshness window to a seen set. VerifyInkAuth is the
// order they run in, with the error code each stage returns and the key
// resolution precedence between them. It mirrors verifyInkAuth in
// src/middleware/ink-auth.ts stage for stage so a request the reference rejects
// with a given code is rejected here with the same code.

// NonceStore is the single-use nonce record a receiver keeps so a captured
// signed request cannot be replayed inside the freshness window. A store MUST
// retain a recorded nonce for at least the five-minute window; evicting sooner
// reopens the replay the store exists to close. A backend error from either
// method fails the request closed with nonce_store_error.
type NonceStore interface {
	Has(nonce string) (bool, error)
	Add(nonce string) error
}

// AtomicNonceStore is a NonceStore with an atomic check-and-record. When a
// store provides it, VerifyInkAuth uses it INSTEAD of Has then Add, which have
// a check-then-act race: on a distributed store, two concurrent replays of one
// signed request can both observe "not seen" before either records it. A
// distributed store SHOULD implement this atomically (a conditional put,
// INSERT ... ON CONFLICT DO NOTHING, or SET key val NX). AddIfAbsent returns
// true when the nonce was newly recorded and false when it was already
// present.
type AtomicNonceStore interface {
	NonceStore
	AddIfAbsent(nonce string) (bool, error)
}

// InkAuthInput is one inbound request as the receiver sees it, plus the
// receiver's own policy: how it resolves the sender's key and how it records
// nonces.
type InkAuthInput struct {
	// AuthHeader is the Authorization header value; empty when absent.
	AuthHeader string
	// Method, Path and RecipientAgentID are the receiver's own view of the
	// request. Path is the path component of the endpoint the receiver
	// published on its card, with no query string, and RecipientAgentID is
	// the receiver's principal.
	Method           string
	Path             string
	RecipientAgentID string
	// Body is the decoded JSON request body. It must carry `from` (the sender
	// agentId) and `timestamp`; `nonce` is required when NonceStore is set.
	Body map[string]interface{}
	// ResolvePublicKey returns the single stored key for a sender (a
	// connection record), or nil when there is none.
	ResolvePublicKey func(agentID string) []byte
	// ResolveKeySet returns the sender's published key set. published=false
	// means the sender has no key set, and the receiver falls through to
	// ResolvePublicKey and then the key embedded in a key-derived agentId. A
	// published set is authoritative even when empty: it is the only set of
	// keys the signature may verify against, and a set that rejects the
	// signature never falls back to a stored or bootstrap key.
	ResolveKeySet func(agentID string) (keys []CandidateKey, published bool)
	// AllowRetiredKey opts into a rotation grace window. By default a
	// signature that only a retired entry verifies is refused with
	// retired_key_for_live_auth; a receiver that sets this MUST bound the
	// window in its own policy, since an unbounded one restores every retired
	// key as a live credential. Only the key-set path carries status, so the
	// stored-key and bootstrap paths are unaffected.
	AllowRetiredKey bool
	// NonceStore records body.nonce after the signature verifies. Exactly one
	// of NonceStore and DeferNonceHandling must be set: a receiver with
	// neither is rejected with nonce_handling_required so a deployment that
	// forgot replay protection fails loudly.
	NonceStore NonceStore
	// DeferNonceHandling is the explicit statement that the caller enforces
	// single use itself (CheckReplay or an equivalent) later in its pipeline.
	DeferNonceHandling bool
	// Now is the receiver clock the freshness window is measured against; nil
	// means time.Now.
	Now func() time.Time
}

// InkAuthResult is the receiver's decision. On Valid, SenderAgentID is the
// raw sender-chosen spelling (for audit and display) and Principal is the
// canonical, prefix-independent identity: authorization, block lists, rate
// limits and every per-sender control MUST key on Principal, never on
// SenderAgentID, or a sender switches the tulpa:/ink: prefix to evade them.
// KeyID and KeyStatus name the key-set entry that verified and are empty on
// the stored-key and bootstrap paths. A rejection carries only Error, so a
// caller cannot log a sender or key as authenticated when it was not.
type InkAuthResult struct {
	Valid         bool
	SenderAgentID string
	Principal     string
	KeyID         string
	KeyStatus     string
	Error         string
}

func authReject(code string) InkAuthResult { return InkAuthResult{Error: code} }

// VerifyInkAuth parses and verifies an INK-Ed25519 Authorization header
// against the request it accompanies, applying the freshness window, the
// fail-closed nonce policy and the key resolution precedence of §3.3.
//
// Stages, in order, with the code each returns:
//
//  1. header absent: missing_authorization; body not an object: missing_sender;
//     header outside the §3.3 grammar: invalid_auth_scheme.
//  2. body.from absent or empty: missing_sender; not a string or longer than
//     256 UTF-16 code units: invalid_from_field.
//  3. body.timestamp absent, empty or not a string: missing_timestamp; not a
//     strict RFC 3339 timestamp: invalid_timestamp; more than 30 s ahead:
//     timestamp_too_far_future; more than 5 min old: timestamp_expired.
//  4. neither NonceStore nor DeferNonceHandling: nonce_handling_required;
//     with a store, a body.nonce that is absent, not a string, or outside 16
//     to 256 characters of [A-Za-z0-9_-]: missing_nonce.
//  5. key resolution. A published key set (ResolveKeySet) is tried first and
//     is authoritative: an empty set or one that rejects the signature is
//     signature_verification_failed with no fallback, and a match on a
//     retired entry is retired_key_for_live_auth unless AllowRetiredKey.
//     Without a published set, ResolvePublicKey and then the key embedded in
//     a key-derived agentId are tried; neither yielding a key is
//     unresolvable_sender_key, and a key that does not verify is
//     invalid_signature.
//  6. nonce recording, only after the signature verified so a forged request
//     never pollutes the store: AddIfAbsent when the store provides it, else
//     Has then Add. A nonce already present is nonce_replay; a backend error
//     or panic is nonce_store_error.
//
// The body is signed as delivered (§3.3 strips nothing before canonicalizing),
// so Body must be the decoded request exactly as received.
func VerifyInkAuth(in InkAuthInput) InkAuthResult {
	if in.AuthHeader == "" {
		return authReject("missing_authorization")
	}
	if in.Body == nil {
		return authReject("missing_sender")
	}
	parsed := ParseInkAuthHeader(in.AuthHeader)
	if !parsed.OK {
		return authReject(parsed.Reason)
	}

	rawFrom, present := in.Body["from"]
	senderID, isString := rawFrom.(string)
	if present && !isString {
		return authReject("invalid_from_field")
	}
	if senderID == "" {
		return authReject("missing_sender")
	}
	// Cap the sender id before it reaches a resolver or the multibase
	// decoder, in the reference's UTF-16 units.
	if utf16Len(senderID) > 256 {
		return authReject("invalid_from_field")
	}

	timestamp, _ := in.Body["timestamp"].(string)
	if timestamp == "" {
		return authReject("missing_timestamp")
	}
	msgMs, ok := ParseInkTimestampMs(timestamp)
	if !ok {
		return authReject("invalid_timestamp")
	}
	now := in.Now
	if now == nil {
		now = time.Now
	}
	drift := msgMs - now().UnixMilli()
	if drift > maxFutureTimestamp.Milliseconds() {
		return authReject("timestamp_too_far_future")
	}
	if -drift > maxTimestampAge.Milliseconds() {
		return authReject("timestamp_expired")
	}

	if in.NonceStore == nil && !in.DeferNonceHandling {
		return authReject("nonce_handling_required")
	}
	var bodyNonce string
	if in.NonceStore != nil {
		candidate, _ := in.Body["nonce"].(string)
		if n := utf16Len(candidate); n < 16 || n > 256 || !nonceRe.MatchString(candidate) {
			return authReject("missing_nonce")
		}
		bodyNonce = candidate
	}

	principal, err := CanonicalAgentPrincipal(senderID)
	if err != nil {
		return authReject("invalid_from_field")
	}

	sigInput := InkSignInput{
		Method:       in.Method,
		Path:         in.Path,
		RecipientDid: in.RecipientAgentID,
		Body:         in.Body,
		Timestamp:    timestamp,
	}

	if in.ResolveKeySet != nil {
		keys, published := in.ResolveKeySet(senderID)
		if published {
			if len(keys) == 0 {
				return authReject("signature_verification_failed")
			}
			r := VerifyInkSignatureForLiveAuth(sigInput, parsed.Signature, keys, parsed.KeyID, in.AllowRetiredKey)
			if !r.Verified {
				return authReject(r.Error)
			}
			if code := recordNonce(in.NonceStore, bodyNonce); code != "" {
				return authReject(code)
			}
			return InkAuthResult{
				Valid:         true,
				SenderAgentID: senderID,
				Principal:     principal,
				KeyID:         r.KeyID,
				KeyStatus:     r.KeyStatus,
			}
		}
	}

	var publicKey []byte
	if in.ResolvePublicKey != nil {
		publicKey = in.ResolvePublicKey(senderID)
	}
	if len(publicKey) == 0 {
		publicKey, err = extractPublicKeyFromAgentID(senderID)
		if err != nil || len(publicKey) == 0 {
			return authReject("unresolvable_sender_key")
		}
	}
	if !VerifyInkSignature(sigInput, parsed.Signature, publicKey) {
		return authReject("invalid_signature")
	}
	if code := recordNonce(in.NonceStore, bodyNonce); code != "" {
		return authReject(code)
	}
	return InkAuthResult{Valid: true, SenderAgentID: senderID, Principal: principal}
}

// recordNonce is the post-verify check-and-record. It returns the rejection
// code, or "" when the nonce was newly recorded or no store is in use. A
// store that panics is treated like one that returned an error.
func recordNonce(store NonceStore, nonce string) (code string) {
	if store == nil {
		return ""
	}
	defer func() {
		if r := recover(); r != nil {
			code = "nonce_store_error"
		}
	}()
	if atomic, ok := store.(AtomicNonceStore); ok {
		added, err := atomic.AddIfAbsent(nonce)
		if err != nil {
			return "nonce_store_error"
		}
		if !added {
			return "nonce_replay"
		}
		return ""
	}
	seen, err := store.Has(nonce)
	if err != nil {
		return "nonce_store_error"
	}
	if seen {
		return "nonce_replay"
	}
	if err := store.Add(nonce); err != nil {
		return "nonce_store_error"
	}
	return ""
}
