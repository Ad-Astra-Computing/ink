package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
)

// The evidence primitive of specs/ink-attestation.md: a signed claim by one
// principal about another, verified from raw bytes, judged only by receiver
// policy. Base verification is signature, shape and window; there is no
// audience, no replay and no judgment of issuer or claim.

var attestationTopLevelKeys = map[string]bool{
	"protocol": true, "type": true, "issuer": true, "subject": true,
	"claimType": true, "claim": true, "attestationId": true,
	"issuedAt": true, "expiresAt": true, "signature": true,
}

var attestationRequiredKeys = []string{
	"protocol", "type", "issuer", "subject", "claimType", "claim",
	"attestationId", "issuedAt", "expiresAt", "signature",
}

const (
	attestationIDMin  = 16
	attestationIDMax  = 256
	claimTypeMin      = 3
	claimTypeMax      = 128
	attestationIDMaxs = 512 // issuer and subject share the DID/agent-id bound
)

// MaxAttestationBodyBytes is the byte ceiling on a raw attestation body,
// enforced before decoding, matching the reference MAX_ATTESTATION_BODY_BYTES.
const MaxAttestationBodyBytes = 65536

var claimTypeRe = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)
var attestationIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// AttestationReason is the stable rejection discriminator, matching the
// reference verifier's reason strings.
type AttestationReason string

const (
	AttestationReasonNone        AttestationReason = ""
	AttestationReasonSchema      AttestationReason = "schema"
	AttestationReasonSignature   AttestationReason = "signature"
	AttestationReasonNotYetValid AttestationReason = "not_yet_valid"
	AttestationReasonExpired     AttestationReason = "expired"
)

// VerifyAttestation verifies an attestation from its raw bytes against the
// resolved issuer public key and the verifier clock. It mirrors the TypeScript
// verifyAttestation byte for byte: byte cap, the shared signed-body parse,
// structural bounds, strict schema, a body signature over "tulpa/sign\n" +
// JCS(attestation without signature) under RFC 8032 strict Ed25519, then the
// validity window with an inclusive lower and exclusive upper bound. It fails
// closed with a typed reason on the first failure.
func VerifyAttestation(raw []byte, issuerPublicKey []byte, now string) (bool, AttestationReason) {
	reason, _ := verifyAttestationWith(raw, fixedKey(issuerPublicKey), now)
	return reason == AttestationReasonNone, reason
}

// AttestationKeyResult is the result of VerifyAttestationWithKeys: whether
// the attestation verified, the typed rejection reason on failure, and the
// candidate key that verified it on success.
type AttestationKeyResult struct {
	OK     bool
	Reason AttestationReason
	Key    MultiKeyResult
}

// VerifyAttestationWithKeys verifies an attestation from its raw bytes
// against a rotation-aware candidate issuer key set. Security
// considerations §"Issuer key rotation" (ink-attestation.md): an
// attestation verifies under the same rotation rules as any other signed
// body. A retired issuer key still verifies an attestation issued inside
// that key's validity window, and a revoked issuer key never verifies,
// even for an attestation whose issuedAt predates the revocation.
//
// The artifact clock is issuedAt, the moment the issuer signed the claim,
// not now (the verifier's clock, used only to judge freshness against
// expiresAt). Same code path as VerifyAttestation; only the signature step
// is rotation-aware.
func VerifyAttestationWithKeys(raw []byte, keys []CandidateKey, now string, hintKeyID string) AttestationKeyResult {
	reason, key := verifyAttestationWith(raw, candidateKeys(keys, hintKeyID), now)
	if reason != AttestationReasonNone {
		return AttestationKeyResult{Reason: reason}
	}
	return AttestationKeyResult{OK: true, Reason: reason, Key: key}
}

func verifyAttestationWith(raw []byte, s signerStrategy, now string) (AttestationReason, MultiKeyResult) {
	if len(raw) > MaxAttestationBodyBytes {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	obj, okParse := ParseSignedObject(raw)
	if !okParse {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	if !withinBodyBounds(obj) {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	signature, ok := validateAttestation(obj)
	if !ok {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	if !signatureRe.MatchString(signature) {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	if !s.keyOK() {
		return AttestationReasonSignature, MultiKeyResult{}
	}
	var artifactMs int64
	if s.needsClock {
		issuedAt, _ := obj["issuedAt"].(string)
		ms, ok := ParseInkTimestampMs(issuedAt)
		if !ok {
			return AttestationReasonSchema, MultiKeyResult{}
		}
		artifactMs = ms
	}
	unsigned := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	result := s.verify(func(pub []byte) bool {
		return ed25519.Verify(ed25519.PublicKey(pub), []byte("tulpa/sign\n"+canonical), sig)
	}, artifactMs)
	if !result.Verified {
		return AttestationReasonSignature, MultiKeyResult{}
	}

	issuedAt, _ := obj["issuedAt"].(string)
	expiresAt, _ := obj["expiresAt"].(string)
	start, okStart := ParseInkTimestampMs(issuedAt)
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okStart || !okEnd {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	nowMs, okNow := ParseInkTimestampMs(now)
	if !okNow {
		return AttestationReasonSchema, MultiKeyResult{}
	}
	if nowMs < start {
		return AttestationReasonNotYetValid, MultiKeyResult{}
	}
	if nowMs >= end {
		return AttestationReasonExpired, MultiKeyResult{}
	}
	return AttestationReasonNone, result
}

// validateClaimTypeSet enforces the claim-type set shape shared by the
// evidence policy and the structured refusal: an array of 1 to 32 distinct
// strings under the claim-type grammar and bounds.
func validateClaimTypeSet(v interface{}) bool {
	arr, ok := v.([]interface{})
	if !ok || len(arr) < 1 || len(arr) > 32 {
		return false
	}
	seen := make(map[string]bool, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok || utf16Len(s) < claimTypeMin || utf16Len(s) > claimTypeMax || !claimTypeRe.MatchString(s) {
			return false
		}
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// validateCardAttestations enforces the Agent Card attestations member: an
// array of 1 to 16 entries, each a well-formed attestation by shape and
// signature grammar. Signature verification and the validity window against a
// clock are verify-time decisions, not card validation: a card carrying a
// stale but well-formed attestation stays valid.
func validateCardAttestations(v interface{}) bool {
	arr, ok := v.([]interface{})
	if !ok || len(arr) < 1 || len(arr) > 16 {
		return false
	}
	for _, e := range arr {
		obj, ok := e.(map[string]interface{})
		if !ok {
			return false
		}
		sig, ok := validateAttestation(obj)
		if !ok || !signatureRe.MatchString(sig) {
			return false
		}
	}
	return true
}

// validateEvidencePolicy enforces the Agent Card evidencePolicy member: an
// object whose optional required and preferred members are claim-type sets.
// Unknown members inside it are ignored for interpretation, matching the
// reference schema's passthrough.
func validateEvidencePolicy(v interface{}) bool {
	p, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	for _, k := range []string{"required", "preferred"} {
		if pv, present := p[k]; present {
			if !validateClaimTypeSet(pv) {
				return false
			}
		}
	}
	return true
}

// ValidateEvidenceRefusal validates the structured policy:evidence_required
// refusal body of specs/ink-attestation.md, mirroring the reference
// parseEvidenceRefusal: the standard endpoint error members are pinned, the
// claim-type set is bounded and distinct, and unknown members are tolerated
// for forward compatibility.
func ValidateEvidenceRefusal(m map[string]interface{}) bool {
	if m == nil {
		return false
	}
	if s, _ := m["protocol"].(string); s != "ink/0.1" {
		return false
	}
	if b, ok := m["error"].(bool); !ok || !b {
		return false
	}
	if s, _ := m["code"].(string); s != "policy:evidence_required" {
		return false
	}
	v, present := m["requiredClaimTypes"]
	if !present || !validateClaimTypeSet(v) {
		return false
	}
	if mv, present := m["message"]; present {
		s, ok := mv.(string)
		if !ok || utf16Len(s) > 500 {
			return false
		}
	}
	return true
}

// validateAttestation enforces the strict shape: exactly the ten members, the
// single vendor-neutral wire spelling, the claim-type and attestation-id
// grammars, the id bounds and a strictly positive validity window. It returns
// the signature string on success.
func validateAttestation(obj map[string]interface{}) (string, bool) {
	for k := range obj {
		if !attestationTopLevelKeys[k] {
			return "", false
		}
	}
	for _, k := range attestationRequiredKeys {
		if _, ok := obj[k]; !ok {
			return "", false
		}
	}
	if s, _ := obj["protocol"].(string); s != "ink/0.1" {
		return "", false
	}
	if s, _ := obj["type"].(string); s != "network.ink.attestation" {
		return "", false
	}
	issuer, ok := obj["issuer"].(string)
	if !ok || issuer == "" || utf16Len(issuer) > attestationIDMaxs {
		return "", false
	}
	subject, ok := obj["subject"].(string)
	if !ok || subject == "" || utf16Len(subject) > attestationIDMaxs {
		return "", false
	}
	claimType, ok := obj["claimType"].(string)
	if !ok || utf16Len(claimType) < claimTypeMin || utf16Len(claimType) > claimTypeMax || !claimTypeRe.MatchString(claimType) {
		return "", false
	}
	if _, ok := obj["claim"].(map[string]interface{}); !ok {
		return "", false
	}
	attestationID, ok := obj["attestationId"].(string)
	if !ok || utf16Len(attestationID) < attestationIDMin || utf16Len(attestationID) > attestationIDMax || !attestationIDRe.MatchString(attestationID) {
		return "", false
	}
	issuedAt, ok := obj["issuedAt"].(string)
	if !ok {
		return "", false
	}
	expiresAt, ok := obj["expiresAt"].(string)
	if !ok {
		return "", false
	}
	start, okStart := ParseInkTimestampMs(issuedAt)
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okStart || !okEnd || end <= start {
		return "", false
	}
	signature, ok := obj["signature"].(string)
	if !ok {
		return "", false
	}
	return signature, true
}
