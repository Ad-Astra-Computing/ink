package ink

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Self-authenticating Agent Card verifier tests (ink-agent-card-signature.md,
// Phase A slice 2). These port the key cases from
// test/agent-card-signature.test.ts and confirm the Go verifier reaches the same
// accept/reject decision with the same reason. The signing helpers below let Go
// mint fixtures; Go's production role is verify-only, so they live in the test.
// Keypairs are fixed 32-byte seeds so the fixtures are deterministic.

const (
	testValidFrom = "2026-01-01T00:00:00Z"
	testUpdatedAt = "2026-07-20T00:00:00Z"
)

type kp struct {
	priv      ed25519.PrivateKey
	pub       []byte
	multibase string
}

func fixedKeypair(t *testing.T, seed byte) kp {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	mb, err := EncodePublicKeyMultibase(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyMultibase: %v", err)
	}
	return kp{priv: priv, pub: []byte(pub), multibase: mb}
}

func deriveAgentID(k kp) string { return "tulpa:" + k.multibase }

// ── Signing helpers (fixture side; Go may sign for tests) ──

func signOverDomainTest(t *testing.T, domain string, obj map[string]interface{}, priv ed25519.PrivateKey) string {
	t.Helper()
	if !isWithinCanonicalizeBounds(obj) {
		t.Fatal("fixture exceeds canonicalize bounds")
	}
	canonical, err := canonicalizeJSON(obj)
	if err != nil {
		t.Fatalf("canonicalizeJSON: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(domain+canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// signAgentCardTest computes cardSignature.signature over ink/agent-card\n +
// JCS(card without cardSignature).
func signAgentCardTest(t *testing.T, card map[string]interface{}, priv ed25519.PrivateKey) string {
	t.Helper()
	return signOverDomainTest(t, cardSignatureDomain, stripCardKey(card, "cardSignature"), priv)
}

// signRotationLinkTest computes a link signature over ink/card-rotation\n +
// JCS(link without `signature`) (§4.1): the whole link minus the one member
// that cannot commit to itself, nothing else stripped.
func signRotationLinkTest(t *testing.T, link map[string]interface{}, priv ed25519.PrivateKey) string {
	t.Helper()
	return signOverDomainTest(t, cardRotationDomain, stripCardKey(link, "signature"), priv)
}

// signedLink builds a full rotation link (body plus its signature).
func signedLink(t *testing.T, keySetVersion int, signing []interface{}, prevKeyID string, priv ed25519.PrivateKey) map[string]interface{} {
	t.Helper()
	link := map[string]interface{}{
		"keySetVersion": keySetVersion,
		"signing":       signing,
		"prevKeyId":     prevKeyID,
	}
	link["signature"] = signRotationLinkTest(t, link, priv)
	return link
}

func attachCardSignature(t *testing.T, card map[string]interface{}, keyID string, priv ed25519.PrivateKey) map[string]interface{} {
	t.Helper()
	out := stripCardKey(card, "cardSignature")
	out["cardSignature"] = map[string]interface{}{
		"keyId":     keyID,
		"signature": signAgentCardTest(t, card, priv),
	}
	return out
}

// ── Fixture builders ──

func signingEntry(keyID string, k kp, status string) map[string]interface{} {
	return map[string]interface{}{
		"keyId":              keyID,
		"algorithm":          "Ed25519",
		"publicKeyMultibase": k.multibase,
		"status":             status,
		"validFrom":          testValidFrom,
	}
}

func baseCard(agentID, topKeyMultibase string) map[string]interface{} {
	return map[string]interface{}{
		"protocol":           "ink/0.1",
		"agentId":            agentID,
		"handle":             "agent",
		"displayName":        "Agent",
		"endpoint":           "https://example.com/ink",
		"publicKeyMultibase": topKeyMultibase,
		"capabilities": map[string]interface{}{
			"intentsAccepted": []interface{}{},
			"intentsSent":     []interface{}{},
		},
		"availability": map[string]interface{}{"timezone": "UTC"},
	}
}

func keySet(signing ...map[string]interface{}) map[string]interface{} {
	arr := make([]interface{}, 0, len(signing))
	for _, e := range signing {
		arr = append(arr, e)
	}
	return map[string]interface{}{"signing": arr, "encryption": []interface{}{}}
}

// mustWire JSON round-trips a fixture into the decoded-map shape a fetched card
// arrives as (every number a float64), the exact input the production verifier
// consumes. Canonicalization is identical across int and float64, so a signature
// minted over the pre-wire fixture verifies over its wire form.
func mustWire(t *testing.T, m map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// ── Assertion helpers ──

func expectAccept(t *testing.T, res CardVerifyResult, reason CardVerifyReason) {
	t.Helper()
	if !res.Authenticated || res.Rejected {
		t.Fatalf("expected accept, got authenticated=%v rejected=%v reason=%s", res.Authenticated, res.Rejected, res.Reason)
	}
	if res.Reason != reason {
		t.Fatalf("reason = %s, want %s", res.Reason, reason)
	}
}

func expectReject(t *testing.T, res CardVerifyResult, reason CardVerifyReason) {
	t.Helper()
	if res.Authenticated || !res.Rejected {
		t.Fatalf("expected reject, got authenticated=%v rejected=%v reason=%s", res.Authenticated, res.Rejected, res.Reason)
	}
	if res.Reason != reason {
		t.Fatalf("reason = %s, want %s", res.Reason, reason)
	}
}

func containsEvent(events []string, want string) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}

// ── Accept paths ──

func TestCardVerify_SignedKeyDerivedNoChainAccept(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	card["updatedAt"] = testUpdatedAt
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: Profile10})
	expectAccept(t, res, ReasonSignedAuthenticated)
	if len(res.AuditEvents) != 0 {
		t.Fatalf("expected no audit events, got %v", res.AuditEvents)
	}
}

func TestCardVerify_RotatedChainAccept(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)

	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	link2 := signedLink(t, 2, []interface{}{signingEntry("kA", a, "retired"), signingEntry("kB", b, "active")}, "kA", a.priv)

	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "retired"), signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kB"
	card["keySetVersion"] = 2
	card["rotationChain"] = []interface{}{link1, link2}
	signed := attachCardSignature(t, card, "kB", b.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: Profile10})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

// §4.1 preimage: a link signature covers JCS(link minus `signature`) with
// NOTHING else stripped. A verifier that rebuilt the preimage from the three
// named members would leave every other member of a received link outside the
// signature and freely mutable, and would exclude the `algorithm` member §4.1
// reserves for a later additive minor from ever being covered.
func TestCardVerify_UnknownLinkMemberIsCovered(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)

	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	// The reserved extension shape: a link carrying an `algorithm` member.
	link2 := map[string]interface{}{
		"keySetVersion": 2,
		"signing":       []interface{}{signingEntry("kA", a, "retired"), signingEntry("kB", b, "active")},
		"prevKeyId":     "kA",
		"algorithm":     "Ed25519",
	}
	link2["signature"] = signRotationLinkTest(t, link2, a.priv)

	mkCard := func(chain ...interface{}) map[string]interface{} {
		card := baseCard(agentID, g.multibase)
		card["keys"] = keySet(signingEntry("kA", a, "retired"), signingEntry("kB", b, "active"))
		card["currentSigningKeyId"] = "kB"
		card["keySetVersion"] = 2
		card["rotationChain"] = chain
		return attachCardSignature(t, card, "kB", b.priv)
	}

	// Signer and verifier agree on the full-link preimage.
	res := VerifyAgentCardSignature(mustWire(t, mkCard(link1, link2)), agentID, CardVerifyOptions{Profile: Profile10})
	expectAccept(t, res, ReasonSignedAuthenticated)

	// Mutating the unknown member breaks the signature. Under a three-field
	// reconstruction this forgery would still have verified.
	mutated := stripCardKey(link2, "algorithm")
	mutated["algorithm"] = "Ed448"
	res = VerifyAgentCardSignature(mustWire(t, mkCard(link1, mutated)), agentID, CardVerifyOptions{Profile: Profile10})
	expectReject(t, res, ReasonChainLinkInvalidSig)

	// Same on link 1, whose signer is a root candidate rather than an entry of
	// a prior link's committed set.
	root := map[string]interface{}{
		"keySetVersion": 1,
		"signing":       []interface{}{signingEntry("g1", g, "active")},
		"prevKeyId":     "g",
		"algorithm":     "Ed25519",
	}
	root["signature"] = signRotationLinkTest(t, root, g.priv)
	mkRootCard := func(link interface{}) map[string]interface{} {
		card := baseCard(agentID, g.multibase)
		card["keys"] = keySet(signingEntry("g1", g, "active"))
		card["currentSigningKeyId"] = "g1"
		card["keySetVersion"] = 1
		card["rotationChain"] = []interface{}{link}
		return attachCardSignature(t, card, "g1", g.priv)
	}
	res = VerifyAgentCardSignature(mustWire(t, mkRootCard(root)), agentID, CardVerifyOptions{Profile: Profile10})
	expectAccept(t, res, ReasonSignedAuthenticated)

	mutatedRoot := stripCardKey(root, "algorithm")
	mutatedRoot["algorithm"] = "Ed448"
	res = VerifyAgentCardSignature(mustWire(t, mkRootCard(mutatedRoot)), agentID, CardVerifyOptions{Profile: Profile10})
	expectReject(t, res, ReasonChainLinkInvalidSig)
}

func TestCardVerify_LegacyBootstrapAccept(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	// No keys.signing set -> legacy single-key card. keyId MUST be `bootstrap`
	// and the top-level publicKeyMultibase is the genesis key.
	card := baseCard(agentID, g.multibase)
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "bootstrap", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

// ── Proof rejects ──

func TestCardVerify_RetiredSignerReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "retired"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonSignerNotActive)
}

func TestCardVerify_RevokedSignerReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "revoked"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonSignerNotActive)
}

func TestCardVerify_SignerNotCurrentReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	h := fixedKeypair(t, 5)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"), signingEntry("g2", h, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g2", h.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonSignerNotCurrent)
}

func TestCardVerify_SignerAbsentReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "nope", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonSignerAbsentFromSigning)
}

func TestCardVerify_MissingCurrentSigningKeyIDReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["keySetVersion"] = 1 // currentSigningKeyId omitted
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonMissingCurrentSigningKeyID)
}

func TestCardVerify_LegacyBootstrapMismatchReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	// No keys.signing -> legacy card; keyId MUST be `bootstrap` (§3.3).
	card := baseCard(agentID, g.multibase)
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonLegacyBootstrapMismatch)
}

// A malformed key set must not demote the card to the legacy single-key path.
// It would authenticate the card against the top-level publicKeyMultibase, so
// a set that retires or revokes that key would stop being consulted at all.
func TestCardVerify_MalformedKeySetDoesNotDemoteToLegacy(t *testing.T) {
	for _, signing := range []interface{}{
		map[string]interface{}{"bad": true}, nil, false, float64(0), "", "x", float64(7),
	} {
		g := fixedKeypair(t, 1)
		agentID := deriveAgentID(g)
		card := baseCard(agentID, g.multibase)
		card["keySetVersion"] = 1
		card["keys"] = map[string]interface{}{"signing": signing, "encryption": []interface{}{}}
		signed := attachCardSignature(t, card, legacyBootstrapKeyID, g.priv)

		res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
		expectReject(t, res, ReasonInvalidCard)
	}
}

// A malformed rotationChain must not read as absent either: that roots the card
// at genesis and skips the chain it declared.
func TestCardVerify_MalformedRotationChainDoesNotRootAtGenesis(t *testing.T) {
	for _, chain := range []interface{}{
		map[string]interface{}{"bad": true}, nil, false, float64(0), "", "x",
	} {
		g := fixedKeypair(t, 1)
		agentID := deriveAgentID(g)
		card := baseCard(agentID, g.multibase)
		card["keys"] = map[string]interface{}{"signing": []interface{}{signingEntry("g1", g, "active")}, "encryption": []interface{}{}}
		card["currentSigningKeyId"] = "g1"
		card["keySetVersion"] = 1
		card["rotationChain"] = chain
		signed := attachCardSignature(t, card, "g1", g.priv)

		res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
		expectReject(t, res, ReasonInvalidCard)
	}
}

func TestCardVerify_WrongDomainReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	// Sign over the body domain tulpa/sign\n instead of ink/agent-card\n.
	wrong := signOverDomainTest(t, "tulpa/sign\n", card, g.priv)
	signed := stripCardKey(card, "cardSignature")
	signed["cardSignature"] = map[string]interface{}{"keyId": "g1", "signature": wrong}

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonInvalidSignature)
}

func TestCardVerify_ActiveKeySubstitutedReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	h := fixedKeypair(t, 5)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)
	// Swap the signing key's public material after the signature was computed.
	signed["keys"].(map[string]interface{})["signing"].([]interface{})[0].(map[string]interface{})["publicKeyMultibase"] = h.multibase

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonInvalidSignature)
}

func TestCardVerify_InvalidKeyEncodingReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	// An X25519 (0xec01) multibase where an Ed25519 (0xed01) key is required, so
	// the signer entry's key fails to decode before any signature check.
	badMultibase := encodeBadMulticodec(g.pub)
	card := baseCard(agentID, g.multibase)
	card["keys"] = map[string]interface{}{
		"signing": []interface{}{map[string]interface{}{
			"keyId":              "g1",
			"algorithm":          "Ed25519",
			"publicKeyMultibase": badMultibase,
			"status":             "active",
			"validFrom":          testValidFrom,
		}},
		"encryption": []interface{}{},
	}
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := stripCardKey(card, "cardSignature")
	signed["cardSignature"] = map[string]interface{}{"keyId": "g1", "signature": string(bytes.Repeat([]byte{'A'}, 86))}

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonInvalidKeyEncode)
}

// encodeBadMulticodec builds a z-multibase string with the X25519 (0xec 0x01)
// multicodec, which the Ed25519 decoder MUST reject.
func encodeBadMulticodec(pub []byte) string {
	prefixed := append([]byte{0xec, 0x01}, pub...)
	return "z" + encodeBase58(prefixed)
}

// ── Rooting rejects ──

func TestCardVerify_HeadVersionMismatchReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "active"))
	card["currentSigningKeyId"] = "kA"
	card["keySetVersion"] = 2 // head link commits version 1
	card["rotationChain"] = []interface{}{link1}
	signed := attachCardSignature(t, card, "kA", a.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonHeadVersionMismatch)
}

func TestCardVerify_HeadSetMismatchReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	h := fixedKeypair(t, 5)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	card := baseCard(agentID, g.multibase)
	// Card carries an extra signing entry the head link does not commit.
	card["keys"] = keySet(signingEntry("kA", a, "active"), signingEntry("kC", h, "active"))
	card["currentSigningKeyId"] = "kA"
	card["keySetVersion"] = 1
	card["rotationChain"] = []interface{}{link1}
	signed := attachCardSignature(t, card, "kA", a.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonHeadSetMismatch)
}

func TestCardVerify_HeadSetStatusDisagreementReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)
	// Head link commits kB active; the card carries kB retired.
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active"), signingEntry("kB", b, "active")}, "g", g.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "active"), signingEntry("kB", b, "retired"))
	card["currentSigningKeyId"] = "kA"
	card["keySetVersion"] = 1
	card["rotationChain"] = []interface{}{link1}
	signed := attachCardSignature(t, card, "kA", a.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonHeadSetMismatch)
}

func TestCardVerify_NonContiguousVersionReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	// Gap: link1 v1, link2 v3.
	link2 := signedLink(t, 3, []interface{}{signingEntry("kB", b, "active")}, "kA", a.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kB"
	card["keySetVersion"] = 3
	card["rotationChain"] = []interface{}{link1, link2}
	signed := attachCardSignature(t, card, "kB", b.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonChainNoncontiguous)
}

func TestCardVerify_ChainLinkSignerNotActiveReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)
	// link1 marks kA retired; link2 claims to be signed by kA.
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "retired")}, "g", g.priv)
	link2 := signedLink(t, 2, []interface{}{signingEntry("kB", b, "active")}, "kA", a.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kB"
	card["keySetVersion"] = 2
	card["rotationChain"] = []interface{}{link1, link2}
	signed := attachCardSignature(t, card, "kB", b.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonChainLinkSignerNotActive)
}

func TestCardVerify_GenesisKeyMismatchReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	agentID := deriveAgentID(g)
	// Card signed by A, no chain roots A to the genesis key G.
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "active"))
	card["currentSigningKeyId"] = "kA"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "kA", a.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonGenesisKeyMismatch)
}

func TestCardVerify_ChainTooLongReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	chain := make([]interface{}, 0, 33)
	for i := 0; i < 33; i++ {
		chain = append(chain, map[string]interface{}{
			"keySetVersion": i + 1,
			"signing":       []interface{}{signingEntry("k", g, "active")},
			"prevKeyId":     "g",
			"signature":     string(bytes.Repeat([]byte{'A'}, 86)),
		})
	}
	card["rotationChain"] = chain
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonChainTooLong)
}

func TestCardVerify_CardDuplicateKeyIDReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	h := fixedKeypair(t, 5)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"), signingEntry("g1", h, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonDuplicateKeyID)
}

func TestCardVerify_ChainDuplicateKeyIDReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active"), signingEntry("kA", b, "active")}, "g", g.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "active"))
	card["currentSigningKeyId"] = "kA"
	card["keySetVersion"] = 1
	card["rotationChain"] = []interface{}{link1}
	signed := attachCardSignature(t, card, "kA", a.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonChainDuplicateKeyID)
}

func TestCardVerify_UnrootedPrincipalReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	// A did:key principal is neither key-derived nor did:web; §4 defines no root.
	agentID := "did:key:" + g.multibase
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonUnrootedPrincipal)
}

func TestCardVerify_MissingKeySetVersionReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	// No keySetVersion.
	signed := attachCardSignature(t, card, "g1", g.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectReject(t, res, ReasonMissingKeySetVersion)
}

// ── Unsigned ratchet and profile ──

func TestCardVerify_UnsignedAfterAuthenticatedReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	unsigned := baseCard(agentID, g.multibase)
	cached := baseCard(agentID, g.multibase)
	cached["keys"] = keySet(signingEntry("g1", g, "active"))
	cached["keySetVersion"] = 1

	res := VerifyAgentCardSignature(mustWire(t, unsigned), agentID, CardVerifyOptions{Profile: ProfilePre10, CachedCard: mustWire(t, cached)})
	expectReject(t, res, ReasonUnsignedAfterAuthenticated)
}

func TestCardVerify_UnsignedFirstContactPre10Accept(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := "did:web:example.com"
	unsigned := baseCard(agentID, g.multibase)
	res := VerifyAgentCardSignature(mustWire(t, unsigned), agentID, CardVerifyOptions{Profile: ProfilePre10})
	expectAccept(t, res, ReasonUnsignedFirstContactAccept)
}

func TestCardVerify_UnsignedFirstContact10Reject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := "did:web:example.com"
	unsigned := baseCard(agentID, g.multibase)
	res := VerifyAgentCardSignature(mustWire(t, unsigned), agentID, CardVerifyOptions{Profile: Profile10})
	expectReject(t, res, ReasonUnsigned10Profile)
}

func TestCardVerify_UnsignedKeyDerived10Reject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	unsigned := baseCard(agentID, g.multibase)
	res := VerifyAgentCardSignature(mustWire(t, unsigned), agentID, CardVerifyOptions{Profile: Profile10})
	expectReject(t, res, ReasonUnsignedKeyDerived10)
}

// ── Continuity ──

func TestCardVerify_ContinuityVersionRegressionReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	signed := attachCardSignature(t, card, "g1", g.priv)

	cached := baseCard(agentID, g.multibase)
	cached["keys"] = keySet(signingEntry("g1", g, "active"))
	cached["keySetVersion"] = 5

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: Profile10, CachedCard: mustWire(t, cached)})
	expectReject(t, res, ReasonContinuityVersionReg)
	if !containsEvent(res.AuditEvents, "card.continuity_violation") {
		t.Fatalf("expected card.continuity_violation, got %v", res.AuditEvents)
	}
}

// ── Chain-extension fork (honest residual) ──

// forgedExtensionCard: genuine link1 (v1, kA active, signed by genesis G). An
// attacker who leaked kA OMITS the genuine revoking link2 and appends a FORGED
// link2' signed by kA committing an attacker key kX.
func forgedExtensionCard(t *testing.T) (string, map[string]interface{}) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	x := fixedKeypair(t, 4)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	forgedLink2 := signedLink(t, 2, []interface{}{signingEntry("kX", x, "active")}, "kA", a.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kX", x, "active"))
	card["currentSigningKeyId"] = "kX"
	card["keySetVersion"] = 2
	card["rotationChain"] = []interface{}{link1, forgedLink2}
	return agentID, attachCardSignature(t, card, "kX", x.priv)
}

func TestCardVerify_ColdAcceptsForgedExtension(t *testing.T) {
	agentID, card := forgedExtensionCard(t)
	// No cached state to constrain the chain: the leaked kA is active in link1, so
	// the forged link and its head bind cleanly. Cold accept is inherent.
	res := VerifyAgentCardSignature(mustWire(t, card), agentID, CardVerifyOptions{Profile: Profile10})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

func TestCardVerify_WarmRejectsForgedExtension(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	agentID, card := forgedExtensionCard(t)
	// Cached genuine v2: kA revoked, kB the current key. The forged head branches
	// from kA, revoked in the cached non-revoked set, so continuity rejects.
	cached := baseCard(agentID, g.multibase)
	cached["keys"] = keySet(signingEntry("kA", a, "revoked"), signingEntry("kB", b, "active"))
	cached["currentSigningKeyId"] = "kB"
	cached["keySetVersion"] = 2

	res := VerifyAgentCardSignature(mustWire(t, card), agentID, CardVerifyOptions{Profile: Profile10, CachedCard: mustWire(t, cached)})
	expectReject(t, res, ReasonContinuityUnreachableKey)
	if !containsEvent(res.AuditEvents, "card.continuity_violation") {
		t.Fatalf("expected card.continuity_violation, got %v", res.AuditEvents)
	}
}

// TestCardVerify_WarmRejectsCommittedSetStuffing is the crux: the attacker STUFFS
// the genuine current key kB into a forged link's committed set alongside the
// attacker key kX. kB signs NOTHING in the forged chain, so continuity must NOT
// bridge through its mere committed-set presence.
func TestCardVerify_WarmRejectsCommittedSetStuffing(t *testing.T) {
	g := fixedKeypair(t, 1)
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	x := fixedKeypair(t, 4)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "g", g.priv)
	forgedLink2 := signedLink(t, 2, []interface{}{signingEntry("kX", x, "active"), signingEntry("kB", b, "active")}, "kA", a.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kX", x, "active"), signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kX"
	card["keySetVersion"] = 2
	card["rotationChain"] = []interface{}{link1, forgedLink2}
	signed := attachCardSignature(t, card, "kX", x.priv)

	// Cached genuine v2: kA revoked, kB the active current key.
	cached := baseCard(agentID, g.multibase)
	cached["keys"] = keySet(signingEntry("kA", a, "revoked"), signingEntry("kB", b, "active"))
	cached["currentSigningKeyId"] = "kB"
	cached["keySetVersion"] = 2

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: Profile10, CachedCard: mustWire(t, cached)})
	expectReject(t, res, ReasonContinuityUnreachableKey)
	if !containsEvent(res.AuditEvents, "card.continuity_violation") {
		t.Fatalf("expected card.continuity_violation, got %v", res.AuditEvents)
	}
}

// TestCardVerify_MultiHopWarmAccept: the agent rotated TWICE between two warm
// fetches. Cached v1 holds kB; the new v3 card carries a genesis->kB->kC->kD
// chain. Reachability holds because an INTERIOR link's verified signer is kB.
func TestCardVerify_MultiHopWarmAccept(t *testing.T) {
	g := fixedKeypair(t, 1)
	b := fixedKeypair(t, 3)
	h := fixedKeypair(t, 5)
	d := fixedKeypair(t, 6)
	agentID := deriveAgentID(g)
	link1 := signedLink(t, 1, []interface{}{signingEntry("kB", b, "active")}, "g", g.priv)
	link2 := signedLink(t, 2, []interface{}{signingEntry("kB", b, "retired"), signingEntry("kC", h, "active")}, "kB", b.priv)
	link3 := signedLink(t, 3, []interface{}{signingEntry("kC", h, "retired"), signingEntry("kD", d, "active")}, "kC", h.priv)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("kC", h, "retired"), signingEntry("kD", d, "active"))
	card["currentSigningKeyId"] = "kD"
	card["keySetVersion"] = 3
	card["rotationChain"] = []interface{}{link1, link2, link3}
	signed := attachCardSignature(t, card, "kD", d.priv)

	cached := baseCard(agentID, g.multibase)
	cached["keys"] = keySet(signingEntry("kB", b, "active"))
	cached["currentSigningKeyId"] = "kB"
	cached["keySetVersion"] = 1

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{Profile: Profile10, CachedCard: mustWire(t, cached)})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

// ── did:web anchoring ──

func didCard(t *testing.T, d kp) (string, map[string]interface{}) {
	agentID := "did:web:example.com"
	card := baseCard(agentID, d.multibase)
	card["keys"] = keySet(signingEntry("d1", d, "active"))
	card["currentSigningKeyId"] = "d1"
	card["keySetVersion"] = 1
	return agentID, card
}

func TestCardVerify_DidWebSignerPresentAccept(t *testing.T) {
	d := fixedKeypair(t, 6)
	agentID, card := didCard(t, d)
	signed := attachCardSignature(t, card, "d1", d.priv)
	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		DidVerificationKeys: &DidResolution{Status: DidResolved, VerificationKeys: []string{d.multibase}},
	})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

func TestCardVerify_DidWebSignerAbsentReject(t *testing.T) {
	d := fixedKeypair(t, 6)
	other := fixedKeypair(t, 7)
	agentID, card := didCard(t, d)
	signed := attachCardSignature(t, card, "d1", d.priv)
	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		DidVerificationKeys: &DidResolution{Status: DidResolved, VerificationKeys: []string{other.multibase}},
	})
	expectReject(t, res, ReasonDidwebSignerNotAnchored)
}

func TestCardVerify_DidWebResolverUnavailableColdReject(t *testing.T) {
	d := fixedKeypair(t, 6)
	agentID, card := didCard(t, d)
	signed := attachCardSignature(t, card, "d1", d.priv)
	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		DidVerificationKeys: &DidResolution{Status: DidUnavailable},
	})
	expectReject(t, res, ReasonDidwebResolverUnavail)
}

func TestCardVerify_DidWebResolverUnavailableWarmAccept(t *testing.T) {
	d := fixedKeypair(t, 6)
	agentID, card := didCard(t, d)
	signed := attachCardSignature(t, card, "d1", d.priv)
	cached := baseCard(agentID, d.multibase)
	cached["keys"] = keySet(signingEntry("d1", d, "active"))
	cached["keySetVersion"] = 1
	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		CachedCard:          mustWire(t, cached),
		DidVerificationKeys: &DidResolution{Status: DidUnavailable},
	})
	expectAccept(t, res, ReasonSignedAuthenticated)
	if !containsEvent(res.AuditEvents, "card.anchor_unverified") {
		t.Fatalf("expected card.anchor_unverified, got %v", res.AuditEvents)
	}
}

func TestCardVerify_DidWebWithChainAccept(t *testing.T) {
	a := fixedKeypair(t, 2)
	b := fixedKeypair(t, 3)
	d := fixedKeypair(t, 6)
	agentID := "did:web:example.com"
	// Link 1 re-rooted on the DID-document key D (§4.2), rotating to kB, itself a
	// DID-document verification method so it anchors the card.
	link1 := signedLink(t, 1, []interface{}{signingEntry("kA", a, "active")}, "did-root", d.priv)
	link2 := signedLink(t, 2, []interface{}{signingEntry("kA", a, "retired"), signingEntry("kB", b, "active")}, "kA", a.priv)
	card := baseCard(agentID, d.multibase)
	card["keys"] = keySet(signingEntry("kA", a, "retired"), signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kB"
	card["keySetVersion"] = 2
	card["rotationChain"] = []interface{}{link1, link2}
	signed := attachCardSignature(t, card, "kB", b.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		DidVerificationKeys: &DidResolution{Status: DidResolved, VerificationKeys: []string{d.multibase, b.multibase}},
	})
	expectAccept(t, res, ReasonSignedAuthenticated)
}

func TestCardVerify_DidWebWithChainLink1NotDidKeyReject(t *testing.T) {
	g := fixedKeypair(t, 1)
	b := fixedKeypair(t, 3)
	agentID := "did:web:example.com"
	// The card signer kB is anchored, but link 1 is signed by G, not a
	// DID-document verification method, so link-1 re-rooting fails (§4.2).
	link1 := signedLink(t, 1, []interface{}{signingEntry("kB", b, "active")}, "did-root", g.priv)
	card := baseCard(agentID, b.multibase)
	card["keys"] = keySet(signingEntry("kB", b, "active"))
	card["currentSigningKeyId"] = "kB"
	card["keySetVersion"] = 1
	card["rotationChain"] = []interface{}{link1}
	signed := attachCardSignature(t, card, "kB", b.priv)

	res := VerifyAgentCardSignature(mustWire(t, signed), agentID, CardVerifyOptions{
		Profile:             Profile10,
		DidVerificationKeys: &DidResolution{Status: DidResolved, VerificationKeys: []string{b.multibase}},
	})
	expectReject(t, res, ReasonDidwebSignerNotAnchored)
}

// ── Schema validation for the new members ──

func TestValidateAgentCard_AcceptsSignedCard(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keys"] = keySet(signingEntry("g1", g, "active"))
	card["currentSigningKeyId"] = "g1"
	card["keySetVersion"] = 1
	card["updatedAt"] = testUpdatedAt
	signed := attachCardSignature(t, card, "g1", g.priv)
	if !ValidateAgentCard(mustWire(t, signed)) {
		t.Fatal("expected a signed card to validate")
	}
}

func TestValidateAgentCard_RejectsMalformedCardSignature(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	card["keySetVersion"] = 1
	card["cardSignature"] = map[string]interface{}{"keyId": "g1", "signature": "too-short"}
	if ValidateAgentCard(mustWire(t, card)) {
		t.Fatal("expected a card with a malformed cardSignature to fail validation")
	}
}

func TestValidateAgentCard_UnsignedStillValidates(t *testing.T) {
	g := fixedKeypair(t, 1)
	agentID := deriveAgentID(g)
	card := baseCard(agentID, g.multibase)
	if !ValidateAgentCard(mustWire(t, card)) {
		t.Fatal("expected an unsigned card to validate (backward-compatible)")
	}
}
