#!/usr/bin/env node
// Regenerate the ink/1 conformance vectors. Deterministic: a fixed test seed
// drives a single Ed25519 key, so re-running produces byte-identical output.
// The vectors are the cross-implementation contract; the TypeScript runner in
// test/conformance.test.ts asserts this reference implementation agrees with
// them, and a second implementation must make the same accept/reject decisions.
//
//   node conformance/v1/generate.mjs   # writes vectors/*.json next to this file
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import {
  encodePublicKeyMultibase,
  canonicalAgentPrincipal,
  signInkMessage,
  bytesToHex,
} from "../../dist/index.js";

const enc = new TextEncoder();
const here = fileURLToPath(new URL(".", import.meta.url).href);

const seed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-v1-test-key")));
const publicKey = await ed.getPublicKeyAsync(seed);
const mb = encodePublicKeyMultibase(publicKey);
const publicKeyHex = bytesToHex(publicKey);
const principal = canonicalAgentPrincipal(`tulpa:${mb}`);

function vectorFile(category, cases) {
  const doc = { format: "ink.conformance.v1", category, cases };
  writeFileSync(`${here}vectors/${category}.json`, JSON.stringify(doc, null, 2) + "\n");
}

// ── principal-normalization ────────────────────────────────────────────────
vectorFile("principal-normalization", [
  {
    caseId: "tulpa-prefix-canonical",
    description: "A tulpa: agentId normalizes to the key principal.",
    input: { agentId: `tulpa:${mb}` },
    expect: { result: "accept", canonicalPrincipal: principal },
  },
  {
    caseId: "ink-alias-same-principal",
    description: "The ink: alias of the same key normalizes to the same principal.",
    input: { agentId: `ink:${mb}` },
    expect: { result: "accept", canonicalPrincipal: principal },
  },
  {
    caseId: "literal-key-prefix-escaped",
    description: "A literal key: agentId is escaped to raw:key:, never confused with the canonical key principal.",
    input: { agentId: `key:${mb}` },
    expect: { result: "accept", canonicalPrincipal: `raw:${`key:${mb}`}` },
  },
  {
    caseId: "did-web-passthrough",
    description: "A did:web identity is carried through unchanged.",
    input: { agentId: "did:web:example.com" },
    expect: { result: "accept", canonicalPrincipal: "did:web:example.com" },
  },
  {
    caseId: "non-ascii-under-utf16-cap-passes-through",
    description: "A non-ASCII identifier whose UTF-16 length is within the 512 cap (its UTF-8 byte length is not) is accepted and passed through, so an implementation that measures length in bytes instead of UTF-16 code units would diverge here.",
    input: { agentId: "你".repeat(200) },
    expect: { result: "accept", canonicalPrincipal: "你".repeat(200) },
  },
  {
    caseId: "empty-agentid-rejected",
    description: "An empty agentId is rejected.",
    input: { agentId: "" },
    expect: { result: "reject" },
  },
]);

// ── signature-base ─────────────────────────────────────────────────────────
const signInput = {
  method: "POST",
  path: `/ink/v1/tulpa:${mb}/intent`,
  recipientDid: `tulpa:${mb}`,
  body: {
    protocol: "ink/0.1",
    id: "11111111-1111-4111-8111-111111111111",
    correlationId: "22222222-2222-4222-8222-222222222222",
    createdAt: "2026-06-11T00:00:00.000Z",
    from: `tulpa:${mb}`,
    to: `tulpa:${mb}`,
    intent: "ping",
    payload: { note: "conformance", scope: "deep" },
    timestamp: "2026-06-11T00:00:00.000Z",
    nonce: "33333333-3333-4333-8333-333333333333",
  },
  timestamp: "2026-06-11T00:00:00.000Z",
};
const signature = await signInkMessage(signInput, seed);
// Reorder members of the nested payload only: JCS sorts keys recursively, so
// verification is over the canonical bytes, not the raw JSON member order.
const nestedReordered = {
  ...signInput,
  body: { ...signInput.body, payload: { scope: signInput.body.payload.scope, note: signInput.body.payload.note } },
};
// Same semantic body, members emitted in a different order: JCS canonicalizes
// both to the same bytes, so the original signature must still verify.
const reordered = {
  ...signInput,
  body: {
    nonce: signInput.body.nonce,
    payload: signInput.body.payload,
    timestamp: signInput.body.timestamp,
    intent: signInput.body.intent,
    to: signInput.body.to,
    from: signInput.body.from,
    createdAt: signInput.body.createdAt,
    correlationId: signInput.body.correlationId,
    id: signInput.body.id,
    protocol: signInput.body.protocol,
  },
};
const tampered = { ...signInput, body: { ...signInput.body, intent: "schedule_meeting" } };
// A body string carrying a literal newline: JCS escapes it to \n, so the bytes
// are unambiguous and the signature over them must verify in any implementation.
const newlineBody = {
  ...signInput,
  body: { ...signInput.body, payload: { note: "line1\nline2", scope: "tab\there" } },
};
const newlineSignature = await signInkMessage(newlineBody, seed);

vectorFile("signature-base", [
  {
    caseId: "valid-signature-accepts",
    description: "A signature over the canonical signature base verifies.",
    input: { signInput, signature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "member-reorder-accepts",
    description: "Reordering JSON members of the signed body does not change the canonical bytes, so the signature still verifies.",
    input: { signInput: reordered, signature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "nested-member-reorder-accepts",
    description: "Reordering members of the nested payload also leaves the canonical bytes unchanged, so verification is over the JCS form and not the raw member order.",
    input: { signInput: nestedReordered, signature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "tampered-field-rejects",
    description: "Altering a signed field (intent) invalidates the signature.",
    input: { signInput: tampered, signature, publicKeyHex },
    expect: { result: "reject" },
  },
  {
    caseId: "wrong-key-rejects",
    description: "Verifying against a different public key fails.",
    input: { signInput, signature, publicKeyHex: bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(7))) },
    expect: { result: "reject" },
  },
  {
    caseId: "body-string-with-newline-accepts",
    description: "A signed body string containing a newline and a tab is JCS-escaped, so the signature over it verifies and the control characters cannot shift the signature base boundaries.",
    input: { signInput: newlineBody, signature: newlineSignature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "malformed-signature-rejects",
    description: "A signature that is not 86 base64url characters is rejected before any verification work.",
    input: { signInput, signature: signature.slice(0, 85) + "+", publicKeyHex },
    expect: { result: "reject" },
  },
]);

// ── jcs-number ─────────────────────────────────────────────────────────────
function envelope(payload) {
  return {
    protocol: "ink/0.1",
    id: "44444444-4444-4444-8444-444444444444",
    correlationId: "55555555-5555-4555-8555-555555555555",
    createdAt: "2026-06-11T00:00:00.000Z",
    from: `tulpa:${mb}`,
    to: `tulpa:${mb}`,
    intent: "ask_response",
    payload,
    // validateMessage checks envelope shape, including that signature is a
    // present string; it does not verify the signature cryptographically (that
    // is the signature-base category). A placeholder keeps the envelope valid.
    signature: "A".repeat(86),
    timestamp: "2026-06-11T00:00:00.000Z",
    nonce: "66666666-6666-4666-8666-666666666666",
  };
}
vectorFile("jcs-number", [
  {
    caseId: "ordinary-integer-accepts",
    description: "An ordinary integer in a numeric payload field is accepted.",
    input: { envelope: envelope({ answer: "ok", choiceIndex: 3 }) },
    expect: { result: "accept" },
  },
  {
    caseId: "exponential-number-rejects",
    description: "A value whose shortest form uses exponential notation is rejected as not JCS-safe even though it is a valid integer, so the signed bytes stay canonicalizer-agnostic.",
    input: { envelope: envelope({ answer: "ok", choiceIndex: 1e21 }) },
    expect: { result: "reject" },
  },
]);

// ── key-rotation ───────────────────────────────────────────────────────────
// The same signed message verified against a key set. The authority rule:
// revoked keys are always skipped, active keys are tried before retired, and a
// key only admits a message whose timestamp falls inside its validity window.
const otherKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(7)));
function keyEntry(status, extra = {}) {
  return { keyId: `signer-${status}`, publicKeyHex, status, ...extra };
}
vectorFile("key-rotation", [
  {
    caseId: "active-key-accepts",
    description: "A signature verifies against the signer's active key.",
    input: { signInput, signature, keys: [keyEntry("active")] },
    expect: { result: "accept", keyStatus: "active" },
  },
  {
    caseId: "retired-key-in-window-accepts",
    description: "A retired key whose validity window still contains the message timestamp verifies.",
    input: { signInput, signature, keys: [keyEntry("retired", { validUntil: "2027-01-01T00:00:00.000Z" })] },
    expect: { result: "accept", keyStatus: "retired" },
  },
  {
    caseId: "revoked-key-rejects",
    description: "A revoked key is always skipped, so verification fails even though the signature matches it.",
    input: { signInput, signature, keys: [keyEntry("revoked")] },
    expect: { result: "reject" },
  },
  {
    caseId: "expired-window-rejects",
    description: "A retired key whose validUntil precedes the message timestamp is out of window and is skipped.",
    input: { signInput, signature, keys: [keyEntry("retired", { validUntil: "2025-01-01T00:00:00.000Z" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "unknown-key-rejects",
    description: "A key set that does not contain the signing key cannot verify the signature.",
    input: { signInput, signature, keys: [{ keyId: "someone-else", publicKeyHex: otherKeyHex, status: "active" }] },
    expect: { result: "reject" },
  },
  {
    caseId: "fallthrough-active-to-retired",
    description: "When a non-matching active key precedes the retired signing key, verification falls through to the retired key.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "rotated-in", publicKeyHex: otherKeyHex, status: "active" },
        keyEntry("retired", { validUntil: "2027-01-01T00:00:00.000Z" }),
      ],
    },
    expect: { result: "accept", keyStatus: "retired", keyId: "signer-retired" },
  },
  {
    caseId: "active-preferred-over-retired",
    description: "When the signing key is listed as both active and retired, the active entry verifies first.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "signer-retired", publicKeyHex, status: "retired", validUntil: "2027-01-01T00:00:00.000Z" },
        { keyId: "signer-active", publicKeyHex, status: "active" },
      ],
    },
    expect: { result: "accept", keyStatus: "active", keyId: "signer-active" },
  },
  {
    caseId: "not-yet-valid-key-rejects",
    description: "A key whose validFrom is after the message timestamp is not yet valid and is skipped.",
    input: { signInput, signature, keys: [keyEntry("active", { validFrom: "2027-01-01T00:00:00.000Z" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "revoked-at-set-skips-key",
    description: "A key with status active but a revokedAt timestamp present is treated as revoked and skipped.",
    input: { signInput, signature, keys: [keyEntry("active", { revokedAt: "2026-06-10T00:00:00.000Z" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "hinted-key-accepts",
    description: "A keyId hint that names the signing key verifies it directly.",
    input: { signInput, signature, keys: [keyEntry("active")], hintKeyId: "signer-active" },
    expect: { result: "accept", keyStatus: "active", keyId: "signer-active" },
  },
  {
    caseId: "hinted-out-of-window-key-falls-through-to-active",
    description: "A hint that names a key whose status is allowed but whose validity window has expired does not verify via the hint, so verification falls through to a usable active key.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "hinted-expired", publicKeyHex, status: "active", validUntil: "2025-01-01T00:00:00.000Z" },
        { keyId: "current-active", publicKeyHex, status: "active" },
      ],
      hintKeyId: "hinted-expired",
    },
    expect: { result: "accept", keyStatus: "active", keyId: "current-active" },
  },
  {
    caseId: "hinted-revoked-key-falls-through-to-active",
    description: "A hint that names a revoked key is rejected by the hint allowlist, so verification still falls through to a usable active key.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "old-revoked", publicKeyHex, status: "revoked" },
        { keyId: "current-active", publicKeyHex, status: "active" },
      ],
      hintKeyId: "old-revoked",
    },
    expect: { result: "accept", keyStatus: "active", keyId: "current-active" },
  },
  {
    caseId: "hinted-out-of-window-key-no-fallback-rejects",
    description: "A hint that names an out-of-window key with no other usable key in the set is rejected; the hint does not bypass the validity window.",
    input: {
      signInput,
      signature,
      keys: [{ keyId: "only-expired", publicKeyHex, status: "active", validUntil: "2025-01-01T00:00:00.000Z" }],
      hintKeyId: "only-expired",
    },
    expect: { result: "reject" },
  },
  {
    caseId: "hinted-revoked-key-no-fallback-rejects",
    description: "A hint that names a revoked key with no other usable key in the set is rejected; a revoked key is never selected even when it is the only candidate.",
    input: {
      signInput,
      signature,
      keys: [{ keyId: "only-revoked", publicKeyHex, status: "revoked" }],
      hintKeyId: "only-revoked",
    },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-status-skipped-rejects",
    description: "A key whose status is not one of active/retired/revoked is skipped by the status allowlist, so a set with only such a key cannot verify.",
    input: { signInput, signature, keys: [{ keyId: "weird", publicKeyHex, status: "Active" }] },
    expect: { result: "reject" },
  },
]);

// ── replay-freshness ───────────────────────────────────────────────────────
// Pure timestamp-freshness + nonce-dedup decision. A message is fresh only
// within [receiverClock - 5min, receiverClock + 30s], and a nonce already seen
// is a replay. No key material is involved.
const recvClock = "2026-06-11T00:00:00.000Z";
const goodNonce = "nonce-conformance-0001";
function replayInput(messageTimestamp, nonce, previouslySeenNonces = []) {
  return { messageTimestamp, receiverClock: recvClock, nonce, previouslySeenNonces };
}
vectorFile("replay-freshness", [
  {
    caseId: "fresh-unseen-nonce-accepts",
    description: "A current timestamp with a nonce not seen before is accepted.",
    input: { replay: replayInput(recvClock, goodNonce) },
    expect: { result: "accept" },
  },
  {
    caseId: "within-window-accepts",
    description: "A timestamp 20 seconds in the past is inside the freshness window and is accepted.",
    input: { replay: replayInput("2026-06-10T23:59:40.000Z", goodNonce) },
    expect: { result: "accept" },
  },
  {
    caseId: "duplicate-nonce-rejects",
    description: "A nonce already in previouslySeenNonces is a replay and is rejected.",
    input: { replay: replayInput(recvClock, goodNonce, [goodNonce]) },
    expect: { result: "reject" },
  },
  {
    caseId: "stale-timestamp-rejects",
    description: "A timestamp older than the 5 minute age window is rejected.",
    input: { replay: replayInput("2026-06-10T23:54:00.000Z", goodNonce) },
    expect: { result: "reject" },
  },
  {
    caseId: "future-timestamp-rejects",
    description: "A timestamp more than 30 seconds in the future is rejected.",
    input: { replay: replayInput("2026-06-11T00:00:31.000Z", goodNonce) },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-nonce-rejects",
    description: "A nonce shorter than the minimum length is rejected before any freshness check.",
    input: { replay: replayInput(recvClock, "short") },
    expect: { result: "reject" },
  },
]);

console.log(`Wrote conformance/v1/vectors for principal (key ${mb.slice(0, 12)}...).`);
