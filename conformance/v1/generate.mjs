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

// A small-order public key (the identity point) makes [h]A constant across all
// messages, so for A = identity the cofactorless verification equation
// [S]B = R + [h]A reduces to [S]B = R; with S = 1 and R = [1]B = B (the
// basepoint) the signature R||S verifies for any message. @noble/ed25519 with
// {zip215:false} rejects small-order keys before any arithmetic, so a conforming
// verifier must reject this universal forgery. Go's bare crypto/ed25519.Verify
// does not, which this vector pins.
const identityPublicKeyHex = "01" + "00".repeat(31);
const basepointBytes = Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex");
const scalarOneBytes = Buffer.alloc(32);
scalarOneBytes[0] = 1;
const smallOrderForgedSig = Buffer.concat([basepointBytes, scalarOneBytes]).toString("base64url");

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
  {
    caseId: "small-order-public-key-rejects",
    description: "A small-order public key (the identity point) yields a signature that verifies for any message under the cofactorless equation; the reference rejects small-order keys before any arithmetic, so a conforming verifier must reject this universal forgery rather than accept it.",
    input: { signInput, signature: smallOrderForgedSig, publicKeyHex: identityPublicKeyHex },
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
  // Key-window presence is semantic: a window field that is present at all
  // constrains the key, even when its value is empty, null, or not a string.
  // A present revokedAt of any value marks the key unusable; a present
  // validFrom/validUntil that is not a strict RFC 3339 timestamp fails closed.
  // An absent field is unconstrained. A malformed window invalidates only that
  // candidate key, not the whole verify call.
  {
    caseId: "no-window-accepts",
    description: "A key with no window fields at all is unconstrained and verifies.",
    input: { signInput, signature, keys: [keyEntry("active")] },
    expect: { result: "accept", keyStatus: "active", keyId: "signer-active" },
  },
  {
    caseId: "empty-revoked-at-skips-key",
    description: "A present empty-string revokedAt is present, so the key is treated as revoked and skipped; an implementation that read empty as absent would accept it.",
    input: { signInput, signature, keys: [keyEntry("active", { revokedAt: "" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "null-revoked-at-skips-key",
    description: "A present null revokedAt is present, so the key is treated as revoked and skipped.",
    input: { signInput, signature, keys: [keyEntry("active", { revokedAt: null })] },
    expect: { result: "reject" },
  },
  {
    caseId: "empty-valid-from-rejects",
    description: "A present empty-string validFrom is not a valid timestamp, so the key fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validFrom: "" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "null-valid-until-rejects",
    description: "A present null validUntil is not a valid timestamp, so the key fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validUntil: null })] },
    expect: { result: "reject" },
  },
  {
    caseId: "non-string-valid-from-rejects",
    description: "A present non-string validFrom (a number) is not a valid timestamp, so the key fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validFrom: 0 })] },
    expect: { result: "reject" },
  },
  {
    caseId: "non-string-valid-until-rejects",
    description: "A present non-string validUntil (an object) is not a valid timestamp, so the key fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validUntil: {} })] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-valid-from-string-rejects",
    description: "A present validFrom that is a string but not a strict RFC 3339 timestamp fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validFrom: "not-a-date" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-window-key-falls-through-to-valid",
    description: "A key with a malformed window is skipped, not fatal, so verification still succeeds via a second usable key.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "malformed", publicKeyHex, status: "active", revokedAt: "" },
        { keyId: "good", publicKeyHex, status: "active" },
      ],
    },
    expect: { result: "accept", keyStatus: "active", keyId: "good" },
  },
  {
    caseId: "empty-valid-until-rejects",
    description: "A present empty-string validUntil is not a valid timestamp, so the key fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validUntil: "" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-valid-until-string-rejects",
    description: "A present validUntil that is a string but not a strict RFC 3339 timestamp fails closed.",
    input: { signInput, signature, keys: [keyEntry("active", { validUntil: "not-a-date" })] },
    expect: { result: "reject" },
  },
  {
    caseId: "non-string-revoked-at-skips-key",
    description: "A present non-string revokedAt is still present, so the key is treated as revoked and skipped.",
    input: { signInput, signature, keys: [keyEntry("active", { revokedAt: false })] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-valid-from-key-falls-through-to-valid",
    description: "A key with a malformed validFrom is skipped, not fatal, so verification still succeeds via a second usable key.",
    input: {
      signInput,
      signature,
      keys: [
        { keyId: "bad-window", publicKeyHex, status: "active", validFrom: "" },
        { keyId: "good", publicKeyHex, status: "active" },
      ],
    },
    expect: { result: "accept", keyStatus: "active", keyId: "good" },
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

// ── timestamp-validity ───────────────────────────────────────────────────
// INK timestamps (message timestamp, key validFrom/validUntil) use one strict
// RFC 3339 grammar and millisecond precision across implementations. A value is
// accepted only as a full date-time with a `T` and a `Z` or numeric offset; the
// parsed instant is whole milliseconds. epochMs is computed with the engine's
// Date.parse as an independent oracle, so both implementations must agree with
// it. A lenient form (date-only, no zone, space-separated, lowercase `t`) or an
// out-of-range value is rejected.
vectorFile("timestamp-validity", [
  {
    caseId: "utc-millis-accepts",
    description: "A full RFC 3339 UTC date-time with millisecond precision is accepted and parses to whole milliseconds.",
    input: { timestamp: "2026-06-11T00:00:00.000Z" },
    expect: { result: "accept", epochMs: Date.parse("2026-06-11T00:00:00.000Z") },
  },
  {
    caseId: "numeric-offset-accepts",
    description: "A date-time with a numeric +HH:MM offset is accepted and normalized to the same instant.",
    input: { timestamp: "2026-06-11T02:00:00+02:00" },
    expect: { result: "accept", epochMs: Date.parse("2026-06-11T02:00:00+02:00") },
  },
  {
    caseId: "no-fraction-accepts",
    description: "A date-time without fractional seconds is accepted.",
    input: { timestamp: "2026-06-11T00:00:00Z" },
    expect: { result: "accept", epochMs: Date.parse("2026-06-11T00:00:00Z") },
  },
  {
    caseId: "sub-millisecond-truncates",
    description: "Sub-millisecond precision is truncated to whole milliseconds, so an implementation comparing at nanoseconds would diverge here.",
    input: { timestamp: "2026-06-11T00:00:00.123456Z" },
    expect: { result: "accept", epochMs: Date.parse("2026-06-11T00:00:00.123456Z") },
  },
  {
    caseId: "leap-day-accepts",
    description: "February 29 in a leap year is a valid date and is accepted.",
    input: { timestamp: "2024-02-29T00:00:00Z" },
    expect: { result: "accept", epochMs: Date.parse("2024-02-29T00:00:00Z") },
  },
  {
    caseId: "early-year-accepts",
    description: "A four-digit year below 0100 is the literal year, so an implementation that mapped 0..99 to 1900..1999 would diverge here.",
    input: { timestamp: "0099-01-01T00:00:00Z" },
    expect: { result: "accept", epochMs: Date.parse("0099-01-01T00:00:00Z") },
  },
  {
    caseId: "pre-epoch-sub-millisecond-floors",
    description: "A pre-epoch instant with sub-millisecond precision floors to the containing millisecond (negative), so a truncate-toward-zero implementation would diverge.",
    input: { timestamp: "1969-12-31T23:59:59.9999Z" },
    expect: { result: "accept", epochMs: Date.parse("1969-12-31T23:59:59.9999Z") },
  },
  {
    caseId: "non-leap-feb-29-rejects",
    description: "February 29 in a non-leap year is out of range and is rejected; a parser that normalizes it to March 1 would diverge.",
    input: { timestamp: "2026-02-29T00:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "day-out-of-range-rejects",
    description: "A day past the end of the month (June 31) is rejected rather than rolled into the next month.",
    input: { timestamp: "2026-06-31T00:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "hour-24-rejects",
    description: "Hour 24 is out of range and is rejected rather than rolled into the next day.",
    input: { timestamp: "2026-06-11T24:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "comma-fraction-rejects",
    description: "A comma fractional-second separator is rejected; the grammar requires a dot, even though some parsers accept a comma.",
    input: { timestamp: "2026-06-11T00:00:00,123Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "date-only-rejects",
    description: "A date with no time component is not a full RFC 3339 date-time and is rejected.",
    input: { timestamp: "2026-06-11" },
    expect: { result: "reject" },
  },
  {
    caseId: "missing-zone-rejects",
    description: "A date-time without a zone designator is rejected; the instant would be ambiguous.",
    input: { timestamp: "2026-06-11T00:00:00" },
    expect: { result: "reject" },
  },
  {
    caseId: "space-separated-rejects",
    description: "A space instead of the RFC 3339 `T` separator is rejected even though some lenient parsers accept it.",
    input: { timestamp: "2026-06-11 00:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "lowercase-t-rejects",
    description: "A lowercase `t` separator is rejected; the grammar requires an uppercase `T`.",
    input: { timestamp: "2026-06-11t00:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "out-of-range-month-rejects",
    description: "A syntactically shaped but out-of-range date (month 13) is rejected.",
    input: { timestamp: "2026-13-11T00:00:00Z" },
    expect: { result: "reject" },
  },
  {
    caseId: "empty-rejects",
    description: "An empty string is not a timestamp.",
    input: { timestamp: "" },
    expect: { result: "reject" },
  },
]);

// ── jcs-string-safety ────────────────────────────────────────────────────
// A signed body MUST NOT contain a \uXXXX escape for an unpaired UTF-16
// surrogate in any string member name or value. The check runs on the raw JSON
// text before parsing, because a parser (notably Go's encoding/json) silently
// rewrites a lone surrogate to U+FFFD, which would sign different bytes than an
// implementation that preserves it. bodyRaw is the raw JSON text. A backslash
// const keeps a literal escape out of the generator source.
const bs = "\\";
const sHi = bs + "uD83D";
const sLo = bs + "uDE00";
const sLoneHi = bs + "uD800";
const sLoneLo = bs + "uDC00";
vectorFile("jcs-string-safety", [
  {
    caseId: "plain-string-accepts",
    description: "An ordinary string with no surrogate escapes is accepted.",
    input: { bodyRaw: `{"note":"hello"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "valid-surrogate-pair-accepts",
    description: "A valid high+low surrogate pair (an astral code point) is accepted.",
    input: { bodyRaw: `{"note":"${sHi}${sLo}"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "literal-escaped-backslash-u-accepts",
    description: "An escaped backslash followed by uD800 is the literal text, not a Unicode escape, so it is accepted.",
    input: { bodyRaw: `{"note":"${bs}${bs}uD800"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "bmp-escape-accepts",
    description: "A non-surrogate Unicode escape is accepted.",
    input: { bodyRaw: `{"note":"${bs}u0041"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "lone-high-surrogate-rejects",
    description: "A lone high surrogate escape is rejected; a parser that rewrote it to U+FFFD would sign different bytes.",
    input: { bodyRaw: `{"note":"${sLoneHi}"}` },
    expect: { result: "reject" },
  },
  {
    caseId: "lone-low-surrogate-rejects",
    description: "A lone low surrogate escape with no preceding high is rejected.",
    input: { bodyRaw: `{"note":"${sLoneLo}"}` },
    expect: { result: "reject" },
  },
  {
    caseId: "lowercase-lone-surrogate-rejects",
    description: "Lowercase hex does not change the rule; a lone surrogate is rejected.",
    input: { bodyRaw: `{"note":"${bs}ud800"}` },
    expect: { result: "reject" },
  },
  {
    caseId: "high-split-from-low-rejects",
    description: "A high surrogate not immediately followed by a low surrogate escape is rejected, even when a low appears later.",
    input: { bodyRaw: `{"note":"${sLoneHi}x${sLoneLo}"}` },
    expect: { result: "reject" },
  },
  {
    caseId: "lone-surrogate-in-key-rejects",
    description: "A lone surrogate in an object member name is rejected, not just in a value.",
    input: { bodyRaw: `{"${sLoneHi}":"v"}` },
    expect: { result: "reject" },
  },
  {
    caseId: "lone-surrogate-in-array-rejects",
    description: "A lone surrogate in a nested array element is rejected.",
    input: { bodyRaw: `{"a":["x","${sLoneLo}"]}` },
    expect: { result: "reject" },
  },
]);

console.log(`Wrote conformance/v1/vectors for principal (key ${mb.slice(0, 12)}...).`);
