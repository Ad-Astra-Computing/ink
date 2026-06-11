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

console.log(`Wrote conformance/v1/vectors for principal (key ${mb.slice(0, 12)}...).`);
