#!/usr/bin/env node
// Regenerate the ink/1 conformance vectors. Deterministic: a fixed test seed
// drives a single Ed25519 key, so re-running produces byte-identical output.
// The vectors are the cross-implementation contract; the TypeScript runner in
// test/conformance.test.ts asserts this reference implementation agrees with
// them, and a second implementation must make the same accept/reject decisions.
//
//   node conformance/v1/generate.mjs   # writes vectors/*.json next to this file
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  encodePublicKeyMultibase,
  canonicalAgentPrincipal,
  signInkMessage,
  bytesToHex,
  hexToBytes,
  parseCheckpoint,
  formatCheckpoint,
  computeAuditMerkleLeafHash,
  jcsCanonicalize,
  signAuditEvent,
  signAuditQueryResponse,
  encryptInkPayload,
  base64urlEncode,
  buildDiscoveryQueryEnvelope,
} from "../../dist/index.js";

const enc = new TextEncoder();
const here = fileURLToPath(new URL(".", import.meta.url).href);

const seed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-v1-test-key")));
const publicKey = await ed.getPublicKeyAsync(seed);
const mb = encodePublicKeyMultibase(publicKey);
const publicKeyHex = bytesToHex(publicKey);
const principal = canonicalAgentPrincipal(`tulpa:${mb}`);

// Per-category metadata for the manifest: the normative spec each category
// pins, and a one-line summary. Adding a category requires an entry here, so a
// new vector file without a manifest description fails generation (and the
// drift tests) rather than shipping undocumented.
// The `profile` pins each category to the conformance profile that requires it,
// the machine-readable half of the 1.0 base-profile freeze (see
// specs/ink-conformance-profile.md): `base` is the floor every conforming INK
// implementation MUST satisfy; `encryption`, `audit`, `witness`, and
// `containment` are capability-gated and required only when the implementation
// advertises that capability. The base set is frozen by drift tripwires in
// test/conformance-profile.test.ts and go/ink/conformance_manifest_test.go.
const KNOWN_PROFILES = new Set(["base", "encryption", "audit", "witness", "containment", "discovery"]);
const CATEGORY_META = {
  "principal-normalization": { profile: "base", spec: "specs/ink-authorization-chain.md", summary: "Agent principal canonicalization (tulpa:/ink:/key: prefixes)." },
  "signature-base": { profile: "base", spec: "specs/ink-jcs-number-profile.md", summary: "Ed25519 verification over the canonical signature base." },
  "jcs-number": { profile: "base", spec: "specs/ink-jcs-number-profile.md", summary: "RFC 8785 JCS canonicalization and the safe-integer number profile." },
  "key-rotation": { profile: "base", spec: "specs/ink-key-rotation-spec.md", summary: "Key-window verification across active, retired, and revoked keys." },
  "replay-freshness": { profile: "base", spec: "specs/ink-timestamp-grammar.md", summary: "Timestamp window and nonce replay rejection." },
  "timestamp-validity": { profile: "base", spec: "specs/ink-timestamp-grammar.md", summary: "Strict INK timestamp grammar and epoch-millisecond parsing." },
  "jcs-string-safety": { profile: "base", spec: "specs/ink-signed-string-safety.md", summary: "Lone UTF-16 surrogate rejection in signed strings." },
  "signed-body-utf8": { profile: "base", spec: "specs/ink-signed-string-safety.md", summary: "Raw-UTF-8 validity of a signed body, enforced at the byte boundary before parsing." },
  "merkle-inclusion": { profile: "witness", spec: "specs/ink-merkle-inclusion.md", summary: "RFC 6962 inclusion-proof verification." },
  "merkle-consistency": { profile: "witness", spec: "specs/ink-merkle-consistency.md", summary: "RFC 6962 consistency-proof verification." },
  "merkle-checkpoint": { profile: "witness", spec: "specs/ink-merkle-checkpoint.md", summary: "C2SP tlog-checkpoint parsing and canonical formatting." },
  "merkle-leaf": { profile: "audit", spec: "specs/ink-merkle-leaf.md", summary: "Audit-event Merkle leaf-hash computation." },
  "inclusion-receipt": { profile: "audit", spec: "specs/ink-inclusion-receipt.md", summary: "Composite inclusion-receipt verification." },
  "audit-query-response": { profile: "audit", spec: "specs/ink-audit-query-response.md", summary: "Composite audit-query-response verification." },
  "handshake-message": { profile: "containment", spec: "specs/ink-handshake-message.md", summary: "Challenge, rejection, and resolution message validation." },
  "connection-payload": { profile: "base", spec: "specs/ink-connection-payload.md", summary: "Connection request and response payload validation." },
  "agent-card": { profile: "base", spec: "specs/ink-agent-card.md", summary: "Agent Card validation, the pinned INK endpoint URL grammar, and the opt-in discovery descriptor exposure bound." },
  "agent-card-fetch": { profile: "base", spec: "specs/ink-agent-card-discovery-fetch.md", summary: "Agent Card discovery response contract (status, content type, size caps, identity binding)." },
  "private-hostname": { profile: "base", spec: "specs/ink-private-hostname.md", summary: "SSRF host-safety gate: classify a hostname as public or private/special/malformed." },
  "payload-encryption": { profile: "encryption", spec: "specs/ink-payload-encryption.md", summary: "ECIES payload decryption: X25519 + HKDF-SHA256 + AES-256-GCM with the AAD-bound outer envelope." },
  "first-contact-transcript": { profile: "base", spec: "specs/ink-first-contact-transcript.md", summary: "End-to-end first-contact flow: card fetch, version selection, signed connection_request, accepted connection_response." },
  "discovery-query-envelope": { profile: "discovery", spec: "specs/ink-discovery-query.md", summary: "Authenticated discovery query envelope: schema bounds and requester-key signature verification." },
};

// Each vectorFile() call records the bytes it wrote so the manifest can pin a
// SHA-256 over the exact corpus file, deterministically, from this one run.
const writtenVectors = [];

function vectorFile(category, cases) {
  const doc = { format: "ink.conformance.v1", category, cases };
  const bytes = JSON.stringify(doc, null, 2) + "\n";
  writeFileSync(`${here}vectors/${category}.json`, bytes);
  writtenVectors.push({ category, caseCount: cases.length, sha256: createHash("sha256").update(bytes).digest("hex") });
}

// Emit the machine-readable manifest: the stable index a second implementation
// reads to enumerate the corpus and detect drift. Counts and hashes are derived
// from the same bytes just written, never hand-maintained.
function writeManifest() {
  const categories = writtenVectors
    .slice()
    .sort((a, b) => (a.category < b.category ? -1 : a.category > b.category ? 1 : 0))
    .map(({ category, caseCount, sha256 }) => {
      const meta = CATEGORY_META[category];
      if (!meta) throw new Error(`conformance manifest: no CATEGORY_META entry for ${category}`);
      if (!KNOWN_PROFILES.has(meta.profile)) throw new Error(`conformance manifest: category ${category} has unknown profile ${JSON.stringify(meta.profile)}`);
      return { id: category, vector: `vectors/${category}.json`, profile: meta.profile, spec: meta.spec, summary: meta.summary, caseCount, sha256 };
    });
  const manifest = { format: "ink.conformance.manifest.v1", corpus: "ink.conformance.v1", categories };
  writeFileSync(`${here}manifest.json`, JSON.stringify(manifest, null, 2) + "\n");
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
// Signed-body numbers are restricted to the safe-integer profile: a value with
// no fractional part in |v| <= 2^53-1, not negative zero. A safe integer prints
// as a plain base-10 decimal that is byte-identical across ECMAScript and Go.
// The vector is the raw JSON body text; each runner parses it, canonicalizes the
// decoded value, and on accept pins the exact canonical string. The profile is
// on the decoded value, not the source token, so 1e2 canonicalizes to "100".
// bodyRaw (a string) lets a vector express -0, which JSON serialization of a
// parsed object would otherwise collapse to 0.
vectorFile("jcs-number", [
  {
    caseId: "zero-accepts",
    description: "Zero is a safe integer and canonicalizes to 0.",
    input: { bodyRaw: `{"n":0}` },
    expect: { result: "accept", canonicalString: `{"n":0}` },
  },
  {
    caseId: "positive-integer-accepts",
    description: "A small positive integer canonicalizes to its plain decimal.",
    input: { bodyRaw: `{"n":42}` },
    expect: { result: "accept", canonicalString: `{"n":42}` },
  },
  {
    caseId: "negative-integer-accepts",
    description: "A negative integer keeps its sign.",
    input: { bodyRaw: `{"n":-7}` },
    expect: { result: "accept", canonicalString: `{"n":-7}` },
  },
  {
    caseId: "max-safe-integer-accepts",
    description: "2^53-1 is the largest exactly representable integer and is accepted.",
    input: { bodyRaw: `{"n":9007199254740991}` },
    expect: { result: "accept", canonicalString: `{"n":9007199254740991}` },
  },
  {
    caseId: "exponential-source-integer-accepts",
    description: "An integer written in exponential notation decodes to its value and canonicalizes as a plain decimal, so the profile is on the value not the token.",
    input: { bodyRaw: `{"n":1e2}` },
    expect: { result: "accept", canonicalString: `{"n":100}` },
  },
  {
    caseId: "fraction-rejects",
    description: "A value with a fractional part is rejected; fractional canonicalization is where serializers disagree.",
    input: { bodyRaw: `{"n":3.14}` },
    expect: { result: "reject" },
  },
  {
    caseId: "exponential-magnitude-rejects",
    description: "A magnitude large enough to serialize in exponential notation is rejected even though it is an integer value.",
    input: { bodyRaw: `{"n":1e21}` },
    expect: { result: "reject" },
  },
  {
    caseId: "negative-zero-rejects",
    description: "Negative zero is rejected because it serializes as 0, losing the sign.",
    input: { bodyRaw: `{"n":-0}` },
    expect: { result: "reject" },
  },
  {
    caseId: "above-safe-integer-rejects",
    description: "2^53 exceeds the safe-integer range and is rejected.",
    input: { bodyRaw: `{"n":9007199254740992}` },
    expect: { result: "reject" },
  },
  {
    caseId: "far-above-safe-integer-rejects",
    description: "A value above the safe-integer range that does not round-trip exactly is rejected.",
    input: { bodyRaw: `{"n":9007199254740993}` },
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

// ── signed-body-utf8 ─────────────────────────────────────────────────────
// A signed body is verified over its raw bytes, so a receiver MUST reject a body
// whose bytes are not valid UTF-8 before parsing. encoding/json (and a lenient
// TextDecoder) substitutes U+FFFD for an invalid sequence, so a body carrying
// invalid UTF-8 would be signed over different bytes across implementations, the
// same parser-loss hazard as a lone surrogate. The carrier is bodyHex, the raw
// bytes hex-encoded, because a JSON string cannot hold invalid UTF-8. A runner
// decodes the hex, then runs the byte-level parse (fatal UTF-8 decode, then the
// lone-surrogate scan, then JSON parse) and pins the accept or reject decision.
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const utf8Hex = (text) => Buffer.from(text, "utf8").toString("hex");
vectorFile("signed-body-utf8", [
  {
    caseId: "ascii-body-accepts",
    description: "An ASCII signed body is valid UTF-8 and parses.",
    input: { bodyHex: utf8Hex(`{"note":"hello"}`) },
    expect: { result: "accept" },
  },
  {
    caseId: "multibyte-utf8-accepts",
    description: "A body with a two-byte, a four-byte, and a three-byte UTF-8 sequence is valid and parses, so an implementation must accept multibyte content the byte cap does not reject.",
    input: { bodyHex: utf8Hex(`{"note":"€ 😀 你"}`) },
    expect: { result: "accept" },
  },
  {
    caseId: "lone-continuation-byte-rejects",
    description: "A lone continuation byte (0x80) with no lead byte is not valid UTF-8 and is rejected before parsing.",
    input: { bodyHex: toHex([0x7b, 0x80, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "truncated-multibyte-rejects",
    description: "A three-byte sequence (0xE2 0x82) missing its final byte is not valid UTF-8 and is rejected.",
    input: { bodyHex: toHex([0x7b, 0xe2, 0x82, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "overlong-encoding-rejects",
    description: "An overlong two-byte encoding of the solidus (0xC0 0xAF) is not valid UTF-8 and is rejected, so an implementation that decoded it to '/' would sign different bytes.",
    input: { bodyHex: toHex([0x7b, 0xc0, 0xaf, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "invalid-byte-ff-rejects",
    description: "The byte 0xFF never appears in valid UTF-8 and is rejected.",
    input: { bodyHex: toHex([0x7b, 0xff, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "utf16-bytes-reject",
    description: "The UTF-16BE code unit for the euro sign (0x20 0xAC) puts a continuation byte where UTF-8 wants a lead byte, so a UTF-16-encoded body is rejected.",
    input: { bodyHex: toHex([0x7b, 0x20, 0xac, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "valid-utf8-lone-surrogate-rejects",
    description: "A body whose bytes are valid UTF-8 but whose JSON text carries a lone high-surrogate escape is rejected, so the surrogate scan still runs after the UTF-8 decode passes.",
    input: { bodyHex: utf8Hex(`{"note":"${sLoneHi}"}`) },
    expect: { result: "reject" },
  },
  {
    caseId: "not-json-rejects",
    description: "A body that is valid UTF-8 but not JSON is rejected at the parse step.",
    input: { bodyHex: utf8Hex("{not json") },
    expect: { result: "reject" },
  },
  {
    caseId: "nfc-form-accepts",
    description: "A body carrying e-acute as the precomposed U+00E9 (bytes 0xC3 0xA9) is valid UTF-8 and parses, so it is accepted.",
    input: { bodyHex: toHex([0x7b, 0x22, 0x6e, 0x22, 0x3a, 0x22, 0xc3, 0xa9, 0x22, 0x7d]) },
    expect: { result: "accept" },
  },
  {
    caseId: "nfd-form-accepts",
    description: "The same e-acute decomposed as U+0065 U+0301 (bytes 0x65 0xCC 0x81) is also valid UTF-8 and parses, so with nfc-form-accepts this pins the rule as byte validity, not Unicode normalization.",
    input: { bodyHex: toHex([0x7b, 0x22, 0x6e, 0x22, 0x3a, 0x22, 0x65, 0xcc, 0x81, 0x22, 0x7d]) },
    expect: { result: "accept" },
  },
  {
    caseId: "invalid-byte-fe-rejects",
    description: "The byte 0xFE never appears in valid UTF-8 and is rejected before parsing.",
    input: { bodyHex: toHex([0x7b, 0xfe, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "raw-surrogate-bytes-reject",
    description: "The CESU-8 style raw encoding of the surrogate code point U+D800 (bytes 0xED 0xA0 0x80) is not valid UTF-8 and is rejected, the byte-level twin of the lone-surrogate escape case.",
    input: { bodyHex: toHex([0x7b, 0xed, 0xa0, 0x80, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "above-max-codepoint-rejects",
    description: "The sequence 0xF4 0x90 0x80 0x80 would encode U+110000, above the U+10FFFF maximum, so it is not valid UTF-8 and is rejected.",
    input: { bodyHex: toHex([0x7b, 0xf4, 0x90, 0x80, 0x80, 0x7d]) },
    expect: { result: "reject" },
  },
  {
    caseId: "bom-prefixed-rejects",
    description: "A UTF-8 BOM (bytes 0xEF 0xBB 0xBF) prefixing an otherwise valid ASCII JSON object is valid UTF-8 but rejected at the parse step, because the surviving U+FEFF is not a legal JSON character; this pins the fatal decoder against a lenient BOM-stripping decode that would diverge.",
    input: { bodyHex: toHex([0xef, 0xbb, 0xbf, ...Buffer.from(`{"note":"ok"}`, "utf8")]) },
    expect: { result: "reject" },
  },
]);

// ── merkle-inclusion ─────────────────────────────────────────────────────
// RFC 6962 §2.1.1 inclusion-proof walk. A verifier recomputes the Merkle root
// from a leaf hash and an ordered list of sibling hashes and accepts only when
// it equals the claimed root. Internal nodes are SHA-256(0x01 || left || right);
// proof elements are ordered top-down (sibling nearest the root first). The
// vectors pin every leaf position in a power-of-two and a non-power-of-two tree
// plus the rejection cases (tampered root, out-of-range index, short proof,
// padded proof, malformed element) where a mis-ordered or under-checked walker
// would diverge. See specs/ink-merkle-inclusion.md.
function largestPowerOf2LessThan(n) {
  if (n <= 1) return 0;
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}
async function sha256Hex(bytes) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}
async function merkleLeafHash(label) {
  const data = enc.encode(label);
  const buf = new Uint8Array(1 + data.length);
  buf[0] = 0x00;
  buf.set(data, 1);
  return sha256Hex(buf);
}
async function merkleNodeHash(lHex, rHex) {
  const l = hexToBytes(lHex);
  const r = hexToBytes(rHex);
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01;
  buf.set(l, 1);
  buf.set(r, 1 + l.length);
  return sha256Hex(buf);
}
async function merkleRoot(leaves) {
  if (leaves.length === 1) return leaves[0];
  const k = largestPowerOf2LessThan(leaves.length);
  return merkleNodeHash(await merkleRoot(leaves.slice(0, k)), await merkleRoot(leaves.slice(k)));
}
// Build the inclusion proof top-down: the sibling at the level just below the
// root comes first, the sibling adjacent to the leaf last — the order the
// reference walker consumes.
async function inclusionProof(m, leaves) {
  if (leaves.length === 1) return [];
  const k = largestPowerOf2LessThan(leaves.length);
  if (m < k) {
    return [await merkleRoot(leaves.slice(k)), ...(await inclusionProof(m, leaves.slice(0, k)))];
  }
  return [await merkleRoot(leaves.slice(0, k)), ...(await inclusionProof(m - k, leaves.slice(k)))];
}
async function inclusionInput(leaves, root, m) {
  return {
    leafHash: leaves[m],
    inclusionProof: await inclusionProof(m, leaves),
    leafIndex: m,
    treeSize: leaves.length,
    rootHash: root,
  };
}
function flipLastHex(h) {
  const last = h[h.length - 1];
  const repl = last === "0" ? "1" : "0";
  return h.slice(0, -1) + repl;
}

const mLeaves = [];
for (let i = 0; i < 5; i++) mLeaves.push(await merkleLeafHash(`ink-conformance-merkle-leaf-${i}`));
const t1 = mLeaves.slice(0, 1);
const t1Root = await merkleRoot(t1);
const t4 = mLeaves.slice(0, 4);
const t4Root = await merkleRoot(t4);
const t5 = mLeaves.slice(0, 5);
const t5Root = await merkleRoot(t5);
const t4Proof0 = await inclusionProof(0, t4);

vectorFile("merkle-inclusion", [
  {
    caseId: "single-leaf-accepts",
    description: "In a one-leaf tree the leaf is its own root and the proof is empty.",
    input: await inclusionInput(t1, t1Root, 0),
    expect: { result: "accept" },
  },
  {
    caseId: "pow2-index0-accepts",
    description: "Leaf 0 of a four-leaf (power-of-two) tree verifies against the root.",
    input: await inclusionInput(t4, t4Root, 0),
    expect: { result: "accept" },
  },
  {
    caseId: "pow2-index1-accepts",
    description: "Leaf 1 of a four-leaf tree verifies; its sibling order differs from leaf 0.",
    input: await inclusionInput(t4, t4Root, 1),
    expect: { result: "accept" },
  },
  {
    caseId: "pow2-index2-accepts",
    description: "Leaf 2 of a four-leaf tree sits in the right subtree and verifies.",
    input: await inclusionInput(t4, t4Root, 2),
    expect: { result: "accept" },
  },
  {
    caseId: "pow2-index3-accepts",
    description: "Leaf 3, the last leaf of a four-leaf tree, verifies.",
    input: await inclusionInput(t4, t4Root, 3),
    expect: { result: "accept" },
  },
  {
    caseId: "nonpow2-index0-accepts",
    description: "Leaf 0 of a five-leaf tree, where the split is 4|1, verifies; an implementation that split 2|3 would diverge.",
    input: await inclusionInput(t5, t5Root, 0),
    expect: { result: "accept" },
  },
  {
    caseId: "nonpow2-index3-accepts",
    description: "Leaf 3 of a five-leaf tree is the last leaf of the left subtree and verifies.",
    input: await inclusionInput(t5, t5Root, 3),
    expect: { result: "accept" },
  },
  {
    caseId: "nonpow2-index4-accepts",
    description: "Leaf 4 of a five-leaf tree is the lone leaf of the right subtree and verifies with a shorter proof.",
    input: await inclusionInput(t5, t5Root, 4),
    expect: { result: "accept" },
  },
  {
    caseId: "tampered-root-rejects",
    description: "A valid proof against a root with one flipped hex digit does not reconstruct that root.",
    input: { ...(await inclusionInput(t4, t4Root, 0)), rootHash: flipLastHex(t4Root) },
    expect: { result: "reject" },
  },
  {
    caseId: "index-out-of-range-rejects",
    description: "A leafIndex equal to treeSize is out of range and is rejected before any walk.",
    input: { ...(await inclusionInput(t4, t4Root, 0)), leafIndex: 4 },
    expect: { result: "reject" },
  },
  {
    caseId: "proof-too-short-rejects",
    description: "A proof one entry shorter than the tree depth cannot reach the root and is rejected, not silently equated to the leaf hash.",
    input: { ...(await inclusionInput(t4, t4Root, 0)), inclusionProof: t4Proof0.slice(0, t4Proof0.length - 1) },
    expect: { result: "reject" },
  },
  {
    caseId: "proof-extra-entry-rejects",
    description: "A valid proof padded with one unused entry is rejected; a verifier that stops once it reaches the leaf would wrongly accept it.",
    input: { ...(await inclusionInput(t4, t4Root, 0)), inclusionProof: [...t4Proof0, mLeaves[4]] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-proof-element-rejects",
    description: "A proof element that is not 64 lowercase hex characters is rejected.",
    input: { ...(await inclusionInput(t4, t4Root, 0)), inclusionProof: [t4Proof0[0], "zz"] },
    expect: { result: "reject" },
  },
  {
    caseId: "treesize-above-safe-integer-rejects",
    description: "A treeSize of 2^53 is past the ECMAScript safe-integer range, where a JSON number loses precision; both implementations reject it before walking rather than splitting on a value one of them cannot represent exactly.",
    input: { leafHash: mLeaves[0], inclusionProof: [], leafIndex: 0, treeSize: 9007199254740992, rootHash: mLeaves[0] },
    expect: { result: "reject" },
  },
]);

// ── merkle-consistency ───────────────────────────────────────────────────
// RFC 6962 §2.1.2 consistency-proof walk. A verifier checks that the tree of
// `first` leaves (root `firstRoot`) is a prefix of the tree of `second` leaves
// (root `secondRoot`): proof that the log only ever appended and never forked
// its history (a split view), which the `second >= first` size check alone
// cannot detect. The proof is the ordered list of node hashes that reconstruct
// both roots. The vectors pin a boundary matrix of accepted prefixes plus the
// rejection cases (tampered roots, wrong/short/padded proof, first > second, a
// size mismatch, a non-empty root for first = 0, a malformed element, a size
// past the safe-integer range). The leaf and node hashing match the inclusion
// walk, so the two share tree shape. See specs/ink-merkle-consistency.md.
const CONSISTENCY_EMPTY_ROOT = await sha256Hex(new Uint8Array(0));
async function consistencyMth(leaves, start, size) {
  if (size === 0) return CONSISTENCY_EMPTY_ROOT;
  if (size === 1) return leaves[start];
  const k = largestPowerOf2LessThan(size);
  return merkleNodeHash(await consistencyMth(leaves, start, k), await consistencyMth(leaves, start + k, size - k));
}
// Recursive RFC 6962 SUBPROOF(m, D[start:start+size], b), independent of the
// imperative production verifier so agreement is meaningful.
async function consistencySubproof(leaves, m, start, size, b) {
  if (m === size) return b ? [] : [await consistencyMth(leaves, start, size)];
  const k = largestPowerOf2LessThan(size);
  if (m <= k) {
    return [...(await consistencySubproof(leaves, m, start, k, b)), await consistencyMth(leaves, start + k, size - k)];
  }
  return [...(await consistencySubproof(leaves, m - k, start + k, size - k, false)), await consistencyMth(leaves, start, k)];
}
async function consistencyProof(leaves, m, n) {
  if (m === 0 || m === n) return [];
  return consistencySubproof(leaves, m, 0, n, true);
}
async function consistencyInput(leaves, first, second) {
  return {
    first,
    firstRoot: await consistencyMth(leaves, 0, first),
    second,
    secondRoot: await consistencyMth(leaves, 0, second),
    proof: await consistencyProof(leaves, first, second),
  };
}

const cLeaves = [];
for (let i = 0; i < 8; i++) cLeaves.push(await merkleLeafHash(`ink-conformance-consistency-leaf-${i}`));
const cBase = await consistencyInput(cLeaves, 5, 8);

vectorFile("merkle-consistency", [
  {
    caseId: "one-to-two-accepts",
    description: "A 1-leaf tree is a prefix of a 2-leaf tree; the single-node proof reconstructs both roots.",
    input: await consistencyInput(cLeaves, 1, 2),
    expect: { result: "accept" },
  },
  {
    caseId: "two-to-three-accepts",
    description: "A 2-leaf prefix of a 3-leaf tree, where the second tree splits 2|1.",
    input: await consistencyInput(cLeaves, 2, 3),
    expect: { result: "accept" },
  },
  {
    caseId: "three-to-four-accepts",
    description: "A 3-leaf prefix of a 4-leaf tree; the rightmost path differs between the trees.",
    input: await consistencyInput(cLeaves, 3, 4),
    expect: { result: "accept" },
  },
  {
    caseId: "four-to-eight-accepts",
    description: "A 4-leaf (power-of-two) prefix of an 8-leaf tree; firstRoot is a left subtree of secondRoot.",
    input: await consistencyInput(cLeaves, 4, 8),
    expect: { result: "accept" },
  },
  {
    caseId: "five-to-eight-accepts",
    description: "A 5-leaf prefix of an 8-leaf tree, a non-power-of-two first size with a multi-node proof.",
    input: cBase,
    expect: { result: "accept" },
  },
  {
    caseId: "seven-to-eight-accepts",
    description: "A 7-leaf prefix of an 8-leaf tree; only the last leaf is new.",
    input: await consistencyInput(cLeaves, 7, 8),
    expect: { result: "accept" },
  },
  {
    caseId: "one-to-eight-accepts",
    description: "A 1-leaf prefix of an 8-leaf tree, the deepest single-leaf proof in the matrix.",
    input: await consistencyInput(cLeaves, 1, 8),
    expect: { result: "accept" },
  },
  {
    caseId: "equal-size-accepts",
    description: "A tree is consistent with itself: equal sizes, equal roots, and an empty proof.",
    input: await consistencyInput(cLeaves, 4, 4),
    expect: { result: "accept" },
  },
  {
    caseId: "empty-prefix-accepts",
    description: "The empty tree is a prefix of every tree; first = 0 with the fixed empty-tree root and an empty proof.",
    input: { first: 0, firstRoot: CONSISTENCY_EMPTY_ROOT, second: 4, secondRoot: await consistencyMth(cLeaves, 0, 4), proof: [] },
    expect: { result: "accept" },
  },
  {
    caseId: "tampered-second-root-rejects",
    description: "The same proof against a second root with one flipped hex digit does not reconstruct that root.",
    input: { ...cBase, secondRoot: flipLastHex(cBase.secondRoot) },
    expect: { result: "reject" },
  },
  {
    caseId: "tampered-first-root-rejects",
    description: "A first root with one flipped hex digit is not the prefix the proof reconstructs.",
    input: { ...cBase, firstRoot: flipLastHex(cBase.firstRoot) },
    expect: { result: "reject" },
  },
  {
    caseId: "wrong-proof-element-rejects",
    description: "Flipping a hex digit in the first proof node breaks both reconstructions.",
    input: { ...cBase, proof: [flipLastHex(cBase.proof[0]), ...cBase.proof.slice(1)] },
    expect: { result: "reject" },
  },
  {
    caseId: "proof-too-short-rejects",
    description: "A proof one node shorter than the walk requires is exhausted before reaching the roots.",
    input: { ...cBase, proof: cBase.proof.slice(0, cBase.proof.length - 1) },
    expect: { result: "reject" },
  },
  {
    caseId: "proof-extra-entry-rejects",
    description: "A valid proof padded with one unused node is rejected; every element must be consumed.",
    input: { ...cBase, proof: [...cBase.proof, cLeaves[0]] },
    expect: { result: "reject" },
  },
  {
    caseId: "first-greater-than-second-rejects",
    description: "A first size larger than the second cannot be a prefix and is rejected before any walk.",
    input: { first: 8, firstRoot: await consistencyMth(cLeaves, 0, 8), second: 4, secondRoot: await consistencyMth(cLeaves, 0, 4), proof: [] },
    expect: { result: "reject" },
  },
  {
    caseId: "equal-size-root-mismatch-rejects",
    description: "Equal sizes with differing roots is a fork, not consistency, even with an empty proof.",
    input: { first: 4, firstRoot: await consistencyMth(cLeaves, 0, 4), second: 4, secondRoot: flipLastHex(await consistencyMth(cLeaves, 0, 4)), proof: [] },
    expect: { result: "reject" },
  },
  {
    caseId: "empty-prefix-wrong-root-rejects",
    description: "first = 0 must carry the fixed empty-tree root; any other firstRoot is rejected.",
    input: { first: 0, firstRoot: await consistencyMth(cLeaves, 0, 3), second: 4, secondRoot: await consistencyMth(cLeaves, 0, 4), proof: [] },
    expect: { result: "reject" },
  },
  {
    caseId: "malformed-proof-element-rejects",
    description: "A proof node that is not 64 lowercase hex characters is rejected.",
    input: { ...cBase, proof: ["zz", ...cBase.proof.slice(1)] },
    expect: { result: "reject" },
  },
  {
    caseId: "second-above-safe-integer-rejects",
    description: "A second size of 2^53 is past the ECMAScript safe-integer range; both implementations reject it before walking rather than splitting on a value one cannot represent exactly.",
    input: { first: 1, firstRoot: cLeaves[0], second: 9007199254740992, secondRoot: cLeaves[1], proof: [] },
    expect: { result: "reject" },
  },
]);

// ── merkle-checkpoint ────────────────────────────────────────────────────
// C2SP tlog-checkpoint body grammar (INK Auditability §7.7). A checkpoint body
// is three lines plus a trailing newline: origin, decimal tree size, and a
// 64-hex root hash. A verifier parses this before checking the witness
// signature; a parser differential, where one implementation accepts a body
// another rejects, would let a forged or malformed checkpoint through one side.
// The vectors pin the accept set (with the canonical re-serialization) and the
// rejection edges (line count, trailing junk, empty origin, a non-decimal or
// out-of-range tree size, and a malformed root hash). See
// specs/ink-merkle-checkpoint.md.
const cpRoot = await sha256Hex(enc.encode("ink-conformance-checkpoint-root"));
function cpAccept(caseId, description, body) {
  const parsed = parseCheckpoint(body);
  if (!parsed) throw new Error(`cpAccept given a body that does not parse: ${caseId}`);
  return { caseId, description, input: { body }, expect: { result: "accept", canonicalString: formatCheckpoint(parsed) } };
}
function cpReject(caseId, description, body) {
  return { caseId, description, input: { body }, expect: { result: "reject" } };
}

vectorFile("merkle-checkpoint", [
  cpAccept("valid-accepts", "A well-formed origin, tree size, and root hash parse, and the body is already canonical.", `example.com/ink-log\n5\n${cpRoot}\n`),
  cpAccept("tree-size-zero-accepts", "A fresh log with tree size 0 is a valid checkpoint.", `example.com/ink-log\n0\n${cpRoot}\n`),
  cpAccept("max-safe-integer-tree-size-accepts", "A tree size at the safe-integer ceiling (2^53-1) parses.", `example.com/ink-log\n9007199254740991\n${cpRoot}\n`),
  cpAccept("leading-zero-tree-size-normalizes", "A tree size written with a leading zero parses and re-serializes without it, so the canonical form is agnostic to the input padding.", `example.com/ink-log\n05\n${cpRoot}\n`),
  cpReject("empty-body-rejects", "An empty body is not a checkpoint.", ""),
  cpReject("missing-trailing-newline-rejects", "Without the trailing newline the body has only three parts and is rejected.", `example.com/ink-log\n5\n${cpRoot}`),
  cpReject("extra-trailing-line-rejects", "An extra blank line past the trailing newline is rejected, not silently ignored.", `example.com/ink-log\n5\n${cpRoot}\n\n`),
  cpReject("trailing-junk-rejects", "Any non-empty content after the final newline is rejected.", `example.com/ink-log\n5\n${cpRoot}\nx`),
  cpReject("empty-origin-rejects", "The origin line is the domain separator and must be non-empty.", `\n5\n${cpRoot}\n`),
  cpReject("non-numeric-tree-size-rejects", "A tree size that is not a decimal integer is rejected.", `example.com/ink-log\nabc\n${cpRoot}\n`),
  cpReject("negative-tree-size-rejects", "A leading minus sign is not a decimal-digit tree size.", `example.com/ink-log\n-5\n${cpRoot}\n`),
  cpReject("leading-plus-tree-size-rejects", "A leading plus sign is not a decimal-digit tree size.", `example.com/ink-log\n+5\n${cpRoot}\n`),
  cpReject("tree-size-above-safe-integer-rejects", "A tree size of 2^53 is past the safe-integer range and is rejected.", `example.com/ink-log\n9007199254740992\n${cpRoot}\n`),
  cpReject("uppercase-root-hash-rejects", "The root hash must be lowercase hex; an uppercase digit is rejected.", `example.com/ink-log\n5\n${cpRoot.toUpperCase()}\n`),
  cpReject("short-root-hash-rejects", "A root hash of 63 hex characters is rejected.", `example.com/ink-log\n5\n${cpRoot.slice(0, 63)}\n`),
  cpReject("long-root-hash-rejects", "A root hash of 65 hex characters is rejected.", `example.com/ink-log\n5\n${cpRoot}a\n`),
  cpReject("non-hex-root-hash-rejects", "A root hash with a non-hex character is rejected.", `example.com/ink-log\n5\n${"z".repeat(64)}\n`),
  cpReject("trailing-cr-root-hash-rejects", "A carriage return left on the root-hash line by CRLF splitting makes it not 64 hex characters.", `example.com/ink-log\n5\n${cpRoot}\r\n`),
  cpReject("oversized-body-rejects", "A body past the size cap is rejected before it is split, bounding parser work on a hostile blob.", "a".repeat(1025)),
  cpAccept("utf16-boundary-origin-accepts", "An origin of 256 two-byte characters is exactly 256 UTF-16 code units and accepts; an implementation that measured the line cap in bytes (512) would wrongly reject it.", `${"é".repeat(256)}\n5\n${cpRoot}\n`),
  cpReject("astral-origin-over-utf16-cap-rejects", "An origin of 200 astral-plane characters is 400 UTF-16 code units, past the 256-unit line cap, and rejects; an implementation that measured the cap in Unicode scalar values (200) would wrongly accept it.", `${String.fromCodePoint(0x1d400).repeat(200)}\n5\n${cpRoot}\n`),
]);

// ── merkle-leaf ──────────────────────────────────────────────────────────
// RFC 6962 leaf hash for an INK audit event (Auditability §7.3):
//   SHA-256(0x00 || JCS(event-without-agentSignature)).
// This is the value a witness commits to its transparency log and the value an
// inclusion proof walks up from. The leaf strips agentSignature before
// canonicalizing, so it does not change when the agent signature is attached,
// and it carries the 0x00 leaf-domain prefix that distinguishes a leaf from an
// internal node (0x01 || left || right). The accept vectors pin the exact
// digest for representative events; member order and a present agentSignature
// do not change it. The reject vectors are inputs the signed-body contract
// already forbids: a non-object, a lone surrogate, and an unsafe-integer
// number, so the leaf path enforces the same profile as signing. See
// specs/ink-merkle-leaf.md.
async function leafAccept(caseId, description, eventRaw) {
  const leafHash = await computeAuditMerkleLeafHash(JSON.parse(eventRaw));
  return { caseId, description, input: { eventRaw }, expect: { result: "accept", leafHash } };
}
function leafReject(caseId, description, eventRaw) {
  return { caseId, description, input: { eventRaw }, expect: { result: "reject" } };
}

vectorFile("merkle-leaf", [
  await leafAccept("minimal-event-accepts", "A minimal audit event hashes to its leaf digest under SHA-256(0x00 || JCS(event)).", `{"id":"evt-1","type":"connection_request"}`),
  await leafAccept("member-order-irrelevant-accepts", "The same event with its members in a different source order canonicalizes identically, so it pins the same leaf digest as minimal-event-accepts.", `{"type":"connection_request","id":"evt-1"}`),
  await leafAccept("strips-agent-signature-accepts", "agentSignature is removed before canonicalizing, so attaching it does not change the leaf; this pins the same digest as minimal-event-accepts.", `{"id":"evt-1","type":"connection_request","agentSignature":"z3kmY29udGVudA"}`),
  await leafAccept("nested-and-number-accepts", "A nested object, an array, and a safe-integer number canonicalize and pin the leaf digest.", `{"id":"evt-2","payload":{"items":["a","b"],"count":42},"ts":"2026-06-15T00:00:00.000Z"}`),
  await leafAccept("unicode-value-accepts", "A non-ASCII string value is canonicalized with minimal JCS escaping and pins the leaf digest, exercising UTF-16 member handling.", `{"id":"evt-3","note":"café 日本語"}`),
  await leafAccept("empty-object-accepts", "An empty object is a valid event and hashes SHA-256(0x00 || \"{}\").", `{}`),
  leafReject("array-not-object-rejects", "A JSON array is not an audit event object and is rejected.", `[1,2,3]`),
  leafReject("string-not-object-rejects", "A JSON string is not an audit event object and is rejected.", `"hello"`),
  leafReject("null-not-object-rejects", "JSON null is not an audit event object and is rejected.", `null`),
  leafReject("lone-surrogate-value-rejects", "A lone UTF-16 surrogate escape in a value is rejected before hashing, because a parser that rewrote it to U+FFFD would commit different bytes.", `{"id":"\\ud800"}`),
  leafReject("unsafe-integer-number-rejects", "A number past the safe-integer range (2^53) is rejected, so the leaf path enforces the same number profile as signing.", `{"n":9007199254740992}`),
  leafReject("excessive-depth-rejects", "An event nested past the depth bound (32) is rejected before canonicalization, in both implementations, so neither commits a leaf the other refuses.", (() => { let v = "1"; for (let i = 0; i < 40; i++) v = `{"a":${v}}`; return v; })()),
  leafReject("excessive-node-count-rejects", "An event with more nodes than the bound (10000) is rejected before canonicalization, bounding the work a hostile event can force.", `{"a":[${Array.from({ length: 10001 }, () => "0").join(",")}]}`),
  leafReject("oversized-canonical-body-rejects", "An event whose canonical body exceeds the 1 MiB cap is rejected after canonicalization, so a Go witness cannot commit a leaf the reference refuses to hash.", `{"d":"${"x".repeat(1048569)}"}`),
]);

// ── inclusion-receipt ─────────────────────────────────────────────────────
// End-to-end verification of a witness inclusion receipt (INK Auditability §7):
// structural validation, the witness Ed25519 service signature over
// "ink/audit-inclusion/v1\n" + JCS({eventId, leafIndex, treeSize, rootHash,
// timestamp}), an optional leaf-to-root proof walk bound to the named event,
// and an optional later-checkpoint anti-rollback and fork cross-check. The
// vectors pin the accept set and every rejection edge across the four steps so a
// verifier that skips or mis-orders one of them diverges. See
// specs/ink-inclusion-receipt.md.
const rcptTs = "2026-06-15T12:00:00.000Z";
const rcptEvents = [0, 1, 2, 3].map((i) => ({ id: `evt-${i}`, type: "connection_request", seq: i }));
const rcptLeaves = await Promise.all(rcptEvents.map((e) => computeAuditMerkleLeafHash(e)));
const rcptRoot = await merkleRoot(rcptLeaves);
const rcptIdx = 1;
const rcptProof = await inclusionProof(rcptIdx, rcptLeaves);
const otherWitnessSeed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-v1-other-witness")));
const otherWitnessHex = bytesToHex(await ed.getPublicKeyAsync(otherWitnessSeed));

async function signReceiptCore(core) {
  const sigBase = `ink/audit-inclusion/v1\n` + jcsCanonicalize(core);
  const sig = await ed.signAsync(enc.encode(sigBase), seed);
  return Buffer.from(sig).toString("base64url");
}
async function makeReceipt(overrides = {}) {
  const base = { eventId: rcptEvents[rcptIdx].id, leafIndex: rcptIdx, treeSize: 4, rootHash: rcptRoot, timestamp: rcptTs };
  const core = { ...base, ...overrides };
  const serviceSignature = await signReceiptCore(core);
  return { ...core, inclusionProof: rcptProof, serviceSignature };
}
// A receipt whose signature is valid for the unmodified core; structural and
// tamper mutations are applied AFTER signing so the signature no longer matches.
const validReceipt = await makeReceipt();
function rcptAccept(caseId, description, input) {
  return { caseId, description, input, expect: { result: "accept" } };
}
function rcptReject(caseId, description, input) {
  return { caseId, description, input, expect: { result: "reject" } };
}
const wpk = { witnessPublicKeyHex: publicKeyHex };

vectorFile("inclusion-receipt", [
  rcptAccept("valid-signature-only-accepts", "A structurally valid receipt with a valid witness signature verifies when no event or checkpoint is supplied; the proof and checkpoint steps are skipped.", { receipt: validReceipt, ...wpk }),
  // structural rejections
  rcptReject("receipt-not-object-rejects", "A receipt that is not an object is rejected.", { receipt: "not-a-receipt", ...wpk }),
  rcptReject("empty-event-id-rejects", "An empty eventId is rejected.", { receipt: { ...validReceipt, eventId: "" }, ...wpk }),
  rcptReject("negative-leaf-index-rejects", "A negative leafIndex is rejected.", { receipt: { ...validReceipt, leafIndex: -1 }, ...wpk }),
  rcptReject("zero-tree-size-rejects", "A treeSize below 1 is rejected; a receipt commits to at least its own leaf.", { receipt: { ...validReceipt, treeSize: 0 }, ...wpk }),
  rcptReject("leaf-index-ge-tree-size-rejects", "A leafIndex not less than treeSize is rejected.", { receipt: { ...validReceipt, leafIndex: 4, treeSize: 4 }, ...wpk }),
  rcptReject("uppercase-root-hash-rejects", "A non-lowercase-hex rootHash is rejected.", { receipt: { ...validReceipt, rootHash: rcptRoot.toUpperCase() }, ...wpk }),
  rcptReject("short-root-hash-rejects", "A rootHash that is not 64 hex characters is rejected.", { receipt: { ...validReceipt, rootHash: rcptRoot.slice(0, 63) }, ...wpk }),
  rcptReject("proof-not-array-rejects", "An inclusionProof that is not an array is rejected.", { receipt: { ...validReceipt, inclusionProof: "nope" }, ...wpk }),
  rcptReject("proof-too-long-rejects", "An inclusionProof past the 64-entry cap is rejected before any walk.", { receipt: { ...validReceipt, inclusionProof: Array(65).fill(rcptRoot) }, ...wpk }),
  rcptReject("proof-bad-element-rejects", "An inclusionProof entry that is not 64 lowercase hex is rejected.", { receipt: { ...validReceipt, inclusionProof: ["not-a-hash"] }, ...wpk }),
  rcptReject("empty-timestamp-rejects", "An empty timestamp is rejected.", { receipt: { ...validReceipt, timestamp: "" }, ...wpk }),
  rcptReject("empty-signature-rejects", "An empty serviceSignature is rejected.", { receipt: { ...validReceipt, serviceSignature: "" }, ...wpk }),
  // signature rejections (structure stays valid; the signed core is tampered after signing)
  rcptReject("tampered-root-hash-rejects", "Changing rootHash after signing breaks the witness signature.", { receipt: { ...validReceipt, rootHash: rcptLeaves[0] }, ...wpk }),
  rcptReject("tampered-leaf-index-rejects", "Changing leafIndex after signing breaks the witness signature.", { receipt: { ...validReceipt, leafIndex: 2 }, ...wpk }),
  rcptReject("tampered-tree-size-rejects", "Changing treeSize after signing breaks the witness signature.", { receipt: { ...validReceipt, treeSize: 8 }, ...wpk }),
  rcptReject("tampered-event-id-rejects", "Changing eventId after signing breaks the witness signature.", { receipt: { ...validReceipt, eventId: "evt-9" }, ...wpk }),
  rcptReject("tampered-timestamp-rejects", "Changing timestamp after signing breaks the witness signature.", { receipt: { ...validReceipt, timestamp: "2026-06-15T13:00:00.000Z" }, ...wpk }),
  rcptReject("wrong-witness-key-rejects", "A valid signature checked against a different witness key is rejected.", { receipt: validReceipt, witnessPublicKeyHex: otherWitnessHex }),
  rcptReject("malformed-signature-rejects", "A serviceSignature that decodes to the wrong length is rejected.", { receipt: { ...validReceipt, serviceSignature: "AAAA" }, ...wpk }),
  // proof-walk step (an event or eventHash is supplied; inclusionProof is not signed, so a tampered proof keeps the signature valid and isolates the walk)
  rcptAccept("event-bound-proof-accepts", "Supplying the named event recomputes its leaf hash, binds event.id to the receipt, and walks the proof up to rootHash.", { receipt: validReceipt, ...wpk, event: rcptEvents[rcptIdx] }),
  rcptReject("event-id-mismatch-rejects", "An event whose id differs from the receipt's eventId is rejected, even if its leaf would otherwise be in the tree.", { receipt: validReceipt, ...wpk, event: { ...rcptEvents[rcptIdx], id: "evt-9" } }),
  rcptReject("event-leaf-not-at-index-rejects", "An event whose id matches but whose body hashes to a different leaf does not walk to rootHash and is rejected.", { receipt: validReceipt, ...wpk, event: { ...rcptEvents[rcptIdx], seq: 99 } }),
  rcptReject("event-missing-id-rejects", "An event without a string id cannot be bound to the receipt and is rejected.", { receipt: validReceipt, ...wpk, event: { type: "connection_request", seq: 1 } }),
  rcptAccept("event-hash-legacy-accepts", "A pre-computed leaf hash that sits at leafIndex walks to rootHash and verifies, the lower-assurance unbound path.", { receipt: validReceipt, ...wpk, eventHash: rcptLeaves[rcptIdx] }),
  rcptReject("event-hash-bad-format-rejects", "An eventHash that is not 64 lowercase hex is rejected.", { receipt: validReceipt, ...wpk, eventHash: "not-a-hash" }),
  rcptReject("event-hash-not-in-tree-rejects", "A well-formed eventHash that is not the leaf at leafIndex does not walk to rootHash and is rejected.", { receipt: validReceipt, ...wpk, eventHash: rcptLeaves[0] }),
  rcptReject("tampered-proof-rejects", "With the event supplied, a proof whose sibling is replaced does not reconstruct rootHash and is rejected; the witness signature stays valid because the proof is not signed.", { receipt: { ...validReceipt, inclusionProof: [rcptLeaves[0], ...rcptProof.slice(1)] }, ...wpk, event: rcptEvents[rcptIdx] }),
  // later-checkpoint cross-check
  rcptAccept("checkpoint-newer-accepts", "A later checkpoint whose tree is larger is consistent with the receipt; the tree only grew.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: 8, rootHash: rcptRoot } }),
  rcptAccept("checkpoint-equal-same-root-accepts", "A later checkpoint at the same size with the same root is consistent.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: 4, rootHash: rcptRoot } }),
  rcptReject("checkpoint-rollback-rejects", "A later checkpoint whose tree is smaller than the receipt's means the witness rewound the log and is rejected.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: 2, rootHash: rcptRoot } }),
  rcptReject("checkpoint-fork-rejects", "A later checkpoint at the same size with a different root is a fork and is rejected.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: 4, rootHash: rcptLeaves[0] } }),
  rcptReject("checkpoint-bad-root-rejects", "A later checkpoint whose rootHash is not 64 lowercase hex is rejected.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: 8, rootHash: "not-a-hash" } }),
  rcptReject("checkpoint-negative-size-rejects", "A later checkpoint with a negative tree size is rejected.", { receipt: validReceipt, ...wpk, laterCheckpoint: { treeSize: -1, rootHash: rcptRoot } }),
  rcptAccept("full-receipt-accepts", "A receipt that passes structure, signature, the event-bound proof walk, and a newer-checkpoint cross-check all at once verifies.", { receipt: validReceipt, ...wpk, event: rcptEvents[rcptIdx], laterCheckpoint: { treeSize: 8, rootHash: rcptRoot } }),
  // signed-string and number-spelling parity (parser-differential guards)
  rcptReject("surrogate-in-event-id-rejects", "A lone UTF-16 surrogate in the signed eventId is rejected before the signature step, because a parser that rewrote it to U+FFFD would verify different bytes.", { receipt: { ...validReceipt, eventId: "\ud800" }, ...wpk }),
  rcptReject("surrogate-in-event-rejects", "A lone UTF-16 surrogate in the supplied event is rejected before the leaf is hashed, the same signed-string rule the leaf-hash path enforces.", { receipt: validReceipt, ...wpk, event: { id: rcptEvents[rcptIdx].id, note: "\ud800" } }),
  rcptReject("non-integer-leaf-index-rejects", "A fractional leafIndex is not an integer and is rejected; an integer-valued number of any spelling would be accepted.", { receipt: { ...validReceipt, leafIndex: 1.5 }, ...wpk }),
  rcptReject("null-event-rejects", "A present but null event is rejected at the proof step rather than throwing; a verifier must fail closed on a malformed event.", { receipt: validReceipt, ...wpk, event: null }),
]);

// ── audit-query-response ──────────────────────────────────────────────────
// End-to-end verification of a witness audit-query response (INK Auditability
// §7.3): structure, the requester/messageId bindings, the witness envelope
// Ed25519 signature over "ink/audit-query-response/v1\n" + JCS(response minus
// serviceSignature), the per-event scope rule, the events-to-proofs one-to-one
// mapping, every Merkle proof walk, the required per-event agent signature, and
// an optional later-checkpoint cross-check. Events are signed by an agent key;
// the response envelope is signed by the witness key. The vectors pin the
// accept set and every rejection edge. See specs/ink-audit-query-response.md.
const aqWitnessHex = publicKeyHex;
const aqAgentSeed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-v1-agent-a")));
const aqAgentHex = bytesToHex(await ed.getPublicKeyAsync(aqAgentSeed));
const aqWrongAgentSeed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-v1-agent-wrong")));
const aqRequester = "did:web:agent-a.example";
const aqCounterparty = "did:web:agent-b.example";
const aqServiceDid = "did:web:witness.example";
const aqMessageId = "msg-001";
const aqTs = "2026-06-15T12:00:00.000Z";

async function aqMakeEvent(i, signer = aqAgentSeed) {
  const ev = { id: `evt-${i}`, type: "connection_request", messageId: aqMessageId, agentId: aqRequester, counterpartyId: aqCounterparty, seq: i };
  ev.agentSignature = await signAuditEvent(ev, signer);
  return ev;
}
const aqEvents = await Promise.all([0, 1, 2].map((i) => aqMakeEvent(i)));
const aqLeaves = await Promise.all(aqEvents.map((e) => computeAuditMerkleLeafHash(e)));
const aqRoot = await merkleRoot(aqLeaves);
const aqProofs = await Promise.all(aqEvents.map(async (e, i) => ({ eventId: e.id, leafIndex: i, inclusionProof: await inclusionProof(i, aqLeaves) })));
const aqBasePayload = {
  protocol: "ink/0.1",
  type: "network.tulpa.audit_query_response",
  serviceDid: aqServiceDid,
  messageId: aqMessageId,
  requester: aqRequester,
  events: aqEvents,
  proofs: aqProofs,
  treeSize: 3,
  rootHash: aqRoot,
  timestamp: aqTs,
};
async function aqRawSign(payload) {
  const sigBase = `ink/audit-query-response/v1\n` + jcsCanonicalize(payload);
  const sig = await ed.signAsync(enc.encode(sigBase), seed);
  return Buffer.from(sig).toString("base64url");
}
// Witness-signs the payload (with overrides applied) so the envelope signature
// is valid over the exact content, isolating the step under test.
async function aqSigned(overrides = {}) {
  const payload = { ...aqBasePayload, ...overrides };
  return { ...payload, serviceSignature: await aqRawSign(payload) };
}
const aqValid = await aqSigned();
const aqEmptyResponse = await aqSigned({ events: [], proofs: [], treeSize: 0, rootHash: CONSISTENCY_EMPTY_ROOT });
const aqKeys = { [aqRequester]: aqAgentHex };
// Base input fields shared by most cases.
const aqBase = { witnessPublicKeyHex: aqWitnessHex, expectedRequester: aqRequester, expectedMessageId: aqMessageId, agentKeysHex: aqKeys };
function aqAccept(caseId, description, input) {
  return { caseId, description, input, expect: { result: "accept" } };
}
function aqReject(caseId, description, input) {
  return { caseId, description, input, expect: { result: "reject" } };
}

// An event whose agentSignature is by the wrong agent key (valid envelope, fails the agent-sig step).
const aqEventsWrongSig = await Promise.all([0, 1, 2].map((i) => aqMakeEvent(i, aqWrongAgentSeed)));
// Note the leaves are unchanged (agentSignature is stripped before hashing), so the proofs still walk.
const aqWrongSigResponse = await aqSigned({ events: aqEventsWrongSig });
// An out-of-scope event (messageId mismatch), with the leaves/proofs recomputed so only the scope step fails.
const aqScopeEvent = { id: "evt-x", type: "connection_request", messageId: "other-msg", agentId: aqRequester, counterpartyId: aqCounterparty, seq: 0 };
aqScopeEvent.agentSignature = await signAuditEvent(aqScopeEvent, aqAgentSeed);
const aqScopeLeaf = await computeAuditMerkleLeafHash(aqScopeEvent);
const aqScopeResponse = await aqSigned({ events: [aqScopeEvent], proofs: [{ eventId: "evt-x", leafIndex: 0, inclusionProof: [] }], treeSize: 1, rootHash: aqScopeLeaf });
// An in-scope-by-messageId event whose parties exclude the requester, so only
// the requester-party scope branch fails (envelope messageId still matches).
const aqNonPartyEvent = { id: "evt-np", type: "connection_request", messageId: aqMessageId, agentId: aqCounterparty, counterpartyId: "did:web:agent-c.example", seq: 0 };
aqNonPartyEvent.agentSignature = await signAuditEvent(aqNonPartyEvent, aqAgentSeed);
const aqNonPartyLeaf = await computeAuditMerkleLeafHash(aqNonPartyEvent);
const aqNonPartyResponse = await aqSigned({ events: [aqNonPartyEvent], proofs: [{ eventId: "evt-np", leafIndex: 0, inclusionProof: [] }], treeSize: 1, rootHash: aqNonPartyLeaf });
// ink/0.4 dual-accept: a response under the vendor-neutral namespace, witness-
// signed over its actual type, verifies. The relabel variant keeps the
// legacy-namespace signature but swaps the type, so the envelope signature fails.
const aqInkNamespace = await aqSigned({ type: "network.ink.audit_query_response" });
const aqRelabelled = { ...aqValid, type: "network.ink.audit_query_response" };

vectorFile("audit-query-response", [
  aqAccept("valid-accepts", "A well-formed, witness-signed response with in-scope, agent-signed events and valid Merkle proofs verifies.", { ...aqBase, response: aqValid }),
  aqAccept("ink-namespace-accepts", "A response under the vendor-neutral network.ink namespace, witness-signed over its actual type, verifies (ink/0.4 dual-accept).", { ...aqBase, response: aqInkNamespace }),
  aqReject("relabelled-namespace-rejects", "A response signed under the legacy namespace but relabelled to network.ink fails the witness envelope signature.", { ...aqBase, response: aqRelabelled }),
  aqAccept("empty-tree-accepts", "A fresh witness response with tree size 0, no events or proofs, and the empty-tree root verifies.", { ...aqBase, response: aqEmptyResponse }),
  // structure
  aqReject("wrong-protocol-rejects", "A protocol other than ink/0.1 is rejected.", { ...aqBase, response: { ...aqValid, protocol: "ink/0.2" } }),
  aqReject("wrong-type-rejects", "A type other than the audit-query response type is rejected.", { ...aqBase, response: { ...aqValid, type: "network.tulpa.message" } }),
  aqReject("empty-message-id-rejects", "An empty messageId is rejected.", { ...aqBase, response: { ...aqValid, messageId: "" } }),
  aqReject("bad-root-hash-rejects", "A rootHash that is not 64 lowercase hex is rejected.", { ...aqBase, response: { ...aqValid, rootHash: "not-a-hash" } }),
  aqReject("empty-tree-with-events-rejects", "A tree size of 0 with non-empty events is a fabricated state and is rejected.", { ...aqBase, response: { ...aqValid, treeSize: 0 } }),
  aqReject("proof-leaf-index-out-of-range-rejects", "A proof leafIndex not less than treeSize is rejected.", { ...aqBase, response: { ...aqValid, proofs: [{ eventId: "evt-0", leafIndex: 3, inclusionProof: aqProofs[0].inclusionProof }, aqProofs[1], aqProofs[2]] } }),
  // binding
  aqReject("message-id-binding-mismatch-rejects", "A response whose messageId does not match the one the verifier asked about is rejected.", { ...aqBase, response: aqValid, expectedMessageId: "other-msg" }),
  aqReject("requester-binding-mismatch-rejects", "A response signed for a different requester is rejected (prevents cross-requester replay).", { ...aqBase, response: aqValid, expectedRequester: "did:web:eve.example" }),
  aqReject("service-did-binding-mismatch-rejects", "A response from an unexpected witness DID is rejected when the verifier pins serviceDid.", { ...aqBase, response: aqValid, expectedServiceDid: "did:web:other-witness.example" }),
  // signature
  aqReject("tampered-root-hash-rejects", "Changing rootHash after signing breaks the witness envelope signature.", { ...aqBase, response: { ...aqValid, rootHash: aqLeaves[0] } }),
  aqReject("wrong-witness-key-rejects", "A valid response checked against a different witness key is rejected.", { ...aqBase, response: aqValid, witnessPublicKeyHex: aqAgentHex }),
  // scope
  aqReject("event-message-id-scope-rejects", "An event whose messageId differs from the envelope is out of scope and is rejected.", { ...aqBase, response: aqScopeResponse }),
  aqReject("requester-not-party-rejects", "An event in scope by messageId but whose agentId and counterpartyId both exclude the requester is rejected at the scope step.", { ...aqBase, response: aqNonPartyResponse }),
  // proofs one-to-one
  aqReject("events-proofs-length-mismatch-rejects", "A response with more events than proofs is rejected.", { ...aqBase, response: await aqSigned({ proofs: [aqProofs[0], aqProofs[1]] }) }),
  aqReject("duplicate-event-id-rejects", "A duplicate event id is rejected.", { ...aqBase, response: await aqSigned({ events: [aqEvents[0], aqEvents[0], aqEvents[2]] }) }),
  aqReject("duplicate-proof-rejects", "Two proofs for the same eventId are rejected.", { ...aqBase, response: await aqSigned({ proofs: [aqProofs[0], aqProofs[0], aqProofs[2]] }) }),
  aqReject("proof-unknown-event-id-rejects", "A proof referencing an eventId not present in events is rejected.", { ...aqBase, response: await aqSigned({ proofs: [{ eventId: "evt-9", leafIndex: 0, inclusionProof: aqProofs[0].inclusionProof }, aqProofs[1], aqProofs[2]] }) }),
  // proof walk
  aqReject("tampered-proof-rejects", "A proof whose sibling is replaced does not reconstruct rootHash and is rejected.", { ...aqBase, response: await aqSigned({ proofs: [{ eventId: "evt-0", leafIndex: 0, inclusionProof: [aqLeaves[1]] }, aqProofs[1], aqProofs[2]] }) }),
  // agent signature
  aqReject("wrong-agent-signature-rejects", "An event whose agentSignature is by a different key fails the required per-event provenance check, even though the witness envelope and Merkle proofs are valid.", { ...aqBase, response: aqWrongSigResponse }),
  aqReject("unresolvable-agent-key-rejects", "An event whose agentId has no resolvable key fails the per-event provenance check.", { ...aqBase, response: aqValid, agentKeysHex: {} }),
  // checkpoint cross-check
  aqAccept("checkpoint-newer-accepts", "A later checkpoint with a larger tree is consistent with the response.", { ...aqBase, response: aqValid, laterCheckpoint: { treeSize: 8, rootHash: aqRoot } }),
  aqReject("checkpoint-rollback-rejects", "A later checkpoint with a smaller tree means the witness rewound the log and is rejected.", { ...aqBase, response: aqValid, laterCheckpoint: { treeSize: 1, rootHash: aqRoot } }),
  aqReject("checkpoint-fork-rejects", "A later checkpoint at the same size with a different root is a fork and is rejected.", { ...aqBase, response: aqValid, laterCheckpoint: { treeSize: 3, rootHash: aqLeaves[0] } }),
]);

// ── handshake-message ─────────────────────────────────────────────────────
// Schema validation for the three INK handshake messages (INK Containment):
// network.tulpa.challenge, .rejection, and .resolution. Each pins the protocol
// and type literals, the enum fields, the string-length caps (in UTF-16 code
// units, matching the reference's Zod .max()), the optional array caps, and the
// handshake timestamp grammar (z.string().datetime(): a UTC date-time with a
// literal Z, no numeric offset). An independent validator must accept and
// reject the same messages. See specs/ink-handshake-message.md.
const hsTs = "2026-06-16T12:00:00.000Z";
const hsChallenge = { protocol: "ink/0.1", type: "network.tulpa.challenge", intentRef: "intent-1", challengeType: "availability_query", nonce: "n1", timestamp: hsTs };
const hsRejection = { protocol: "ink/0.1", type: "network.tulpa.rejection", intentRef: "intent-1", reason: "capacity", nonce: "n1", timestamp: hsTs };
const hsResolution = { protocol: "ink/0.1", type: "network.tulpa.resolution", intentRef: "intent-1", outcome: "accepted", nonce: "n1", timestamp: hsTs };
function hsAccept(caseId, description, message) {
  return { caseId, description, input: { message }, expect: { result: "accept" } };
}
function hsReject(caseId, description, message) {
  return { caseId, description, input: { message }, expect: { result: "reject" } };
}

vectorFile("handshake-message", [
  hsAccept("challenge-valid-accepts", "A well-formed challenge message validates.", hsChallenge),
  hsAccept("rejection-valid-accepts", "A well-formed rejection message validates.", hsRejection),
  hsAccept("resolution-valid-accepts", "A well-formed resolution message validates.", hsResolution),
  hsAccept("challenge-with-optional-arrays-accepts", "A challenge with optional field/window/context arrays within their caps validates.", { ...hsChallenge, fields: ["a", "b"], availableWindows: ["w1"], contextFields: ["c1"] }),
  hsAccept("rejection-with-backoff-accepts", "A rejection with a backoff hint validates.", { ...hsRejection, detail: "too busy", backoffHint: { retryAfterSeconds: 30, backoffClass: "sender" } }),
  hsAccept("resolution-with-details-accepts", "A resolution with details and a counterparty DID validates; details passes through extra keys.", { ...hsResolution, details: { scheduledAt: "2026-06-17", duration: "30m", note: "extra" }, counterpartyDid: "did:web:b.example" }),
  // vendor-neutral namespace (ink/0.4 dual-accept)
  hsAccept("challenge-ink-namespace-accepts", "A challenge using the vendor-neutral network.ink namespace validates.", { ...hsChallenge, type: "network.ink.challenge" }),
  hsAccept("rejection-ink-namespace-accepts", "A rejection using the vendor-neutral network.ink namespace validates.", { ...hsRejection, type: "network.ink.rejection" }),
  hsAccept("resolution-ink-namespace-accepts", "A resolution using the vendor-neutral network.ink namespace validates.", { ...hsResolution, type: "network.ink.resolution" }),
  // protocol / type
  hsReject("wrong-protocol-rejects", "A protocol other than ink/0.1 is rejected.", { ...hsChallenge, protocol: "ink/0.2" }),
  hsReject("wrong-type-rejects", "A type not matching any handshake message is rejected.", { ...hsChallenge, type: "network.tulpa.message" }),
  hsReject("missing-type-rejects", "A message with no type is rejected.", (() => { const { type: _t, ...rest } = hsChallenge; return rest; })()),
  // enums
  hsReject("bad-challenge-type-rejects", "An unknown challengeType is rejected.", { ...hsChallenge, challengeType: "bogus" }),
  hsReject("bad-rejection-reason-rejects", "An unknown rejection reason is rejected.", { ...hsRejection, reason: "bogus" }),
  hsReject("bad-resolution-outcome-rejects", "An unknown resolution outcome is rejected.", { ...hsResolution, outcome: "bogus" }),
  // required fields
  hsReject("missing-nonce-rejects", "A missing nonce is rejected.", (() => { const { nonce: _n, ...rest } = hsRejection; return rest; })()),
  hsReject("missing-intent-ref-rejects", "A missing intentRef is rejected.", (() => { const { intentRef: _i, ...rest } = hsRejection; return rest; })()),
  hsReject("missing-timestamp-rejects", "A missing timestamp is rejected.", (() => { const { timestamp: _ts, ...rest } = hsRejection; return rest; })()),
  hsReject("non-string-intent-ref-rejects", "A non-string intentRef is rejected.", { ...hsRejection, intentRef: 42 }),
  // caps
  hsReject("oversized-intent-ref-rejects", "An intentRef past 256 characters is rejected.", { ...hsRejection, intentRef: "x".repeat(257) }),
  hsReject("oversized-detail-rejects", "A rejection detail past 500 characters is rejected.", { ...hsRejection, detail: "x".repeat(501) }),
  hsReject("too-many-fields-rejects", "A challenge fields array past 32 entries is rejected.", { ...hsChallenge, fields: Array(33).fill("a") }),
  hsReject("oversized-field-element-rejects", "A challenge fields element past 256 characters is rejected.", { ...hsChallenge, fields: ["x".repeat(257)] }),
  // timestamp grammar
  hsReject("timestamp-offset-rejects", "A numeric-offset timestamp is rejected by the handshake datetime grammar (Z only).", { ...hsRejection, timestamp: "2026-06-16T12:00:00+00:00" }),
  hsReject("timestamp-no-zone-rejects", "A timestamp with no zone is rejected.", { ...hsRejection, timestamp: "2026-06-16T12:00:00" }),
  hsReject("timestamp-out-of-range-rejects", "A timestamp with an out-of-range month is rejected.", { ...hsRejection, timestamp: "2026-13-16T12:00:00Z" }),
  // nested backoff hint
  hsReject("bad-backoff-seconds-rejects", "A non-positive retryAfterSeconds in the backoff hint is rejected.", { ...hsRejection, backoffHint: { retryAfterSeconds: -5 } }),
  hsReject("bad-backoff-class-rejects", "An unknown backoffClass is rejected.", { ...hsRejection, backoffHint: { backoffClass: "bogus" } }),
  hsReject("backoff-seconds-unsafe-integer-rejects", "A retryAfterSeconds past the safe-integer range (2^53) is rejected, matching the reference's integer bound.", { ...hsRejection, backoffHint: { retryAfterSeconds: 9007199254740992 } }),
]);

// ── connection-payload ────────────────────────────────────────────────────
// Schema validation for the INK connection handshake payloads
// (connection_request, connection_response). Unlike the challenge/rejection/
// resolution messages these schemas are .strict() (an unknown key rejects, not
// strips), and they embed a profile snapshot which embeds an availability
// config, both also .strict(). An independent validator must accept and reject
// the same payloads. See specs/ink-connection-payload.md.
const cpProfile = { headline: "Staff engineer", skills: ["go", "typescript"], interests: ["agents"], openTo: ["roles", "advising"], availability: { timezone: "America/Los_Angeles", meetingHours: "9-5 PT weekdays" } };
const cpRequest = { method: "discovery", context: "met at the conference", profileSnapshot: cpProfile };
const cpResponse = { status: "accepted", profileSnapshot: cpProfile, note: "glad to connect" };
function connAccept(caseId, description, kind, payload) {
  return { caseId, description, input: { kind, payload }, expect: { result: "accept" } };
}
function connReject(caseId, description, kind, payload) {
  return { caseId, description, input: { kind, payload }, expect: { result: "reject" } };
}

vectorFile("connection-payload", [
  connAccept("request-valid-accepts", "A well-formed connection_request with a full profile snapshot validates.", "connection_request", cpRequest),
  connAccept("request-minimal-profile-accepts", "A request whose profile omits the optional availability validates.", "connection_request", { method: "qr", context: "scanned code", profileSnapshot: { headline: "h", skills: [], interests: [], openTo: [] } }),
  connAccept("response-valid-accepts", "A well-formed connection_response validates.", "connection_response", cpResponse),
  connAccept("response-minimal-accepts", "A response with only a status validates; profileSnapshot and note are optional.", "connection_response", { status: "declined" }),
  // unknown kind
  connReject("unknown-kind-rejects", "An unknown payload kind is rejected.", "connection_unknown", cpRequest),
  // strict: unknown keys
  connReject("request-unknown-key-rejects", "An unknown top-level key is rejected because the schema is strict.", "connection_request", { ...cpRequest, extra: 1 }),
  connReject("profile-unknown-key-rejects", "An unknown key in the profile snapshot is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, bogus: true } }),
  connReject("availability-unknown-key-rejects", "An unknown key in the availability config is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, availability: { timezone: "UTC", bogus: 1 } } }),
  connReject("response-unknown-key-rejects", "An unknown top-level key in the response is rejected.", "connection_response", { ...cpResponse, extra: "x" }),
  // enums
  connReject("bad-method-rejects", "An unknown connection method is rejected.", "connection_request", { ...cpRequest, method: "telepathy" }),
  connReject("bad-status-rejects", "An unknown response status is rejected.", "connection_response", { ...cpResponse, status: "maybe" }),
  // required fields
  connReject("missing-context-rejects", "A request without context is rejected.", "connection_request", (() => { const { context: _c, ...rest } = cpRequest; return rest; })()),
  connReject("missing-profile-rejects", "A request without a profile snapshot is rejected.", "connection_request", (() => { const { profileSnapshot: _p, ...rest } = cpRequest; return rest; })()),
  connReject("missing-status-rejects", "A response without a status is rejected.", "connection_response", { profileSnapshot: cpProfile }),
  connReject("profile-missing-headline-rejects", "A profile snapshot missing the required headline is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { skills: [], interests: [], openTo: [] } }),
  // caps
  connReject("oversized-context-rejects", "A request context past 2000 characters is rejected.", "connection_request", { ...cpRequest, context: "x".repeat(2001) }),
  connReject("oversized-note-rejects", "A response note past 1000 characters is rejected.", "connection_response", { ...cpResponse, note: "x".repeat(1001) }),
  connReject("too-many-skills-rejects", "A profile with more than 50 skills is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, skills: Array(51).fill("s") } }),
  connReject("oversized-skill-rejects", "A profile skill past 100 characters is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, skills: ["x".repeat(101)] } }),
  connReject("oversized-timezone-rejects", "An availability timezone past 64 characters is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, availability: { timezone: "x".repeat(65) } } }),
  // type confusion
  connReject("non-string-context-rejects", "A non-string context is rejected.", "connection_request", { ...cpRequest, context: 42 }),
  connReject("non-array-skills-rejects", "A non-array skills value is rejected.", "connection_request", { ...cpRequest, profileSnapshot: { ...cpProfile, skills: "go" } }),
]);

// ── agent-card ────────────────────────────────────────────────────────────
// Schema validation for the canonical .well-known/ink/agent.json document
// (AgentCardSchema). Pins the protocol literal, field caps, enum fields, the
// embedded profile snapshot / key entries / capabilities / governance, the
// pinned INK endpoint URL grammar (https, no userinfo/fragment), and the
// superRefine invariant that inboxEndpoint must equal endpoint when both are
// present. See specs/ink-agent-card.md.
const acTs = "2026-06-16T00:00:00.000Z";
const acKey = { keyId: "k1", algorithm: "Ed25519", publicKeyMultibase: mb, status: "active", validFrom: acTs };
const acCard = {
  protocol: "ink/0.1",
  agentId: "did:web:a.example",
  handle: "alice",
  displayName: "Alice",
  endpoint: "https://a.example/ink/inbox",
  publicKeyMultibase: mb,
  capabilities: { intentsAccepted: ["ask", "ping"], intentsSent: ["ask"] },
  availability: { timezone: "America/Los_Angeles" },
};
const acFullCard = {
  ...acCard,
  inboxEndpoint: "https://a.example/ink/inbox",
  ownerDid: "did:web:owner.example",
  profileSnapshot: { headline: "Engineer", skills: ["go"], interests: ["ai"], openTo: ["roles"] },
  capabilities: {
    intentsAccepted: ["ask", "ping", "connection_request"],
    intentsSent: ["ask"],
    receipts: { send: true, dispositions: ["received", "acted"] },
    auditExchange: true,
    thirdPartyAudit: { services: [{ endpoint: "https://audit.example/submit", did: "did:web:audit.example", publicKey: "zAudit" }], submitPolicy: "high_value" },
  },
  keys: { signing: [acKey], encryption: [{ ...acKey, keyId: "k2", algorithm: "X25519" }] },
  currentSigningKeyId: "k1",
  keySetVersion: 3,
  supportedProtocolVersions: ["ink/0.1", "ink/0.2"],
  visibility: "public",
  governance: { maxAcceptedDelegationDepth: 2, supportedTransports: ["ink_http"], handshakeBudget: { maxIntentsPerMinute: 30 } },
};
function acAccept(caseId, description, card) {
  return { caseId, description, input: { card }, expect: { result: "accept" } };
}
function acReject(caseId, description, card) {
  return { caseId, description, input: { card }, expect: { result: "reject" } };
}

vectorFile("agent-card", [
  acAccept("minimal-card-accepts", "A card with only the required fields validates.", acCard),
  acAccept("full-card-accepts", "A card exercising the optional fields (profile, keys, capabilities, governance, matching inboxEndpoint) validates.", acFullCard),
  // protocol / required fields
  acReject("wrong-protocol-rejects", "A protocol other than ink/0.1 is rejected.", { ...acCard, protocol: "ink/0.2" }),
  acReject("missing-agent-id-rejects", "A card without agentId is rejected.", (() => { const { agentId: _a, ...rest } = acCard; return rest; })()),
  acReject("missing-handle-rejects", "A card without a handle is rejected.", (() => { const { handle: _h, ...rest } = acCard; return rest; })()),
  acReject("missing-capabilities-rejects", "A card without capabilities is rejected.", (() => { const { capabilities: _c, ...rest } = acCard; return rest; })()),
  acReject("missing-availability-rejects", "A card without availability is rejected.", (() => { const { availability: _a, ...rest } = acCard; return rest; })()),
  // endpoint URL grammar (former z.url()-accepted values now reject)
  acReject("endpoint-javascript-rejects", "A javascript: endpoint is rejected by the pinned URL grammar.", { ...acCard, endpoint: "javascript:alert(1)" }),
  acReject("endpoint-mailto-rejects", "A mailto: endpoint is rejected.", { ...acCard, endpoint: "mailto:a@example.com" }),
  acReject("endpoint-ftp-rejects", "An ftp: endpoint is rejected.", { ...acCard, endpoint: "ftp://a.example" }),
  acReject("endpoint-http-rejects", "An http (non-https) endpoint is rejected.", { ...acCard, endpoint: "http://a.example" }),
  acReject("endpoint-trailing-newline-rejects", "An endpoint with a trailing newline is rejected.", { ...acCard, endpoint: "https://a.example\n" }),
  acReject("endpoint-userinfo-rejects", "An endpoint with userinfo is rejected.", { ...acCard, endpoint: "https://user@a.example" }),
  acReject("endpoint-fragment-rejects", "An endpoint with a fragment is rejected.", { ...acCard, endpoint: "https://a.example/x#f" }),
  acReject("endpoint-no-host-rejects", "An endpoint with no host is rejected.", { ...acCard, endpoint: "https://" }),
  acReject("endpoint-scheme-relative-rejects", "A scheme-relative endpoint is rejected.", { ...acCard, endpoint: "//a.example" }),
  acReject("endpoint-no-scheme-rejects", "An endpoint with no scheme is rejected.", { ...acCard, endpoint: "a.example" }),
  acReject("endpoint-bad-port-rejects", "An endpoint with an out-of-range port is rejected.", { ...acCard, endpoint: "https://a.example:99999/x" }),
  acReject("endpoint-backslash-rejects", "A backslash in the endpoint is rejected; a permissive parser would normalize it to a slash, diverging across implementations.", { ...acCard, endpoint: "https://a.example\\inbox" }),
  acReject("endpoint-malformed-percent-rejects", "An endpoint with a malformed percent escape is rejected.", { ...acCard, endpoint: "https://a.example/%zz" }),
  acReject("endpoint-percent-host-rejects", "An endpoint with a percent-encoded host is rejected; a permissive parser would decode it.", { ...acCard, endpoint: "https://%41.com/" }),
  acReject("endpoint-ipv6-zone-rejects", "An endpoint with an IPv6 zone id is rejected.", { ...acCard, endpoint: "https://[fe80::1%25eth0]/" }),
  // superRefine
  acReject("inbox-endpoint-mismatch-rejects", "An inboxEndpoint that differs from endpoint is rejected.", { ...acCard, inboxEndpoint: "https://b.example/ink/inbox" }),
  // publicKeyMultibase
  acReject("public-key-no-z-prefix-rejects", "A publicKeyMultibase not starting with z is rejected.", { ...acCard, publicKeyMultibase: "Qm123" }),
  acReject("public-key-over-cap-rejects", "A publicKeyMultibase past 128 characters is rejected.", { ...acCard, publicKeyMultibase: "z" + "a".repeat(128) }),
  // capabilities
  acReject("bad-intent-enum-rejects", "An unknown intent type in capabilities is rejected.", { ...acCard, capabilities: { intentsAccepted: ["teleport"], intentsSent: [] } }),
  acReject("too-many-intents-rejects", "An intentsAccepted array past 32 entries is rejected.", { ...acCard, capabilities: { intentsAccepted: Array(33).fill("ask"), intentsSent: [] } }),
  acReject("bad-third-party-audit-endpoint-rejects", "A third-party audit service with a non-https endpoint is rejected.", { ...acCard, capabilities: { ...acCard.capabilities, thirdPartyAudit: { services: [{ endpoint: "http://audit.example", did: "did:web:audit.example", publicKey: "zX" }], submitPolicy: "all" } } }),
  // availability
  acReject("missing-timezone-rejects", "An availability without a timezone is rejected.", { ...acCard, availability: { meetingHours: "9-5" } }),
  // keys
  acReject("key-bad-timestamp-rejects", "A key entry with a non-strict validFrom timestamp is rejected.", { ...acCard, keys: { signing: [{ ...acKey, validFrom: "2026-06-16" }], encryption: [] } }),
  acReject("key-bad-algorithm-rejects", "A key entry with an unknown algorithm is rejected.", { ...acCard, keys: { signing: [{ ...acKey, algorithm: "RSA" }], encryption: [] } }),
  acReject("key-missing-id-rejects", "A key entry with an empty keyId is rejected.", { ...acCard, keys: { signing: [{ ...acKey, keyId: "" }], encryption: [] } }),
  // numbers / enums
  acReject("bad-key-set-version-rejects", "A non-positive keySetVersion is rejected.", { ...acCard, keySetVersion: 0 }),
  acReject("bad-visibility-rejects", "An unknown visibility is rejected.", { ...acCard, visibility: "secret" }),
  acReject("bad-governance-depth-rejects", "A non-positive maxAcceptedDelegationDepth is rejected.", { ...acCard, governance: { maxAcceptedDelegationDepth: -1 } }),
  // discovery descriptor (#188): opt-in, additive, and only ever narrowing.
  // The descriptor `scope` reuses the visibility enum and MUST NOT exceed the
  // card's `visibility`; an absent `visibility` is the public upper bound
  // because the card is publicly fetchable. Tags are self-declared hints.
  acAccept("discovery-enabled-accepts", "An enabled discovery descriptor at the card's visibility, with tags and a strict updatedAt, validates.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", tags: ["hiring", "ai"], queryable: true, updatedAt: acTs } }),
  acAccept("discovery-disabled-accepts", "An opt-out (enabled:false) discovery descriptor validates.", { ...acCard, visibility: "public", discovery: { enabled: false, scope: "public" } }),
  acAccept("discovery-narrowing-accepts", "A descriptor narrowing exposure below the card visibility validates.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "network_only" } }),
  acAccept("discovery-absent-visibility-accepts", "With no visibility field the public upper bound applies, so a public-scope descriptor validates.", { ...acCard, discovery: { enabled: true, scope: "public" } }),
  acAccept("discovery-unknown-key-ignored-accepts", "An unknown discovery descriptor key is ignored, not rejected, so later additive fields stay forward compatible.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", rank: 5 } }),
  acReject("discovery-scope-exceeds-visibility-rejects", "A descriptor scope wider than the card visibility is rejected (hard upper bound).", { ...acCard, visibility: "network_only", discovery: { enabled: true, scope: "public" } }),
  acReject("discovery-missing-enabled-rejects", "A discovery descriptor without enabled is rejected.", { ...acCard, visibility: "public", discovery: { scope: "public" } }),
  acReject("discovery-missing-scope-rejects", "A discovery descriptor without scope is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true } }),
  acReject("discovery-bad-scope-enum-rejects", "A discovery scope outside the visibility enum is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "everyone" } }),
  acReject("discovery-too-many-tags-rejects", "A discovery tags array past 32 entries is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", tags: Array(33).fill("x") } }),
  acReject("discovery-empty-tag-rejects", "A discovery tag that is the empty string is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", tags: [""] } }),
  acReject("discovery-over-long-tag-rejects", "A discovery tag past 64 characters is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", tags: ["x".repeat(65)] } }),
  acReject("discovery-bad-updated-at-rejects", "A discovery updatedAt that is not a strict RFC 3339 timestamp is rejected.", { ...acCard, visibility: "public", discovery: { enabled: true, scope: "public", updatedAt: "2026-06-16" } }),
]);

// ── agent-card-fetch ───────────────────────────────────────────────────────
// The discovery RESPONSE-handling contract: given synthetic response metadata
// (status, Content-Type, Content-Length, body, requested agentId), does the
// response yield a valid Agent Card bound to the requested id? See
// specs/ink-agent-card-discovery-fetch.md.
const fetchBody = JSON.stringify(acCard);
const fetchReqId = acCard.agentId;
const fetchInput = (over = {}) => ({ status: 200, contentType: "application/json", contentLength: null, bodyRaw: fetchBody, requestedAgentId: fetchReqId, ...over });
const fAccept = (caseId, description, input) => ({ caseId, description, input, expect: { result: "accept" } });
const fReject = (caseId, description, input) => ({ caseId, description, input, expect: { result: "reject" } });
vectorFile("agent-card-fetch", [
  fAccept("ok-application-json", "200 application/json with a valid bound card accepts.", fetchInput()),
  fAccept("ok-charset-utf8", "A utf-8 charset parameter is accepted.", fetchInput({ contentType: "application/json; charset=utf-8" })),
  fAccept("ok-charset-uppercase", "Charset comparison is case-insensitive.", fetchInput({ contentType: "application/json; charset=UTF-8" })),
  fAccept("ok-charset-quoted", "A quoted utf-8 charset is accepted.", fetchInput({ contentType: 'application/json; charset="utf-8"' })),
  fAccept("ok-content-type-ows", "Optional whitespace around the media type and params is tolerated.", fetchInput({ contentType: " application/json ; charset=utf-8 " })),
  fAccept("ok-content-length-within-cap", "A Content-Length within the cap accepts.", fetchInput({ contentLength: String(Buffer.byteLength(fetchBody, "utf8")) })),
  fAccept("ok-content-length-noncanonical-ignored", "A non-numeric Content-Length is ignored, not fatal.", fetchInput({ contentLength: "not-a-number" })),
  // status
  fReject("status-201-rejects", "A non-200 2xx status rejects; discovery is a fixed 200 GET.", fetchInput({ status: 201 })),
  fReject("status-204-rejects", "204 No Content rejects.", fetchInput({ status: 204 })),
  fReject("status-301-rejects", "A redirect status rejects.", fetchInput({ status: 301 })),
  fReject("status-404-rejects", "404 rejects.", fetchInput({ status: 404 })),
  fReject("status-500-rejects", "500 rejects.", fetchInput({ status: 500 })),
  // content-type
  fReject("content-type-missing-rejects", "An absent Content-Type rejects.", fetchInput({ contentType: null })),
  fReject("content-type-empty-rejects", "An empty Content-Type rejects.", fetchInput({ contentType: "" })),
  fReject("content-type-text-plain-rejects", "text/plain rejects.", fetchInput({ contentType: "text/plain" })),
  fReject("content-type-text-html-rejects", "text/html rejects.", fetchInput({ contentType: "text/html" })),
  fReject("content-type-ldjson-rejects", "application/ld+json rejects; only application/json is accepted.", fetchInput({ contentType: "application/ld+json" })),
  fReject("content-type-octet-stream-rejects", "application/octet-stream rejects.", fetchInput({ contentType: "application/octet-stream" })),
  fReject("content-type-comma-rejects", "A combined or duplicated Content-Type (comma) rejects as ambiguous.", fetchInput({ contentType: "application/json, text/html" })),
  fReject("content-type-bad-charset-rejects", "A non-utf-8 charset rejects.", fetchInput({ contentType: "application/json; charset=iso-8859-1" })),
  // size caps
  fReject("content-length-over-cap-rejects", "A Content-Length over the 64 KiB cap rejects before the body is trusted.", fetchInput({ contentLength: String(64 * 1024 + 1) })),
  fReject("content-length-int64-overflow-rejects", "A Content-Length larger than a 64-bit integer still classifies as over the cap (digit-string comparison, no parse).", fetchInput({ contentLength: "9223372036854775808" })),
  fReject("content-length-astronomical-rejects", "An astronomically large Content-Length rejects.", fetchInput({ contentLength: "1" + "0".repeat(100) })),
  fReject("body-over-cap-rejects", "A body whose actual UTF-8 size exceeds the 64 KiB cap rejects.", fetchInput({ bodyRaw: "x".repeat(64 * 1024 + 1) })),
  fReject("body-over-cap-multibyte-rejects", "A multibyte body over the cap rejects; the cap is UTF-8 bytes, not code units, identically in both implementations.", fetchInput({ bodyRaw: "€".repeat(21846) })),
  // body content
  fReject("body-not-json-rejects", "A non-JSON body rejects.", fetchInput({ bodyRaw: "{not json" })),
  fReject("body-json-not-card-rejects", "Well-formed JSON that is not an Agent Card rejects.", fetchInput({ bodyRaw: JSON.stringify({ hello: "world" }) })),
  fReject("body-array-rejects", "A JSON array body rejects.", fetchInput({ bodyRaw: "[]" })),
  // identity binding
  fReject("identity-mismatch-rejects", "A valid card whose agentId differs from the requested id rejects.", fetchInput({ requestedAgentId: "did:web:other.example" })),
]);

// ── private-hostname ───────────────────────────────────────────────────────
// The SSRF host-safety gate: is a hostname public (accept) or
// private/special/malformed-IP-shaped (reject)? Hostname strings only; URL
// parsing, schemes, and userinfo are out of scope. See
// specs/ink-private-hostname.md.
const phAccept = (caseId, hostname, description) => ({ caseId, description, input: { hostname }, expect: { result: "accept" } });
const phReject = (caseId, hostname, description) => ({ caseId, description, input: { hostname }, expect: { result: "reject" } });
vectorFile("private-hostname", [
  // Public names.
  phAccept("public-dns", "example.com", "A public DNS name is accepted."),
  phAccept("public-dns-uppercase", "EXAMPLE.COM", "Case is normalized before classification."),
  phAccept("public-dns-trailing-dot", "example.com.", "A trailing FQDN dot is stripped; the name stays public."),
  phAccept("public-ipv4", "8.8.8.8", "A public IPv4 literal is accepted."),
  phAccept("public-ipv6", "2606:4700:4700::1111", "A public IPv6 literal is accepted."),
  phAccept("public-ipv6-bracketed", "[2606:4700:4700::1111]", "A bracketed public IPv6 literal is accepted."),
  phAccept("ipv4-mapped-dotted-public", "::ffff:8.8.8.8", "An IPv4-mapped IPv6 of a public v4 is accepted."),
  phAccept("ipv4-mapped-hex-public", "::ffff:0808:0808", "An IPv4-mapped IPv6 (hex form) of a public v4 is accepted."),
  phAccept("sixtofour-public", "2002:0808:0808::1", "A 6to4 address embedding a public v4 is accepted."),
  // Localhost names.
  phReject("localhost", "localhost", "localhost is rejected."),
  phReject("localhost-subdomain", "a.localhost", "A .localhost subdomain is rejected."),
  phReject("localhost-trailing-dot-uppercase", "A.LOCALHOST.", "A .localhost name is rejected after case and trailing-dot normalization."),
  phReject("empty-after-strip", ".", "A name that is empty after stripping trailing dots is rejected."),
  phReject("dots-only", "...", "A dots-only name is rejected."),
  // Private/special IPv4.
  phReject("ipv4-private-10", "10.0.0.1", "10.0.0.0/8 is rejected."),
  phReject("ipv4-loopback", "127.0.0.1", "127.0.0.0/8 loopback is rejected."),
  phReject("ipv4-metadata", "169.254.169.254", "169.254.0.0/16 (cloud metadata) is rejected."),
  phReject("ipv4-private-172", "172.16.0.1", "172.16.0.0/12 is rejected."),
  phReject("ipv4-private-192", "192.168.1.1", "192.168.0.0/16 is rejected."),
  phReject("ipv4-cgnat", "100.64.0.1", "100.64.0.0/10 CGNAT is rejected."),
  phReject("ipv4-testnet", "192.0.2.1", "192.0.2.0/24 TEST-NET-1 is rejected."),
  phReject("ipv4-benchmarking", "198.18.0.1", "198.18.0.0/15 benchmarking is rejected."),
  phReject("ipv4-multicast", "224.0.0.1", "224.0.0.0/4 multicast is rejected."),
  phReject("ipv4-broadcast", "255.255.255.255", "The broadcast address is rejected."),
  phReject("ipv4-leading-zero-private", "010.000.000.001", "A leading-zero decimal form of a private v4 is rejected."),
  // Malformed IP-shaped (fail closed).
  phReject("ipv4-octet-256", "256.1.1.1", "An octet over 255 is a malformed IP-shaped name; fail closed."),
  phReject("ipv4-octet-999", "8.8.8.999", "An over-range last octet fails closed instead of reading as public."),
  phReject("ipv4-all-999", "999.999.999.999", "All-over-range octets fail closed."),
  phReject("ipv4-single-integer", "2130706433", "A single-integer IPv4 form is rejected."),
  // Private/special IPv6.
  phReject("ipv6-unspecified", "::", "The unspecified address is rejected."),
  phReject("ipv6-loopback", "::1", "::1 loopback is rejected."),
  phReject("ipv6-loopback-bracketed", "[::1]", "Bracketed ::1 is rejected."),
  phReject("ipv6-link-local", "fe80::1", "fe80::/10 link-local is rejected."),
  phReject("ipv6-ula-fc", "fc00::1", "fc00::/7 ULA is rejected."),
  phReject("ipv6-ula-fd", "fd00::1", "fd00::/7 ULA (fd) is rejected."),
  phReject("ipv6-multicast", "ff00::1", "ff00::/8 multicast is rejected."),
  phReject("ipv6-doc", "2001:db8::1", "2001:db8::/32 documentation is rejected."),
  phReject("ipv6-teredo", "2001::1", "2001::/32 Teredo is rejected."),
  phReject("ipv6-bmwg", "2001:2::1", "2001:2::/48 BMWG is rejected."),
  phReject("ipv6-orchid", "2001:10::1", "2001:10::/28 ORCHID is rejected."),
  phReject("ipv6-orchidv2", "2001:20::1", "2001:20::/28 ORCHIDv2 is rejected."),
  phReject("ipv6-nat64", "64:ff9b::1", "64:ff9b::/96 NAT64 is rejected."),
  phReject("ipv6-nat64-local", "64:ff9b:1::1", "64:ff9b:1::/48 is rejected."),
  phReject("ipv6-discard", "100::1", "100::/64 discard is rejected."),
  phReject("ipv6-dummy", "100:0:0:1::1", "100:0:0:1::/64 is rejected."),
  phReject("ipv6-bmwg-v6", "3fff::1", "3fff::/20 v6 benchmarking is rejected."),
  phReject("ipv6-srv6", "5f00::1", "5f00::/16 SRv6 is rejected."),
  phReject("ipv4-mapped-dotted-loopback", "::ffff:127.0.0.1", "An IPv4-mapped IPv6 of a loopback v4 is rejected."),
  phReject("ipv4-mapped-hex-loopback", "::ffff:7f00:1", "An IPv4-mapped IPv6 (hex form) of loopback is rejected."),
  phReject("sixtofour-private", "2002:0a00:0001::1", "A 6to4 address embedding a private v4 (10.0.0.1) is rejected."),
  // Malformed IPv6 (fail closed).
  phReject("ipv6-double-collapse", "1::2::3", "Two `::` groups are malformed; fail closed."),
  phReject("ipv6-too-few-groups", "1:2:3:4:5:6:7", "Seven groups without `::` is malformed; fail closed."),
  phReject("ipv6-too-many-groups", "1:2:3:4:5:6:7:8:9", "Nine groups is malformed; fail closed."),
  phReject("ipv6-bad-hex", "gggg::1", "A non-hex group is malformed; fail closed."),
  phReject("ipv6-leading-colon", ":1:2:3:4:5:6:7", "A leading single colon is malformed; fail closed."),
  phReject("ipv6-trailing-colon", "1:2:3:4:5:6:7:", "A trailing single colon is malformed; fail closed."),
  // Zone / scope ids (fail closed).
  phReject("ipv6-zone-private", "fe80::1%eth0", "A zoned link-local address is rejected."),
  phReject("ipv6-zone-public", "2606:4700:4700::1111%eth0", "A zone id on a public literal is rejected, not stripped."),
]);

// ── payload-encryption ──────────────────────────────────────────────────────
// Deterministic ECIES vectors: a fixed recipient X25519 key, a fixed ephemeral
// key, and a fixed AES-GCM nonce make `encryptInkPayload` produce one stable
// envelope that both implementations must decrypt to the same plaintext (and
// reject every tampered/malformed variant of).
{
  const recipientPriv = new Uint8Array(
    await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-encryption-recipient")),
  );
  const recipientPubHex = bytesToHex(x25519.getPublicKey(recipientPriv));
  const recipientPrivHex = bytesToHex(recipientPriv);
  const otherPriv = new Uint8Array(
    await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-encryption-other-recipient")),
  );
  const otherPrivHex = bytesToHex(otherPriv);
  const otherPubB64 = base64urlEncode(x25519.getPublicKey(otherPriv));
  const ephPriv = new Uint8Array(
    await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-encryption-ephemeral")),
  );
  const aesNonce = new Uint8Array(
    (await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-encryption-nonce"))).slice(0, 12),
  );

  const sender = "did:web:sender.example.com";
  const recipientDid = "did:web:recipient.example.com";
  const ts = "2026-01-01T00:00:00.000Z";
  const msgNonce = "01HENCRYPTNONCE0000000000AA";
  const plaintext = { protocol: "ink/0.1", from: sender, to: recipientDid, intent: "ping", payload: { note: "hello" } };
  const opts = { ephemeralPrivateKey: ephPriv, aesNonce };
  const { envelope } = await encryptInkPayload(plaintext, sender, recipientPubHex, ts, msgNonce, opts);
  const canonicalPlaintext = jcsCanonicalize(plaintext);

  // Same recipient + ephemeral, but the inner `from` deliberately disagrees
  // with the outer `from`, so a conformant decrypter rejects on the
  // inner/outer consistency check (not the AAD).
  const innerMismatchPlain = { protocol: "ink/0.1", from: "did:web:other.example.com", to: recipientDid, intent: "ping" };
  const { envelope: innerMismatchEnv } = await encryptInkPayload(
    innerMismatchPlain, sender, recipientPubHex, ts, msgNonce, opts,
  );

  // Vendor-neutral namespace (ink/0.4 dual-accept): the sender opts into
  // network.ink.encrypted. The type is AAD-bound, so this decrypts cleanly while
  // a relabel of the legacy envelope fails the tag. A distinct AES nonce keeps
  // the (key, nonce) pair unique against the legacy envelope above.
  const aesNonceInk = new Uint8Array(
    (await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-encryption-nonce-ink"))).slice(0, 12),
  );
  const { envelope: inkNamespaceEnv } = await encryptInkPayload(
    plaintext, sender, recipientPubHex, ts, msgNonce,
    { ephemeralPrivateKey: ephPriv, aesNonce: aesNonceInk, messageType: "network.ink.encrypted" },
  );

  const clone = () => JSON.parse(JSON.stringify(envelope));
  const tamper = (field, value) => { const e = clone(); e[field] = value; return e; };
  // Flip the FIRST base64url char of the ciphertext to break the GCM tag. The
  // leading char carries the high 6 bits of byte 0, so the change is always
  // significant (a trailing char in an unpadded encoding can carry unused low
  // bits whose flip leaves the decoded bytes unchanged).
  const flippedCipher = (() => {
    const ct = envelope.ciphertext;
    return (ct[0] === "A" ? "B" : "A") + ct.slice(1);
  })();

  const acc = (canonicalString) => ({ result: "accept", canonicalString });
  const rej = { result: "reject" };

  vectorFile("payload-encryption", [
    {
      caseId: "valid-decrypt",
      description: "A well-formed envelope decrypts to the exact plaintext bytes when the recipientDid matches the inner `to`.",
      input: { envelope, recipientPrivateKeyHex: recipientPrivHex, recipientDid },
      expect: acc(canonicalPlaintext),
    },
    {
      caseId: "valid-decrypt-ink-namespace",
      description: "An envelope using the vendor-neutral network.ink.encrypted type decrypts to the same plaintext (ink/0.4 dual-accept).",
      input: { envelope: inkNamespaceEnv, recipientPrivateKeyHex: recipientPrivHex, recipientDid },
      expect: acc(canonicalPlaintext),
    },
    {
      caseId: "relabel-tulpa-to-ink-rejects",
      description: "A legacy network.tulpa.encrypted envelope relabelled to network.ink.encrypted fails the GCM tag: the type is AAD-bound, not normalized.",
      input: { envelope: tamper("type", "network.ink.encrypted"), recipientPrivateKeyHex: recipientPrivHex, recipientDid },
      expect: rej,
    },
    {
      caseId: "unknown-outer-field-ignored",
      description: "An unknown outer field is ignored and not AAD-bound; the envelope still decrypts.",
      input: { envelope: tamper("extra", "ignored"), recipientPrivateKeyHex: recipientPrivHex, recipientDid },
      expect: acc(canonicalPlaintext),
    },
    {
      caseId: "missing-recipient-did",
      description: "Decrypt without a recipientDid rejects: the recipient identity assertion is mandatory.",
      input: { envelope, recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "recipient-binding-mismatch",
      description: "A recipientDid that does not match the inner `to` rejects.",
      input: { envelope, recipientPrivateKeyHex: recipientPrivHex, recipientDid: "did:web:wrong.example.com" },
      expect: rej,
    },
    {
      caseId: "inner-from-mismatch",
      description: "The decrypted inner `from` must equal the outer envelope `from`.",
      input: { envelope: innerMismatchEnv, recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-from",
      description: "Tampering the AAD-bound `from` field fails the GCM tag.",
      input: { envelope: tamper("from", "did:web:attacker.example.com"), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-timestamp",
      description: "Tampering the AAD-bound `timestamp` fails the GCM tag.",
      input: { envelope: tamper("timestamp", "2026-01-01T00:00:01.000Z"), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-message-nonce",
      description: "Tampering the AAD-bound `messageNonce` fails the GCM tag.",
      input: { envelope: tamper("messageNonce", "01HENCRYPTNONCE0000000000BB"), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-nonce",
      description: "Replacing the AES nonce (also AAD-bound) rejects.",
      input: { envelope: tamper("nonce", base64urlEncode(new Uint8Array(12))), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-ephemeral-key",
      description: "Substituting a different valid ephemeral key rejects (wrong ECDH + AAD).",
      input: { envelope: tamper("ephemeralKey", otherPubB64), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-protocol",
      description: "A non-ink/0.1 protocol is rejected before decryption.",
      input: { envelope: tamper("protocol", "ink/0.2"), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-type",
      description: "A wrong envelope `type` is rejected before decryption.",
      input: { envelope: tamper("type", "network.tulpa.other"), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "tamper-ciphertext",
      description: "Flipping a ciphertext byte fails the GCM tag.",
      input: { envelope: tamper("ciphertext", flippedCipher), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "wrong-recipient-key",
      description: "The wrong recipient private key derives a different AES key and fails the tag.",
      input: { envelope, recipientPrivateKeyHex: otherPrivHex },
      expect: rej,
    },
    {
      caseId: "ephemeral-key-wrong-length",
      description: "An ephemeral key that does not decode to 32 bytes rejects.",
      input: { envelope: tamper("ephemeralKey", base64urlEncode(new Uint8Array(16))), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "nonce-wrong-length",
      description: "An AES nonce that does not decode to 12 bytes rejects.",
      input: { envelope: tamper("nonce", base64urlEncode(new Uint8Array(8))), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "ephemeral-key-oversized-field",
      description: "An oversized ephemeralKey field is rejected before base64url decode.",
      input: { envelope: tamper("ephemeralKey", "A".repeat(65)), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "empty-from",
      description: "An empty `from` is rejected (encrypt could never have produced it).",
      input: { envelope: tamper("from", ""), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "all-zero-shared-secret",
      description: "A low-order ephemeral key (32 zero bytes) yields an all-zero ECDH secret and rejects.",
      input: { envelope: tamper("ephemeralKey", base64urlEncode(new Uint8Array(32))), recipientPrivateKeyHex: recipientPrivHex },
      expect: rej,
    },
    {
      caseId: "recipient-key-wrong-length",
      description: "A recipient private key that is not 32 bytes rejects.",
      input: { envelope, recipientPrivateKeyHex: bytesToHex(new Uint8Array(16)) },
      expect: rej,
    },
  ]);
}

// ── first-contact-transcript ────────────────────────────────────────────────
// A full stranger first-contact exchange composed from already-pinned
// primitives: discover the receiver's card, select a protocol version from it,
// verify the signed connection_request under the freshness/replay rule, and
// verify the accepted connection_response. Deterministic: fixed sender and
// receiver Ed25519 keys, fixed timestamps and nonces, so the signatures are
// stable and both implementations verify them identically.
{
  const senderSeed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-firstcontact-sender")));
  const receiverSeed = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ink-conformance-firstcontact-receiver")));
  const senderPub = await ed.getPublicKeyAsync(senderSeed);
  const receiverPub = await ed.getPublicKeyAsync(receiverSeed);
  const senderPubHex = bytesToHex(senderPub);
  const receiverPubHex = bytesToHex(receiverPub);
  const receiverMb = encodePublicKeyMultibase(receiverPub);

  const senderDid = "did:web:sender.example";
  const receiverDid = "did:web:receiver.example";
  const reqTs = "2026-01-01T00:00:00.000Z";
  const respTs = "2026-01-01T00:00:02.000Z";
  const freshClock = "2026-01-01T00:00:05.000Z";
  const reqNonce = "firstcontactreqnonce00000001";
  const profileSnapshot = { headline: "Agent", skills: [], interests: [], openTo: [] };

  // A minimal valid receiver card advertising the given message protocol
  // versions. The signing key it publishes (publicKeyMultibase) is the same
  // receiver key the response signature verifies against.
  // `versions === undefined` omits the supportedProtocolVersions field entirely
  // (a legacy card that predates the field), which must default to ink/0.1.
  const buildCard = (versions) => {
    const card = {
      protocol: "ink/0.1",
      agentId: receiverDid,
      handle: "receiver",
      displayName: "Receiver Agent",
      endpoint: "https://receiver.example/ink/v1/intents",
      publicKeyMultibase: receiverMb,
      capabilities: { intentsAccepted: ["connection_request"], intentsSent: ["connection_response"] },
      availability: { timezone: "UTC" },
    };
    if (versions !== undefined) card.supportedProtocolVersions = versions;
    return card;
  };

  const cardFetch = (card, overrides = {}) => ({
    status: 200,
    contentType: "application/json",
    contentLength: null,
    bodyRaw: JSON.stringify(card),
    requestedAgentId: receiverDid,
    ...overrides,
  });

  const signEnvelope = async (envelope, recipientDid, timestamp, seed) => {
    const signInput = { method: "POST", path: "/ink/v1/intents", recipientDid, body: envelope, timestamp };
    return { signInput, signature: await signInkMessage(signInput, seed) };
  };

  const requestEnvelope = (protocol, envOverrides = {}) => ({
    protocol,
    from: senderDid,
    to: receiverDid,
    intent: "connection_request",
    payload: { method: "intro", context: "We met at the conference.", profileSnapshot },
    nonce: reqNonce,
    timestamp: reqTs,
    ...envOverrides,
  });

  const responseEnvelope = (protocol, envOverrides = {}) => ({
    protocol,
    from: receiverDid,
    to: senderDid,
    intent: "connection_response",
    payload: { status: "accepted", note: "Glad to connect." },
    nonce: "firstcontactrespnonce0000001",
    timestamp: respTs,
    ...envOverrides,
  });

  const flip = (s) => (s[0] === "A" ? "B" : "A") + s.slice(1);

  // Assemble one transcript input. Defaults are the happy path under `selected`;
  // each named option overrides one step so a verifier that skips it diverges.
  const buildTranscript = async ({
    advertised = ["ink/0.1"],
    omitVersions = false,
    clientVersions = ["ink/0.1"],
    selected = "ink/0.1",
    reqEnv,
    respEnv,
    reqSignInputTs,
    respSignInputTs,
    seenNonces = [],
    clock = freshClock,
    cardOverrides = {},
    senderKeyHex = senderPubHex,
    receiverKeyHex = receiverPubHex,
    tamperReqSig = (s) => s,
    tamperRespSig = (s) => s,
  } = {}) => {
    const rq = reqEnv ?? requestEnvelope(selected);
    const rs = respEnv ?? responseEnvelope(selected);
    const card = buildCard(omitVersions ? undefined : advertised);
    const req = await signEnvelope(rq, receiverDid, reqSignInputTs ?? rq.timestamp, senderSeed);
    const resp = await signEnvelope(rs, senderDid, respSignInputTs ?? rs.timestamp, receiverSeed);
    return {
      cardFetch: cardFetch(card, cardOverrides),
      clientSupportedVersions: clientVersions,
      receiverClock: clock,
      seenNonces,
      request: { signInput: req.signInput, signature: tamperReqSig(req.signature), senderPublicKeyHex: senderKeyHex },
      response: { signInput: resp.signInput, signature: tamperRespSig(resp.signature), receiverPublicKeyHex: receiverKeyHex },
    };
  };

  const acc = (selectedVersion) => ({ result: "accept", canonicalString: selectedVersion });
  const rej = { result: "reject" };

  vectorFile("first-contact-transcript", [
    {
      caseId: "valid-first-contact",
      description: "A complete card-fetch, version-select, signed request, and accepted response verifies.",
      input: await buildTranscript(),
      expect: acc("ink/0.1"),
    },
    {
      caseId: "valid-negotiated-v02",
      description: "When both sides support ink/0.2, the higher preferred common version is selected and pinned.",
      input: await buildTranscript({
        advertised: ["ink/0.1", "ink/0.2"],
        clientVersions: ["ink/0.2", "ink/0.1"],
        selected: "ink/0.2",
      }),
      expect: acc("ink/0.2"),
    },
    {
      caseId: "card-fetch-non-200",
      description: "A non-200 discovery response fails the fetch step and rejects the transcript.",
      input: await buildTranscript({ cardOverrides: { status: 404 } }),
      expect: rej,
    },
    {
      caseId: "card-fetch-agentid-mismatch",
      description: "A card whose agentId does not equal the requested agentId fails the identity binding.",
      input: await buildTranscript({ cardOverrides: { requestedAgentId: "did:web:other.example" } }),
      expect: rej,
    },
    {
      caseId: "no-version-overlap",
      description: "When the card and client share no protocol version, selection fails and the transcript rejects.",
      input: await buildTranscript({ advertised: ["ink/0.9"], clientVersions: ["ink/0.1", "ink/0.2"] }),
      expect: rej,
    },
    {
      caseId: "request-unadvertised-version",
      description: "A request emitted under a version the card does not advertise rejects.",
      input: await buildTranscript({ reqEnv: requestEnvelope("ink/0.2") }),
      expect: rej,
    },
    {
      caseId: "request-bad-signature",
      description: "A tampered request signature fails verification.",
      input: await buildTranscript({ tamperReqSig: flip }),
      expect: rej,
    },
    {
      caseId: "request-payload-missing-context",
      description: "A request payload missing the required context fails the connection_request schema.",
      input: await buildTranscript({
        reqEnv: requestEnvelope("ink/0.1", { payload: { method: "intro", profileSnapshot } }),
      }),
      expect: rej,
    },
    {
      caseId: "request-intent-mismatch",
      description: "A request envelope whose intent is not connection_request rejects.",
      input: await buildTranscript({
        reqEnv: requestEnvelope("ink/0.1", { intent: "connection_response" }),
      }),
      expect: rej,
    },
    {
      caseId: "request-timestamp-binding-mismatch",
      description: "A transport timestamp that disagrees with the request envelope timestamp rejects (§3.3 binding).",
      input: await buildTranscript({ reqSignInputTs: "2026-01-01T00:00:01.000Z" }),
      expect: rej,
    },
    {
      caseId: "replayed-request-nonce",
      description: "A request nonce already in the receiver's seen set is a replay and rejects.",
      input: await buildTranscript({ seenNonces: [reqNonce] }),
      expect: rej,
    },
    {
      caseId: "stale-request-timestamp",
      description: "A request older than the freshness window against the receiver clock rejects.",
      input: await buildTranscript({ clock: "2026-01-01T01:00:00.000Z" }),
      expect: rej,
    },
    {
      caseId: "response-bad-signature",
      description: "A tampered response signature fails verification.",
      input: await buildTranscript({ tamperRespSig: flip }),
      expect: rej,
    },
    {
      caseId: "response-status-declined",
      description: "A connection_response whose status is not accepted rejects the first-contact transcript.",
      input: await buildTranscript({
        respEnv: responseEnvelope("ink/0.1", { payload: { status: "declined" } }),
      }),
      expect: rej,
    },
    {
      caseId: "response-payload-unknown-key",
      description: "A connection_response payload with an unknown key fails the strict schema.",
      input: await buildTranscript({
        respEnv: responseEnvelope("ink/0.1", { payload: { status: "accepted", extra: "x" } }),
      }),
      expect: rej,
    },
    {
      caseId: "response-protocol-mismatch",
      description: "A response emitted under a different version than the selected one rejects.",
      input: await buildTranscript({
        advertised: ["ink/0.1", "ink/0.2"],
        clientVersions: ["ink/0.1", "ink/0.2"],
        selected: "ink/0.1",
        respEnv: responseEnvelope("ink/0.2"),
      }),
      expect: rej,
    },
    {
      caseId: "response-intent-mismatch",
      description: "A response envelope whose intent is not connection_response rejects.",
      input: await buildTranscript({
        respEnv: responseEnvelope("ink/0.1", { intent: "connection_request" }),
      }),
      expect: rej,
    },
    {
      caseId: "response-timestamp-binding-mismatch",
      description: "A transport timestamp that disagrees with the response envelope timestamp rejects (§3.3 binding).",
      input: await buildTranscript({ respSignInputTs: "2026-01-01T00:00:03.000Z" }),
      expect: rej,
    },
    {
      caseId: "future-request-timestamp",
      description: "A request timestamp beyond the future skew against the receiver clock rejects.",
      input: await buildTranscript({ clock: "2025-12-31T23:59:00.000Z" }),
      expect: rej,
    },
    {
      caseId: "card-omits-versions-defaults-v01",
      description: "A card without supportedProtocolVersions defaults to ink/0.1 and the ink/0.1 flow accepts.",
      input: await buildTranscript({ omitVersions: true }),
      expect: acc("ink/0.1"),
    },
    {
      caseId: "card-empty-versions-defaults-v01",
      description: "A card advertising an empty version list defaults to ink/0.1 and accepts.",
      input: await buildTranscript({ advertised: [] }),
      expect: acc("ink/0.1"),
    },
  ]);
}

// ── discovery-query-envelope ────────────────────────────────────────────────
// An authenticated discovery query envelope (specs/ink-discovery-query.md). The
// requester signs a bounded query addressed to a directory; the directory
// verifies it against the requester's public key. Each vector carries the full
// envelope and the requester's public key hex; a verifier accepts iff the
// envelope is structurally valid and the signature verifies.
{
  const base = {
    from: `tulpa:${mb}`,
    to: "did:web:directory.example",
    nonce: "conformance-discovery-nonce-1",
    timestamp: "2026-07-09T00:00:00.000Z",
    query: { tags: ["go", "typescript"], scope: "public", limit: 10 },
  };
  const env = await buildDiscoveryQueryEnvelope(base, seed);
  const inkEnv = await buildDiscoveryQueryEnvelope({ ...base, type: "network.ink.discovery_query" }, seed);
  const minimalEnv = await buildDiscoveryQueryEnvelope({ ...base, query: {} }, seed);
  const otherPublicKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(9)));

  const dqe = (caseId, description, input, result) => ({ caseId, description, input, expect: { result } });

  vectorFile("discovery-query-envelope", [
    dqe("valid-query-accepts", "A requester-signed query with tags, scope, and limit verifies against the requester's key.", { envelope: env, publicKeyHex }, "accept"),
    dqe("network-ink-spelling-accepts", "The vendor-neutral network.ink.discovery_query spelling is signed and verifies like the legacy spelling.", { envelope: inkEnv, publicKeyHex }, "accept"),
    dqe("empty-query-accepts", "An empty query object (no tags, scope, or limit) is a valid signed request.", { envelope: minimalEnv, publicKeyHex }, "accept"),
    dqe("tampered-to-rejects", "Changing the addressed directory after signing invalidates the signature.", { envelope: { ...env, to: "did:web:evil.example" }, publicKeyHex }, "reject"),
    dqe("relabeled-type-rejects", "Relabeling the wire type from network.tulpa to network.ink after signing invalidates the signature; the spelling is signed, not normalized.", { envelope: { ...env, type: "network.ink.discovery_query" }, publicKeyHex }, "reject"),
    dqe("tampered-tag-rejects", "Altering a query tag after signing invalidates the signature.", { envelope: { ...env, query: { ...env.query, tags: ["rust", "typescript"] } }, publicKeyHex }, "reject"),
    dqe("wrong-key-rejects", "Verifying against a different public key fails.", { envelope: env, publicKeyHex: otherPublicKeyHex }, "reject"),
    dqe("malformed-signature-rejects", "A signature that is not valid base64url of the right length is rejected.", { envelope: { ...env, signature: env.signature.slice(0, 85) + "+" }, publicKeyHex }, "reject"),
    dqe("unknown-top-level-key-rejects", "An unknown top-level field is rejected by the strict schema before verification.", { envelope: { ...env, extra: 1 }, publicKeyHex }, "reject"),
    dqe("unknown-query-key-rejects", "An unknown field inside the query object is rejected by the strict schema.", { envelope: { ...env, query: { ...env.query, rank: "best" } }, publicKeyHex }, "reject"),
    dqe("over-limit-tags-rejects", "A query with more than 32 tags is out of profile and rejects.", { envelope: { ...env, query: { ...env.query, tags: Array.from({ length: 33 }, (_, i) => `t${i}`) } }, publicKeyHex }, "reject"),
    dqe("limit-over-100-rejects", "A limit above 100 is out of profile and rejects.", { envelope: { ...env, query: { ...env.query, limit: 101 } }, publicKeyHex }, "reject"),
    dqe("invalid-timestamp-rejects", "A timestamp that is not a strict INK timestamp rejects.", { envelope: { ...env, timestamp: "2026-07-09 00:00" }, publicKeyHex }, "reject"),
    dqe("short-nonce-rejects", "A nonce shorter than 16 code units is out of profile and rejects.", { envelope: { ...env, nonce: "short" }, publicKeyHex }, "reject"),
    dqe("missing-signature-rejects", "An envelope with no signature field rejects.", { envelope: (() => { const { signature, ...rest } = env; return rest; })(), publicKeyHex }, "reject"),
  ]);
}

writeManifest();

console.log(`Wrote conformance/v1/vectors + manifest for principal (key ${mb.slice(0, 12)}...).`);
