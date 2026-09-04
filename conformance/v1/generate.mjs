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
  encodeEncryptionKeyMultibase,
  deriveAgentId,
  signAgentCard,
  signRotationLink,
  canonicalAgentPrincipal,
  signInkMessage,
  signMessage,
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
  buildAuthorizationGrant,
  buildAuthorizationChallenge,
  deriveChallengeGrantId,
  buildDelegationLink,
  buildAuthorizationChain,
  buildAttestation,
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
// advertises that capability. `staged` is neither: it holds a category that is
// agreed and anchored now and becomes required on a scheduled date, so the flip
// retags one category rather than negotiating a fresh contract. The base set is
// frozen by drift tripwires in test/conformance-profile.test.ts and
// go/ink/conformance_manifest_test.go.
const KNOWN_PROFILES = new Set(["base", "staged", "encryption", "audit", "witness", "containment", "discovery", "authorization", "delegation", "evidence"]);
const CATEGORY_META = {
  "principal-normalization": { profile: "base", spec: "specs/ink-authorization-chain.md", summary: "Agent principal canonicalization (tulpa:/ink:/key: prefixes)." },
  "signature-base": { profile: "base", spec: "specs/ink-protocol.md", summary: "Ed25519 verification over the canonical signature base." },
  "authorization-header": { profile: "base", spec: "specs/ink-protocol.md", summary: "INK-Ed25519 transport Authorization-header grammar (§3.3): signature and optional keyId extraction, whitespace and CR/LF rejection." },
  "jcs-number": { profile: "base", spec: "specs/ink-jcs-number-profile.md", summary: "RFC 8785 JCS canonicalization and the safe-integer number profile." },
  "key-rotation": { profile: "base", spec: "specs/ink-key-rotation-spec.md", summary: "Key-window verification across active, retired, and revoked keys." },
  "replay-freshness": { profile: "base", spec: "specs/ink-timestamp-grammar.md", summary: "Timestamp window and nonce replay rejection." },
  "timestamp-validity": { profile: "base", spec: "specs/ink-timestamp-grammar.md", summary: "Strict INK timestamp grammar and epoch-millisecond parsing." },
  "jcs-string-safety": { profile: "base", spec: "specs/ink-signed-string-safety.md", summary: "Lone UTF-16 surrogate rejection in signed strings." },
  "signed-body-member-name": { profile: "base", spec: "specs/ink-signed-string-safety.md", summary: "Escaped object member names in a signed body, rejected on the raw text before parsing." },
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
  "agent-card-fetch": { profile: "base", spec: "specs/ink-agent-card-discovery-fetch.md", summary: "Agent Card discovery response contract (status, content type, size caps, identity binding, owner anti-substitution)." },
  "agent-card-signature": { profile: "base", spec: "specs/ink-agent-card-signature.md", summary: "Self-authenticating Agent Card proof: the cardSignature proof, rotation-chain rooting by principal kind, head binding, the unsigned-card ratchet, and the continuity and rollback rules." },
  "agent-card-signature-phase-c": { profile: "staged", spec: "specs/ink-agent-card-signature.md", summary: "Staged Phase C receiver rule: with the explicit enforcePhaseC flag on, an unsigned card is rejected outright and a cold did:web verifier fails closed on an unreachable resolver; with the flag off the pre-Phase-C decision stands." },
  "private-hostname": { profile: "base", spec: "specs/ink-private-hostname.md", summary: "SSRF host-safety gate: classify a hostname as public or private/special/malformed." },
  "payload-encryption": { profile: "encryption", spec: "specs/ink-payload-encryption.md", summary: "ECIES payload decryption: X25519 + HKDF-SHA256 + AES-256-GCM with the AAD-bound outer envelope." },
  "first-contact-transcript": { profile: "base", spec: "specs/ink-first-contact-transcript.md", summary: "End-to-end first-contact flow: card fetch, version selection, signed connection_request, accepted connection_response." },
  "discovery-query-envelope": { profile: "discovery", spec: "specs/ink-discovery-query.md", summary: "Authenticated discovery query envelope: schema bounds, requester-key signature, audience binding, freshness window and nonce replay." },
  "authorization-grant": { profile: "authorization", spec: "specs/ink-authorization-grant.md", summary: "Scoped signed authorization grant: schema bounds, issuer-key signature, audience binding, presentation binding, validity window, replay, revocation, and the optional owner-verification requirement." },
  "agent-authorization": { profile: "authorization", spec: "specs/ink-agent-authorization.md", summary: "Sign-in challenge artifact: bare-host did:web rp, registry requestedScope, parser-independent redirectUri prefix rule, active-key-only RP signature at the verifier clock, validity window, and the challenge-derived grantId." },
  "attestation": { profile: "evidence", spec: "specs/ink-attestation.md", summary: "Signed issuer claim about a subject agent: schema bounds, claim-type and attestation-id grammar, the raw-body gate, the single vendor-neutral wire spelling, issuer-key signature, and the inclusive-start exclusive-end validity window. No audience, no replay, no judgment of issuer or claim." },
  "authorization-chain": { profile: "delegation", spec: "specs/ink-authorization-chain.md", summary: "Linear delegation chain of 2 to 4 grant-shaped links: parent-hash and issuer-subject continuity, monotonic scope and window attenuation with the delegation.extend gate, per-position lifetime ceilings, active-key-only per-link signatures, and the audience, presenter, window, replay, revocation and owner-verification context checks." },
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

// Emit the JSON Schema for a vector file. The `category` enum is DERIVED from
// the categories just written, sorted, never hand-listed, so it cannot silently
// under-list as the corpus grows the way a maintained enum did. The rest is the
// stable shape of a vector file; test/conformance-schema.test.ts validates every
// vector against it and asserts the enum set equals the manifest category set.
function writeSchema() {
  const categoryEnum = writtenVectors
    .map(({ category }) => category)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const schema = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://ink.tulpa.network/conformance/v1/schema.json",
    title: "INK conformance vector file (ink.conformance.v1)",
    type: "object",
    required: ["format", "category", "cases"],
    additionalProperties: false,
    properties: {
      format: { const: "ink.conformance.v1" },
      category: { type: "string", enum: categoryEnum },
      cases: {
        type: "array",
        minItems: 1,
        items: {
          type: "object",
          required: ["caseId", "description", "input", "expect"],
          additionalProperties: false,
          properties: {
            caseId: { type: "string", pattern: "^[a-z0-9-]+$" },
            description: { type: "string" },
            input: { type: "object" },
            // A case whose decision is a MAY in the spec it pins. `expect` still
            // carries the branch the reference takes, so the vector stays a
            // byte-exact pin, and `optionalBehavior.alternative` names the other
            // outcome that is EQUALLY conforming. A runner declares, once per
            // behavior id, which branch its implementation takes, and asserts
            // that branch; without this an implementation that fails closed
            // where the spec allows it would fail a base category for being
            // conformant. See specs/ink-conformance-profile.md.
            optionalBehavior: {
              type: "object",
              required: ["id", "alternative", "spec", "rationale"],
              additionalProperties: false,
              properties: {
                id: { type: "string", pattern: "^[a-z0-9-]+$" },
                alternative: { type: "string", enum: ["accept", "reject"] },
                spec: { type: "string" },
                rationale: { type: "string" },
              },
            },
            expect: {
              type: "object",
              required: ["result"],
              additionalProperties: false,
              properties: {
                result: { type: "string", enum: ["accept", "reject"] },
                reason: { type: "string" },
                auditEvent: { type: "string" },
                canonicalPrincipal: { type: "string" },
                keyStatus: { type: "string", enum: ["active", "retired", "revoked"] },
                keyId: { type: "string" },
                signature: { type: "string", pattern: "^[A-Za-z0-9_-]{86}$" },
                epochMs: { type: "integer" },
                canonicalString: { type: "string" },
                leafHash: { type: "string", pattern: "^[0-9a-f]{64}$" },
                derivedGrantId: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" },
              },
            },
          },
        },
      },
    },
  };
  writeFileSync(`${here}schema.json`, JSON.stringify(schema, null, 2) + "\n");
}

// Member names that discriminate a JCS member-ordering comparator. RFC 8785
// sorts by UTF-16 code unit: the astral key U+1F511 is a surrogate pair whose
// leading unit is D83D, so it sorts BELOW the BMP key U+FF21 (and below any
// member name in U+E000..U+FFFF). Sorting by code point or by UTF-8 byte puts
// it ABOVE. The two orders agree on every all-ASCII object, so a canonicalizer
// with the wrong comparator is invisible until a member name leaves ASCII, and
// then it changes the signed bytes of every signature kind INK defines. Used by
// the jcs-number, signature-base, agent-card-signature and merkle-leaf
// categories; the same discriminator the Go body-signature producer goldens use
// (go/ink/testdata/body-signature-producer.json).
const ordBmpKey = "Ａ"; // U+FF21 FULLWIDTH LATIN CAPITAL LETTER A
const ordAstralKey = "\u{1F511}"; // U+1F511 KEY, surrogate pair D83D DD11

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
  // ── the decode-and-re-encode rule (§7) ──
  // §7 maps a key-prefixed agentId to `key:<canonical-multibase>` by DECODING
  // the multibase body and re-encoding it, not by replacing the prefix. The four
  // cases below are the ones where the two implementations part company: a
  // prefix string-replace passes every case above and turns each of these into a
  // `key:` principal, which is a security decision, not a formatting one. A
  // sender whose malformed or wrongly-typed id became a `key:` principal gets a
  // blocklist entry, a rate-limit window and a nonce scope of its own, and can
  // mint fresh ones at will.
  {
    caseId: "malformed-multibase-body-escaped",
    description: "A tulpa: id whose multibase body is not base58btc at all is escaped to raw:<agentId>, never mapped to a key principal. An implementation that string-replaces the prefix instead produces key:zNotBase58_0IOl and gives an unauthenticatable id its own security scope.",
    input: { agentId: "tulpa:zNotBase58_0IOl" },
    expect: { result: "accept", canonicalPrincipal: "raw:tulpa:zNotBase58_0IOl" },
  },
  {
    caseId: "truncated-key-body-escaped",
    description: "A tulpa: id whose body decodes but is far short of a 34-byte multicodec-plus-key is escaped to raw:, so the length check is part of the decode and not an afterthought.",
    input: { agentId: "tulpa:z6Mk" },
    expect: { result: "accept", canonicalPrincipal: "raw:tulpa:z6Mk" },
  },
  {
    caseId: "leading-zero-padded-multibase-escaped",
    description: "A NON-CANONICAL multibase spelling of the canonical key: an extra base58 '1' prepends a 0x00 byte, so the decoded bytes no longer start with the 0xed01 Ed25519 multicodec and the id is escaped to raw:. A decoder that tolerates the padding re-encodes it to the SAME key principal as the canonical spelling, which merges two distinct wire identifiers; a prefix string-replace instead mints a third principal. The reference does neither.",
    input: { agentId: `tulpa:z1${mb.slice(1)}` },
    expect: { result: "accept", canonicalPrincipal: `raw:tulpa:z1${mb.slice(1)}` },
  },
  {
    caseId: "encryption-key-multicodec-escaped",
    description: "A tulpa: id carrying an X25519 (0xec01) multibase where a signing key belongs is escaped to raw:. The multicodec prefix is checked during the decode, so an encryption key cannot be spelled as a signing principal.",
    input: { agentId: `tulpa:${encodeEncryptionKeyMultibase(publicKey)}` },
    expect: { result: "accept", canonicalPrincipal: `raw:tulpa:${encodeEncryptionKeyMultibase(publicKey)}` },
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

// Every real intent envelope carries a `signature` member (Protocol §2, a MUST):
// the §3.6 body signature over the envelope minus that member. The two signature
// kinds treat it differently, and the difference is invisible in a corpus whose
// signed bodies never carry one. §3.6 strips `signature` before canonicalizing;
// §3.3 strips nothing, so the transport base commits to the body exactly as
// delivered, `signature` member included. The two cases below pin that in both
// directions: an implementation that strips `signature` before building the
// transport base fails the accept case, and one that builds the base over a body
// the signer did not sign passes nothing.
const bodyWithoutSignature = {
  ...signInput.body,
  id: "44444444-4444-4444-8444-444444444444",
  nonce: "55555555-5555-4555-8555-555555555555",
};
const bodySignature = await signMessage(bodyWithoutSignature, seed);
const signedEnvelope = { ...bodyWithoutSignature, signature: bodySignature };
// Transport signature over the FULL envelope, `signature` member included.
const envelopeSignInput = { ...signInput, body: signedEnvelope };
const envelopeTransportSignature = await signInkMessage(envelopeSignInput, seed);
// Transport signature over the envelope with `signature` STRIPPED, presented
// against the full envelope. This is exactly what a §3.6-style stripping
// implementation produces, and a conforming §3.3 verifier must reject it.
const strippedBaseTransportSignature = await signInkMessage(
  { ...signInput, body: bodyWithoutSignature },
  seed,
);

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

// A signed body whose payload carries member names outside ASCII, ordered so
// only a UTF-16 code-unit comparator reproduces the signer's bytes (see the
// ordBmpKey/ordAstralKey note above). The reference signs the canonical form; a
// verifier that sorts by code point or UTF-8 byte builds a different base and
// rejects a signature that is valid. The reordered twin pins that the decision
// is over the canonical bytes and not the source member order.
const orderingBody = {
  ...signInput.body,
  payload: { [ordBmpKey]: "bmp", [ordAstralKey]: "astral", note: "member ordering" },
};
const orderingSignInput = { ...signInput, body: orderingBody };
const orderingSignature = await signInkMessage(orderingSignInput, seed);
const orderingReordered = {
  ...signInput,
  body: {
    ...signInput.body,
    payload: { note: "member ordering", [ordAstralKey]: "astral", [ordBmpKey]: "bmp" },
  },
};

// §3.3 forbids CR and LF in all four scalar fields (METHOD, PATH, recipientDid,
// timestamp) because the base is newline-delimited: an embedded newline shifts
// the field boundaries, so two distinct logical requests can produce one signed
// string. The pair below is exactly that collision — path "/a\nb" with
// recipientDid "x", and path "/a" with recipientDid "b\nx", produce byte-identical
// bases — signed here by minting the signature over the raw base bytes directly,
// since the reference signer refuses to build either. Both MUST reject: the
// signature genuinely verifies, so an implementation that omits the CR/LF check
// accepts both and treats two different requests as the same authenticated one.
const crlfBody = { ...signInput.body, payload: { note: "field boundary" } };
const crlfTs = "2026-06-11T00:00:00.000Z";
const collidingBase = `ink/0.1\nPOST\n/a\nb\nx\n${jcsCanonicalize(crlfBody)}\n${crlfTs}`;
const collidingSignature = Buffer.from(
  await ed.signAsync(enc.encode(collidingBase), seed),
).toString("base64url");
const crBase = `ink/0.1\nPOST\n/a\nx\ry\n${jcsCanonicalize(crlfBody)}\n${crlfTs}`;
const crSignature = Buffer.from(await ed.signAsync(enc.encode(crBase), seed)).toString("base64url");

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
    caseId: "body-with-signature-member-accepts",
    description: "The transport signature base is built over the delivered body with nothing removed, so a body carrying the §3.6 `signature` member verifies with that member included. An implementation that strips `signature` before canonicalizing, which is the §3.6 body-signature rule and not the §3.3 transport rule, canonicalizes different bytes and rejects.",
    input: { signInput: envelopeSignInput, signature: envelopeTransportSignature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "signature-member-stripped-from-base-rejects",
    description: "A transport signature computed over the body with the `signature` member stripped does not verify against the delivered body that carries it. This is the mirror of the case above: an implementation that strips `signature` from the transport base accepts this forgery-equivalent mismatch, a conforming one rejects it.",
    input: { signInput: envelopeSignInput, signature: strippedBaseTransportSignature, publicKeyHex },
    expect: { result: "reject" },
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
  {
    caseId: "non-ascii-member-order-accepts",
    description: "A signed body whose payload carries the member names U+FF21 and U+1F511 verifies only if the canonicalizer sorts members by UTF-16 code unit (RFC 8785), which puts the astral key first. Sorting by code point or by UTF-8 byte builds a different signature base and rejects a valid signature.",
    input: { signInput: orderingSignInput, signature: orderingSignature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "non-ascii-member-reorder-accepts",
    description: "The same non-ASCII payload emitted in a different source order canonicalizes to the same bytes, so the same signature verifies: the ordering rule is the canonicalizer's, not the wire's.",
    input: { signInput: orderingReordered, signature: orderingSignature, publicKeyHex },
    expect: { result: "accept" },
  },
  {
    caseId: "path-with-newline-rejects",
    description: "A PATH containing a line feed is rejected even though the accompanying signature verifies over the resulting base. Together with recipient-with-newline-rejects it pins the §3.3 CR/LF ban: the two inputs differ only in which scalar carries the newline, they produce byte-identical bases, and one signature authenticates both, so an implementation that omits the check authenticates two different requests with one signature.",
    input: { signInput: { method: "POST", path: "/a\nb", recipientDid: "x", body: crlfBody, timestamp: crlfTs }, signature: collidingSignature, publicKeyHex },
    expect: { result: "reject" },
  },
  {
    caseId: "recipient-with-newline-rejects",
    description: "The other half of the field-boundary collision: PATH \"/a\" with a recipientDid of \"b\\nx\" builds the same base bytes as PATH \"/a\\nb\" with recipientDid \"x\", so the identical signature verifies. A conforming verifier rejects on the newline before it ever gets there.",
    input: { signInput: { method: "POST", path: "/a", recipientDid: "b\nx", body: crlfBody, timestamp: crlfTs }, signature: collidingSignature, publicKeyHex },
    expect: { result: "reject" },
  },
  {
    caseId: "recipient-with-carriage-return-rejects",
    description: "The ban covers CR as well as LF: a recipientDid carrying a carriage return is rejected, again against a signature that verifies over the base those bytes produce, so an implementation that scans only for \\n diverges.",
    input: { signInput: { method: "POST", path: "/a", recipientDid: "x\ry", body: crlfBody, timestamp: crlfTs }, signature: crSignature, publicKeyHex },
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
  {
    caseId: "out-of-double-range-literal-rejects",
    description: "A literal with no double at all is rejected. This one is decided before parsing, by the raw-text range rule of ink-signed-string-safety.md, not by the value profile: ECMAScript decodes it to Infinity and Go refuses the document, so the two would otherwise disagree about whether the body exists.",
    input: { bodyRaw: `{"n":1e309}` },
    expect: { result: "reject" },
  },
  {
    caseId: "shadowed-out-of-double-range-literal-rejects",
    description: "An out-of-range literal that a later duplicate member shadows is still rejected. Last-wins member semantics hide it from every check on the decoded value, so an implementation that runs the range rule after parsing canonicalizes {\"n\":1} here and verifies a signature over bytes another implementation refuses outright.",
    input: { bodyRaw: `{"n":1e309,"n":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "in-range-duplicate-member-accepts-last",
    description: "The control for the case above: a duplicate member whose literals are both in range is accepted and canonicalizes to the last one, so the rejection above is about the literal and not about duplicate members.",
    input: { bodyRaw: `{"n":2,"n":1}` },
    expect: { result: "accept", canonicalString: `{"n":1}` },
  },
  {
    caseId: "underflow-exponent-accepts-as-zero",
    description: "An exponent below the smallest subnormal decodes to 0 on every IEEE-754 parser, so it is in range for the raw-text rule and is judged by the value profile in the ordinary way: 0 is a safe integer and canonicalizes to 0.",
    input: { bodyRaw: `{"n":1e-400}` },
    expect: { result: "accept", canonicalString: `{"n":0}` },
  },
  // ── member ordering outside ASCII ──
  // RFC 8785 sorts object members by UTF-16 CODE UNIT, which is not the same
  // order as code point or UTF-8 byte for a member name outside the BMP. A
  // canonicalizer that sorts by code point (the natural sort in Go, Rust and
  // Python) or by UTF-8 bytes agrees on every all-ASCII object and disagrees
  // here: the astral key U+1F511 starts with the high surrogate D83D, which is
  // BELOW U+FF21 as a code unit and ABOVE it as a code point. Every signature
  // kind in INK signs canonical bytes, so a wrong comparator changes the signed
  // bytes of every message carrying such a member and is otherwise invisible.
  {
    caseId: "member-order-astral-before-bmp-accepts",
    description: "JCS sorts members by UTF-16 code unit, so the astral key U+1F511 (high surrogate D83D) sorts BEFORE the BMP key U+FF21. A canonicalizer that sorts by code point or by UTF-8 byte emits the reverse order and signs different bytes.",
    input: { bodyRaw: `{"${ordBmpKey}":1,"${ordAstralKey}":2}` },
    expect: { result: "accept", canonicalString: `{"${ordAstralKey}":2,"${ordBmpKey}":1}` },
  },
  {
    caseId: "member-order-mixed-scripts-nested-accepts",
    description: "The same UTF-16 code-unit ordering applies at every depth and against ASCII and Latin-1 neighbours: the full order is ASCII, then U+00E9, then the astral key, then U+FF21, in both the top-level object and a nested one.",
    input: { bodyRaw: `{"nested":{"${ordBmpKey}":1,"z":2,"${ordAstralKey}":3,"a":4},"${ordBmpKey}":5,"é":6,"${ordAstralKey}":7,"Z":8}` },
    expect: {
      result: "accept",
      canonicalString: `{"Z":8,"nested":{"a":4,"z":2,"${ordAstralKey}":3,"${ordBmpKey}":1},"é":6,"${ordAstralKey}":7,"${ordBmpKey}":5}`,
    },
  },
]);

// ── key-rotation ───────────────────────────────────────────────────────────
// The same signed message verified against a key set. The authority rule:
// revoked keys are always skipped, active keys are tried before retired, and a
// key only admits a message whose timestamp falls inside its validity window.
//
// Two layers live in this category and they decide a retired key differently.
// Cases WITHOUT `liveAuth` exercise HISTORICAL VERIFICATION, the multi-key
// primitive: a retired key inside its validity window verifies, which is what
// lets a receipt, an audit event or a stored message stay verifiable after a
// rotation. Cases WITH `liveAuth: true` exercise LIVE TRANSPORT AUTHENTICATION
// (Protocol §3.3, identity model §4.4): the same primitive runs, then the
// retired-key default rejects a signature that only a retired entry verified,
// with `retired_key_for_live_auth`, unless the deployment has opted into a
// bounded rotation grace window (`liveAuthAllowRetired`). An implementation
// that wires one layer's answer into the other passes one set and fails the
// other.
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
    description: "Historical verification: a retired key whose validity window still contains the message timestamp verifies at the multi-key primitive. This case does not authorize a retired key for live transport auth; see the liveAuth cases below.",
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
  {
    caseId: "live-auth-active-key-accepts",
    description: "Live transport auth over an active key accepts, and reports the active status. The live-auth layer narrows which entries may authenticate a fresh request; it does not change how the signature itself is checked.",
    input: { signInput, signature, keys: [keyEntry("active")], liveAuth: true },
    expect: { result: "accept", keyStatus: "active", keyId: "signer-active" },
  },
  {
    caseId: "live-auth-retired-key-rejects",
    description: "Live transport auth rejects a signature that only a retired entry verified, even though the same key and message are accepted by historical verification in retired-key-in-window-accepts. The retired-key default is on unless the deployment opts out, so an implementation that returns the primitive's answer to its transport-auth caller accepts a superseded key for fresh traffic.",
    input: { signInput, signature, keys: [keyEntry("retired", { validUntil: "2027-01-01T00:00:00.000Z" })], liveAuth: true },
    expect: { result: "reject", reason: "retired_key_for_live_auth" },
  },
  {
    caseId: "live-auth-retired-key-with-grace-window-accepts",
    description: "A deployment that has explicitly opted into a bounded rotation grace window accepts the same retired key for live transport auth. The opt-in is the only thing that changes the previous case, so the default cannot be reached by accident.",
    input: {
      signInput,
      signature,
      keys: [keyEntry("retired", { validUntil: "2027-01-01T00:00:00.000Z" })],
      liveAuth: true,
      liveAuthAllowRetired: true,
    },
    expect: { result: "accept", keyStatus: "retired", keyId: "signer-retired" },
  },
  {
    caseId: "live-auth-revoked-key-rejects",
    description: "A revoked key is skipped by the primitive, so live transport auth rejects for signature failure rather than reaching the retired-key default.",
    input: { signInput, signature, keys: [keyEntry("revoked")], liveAuth: true },
    expect: { result: "reject", reason: "signature_verification_failed" },
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
  // ── the frozen window boundaries (§3.5) ──
  // §3.5 freezes the window at exactly 300000 ms of age and 30000 ms of skew,
  // and rejects when the bound is EXCEEDED, so both bounds are inclusive. The
  // four cases below pin each side to the millisecond. Without them an
  // implementation with an hour-long window, or with an exclusive comparison,
  // passes every other case in this category: -6min and +31s say nothing about
  // where the edge actually is.
  {
    caseId: "age-bound-accepts",
    description: "The age bound is inclusive: a message exactly 300000 ms old is still fresh, because §3.5 rejects only when -drift EXCEEDS 300000.",
    input: { replay: replayInput("2026-06-10T23:55:00.000Z", goodNonce) },
    expect: { result: "accept" },
  },
  {
    caseId: "one-ms-past-age-bound-rejects",
    description: "One millisecond older than the bound rejects, so an implementation with a longer window (or a wider unit) diverges here rather than passing on a coarse case.",
    input: { replay: replayInput("2026-06-10T23:54:59.999Z", goodNonce) },
    expect: { result: "reject" },
  },
  {
    caseId: "skew-bound-accepts",
    description: "The future-skew bound is inclusive on the same reading: a message exactly 30000 ms ahead of the receiver clock is accepted.",
    input: { replay: replayInput("2026-06-11T00:00:30.000Z", goodNonce) },
    expect: { result: "accept" },
  },
  {
    caseId: "one-ms-past-skew-bound-rejects",
    description: "One millisecond past the skew bound rejects, pinning the future edge to the millisecond the way the age edge is pinned.",
    input: { replay: replayInput("2026-06-11T00:00:30.001Z", goodNonce) },
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

// ── signed-body-member-name ──────────────────────────────────────────────
// A signed body MUST NOT contain an object member name written with any escape
// sequence. V8 sizes the character span for an escaped member name from the raw
// source using the decoded length, then adopts a matching hidden-class
// transition's name as the property key without decoding, so the parsed object
// can carry a member name the document never contained. Escapes in string
// values and array elements are unaffected. The rule is stated on the raw text
// because the substituted name is indistinguishable, after parsing, from a name
// the sender chose. `bs` is the backslash const declared above.
vectorFile("signed-body-member-name", [
  {
    caseId: "plain-member-name-accepts",
    description: "A member name with no escape is accepted.",
    input: { bodyRaw: `{"note":1}` },
    expect: { result: "accept" },
  },
  {
    caseId: "non-ascii-member-name-accepts",
    description: "A member name carrying raw non-ASCII UTF-8 is accepted; only escapes are barred.",
    input: { bodyRaw: `{"é":1,"𝄞":2}` },
    expect: { result: "accept" },
  },
  {
    caseId: "empty-member-name-accepts",
    description: "The empty member name is accepted.",
    input: { bodyRaw: `{"":1}` },
    expect: { result: "accept" },
  },
  {
    caseId: "escaped-string-value-accepts",
    description: "An escape in a string value is accepted; the rule covers member names only.",
    input: { bodyRaw: `{"note":"line${bs}nbreak"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "escaped-array-element-accepts",
    description: "An escape in an array element is accepted.",
    input: { bodyRaw: `{"a":["${bs}n","${bs}${bs}"]}` },
    expect: { result: "accept" },
  },
  {
    caseId: "colon-in-string-value-accepts",
    description:
      "A colon inside a string value does not make the preceding string a member name.",
    input: { bodyRaw: `{"a":"b:c","d":"${bs}n:e"}` },
    expect: { result: "accept" },
  },
  {
    caseId: "value-ending-in-escaped-quote-accepts",
    description:
      "A string value ending in an escaped quote must not desynchronise the scan into misreading the following text.",
    input: { bodyRaw: `{"a":"ends with ${bs}"","b":1}` },
    expect: { result: "accept" },
  },
  {
    caseId: "escaped-newline-member-name-rejects",
    description:
      "A member name written with a two-character escape is rejected: V8 can return a different name entirely.",
    input: { bodyRaw: `{"${bs}n":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escaped-backslash-member-name-rejects",
    description:
      "An escaped backslash member name is rejected. This is the name that plants the transition the corruption reuses.",
    input: { bodyRaw: `{"${bs}${bs}":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escaped-quote-member-name-rejects",
    description: "An escaped quotation mark member name is rejected.",
    input: { bodyRaw: `{"${bs}"":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escaped-solidus-member-name-rejects",
    description:
      "An escaped solidus member name is rejected even though the solidus need not be escaped at all.",
    input: { bodyRaw: `{"${bs}/":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "unicode-escape-member-name-rejects",
    description:
      "A \\uXXXX member name is rejected even when it decodes to an ordinary character, because the raw spelling is still longer than the decoded name.",
    input: { bodyRaw: `{"${bs}u0041":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escape-mid-member-name-rejects",
    description: "An escape anywhere inside a member name is rejected, not only at the start.",
    input: { bodyRaw: `{"a${bs}nb":1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "nested-escaped-member-name-rejects",
    description: "An escaped member name nested inside another object is rejected.",
    input: { bodyRaw: `{"a":{"${bs}n":1}}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escaped-member-name-in-array-rejects",
    description: "An escaped member name inside an array element object is rejected.",
    input: { bodyRaw: `{"a":[{"b":{"${bs}${bs}":1}}]}` },
    expect: { result: "reject" },
  },
  {
    caseId: "whitespace-before-colon-rejects",
    description:
      "Whitespace between a member name and its colon does not exempt the name from the rule.",
    input: { bodyRaw: `{"${bs}n"  :  1}` },
    expect: { result: "reject" },
  },
  {
    caseId: "poisoning-and-victim-pair-rejects",
    description:
      "The measured corruption vector: an escaped-backslash name plants a transition that a later escaped name is decoded into. Rejected on the first escaped member name.",
    input: { bodyRaw: `{"x":{"${bs}${bs}":1},"y":{"${bs}n":2}}` },
    expect: { result: "reject" },
  },
  {
    caseId: "escaped-key-after-escaped-quote-value-rejects",
    description:
      "An escaped member name following a string value that ends in an escaped quote is still rejected.",
    input: { bodyRaw: `{"a":"ends with ${bs}"","${bs}n":1}` },
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
  {
    caseId: "bare-out-of-double-range-literal-rejects",
    description: "A body that is nothing but a literal outside the IEEE-754 double range is rejected at the gate. ECMAScript JSON.parse returns Infinity for it and Go's encoding/json refuses the document, so the gate decides it rather than the parser.",
    input: { bodyHex: utf8Hex("1e309") },
    expect: { result: "reject" },
  },
  {
    caseId: "out-of-double-range-member-rejects",
    description: "The same literal as a member value is rejected before parsing, so nothing downstream ever sees an Infinity.",
    input: { bodyHex: utf8Hex(`{"n":1e309}`) },
    expect: { result: "reject" },
  },
  {
    caseId: "shadowed-out-of-double-range-literal-rejects",
    description: "An out-of-range literal shadowed by a later duplicate member is rejected. This is the case a value-level range check cannot make: last-wins semantics drop the literal, so a receiver that checks after parsing admits a body another implementation refuses outright, and then verifies a signature over its canonical bytes.",
    input: { bodyHex: utf8Hex(`{"n":1e309,"n":1}`) },
    expect: { result: "reject" },
  },
  {
    caseId: "number-like-text-in-string-accepts",
    description: "The same characters inside a JSON string are text, not a number literal, so the range scan must read only outside strings.",
    input: { bodyHex: utf8Hex(`{"note":"1e309"}`) },
    expect: { result: "accept" },
  },
  {
    caseId: "underflow-exponent-accepts",
    description: "An exponent below the smallest subnormal decodes to 0 on every IEEE-754 parser rather than to an infinity, so it is in range and the gate accepts it; the value profile then judges the 0.",
    input: { bodyHex: utf8Hex(`{"n":1e-400}`) },
    expect: { result: "accept" },
  },
  {
    caseId: "largest-finite-double-accepts",
    description: "The largest finite double is the boundary the rule is drawn at and is accepted by the gate, so the rule rejects only literals with no double at all.",
    input: { bodyHex: utf8Hex(`{"n":1.7976931348623157e308}`) },
    expect: { result: "accept" },
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
  await leafAccept("non-ascii-member-order-accepts", "An event whose member names include U+FF21 and U+1F511 pins the leaf digest only under RFC 8785 member ordering by UTF-16 code unit, which puts the astral key first. A canonicalizer sorting by code point or by UTF-8 byte commits a different leaf, and every inclusion proof over it diverges.", `{"id":"evt-4","${ordBmpKey}":"bmp","${ordAstralKey}":"astral"}`),
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
  // Handshake messages define no embedded signature member (Protocol §5). An
  // unrecognized signature key is ignored like any other unknown top-level key
  // and MUST NOT be treated as verified provenance; an implementation that
  // rejects it, or verifies it, diverges.
  hsAccept("challenge-unknown-signature-key-accepts", "A challenge carrying an unknown top-level signature key validates; handshake messages define no embedded signature member and the key is ignored, never verified.", { ...hsChallenge, signature: "junk" }),
  hsAccept("rejection-unknown-signature-key-accepts", "A rejection carrying an unknown top-level signature key validates and the key is ignored.", { ...hsRejection, signature: "junk" }),
  hsAccept("resolution-unknown-signature-key-accepts", "A resolution carrying an unknown top-level signature key validates and the key is ignored.", { ...hsResolution, signature: "junk" }),
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
// Identity model §4.1: an encryption entry decodes to 0xec01 X25519, never the
// signing key's 0xed01. Deterministic bytes so the corpus is reproducible.
const acEncMb = encodeEncryptionKeyMultibase(new Uint8Array(32).fill(9));
const acEncKey = { keyId: "k2", algorithm: "X25519", publicKeyMultibase: acEncMb, status: "active", validFrom: acTs };
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
  keys: { signing: [acKey], encryption: [acEncKey] },
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
  // Identity model §4.1: the roles are disjoint and the multicodec enforces
  // it. A signing slot decodes to 0xed01 plus 32 bytes, an encryption slot to
  // 0xec01 plus 32 bytes, and the algorithm label names the role's algorithm.
  acReject("key-role-ed25519-in-encryption-slot-rejects", "An encryption entry whose multibase decodes to the 0xed01 Ed25519 multicodec is rejected: the roles are disjoint and the multicodec enforces it.", { ...acCard, keys: { signing: [acKey], encryption: [{ ...acEncKey, publicKeyMultibase: mb }] } }),
  acReject("key-role-x25519-in-signing-slot-rejects", "A signing entry whose multibase decodes to the 0xec01 X25519 multicodec is rejected.", { ...acCard, keys: { signing: [{ ...acKey, publicKeyMultibase: acEncMb }], encryption: [acEncKey] } }),
  acReject("key-undecodable-multibase-rejects", "A key entry whose multibase body does not decode is rejected; a z prefix alone is not a key.", { ...acCard, keys: { signing: [{ ...acKey, publicKeyMultibase: "zJUNK" }], encryption: [] } }),
  acReject("key-algorithm-contradicts-slot-rejects", "A signing entry labeled X25519 is rejected even when its key bytes are valid Ed25519: the label must name the role's algorithm.", { ...acCard, keys: { signing: [{ ...acKey, algorithm: "X25519" }], encryption: [] } }),
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
  acAccept("card-unknown-top-level-key-ignored-accepts", "An unknown TOP-LEVEL card member is ignored, not rejected. The card top level is a tolerant surface (ink-compatibility-policy.md §3.1), which is what lets a later minor add a member that older receivers ignore; the nested discovery descriptor is a separate surface with its own case, so neither one pins the other.", { ...acCard, futureExtension: { note: "additive" } }),
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
const fetchInput = (over = {}) => ({ status: 200, contentType: "application/json", contentLength: null, bodyRaw: fetchBody, requestedAgentId: fetchReqId, resolutionDid: null, ...over });
// Step 9 (owner anti-substitution) needs a card that carries an ownerDid.
const fetchOwnerDid = "did:web:owner.example";
const fetchOwnedBody = JSON.stringify({ ...acCard, ownerDid: fetchOwnerDid });
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
  // owner anti-substitution (step 9)
  fReject("owner-did-mismatch-rejects", "A DID-mediated fetch whose card names a different ownerDid rejects; a host that legitimately publishes a card for one DID must not answer resolution of another with it.", fetchInput({ bodyRaw: fetchOwnedBody, resolutionDid: "did:web:someone-else.example" })),
  fAccept("owner-did-match-accepts", "A DID-mediated fetch whose card names the DID under resolution accepts; the comparison is byte for byte with no canonicalization.", fetchInput({ bodyRaw: fetchOwnedBody, resolutionDid: fetchOwnerDid })),
  fReject("owner-did-case-differs-rejects", "The step 9 comparison performs no case folding, so a re-cased ownerDid is a different DID and rejects.", fetchInput({ bodyRaw: fetchOwnedBody, resolutionDid: "did:web:Owner.example" })),
  fAccept("owner-did-absent-accepts", "A card without an ownerDid passes step 9 unchanged, even under a DID-mediated fetch.", fetchInput({ resolutionDid: "did:web:owner.example" })),
  fAccept("resolution-did-absent-accepts", "A fetch that was not DID-mediated passes step 9 unchanged, even when the card carries an ownerDid.", fetchInput({ bodyRaw: fetchOwnedBody, resolutionDid: null })),
]);

// ── agent-card-signature ─────────────────────────────────────────────────────
// The self-authenticating Agent Card verifier (ink-agent-card-signature.md §5):
// the cardSignature proof (§3), rotation-chain rooting by principal kind (§4),
// head binding (§4.1 step 3), the unsigned-card ratchet (§7) and the continuity
// and rollback rules (§6). Every vector is a PURE function of its input: any
// prior receiver state (a cached authenticated card, a resolved DID document, or
// its unavailability) and the conformance profile ride in `input.options`, so a
// stateful or profile-keyed case pins one decision per state. Keypairs are fixed
// 32-byte seeds so signatures are byte-deterministic. Both implementations MUST
// reach the same accept-or-reject decision, the same reason, and the same audit
// mark on every case.
{
  const acsKp = async (n) => {
    const priv = new Uint8Array(32).fill(n);
    const pub = await ed.getPublicKeyAsync(priv);
    return { priv, pub, mb: encodePublicKeyMultibase(pub) };
  };
  // G genesis, A rotated/leaked historical key, B genuine current key, X attacker,
  // H a second key, D a did:web key, OTHER an unrelated key, C a third chain key.
  const [G, A, B, X, H, D, OTHER, C] = await Promise.all([1, 2, 3, 4, 5, 6, 7, 8].map(acsKp));

  const ACS_VALID_FROM = "2026-01-01T00:00:00Z";
  const ACS_UPDATED_AT = "2026-07-20T00:00:00Z";

  const acsBaseCard = (agentId, topMb) => ({
    protocol: "ink/0.1",
    agentId,
    handle: "agent",
    displayName: "Agent",
    endpoint: "https://example.com/ink",
    publicKeyMultibase: topMb,
    capabilities: { intentsAccepted: [], intentsSent: [] },
    availability: { timezone: "UTC" },
  });
  // A card `keys.signing` entry carries the full schema shape; a rotation-link
  // committed entry carries only {keyId, publicKeyMultibase, status} (§4.1, no
  // algorithm). Head correspondence compares the two by keyId, decoded key bytes
  // and status, so the extra card-entry fields do not affect the match.
  const signingEntry = (keyId, k, status) => ({ keyId, algorithm: "Ed25519", publicKeyMultibase: k.mb, status, validFrom: ACS_VALID_FROM });
  const linkEntry = (keyId, k, status) => ({ keyId, publicKeyMultibase: k.mb, status });
  const attach = async (card, keyId, priv) => ({ ...card, cardSignature: { keyId, signature: await signAgentCard(card, priv) } });
  const mkLink = async (body, priv) => ({ ...body, signature: await signRotationLink(body, priv) });
  // Corrupt a base64url signature deterministically by flipping the low bit of
  // its FIRST character, which always changes the decoded bytes (a trailing char
  // in an unpadded encoding can carry unused low bits whose flip is a no-op).
  const flipCardSig = (sig) => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return alphabet[alphabet.indexOf(sig[0]) ^ 1] + sig.slice(1);
  };

  const acsAccept = (caseId, description, input, extra = {}) => ({ caseId, description, input, expect: { result: "accept", ...extra } });
  const acsReject = (caseId, description, input, extra = {}) => ({ caseId, description, input, expect: { result: "reject", ...extra } });
  // Tag a case whose decision the spec leaves to the implementation. `expect`
  // keeps the reference's branch, so the vector still pins bytes and reasons for
  // an implementation that takes it; `optionalBehavior.alternative` names the
  // other conformant outcome, and a runner declares which branch it takes.
  // Without this a fail-closed implementation would fail a BASE category for
  // exercising a choice the spec explicitly grants it.
  const acsOptional = (caseObj, behavior) => ({ ...caseObj, optionalBehavior: behavior });

  const keyDerivedId = deriveAgentId(G.pub);
  const DIDWEB = "did:web:example.com";

  // ── no-chain signed key-derived accept, and the byte-exact pin ──
  const noChainCard = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    c.updatedAt = ACS_UPDATED_AT;
    return c;
  })();
  const noChainSigned = await attach(noChainCard, "g1", G.priv);
  // The same card carrying two extension members whose names are outside ASCII,
  // ordered so that only RFC 8785's UTF-16 code-unit comparator reproduces the
  // signer's bytes: U+1F511 sorts BEFORE U+FF21 as code units and after it as
  // code points or UTF-8 bytes. The card top level is a tolerant surface
  // (ink-compatibility-policy.md §3.1), so both members reach canonicalization
  // and the §3.4 card-signature domain commits to them.
  const noChainOrderingSigned = await attach(
    { ...noChainCard, [ordBmpKey]: "bmp", [ordAstralKey]: "astral" },
    "g1",
    G.priv,
  );

  // ── rotated signer, valid two-link chain, accept ──
  const chainCardSigned = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kA", A, "retired"), linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    c.rotationChain = [l1, l2];
    return attach(c, "kB", B.priv);
  })();

  // ── multi-hop honest double-rotation, warm accept through an interior link ──
  const twoHopSigned = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kB", B, "active")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kB", B, "retired"), linkEntry("kC", H, "active")], prevKeyId: "kB" }, B.priv);
    const l3 = await mkLink({ keySetVersion: 3, signing: [linkEntry("kC", H, "retired"), linkEntry("kD", D, "active")], prevKeyId: "kC" }, H.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kC", H, "retired"), signingEntry("kD", D, "active")], encryption: [] };
    c.currentSigningKeyId = "kD";
    c.keySetVersion = 3;
    c.rotationChain = [l1, l2, l3];
    return attach(c, "kD", D.priv);
  })();
  const twoHopCached = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 1;
    return c;
  })();

  // ── chain-extension fork: genuine link1 (kA active, signed by G), OMIT the
  // genuine revoking link2, append a FORGED link2 signed by the leaked kA that
  // commits an attacker key kX. Cold verifier accepts (documented residual);
  // warm verifier rejects via continuity from a cached card that revoked kA. ──
  const forkSigned = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const forged = await mkLink({ keySetVersion: 2, signing: [linkEntry("kX", X, "active")], prevKeyId: "kA" }, A.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kX", X, "active")], encryption: [] };
    c.currentSigningKeyId = "kX";
    c.keySetVersion = 2;
    c.rotationChain = [l1, forged];
    return attach(c, "kX", X.priv);
  })();
  const forkCached = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "revoked"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    return c;
  })();

  // ── committed-set stuffing: the forged link STUFFS the genuine current key kB
  // into its committed set (kB signs nothing). Warm continuity must bridge only
  // through verified signers, so it must NOT accept via kB's mere membership. ──
  const stuffSigned = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const forged = await mkLink({ keySetVersion: 2, signing: [linkEntry("kX", X, "active"), linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kX", X, "active"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kX";
    c.keySetVersion = 2;
    c.rotationChain = [l1, forged];
    return attach(c, "kX", X.priv);
  })();

  // ── keySetVersion regression versus a cached authenticated card ──
  const regressionCached = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 5;
    return c;
  })();

  // ── head-binding rejects ──
  const headVersionMismatch = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 2; // head link commits version 1
    c.rotationChain = [l1];
    return attach(c, "kA", A.priv);
  })();
  const headSetMismatch = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    // Card carries an extra signing entry the head link does not commit.
    c.keys = { signing: [signingEntry("kA", A, "active"), signingEntry("kC", H, "active")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kA", A.priv);
  })();
  const headStatusMismatch = await (async () => {
    // Head link commits kB active; the card carries kB as retired.
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active"), linkEntry("kB", B, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "active"), signingEntry("kB", B, "retired")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kA", A.priv);
  })();
  const headSetMissingSigner = await (async () => {
    // The head link commits only kA; the card carries kA PLUS the signer kB, so
    // the head set omits the very key that signed cardSignature. The proof passes
    // (kB is an active, current entry of keys.signing), and head-binding rejects
    // because the head set does not correspond to keys.signing (§4.1 step 3b: exact
    // correspondence is what guarantees the signer is present in the head set).
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "active"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kB", B.priv);
  })();
  const headPubkeyDisagreement = await (async () => {
    // The head link commits kA bound to A's key; the card carries kA with the SAME
    // keyId and the SAME status but B's public key, a byte-level key disagreement
    // (not an extra entry, not a status difference). The proof passes because the
    // card self-signs with B, so this rejects in head-binding on the decoded-key
    // byte comparison, not in proof verification (§4.1 step 3b, §3.5).
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kA", B.priv);
  })();

  // ── chain-shape rejects ──
  const noncontiguous = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 3, signing: [linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv); // gap 1→3
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 3;
    c.rotationChain = [l1, l2];
    return attach(c, "kB", B.priv);
  })();
  const linkSignerNotActive = await (async () => {
    // link1 marks kA retired; forged link2 claims kA as its signer.
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "retired")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    c.rotationChain = [l1, l2];
    return attach(c, "kB", B.priv);
  })();
  const chainLinkInvalidSig = await (async () => {
    // A valid two-link chain whose SECOND link signature is corrupted, so it no
    // longer verifies against its prevKeyId (kA) signer even though kA is active
    // in link 1's committed set. Rejected at the interior link-signature check,
    // distinct from the link-1 root-failure path.
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kA", A, "retired"), linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv);
    const corrupted = { ...l2, signature: flipCardSig(l2.signature) };
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    c.rotationChain = [l1, corrupted];
    return attach(c, "kB", B.priv);
  })();
  const chainTooLong = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    c.rotationChain = Array.from({ length: 33 }, (_, i) => ({ keySetVersion: i + 1, signing: [linkEntry(`k${i}`, G, "active")], prevKeyId: "g", signature: "A".repeat(86) }));
    return attach(c, "g1", G.priv);
  })();
  const linkDuplicateKeyId = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active"), linkEntry("kA", B, "active")], prevKeyId: "g" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kA", A.priv);
  })();

  // ── proof rejects ──
  const retiredSigner = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "retired")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "g1", G.priv);
  })();
  const revokedSigner = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "revoked")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "g1", G.priv);
  })();
  const signerNotCurrent = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active"), signingEntry("g2", H, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "g2", H.priv); // signed by the non-current active key
  })();
  const signerAbsent = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "nope", G.priv);
  })();
  const missingCurrent = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.keySetVersion = 1; // no currentSigningKeyId
    return attach(c, "g1", G.priv);
  })();
  const missingKsv = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1"; // no keySetVersion
    return attach(c, "g1", G.priv);
  })();
  // Link 1 signed by the key the CARD FIELD carries (A), while the agentId
  // embeds G. A verifier that roots the chain in the mutable
  // card.publicKeyMultibase accepts this; rooting in the agentId, which no card
  // edit can move, rejects it. Until this case, every vector carried the same
  // key in both places, so the two roots were indistinguishable.
  const cardFieldRootedChain = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kB", B, "active")], prevKeyId: "g" }, A.priv);
    const c = acsBaseCard(keyDerivedId, A.mb);
    c.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "kB", B.priv);
  })();

  const genesisMismatch = await (async () => {
    // No chain, signed by A, which is not byte-equal to the genesis key G.
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    c.currentSigningKeyId = "kA";
    c.keySetVersion = 1;
    return attach(c, "kA", A.priv);
  })();
  const cardDuplicateKeyId = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active"), signingEntry("g1", H, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "g1", G.priv);
  })();
  const invalidKeyEncoding = (() => {
    // An X25519 (0xec01) multibase where an Ed25519 (0xed01) key is required.
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [{ keyId: "g1", algorithm: "Ed25519", publicKeyMultibase: encodeEncryptionKeyMultibase(G.pub), status: "active", validFrom: ACS_VALID_FROM }], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return { ...c, cardSignature: { keyId: "g1", signature: "A".repeat(86) } };
  })();

  // ── proof rejects that tamper with the signed bytes ──
  const wrongDomain = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return c;
  })();
  // Sign over the body domain `tulpa/sign\n` instead of `ink/agent-card\n`.
  const wrongDomainSig = base64urlEncode(await ed.signAsync(enc.encode("tulpa/sign\n" + jcsCanonicalize(wrongDomain)), G.priv));
  const wrongDomainSigned = { ...wrongDomain, cardSignature: { keyId: "g1", signature: wrongDomainSig } };
  const versionsMutated = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    c.supportedProtocolVersions = ["ink/0.1", "ink/0.2"];
    const signed = await attach(c, "g1", G.priv);
    signed.supportedProtocolVersions = ["ink/0.1"]; // strip an entry after signing
    return signed;
  })();
  const keySubstituted = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    const signed = await attach(c, "g1", G.priv);
    signed.keys.signing[0].publicKeyMultibase = H.mb; // swap key material after signing
    return signed;
  })();

  // ── legacy single-key card (§3.3) ──
  const legacyAccept = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb); // no keys.signing set
    c.keySetVersion = 1;
    return attach(c, "bootstrap", G.priv);
  })();
  const legacyMismatch = await (async () => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keySetVersion = 1;
    return attach(c, "g1", G.priv); // keyId is not the literal `bootstrap`
  })();

  // ── unrooted principal (§4): a did:key card is neither key-derived nor did:web ──
  const unrootedId = `did:key:${G.mb}`;
  const unrootedSigned = await (async () => {
    const c = acsBaseCard(unrootedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return attach(c, "g1", G.priv);
  })();

  // ── did:web anchoring (§4.2) ──
  const didCard = (() => {
    const c = acsBaseCard(DIDWEB, D.mb);
    c.keys = { signing: [signingEntry("d1", D, "active")], encryption: [] };
    c.currentSigningKeyId = "d1";
    c.keySetVersion = 1;
    return c;
  })();
  const didSigned = await attach(didCard, "d1", D.priv);
  const didCached = (() => {
    const c = acsBaseCard(DIDWEB, D.mb);
    c.keys = { signing: [signingEntry("d1", D, "active")], encryption: [] };
    c.currentSigningKeyId = "d1";
    c.keySetVersion = 1;
    return c;
  })();
  const didChainSigned = await (async () => {
    // Link 1 re-rooted on the DID-document key D (§4.2); rotates to kB, also a
    // DID-document verification method so it anchors the card.
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "did-root" }, D.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kA", A, "retired"), linkEntry("kB", B, "active")], prevKeyId: "kA" }, A.priv);
    const c = acsBaseCard(DIDWEB, D.mb);
    c.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    c.rotationChain = [l1, l2];
    return attach(c, "kB", B.priv);
  })();

  // ── unsigned ratchet (§7) and profile-keyed first-contact (§8) ──
  const unsignedKeyDerived = acsBaseCard(keyDerivedId, G.mb);
  const unsignedDidweb = acsBaseCard(DIDWEB, D.mb);
  const ratchetCached = (() => {
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    return c;
  })();

  // ── schema-invalid: keys.signing is not an array. The verifier assumes schema
  // step 1 ran, so it must fail closed rather than crash or diverge on a
  // structurally invalid card. Both implementations reject (the reason differs
  // by internal path, so only the decision is pinned). ──
  const nonArraySigning = { ...acsBaseCard(keyDerivedId, G.mb), keys: { signing: { bad: true }, encryption: [] }, currentSigningKeyId: "g1", keySetVersion: 1, cardSignature: { keyId: "g1", signature: "A".repeat(86) } };

  // ── base64url non-canonical trailing bit. The final base64url character of an
  // 86-char Ed25519 signature carries 4 padding bits that MUST be zero for a
  // canonical encoding. Both implementations decode the low bits leniently, so a
  // padding-bit flip decodes to the identical 64-byte signature and still
  // verifies. The vector pins that the two implementations agree (accept), so a
  // future strict decoder on one side surfaces as a divergence here. ──
  const nonCanonSigned = (() => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const sig = noChainSigned.cardSignature.signature;
    const last = sig[85];
    const flipped = alphabet[alphabet.indexOf(last) ^ 1]; // flip one padding bit
    return { ...noChainSigned, cardSignature: { keyId: "g1", signature: sig.slice(0, 85) + flipped } };
  })();

  // ── unknown link members (§4.1 preimage). The link preimage is JCS of the
  // WHOLE link minus `signature`, nothing else stripped, so a member the
  // verifier does not recognise is still covered. `algorithm` is the member
  // §4.1 reserves for a later additive minor, so it is the honest shape to pin.
  // A verifier that rebuilt the preimage from {keySetVersion, signing,
  // prevKeyId} instead would REJECT the accept cases (it would reconstruct
  // fewer bytes than the signer signed) and ACCEPT the mutated cases (the
  // mutated member would sit outside its reconstruction). Both directions are
  // pinned so neither reconstruction can pass this category. ──
  const unknownMemberLink1Accept = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("g1", G, "active")], prevKeyId: "g", algorithm: "Ed25519" }, G.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    c.currentSigningKeyId = "g1";
    c.keySetVersion = 1;
    c.rotationChain = [l1];
    return attach(c, "g1", G.priv);
  })();
  // The mutation is re-signed at the CARD level, so the card proof still
  // verifies and the decision lands on the chain step the case is about. Without
  // the re-attach every mutated-link case would reject as `invalid_signature`
  // (the card signature covers rotationChain) and would pin nothing about the
  // link preimage.
  const unknownMemberLink1Mutated = await (async () => {
    const c = JSON.parse(JSON.stringify(unknownMemberLink1Accept));
    c.rotationChain[0].algorithm = "Ed448"; // mutate the unknown member post-signing
    return attach(c, "g1", G.priv);
  })();
  const unknownMemberLink2Accept = await (async () => {
    const l1 = await mkLink({ keySetVersion: 1, signing: [linkEntry("kA", A, "active")], prevKeyId: "g" }, G.priv);
    const l2 = await mkLink({ keySetVersion: 2, signing: [linkEntry("kA", A, "retired"), linkEntry("kB", B, "active")], prevKeyId: "kA", algorithm: "Ed25519" }, A.priv);
    const c = acsBaseCard(keyDerivedId, G.mb);
    c.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    c.currentSigningKeyId = "kB";
    c.keySetVersion = 2;
    c.rotationChain = [l1, l2];
    return attach(c, "kB", B.priv);
  })();
  const unknownMemberLink2Mutated = await (async () => {
    const c = JSON.parse(JSON.stringify(unknownMemberLink2Accept));
    c.rotationChain[1].algorithm = "Ed448"; // mutate the unknown member post-signing
    return attach(c, "kB", B.priv);
  })();

  vectorFile("agent-card-signature", [
    // ── accepts ──
    acsAccept("signed-key-derived-no-chain-accept", "A key-derived card signed by an active key byte-equal to the embedded genesis key, no rotationChain.", { card: noChainSigned, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("byte-exact-signature-pin-accept", "A fixed card, key and 86-character signature triple pinning the exact ink/agent-card signed bytes so two implementations agree byte for byte.", { card: noChainSigned, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("non-ascii-member-order-accept", "A signed card carrying extension members named U+FF21 and U+1F511 verifies only if the card signature is computed over members sorted by UTF-16 code unit, which puts the astral name first. A canonicalizer that sorts by code point or by UTF-8 byte builds different signed bytes and rejects an authentic card.", { card: noChainOrderingSigned, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("rotated-signer-valid-chain-accept", "A rotated signer whose genesis-to-head chain verifies, versions strictly increasing and contiguous, head set corresponding exactly to keys.signing.", { card: chainCardSigned, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("multi-hop-double-rotation-warm-accept", "An agent that rotated twice between two warm fetches: reachability holds through an interior link that committed the cached key.", { card: twoHopSigned, agentId: keyDerivedId, options: { profile: "1.0", cachedCard: twoHopCached } }, { reason: "signed_authenticated" }),
    acsOptional(
      acsAccept("chain-extension-fork-cold-accept", "A COLD verifier accepts a forged chain-extension signed by a leaked historical key: with no cached state, the leaked key is active in the prior genuine link, so the forged head binds cleanly. This is the documented cold residual.", { card: forkSigned, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
      {
        id: "cold-chain-extension-residual",
        alternative: "reject",
        spec: "specs/ink-agent-card-signature.md §6",
        rationale: "§6 records cold acceptance of a forged chain-extension as an inherent RESIDUAL of an unwitnessed hash chain, not as a requirement to accept, and RECOMMENDS external head observation to close it. An implementation that applies a stricter cold policy, refusing a chain head it cannot corroborate, is conformant and rejects here.",
      },
    ),
    acsAccept("legacy-bootstrap-accept", "A legacy single-key card with no keys.signing, cardSignature.keyId the literal bootstrap, verifying against the top-level publicKeyMultibase (the genesis key).", { card: legacyAccept, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("didweb-anchor-present-accept", "A did:web card whose cardSignature key is a verification method in the resolved DID document.", { card: didSigned, agentId: DIDWEB, options: { profile: "1.0", didVerificationKeys: { status: "resolved", verificationKeys: [D.mb] } } }, { reason: "signed_authenticated" }),
    acsAccept("didweb-with-chain-accept", "A did:web card carrying a rotationChain whose link 1 is re-rooted on a DID-document key and whose head anchors the card.", { card: didChainSigned, agentId: DIDWEB, options: { profile: "1.0", didVerificationKeys: { status: "resolved", verificationKeys: [D.mb, B.mb] } } }, { reason: "signed_authenticated" }),
    acsOptional(
      acsAccept("didweb-resolver-unavailable-warm-continuity-accept", "A WARM did:web verifier at 1.0 continues under signature-plus-continuity when the resolver is unavailable, emitting card.anchor_unverified (the MAY branch of §4.2).", { card: didSigned, agentId: DIDWEB, options: { profile: "1.0", cachedCard: didCached, didVerificationKeys: { status: "unavailable" } } }, { reason: "signed_authenticated", auditEvent: "card.anchor_unverified" }),
      {
        id: "didweb-warm-resolver-unavailable",
        alternative: "reject",
        spec: "specs/ink-agent-card-signature.md §4.2",
        rationale: "§4.2 says a WARM verifier MAY continue under signature-plus-continuity when the DID resolver is unreachable. A verifier that instead fails closed, as a cold verifier MUST, is equally conformant and rejects here.",
      },
    ),
    acsAccept("unsigned-first-contact-pre-1-0-accept", "An unsigned first-contact card from a non-key-derived principal, pre-1.0 profile, no cached card.", { card: unsignedDidweb, agentId: DIDWEB, options: { profile: "pre-1.0" } }, { reason: "unsigned_first_contact_accepted" }),
    acsAccept("chain-link-1-unknown-member-accept", "A rotation link carrying an unrecognised member (the reserved `algorithm`) verifies when the signature covers the WHOLE link minus `signature`, which is what makes that extension point additive. Link 1, so the root-candidate branch is the one exercised.", { card: unknownMemberLink1Accept, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("chain-link-unknown-member-accept", "The same full-link coverage on a later link, whose signer is resolved from the prior link's committed set rather than from a root candidate.", { card: unknownMemberLink2Accept, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "signed_authenticated" }),
    acsAccept("base64url-noncanonical-trailing-bit-accept", "A signature whose final base64url character carries a non-canonical padding bit decodes to the identical 64-byte signature in both implementations and still verifies.", { card: nonCanonSigned, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signed_authenticated" }),

    // ── continuity and ratchet rejects ──
    acsReject("chain-extension-fork-warm-reject", "A WARM verifier rejects the forged chain-extension: the forged head branches from a key that is revoked in the cached non-revoked set.", { card: forkSigned, agentId: keyDerivedId, options: { profile: "1.0", cachedCard: forkCached } }, { reason: "continuity_unreachable_key", auditEvent: "card.continuity_violation" }),
    acsReject("committed-set-stuffing-warm-reject", "A WARM verifier rejects a forged link that STUFFS the genuine current key into its committed set: continuity bridges only through verified signers, not committed-set membership.", { card: stuffSigned, agentId: keyDerivedId, options: { profile: "1.0", cachedCard: forkCached } }, { reason: "continuity_unreachable_key", auditEvent: "card.continuity_violation" }),
    acsReject("keyset-version-regression-reject", "A fetched card whose keySetVersion is lower than the cached authenticated card's is rejected and the cached card retained.", { card: noChainSigned, agentId: keyDerivedId, options: { profile: "1.0", cachedCard: regressionCached } }, { reason: "continuity_version_regression", auditEvent: "card.continuity_violation" }),
    acsReject("unsigned-after-authenticated-reject", "Once a valid authenticated card has been observed, a subsequent unsigned card for the same principal is rejected (the signature-stripping ratchet).", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "pre-1.0", cachedCard: ratchetCached } }, { reason: "unsigned_after_authenticated" }),
    acsReject("unsigned-first-contact-1-0-reject", "An unsigned first-contact card from a non-key-derived principal is rejected outright under the 1.0 profile.", { card: unsignedDidweb, agentId: DIDWEB, options: { profile: "1.0" } }, { reason: "unsigned_1_0_profile" }),
    acsReject("unsigned-key-derived-1-0-reject", "An unsigned card for a key-derived principal is rejected under 1.0 even on first contact, since the identifier intrinsically carries signing authority.", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "unsigned_key_derived_1_0" }),

    // ── head-binding rejects ──
    acsReject("head-version-mismatch-reject", "A valid chain whose head link commits a keySetVersion different from the card's top-level keySetVersion.", { card: headVersionMismatch, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "head_version_mismatch" }),
    acsReject("head-set-correspondence-mismatch-reject", "A valid chain whose head set does not correspond exactly to keys.signing (the card carries an extra entry the head omits).", { card: headSetMismatch, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "head_set_mismatch" }),
    acsReject("head-set-status-disagreement-reject", "A valid chain whose head commits a key as active while the card carries it as retired, so the exact head correspondence fails on status.", { card: headStatusMismatch, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "head_set_mismatch" }),
    acsReject("head-set-missing-signer-reject", "A valid chain whose head set does not contain the cardSignature signer: the card carries the active current signer plus a genesis-committed key, so the head omits the very key that signed the card and exact correspondence fails.", { card: headSetMissingSigner, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "head_set_mismatch" }),
    acsReject("head-set-pubkey-disagreement-reject", "A valid chain whose head commits a keyId bound to one public key while the card carries the same keyId and status bound to a different public key, so exact head correspondence fails on the decoded-key byte comparison rather than on an extra entry or a status difference.", { card: headPubkeyDisagreement, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "head_set_mismatch" }),

    // ── chain-shape rejects ──
    acsReject("chain-noncontiguous-version-reject", "A chain whose consecutive link versions have a gap (1 then 3).", { card: noncontiguous, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_noncontiguous_version" }),
    acsReject("chain-link-signer-not-active-reject", "A chain whose later link names a prevKeyId that is retired in the prior link's committed set.", { card: linkSignerNotActive, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_link_signer_not_active" }),
    acsReject("chain-link-invalid-signature-reject", "A chain whose later link carries a corrupted signature that no longer verifies against its prevKeyId signer, even though that signer is active in the prior link's committed set.", { card: chainLinkInvalidSig, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_link_invalid_signature" }),
    acsReject("chain-link-1-unknown-member-mutated-reject", "An unrecognised member of link 1 mutated after signing. Full-link coverage means the mutation breaks the signature, so link 1 roots to no candidate (the key-derived link-1 failure reason).", { card: unknownMemberLink1Mutated, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_link_invalid_signature" }),
    acsReject("chain-link-unknown-member-mutated-reject", "An unrecognised member of a later link mutated after signing. A verifier that rebuilt the preimage from the three named members would accept this forgery.", { card: unknownMemberLink2Mutated, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_link_invalid_signature" }),
    acsReject("chain-too-long-reject", "A rotationChain longer than the 32-link cap.", { card: chainTooLong, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_too_long" }),
    acsReject("chain-duplicate-key-id-reject", "A rotation link whose committed signing set repeats a keyId.", { card: linkDuplicateKeyId, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_duplicate_key_id" }),

    // ── proof rejects ──
    acsReject("retired-signer-reject", "cardSignature.keyId names an entry with status retired.", { card: retiredSigner, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signer_not_active" }),
    acsReject("revoked-signer-reject", "cardSignature.keyId names an entry with status revoked.", { card: revokedSigner, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signer_not_active" }),
    acsReject("signer-not-current-reject", "A signed key-set card whose cardSignature.keyId names an active entry that is not currentSigningKeyId.", { card: signerNotCurrent, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signer_not_current" }),
    acsReject("signer-absent-from-signing-reject", "cardSignature.keyId names no entry in the card's own signing set.", { card: signerAbsent, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "signer_absent_from_signing" }),
    acsReject("missing-current-signing-key-id-reject", "A signed key-set card with no currentSigningKeyId.", { card: missingCurrent, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "missing_current_signing_key_id" }),
    acsReject("missing-key-set-version-reject", "A signed card that omits keySetVersion, the sole monotonic quantity the continuity rules compare.", { card: missingKsv, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "missing_key_set_version" }),
    acsReject("card-field-rooted-chain-reject", "A one-link chain signed by the key in card.publicKeyMultibase, which differs from the key inside the agentId. The identity root is the agentId; a verifier rooting link 1 in the mutable card field accepts a chain the identity's holder never signed.", { card: cardFieldRootedChain, agentId: keyDerivedId, options: { profile: "1.0" } }, { reason: "chain_link_invalid_signature" }),
    acsReject("genesis-key-mismatch-reject", "A no-chain key-derived card whose signing key is not byte-equal to the embedded genesis key.", { card: genesisMismatch, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "genesis_key_mismatch" }),
    acsReject("card-duplicate-key-id-reject", "The card's own keys.signing set repeats a keyId, making signer resolution ambiguous.", { card: cardDuplicateKeyId, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "duplicate_key_id" }),
    acsReject("invalid-key-encoding-reject", "The signer entry's publicKeyMultibase is an X25519 (0xec01) key where an Ed25519 (0xed01) key is required.", { card: invalidKeyEncoding, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "invalid_key_encoding" }),
    acsReject("wrong-domain-signature-reject", "A signature computed over tulpa/sign rather than ink/agent-card; never demoted to unsigned.", { card: wrongDomainSigned, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "invalid_signature" }),
    acsReject("supported-protocol-versions-mutated-reject", "A supportedProtocolVersions entry stripped after signing so the signature no longer verifies.", { card: versionsMutated, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "invalid_signature" }),
    acsReject("active-key-substituted-reject", "The active signing key's public material swapped after signing.", { card: keySubstituted, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "invalid_signature" }),
    acsReject("legacy-bootstrap-mismatch-reject", "A legacy single-key card whose cardSignature.keyId is not the literal bootstrap.", { card: legacyMismatch, agentId: keyDerivedId, options: { profile: "pre-1.0" } }, { reason: "legacy_bootstrap_mismatch" }),

    // ── rooting rejects ──
    acsReject("unrooted-principal-reject", "A did:key card self-signed by a key in its own keys.signing: §4 defines no trust root for it, so it is rejected rather than accepted with no anchor or demoted to unsigned.", { card: unrootedSigned, agentId: unrootedId, options: { profile: "pre-1.0" } }, { reason: "unrooted_principal" }),
    acsReject("didweb-anchor-absent-reject", "A did:web card whose cardSignature key is not a verification method in the resolved DID document.", { card: didSigned, agentId: DIDWEB, options: { profile: "1.0", didVerificationKeys: { status: "resolved", verificationKeys: [OTHER.mb] } } }, { reason: "didweb_signer_not_anchored" }),
    acsReject("didweb-resolver-unavailable-cold-1-0-reject", "A COLD did:web verifier at 1.0 fails closed when the DID document is unreachable.", { card: didSigned, agentId: DIDWEB, options: { profile: "1.0", didVerificationKeys: { status: "unavailable" } } }, { reason: "didweb_resolver_unavailable" }),

    // ── structural reject ──
    acsReject("schema-invalid-non-array-signing-reject", "A card whose keys.signing is not an array fails closed rather than crashing or diverging; the verifier assumes schema validation already ran.", { card: nonArraySigning, agentId: keyDerivedId, options: { profile: "pre-1.0" } }),
  ]);

  // ── agent-card-signature-phase-c (STAGED) ──────────────────────────────────
  // The Phase C receiver rule of §10, pinned before it is required. This
  // category carries `profile: "staged"` in the manifest: it is anchored and
  // agreed now, and it becomes a `base` obligation at the scheduled flip, so the
  // flip retags one category rather than negotiating a fresh contract.
  //
  // Every case sets `options.enforcePhaseC` EXPLICITLY. The flag is a boolean,
  // not a version string, and it OVERRIDES `profile` in both directions: a
  // `pre-1.0` profile with the flag ON enforces Phase C, and a `1.0` profile
  // with the flag OFF does not. That is what makes the category a real test of
  // the flag rather than a restatement of the profile-keyed cases already in the
  // base `agent-card-signature` category. A verifier that ignores the flag
  // reaches the wrong decision on every flag-on reject and on the flag-off
  // override, so it cannot pass this category by accident.
  const inkAliasId = `ink:${G.mb}`;
  const unsignedInkAlias = acsBaseCard(inkAliasId, G.mb);

  vectorFile("agent-card-signature-phase-c", [
    // ── flag ON: the Phase C rejections ──
    acsReject("phase-c-on-unsigned-key-derived-reject", "With enforcePhaseC on, an unsigned first-contact card for a tulpa: key-derived principal is rejected, even though the profile input is pre-1.0.", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "pre-1.0", enforcePhaseC: true } }, { reason: "unsigned_key_derived_1_0" }),
    acsReject("phase-c-on-unsigned-ink-alias-reject", "The same rejection holds for the ink: spelling of a key-derived principal, since both prefixes embed the genesis key.", { card: unsignedInkAlias, agentId: inkAliasId, options: { profile: "pre-1.0", enforcePhaseC: true } }, { reason: "unsigned_key_derived_1_0" }),
    acsReject("phase-c-on-unsigned-didweb-reject", "With enforcePhaseC on, an unsigned first-contact did:web card is rejected outright under the 1.0 profile rule.", { card: unsignedDidweb, agentId: DIDWEB, options: { profile: "pre-1.0", enforcePhaseC: true } }, { reason: "unsigned_1_0_profile" }),
    acsReject("phase-c-on-didweb-resolver-unavailable-cold-reject", "With enforcePhaseC on, a COLD did:web verifier fails closed when the DID document is unreachable, the second Phase C decision point.", { card: didSigned, agentId: DIDWEB, options: { profile: "pre-1.0", enforcePhaseC: true, didVerificationKeys: { status: "unavailable" } } }, { reason: "didweb_resolver_unavailable" }),
    acsReject("phase-c-on-unsigned-after-authenticated-reject", "The ratchet still precedes the Phase C rule: a warm verifier rejects an unsigned card as unsigned_after_authenticated rather than as a Phase C first-contact reject.", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "pre-1.0", enforcePhaseC: true, cachedCard: ratchetCached } }, { reason: "unsigned_after_authenticated" }),

    // ── flag ON: everything that was already accepted stays accepted ──
    acsAccept("phase-c-on-signed-key-derived-accept", "Phase C rejects unsigned cards only: a signed key-derived card rooted on its genesis key still authenticates with the flag on.", { card: noChainSigned, agentId: keyDerivedId, options: { profile: "pre-1.0", enforcePhaseC: true } }, { reason: "signed_authenticated" }),
    acsAccept("phase-c-on-legacy-bootstrap-accept", "A legacy single-key card signed under the literal bootstrap keyId is signed, not unsigned, so Phase C leaves it accepted.", { card: legacyAccept, agentId: keyDerivedId, options: { profile: "pre-1.0", enforcePhaseC: true } }, { reason: "signed_authenticated" }),
    acsAccept("phase-c-on-didweb-resolver-unavailable-warm-accept", "A WARM did:web verifier with the flag on still continues under signature-plus-continuity and emits card.anchor_unverified; only the cold path fails closed.", { card: didSigned, agentId: DIDWEB, options: { profile: "pre-1.0", enforcePhaseC: true, cachedCard: didCached, didVerificationKeys: { status: "unavailable" } } }, { reason: "signed_authenticated", auditEvent: "card.anchor_unverified" }),

    // ── flag OFF: the pre-Phase-C decision stands, and the flag wins over the profile ──
    acsAccept("phase-c-off-unsigned-key-derived-accept", "With enforcePhaseC explicitly off, an unsigned first-contact key-derived card is accepted exactly as it is today.", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "pre-1.0", enforcePhaseC: false } }, { reason: "unsigned_first_contact_accepted" }),
    acsAccept("phase-c-off-overrides-1-0-profile-accept", "The flag is authoritative in both directions: enforcePhaseC off suppresses the Phase C rule even when the profile input says 1.0, so the decision is never inferred from a version string.", { card: unsignedKeyDerived, agentId: keyDerivedId, options: { profile: "1.0", enforcePhaseC: false } }, { reason: "unsigned_first_contact_accepted" }),
  ]);
}

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

/**
 * Seal an INK ECIES envelope WITHOUT the inner/outer binding encryptInkPayload
 * enforces at seal time, so the corpus can carry an envelope a conformant
 * decrypter MUST reject. Every other step (ECDH, HKDF, the AAD member set and
 * its JCS ordering, the AES-GCM layout and the outer envelope shape) is the
 * reference construction, so for a fixed ephemeral key and AES nonce the output
 * is byte-identical to what encryptInkPayload would have produced.
 */
async function sealUnbound(plaintext, senderDid, recipientPubHex, timestamp, messageNonce, opts) {
  const messageType = opts.messageType ?? "network.tulpa.encrypted";
  const recipientPub = hexToBytes(recipientPubHex);
  const ephPub = x25519.getPublicKey(opts.ephemeralPrivateKey);
  const shared = x25519.getSharedSecret(opts.ephemeralPrivateKey, recipientPub);
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("ink/0.1"), info: enc.encode("ink/0.1/encrypt") },
    hkdfKey, 256,
  );
  const aesKey = await crypto.subtle.importKey("raw", new Uint8Array(bits), "AES-GCM", false, ["encrypt"]);
  const aad = enc.encode(`ink/0.1:envelope\n${jcsCanonicalize({
    protocol: "ink/0.1",
    type: messageType,
    from: senderDid,
    recipientKey: base64urlEncode(recipientPub),
    ephemeralKey: base64urlEncode(ephPub),
    nonce: base64urlEncode(opts.aesNonce),
    timestamp,
    messageNonce,
  })}`);
  const ciphertextWithTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: opts.aesNonce, additionalData: aad },
    aesKey,
    enc.encode(JSON.stringify(plaintext)),
  ));
  return {
    protocol: "ink/0.1",
    type: messageType,
    from: senderDid,
    ephemeralKey: base64urlEncode(ephPub),
    nonce: base64urlEncode(opts.aesNonce),
    ciphertext: base64urlEncode(ciphertextWithTag),
    timestamp,
    messageNonce,
  };
}

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
  //
  // encryptInkPayload will not mint this: the seal path enforces the same inner
  // binding its decrypter requires, so a producer cannot emit an envelope no
  // conformant decrypter opens. The corpus still needs the artifact, so it is
  // built here by a deliberately non-conformant sealer, the same way every other
  // reject case in this category is a deliberate tamper rather than library
  // output. sealUnbound reproduces the reference seal byte for byte for a given
  // ephemeral key and AES nonce; the only rule it drops is the binding check.
  const innerMismatchPlain = { protocol: "ink/0.1", from: "did:web:other.example.com", to: recipientDid, intent: "ping" };
  const innerMismatchEnv = await sealUnbound(innerMismatchPlain, sender, recipientPubHex, ts, msgNonce, opts);

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
      description:
        "The decrypted inner `from` must equal the outer envelope `from`. The recipient DID is supplied and the inner `to` matches it, so the inner/outer `from` consistency check is the ONLY rule this case exercises; without the DID it would reject for the missing binding instead and never isolate this rule.",
      input: { envelope: innerMismatchEnv, recipientPrivateKeyHex: recipientPrivHex, recipientDid },
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
  const buildCard = (versions, endpoint = "https://receiver.example/ink/v1/intents") => {
    const card = {
      protocol: "ink/0.1",
      agentId: receiverDid,
      handle: "receiver",
      displayName: "Receiver Agent",
      endpoint,
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

  const signEnvelope = async (envelope, recipientDid, timestamp, seed, path = "/ink/v1/intents") => {
    const signInput = { method: "POST", path, recipientDid, body: envelope, timestamp };
    return { signInput, signature: await signInkMessage(signInput, seed) };
  };

  // Both envelopes are COMPLETE §3.1 intent envelopes. `id`, `correlationId`,
  // `createdAt` and `signature` are MUSTs there, so a receiver that validates the
  // envelope before verifying anything else is conforming, and a transcript built
  // from a shortened envelope would make that receiver fail a base category for
  // being correct. `signature` is attached by buildTranscript, after any
  // structural mutation, as the §3.6 body signature over the envelope minus that
  // member; the §3.3 transport base then covers the whole envelope including it.
  const requestEnvelope = (protocol, envOverrides = {}) => ({
    protocol,
    id: "firstcontact-req-0000000000000001",
    correlationId: "firstcontact-corr-000000000000001",
    createdAt: reqTs,
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
    id: "firstcontact-resp-000000000000001",
    correlationId: "firstcontact-corr-000000000000001",
    createdAt: respTs,
    from: receiverDid,
    to: senderDid,
    intent: "connection_response",
    payload: { status: "accepted", note: "Glad to connect." },
    nonce: "firstcontactrespnonce0000001",
    timestamp: respTs,
    ...envOverrides,
  });

  // Drop a member from an envelope before it is signed, so the resulting
  // transcript fails ONLY the §3.1 structure step: the body signature and the
  // transport signature both verify over the shortened envelope.
  const without = (key) => (env) => {
    const { [key]: _omit, ...rest } = env;
    return rest;
  };

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
    // The receiver's advertised inbound URL and the path the sender actually
    // signs. INK reserves no fixed inbound path (Protocol §3.3), so the card is
    // the only thing binding the two sides to one spelling; a case that moves
    // one without the other must reject.
    cardEndpoint = "https://receiver.example/ink/v1/intents",
    reqPath = new URL(cardEndpoint).pathname,
    senderKeyHex = senderPubHex,
    receiverKeyHex = receiverPubHex,
    tamperReqSig = (s) => s,
    tamperRespSig = (s) => s,
    // Structural mutations run BEFORE the body signature is attached, so a case
    // that violates §3.1 still carries a body signature that verifies over the
    // envelope as delivered and is decided by the structure step alone.
    reqEnvMutate = (e) => e,
    respEnvMutate = (e) => e,
    // The key each body signature is made with. A transcript that signs the body
    // with the wrong key still carries a valid transport signature, so only the
    // §3.6 check separates them.
    reqBodySeed = senderSeed,
    respBodySeed = receiverSeed,
  } = {}) => {
    const rqUnsigned = reqEnvMutate(reqEnv ?? requestEnvelope(selected));
    const rsUnsigned = respEnvMutate(respEnv ?? responseEnvelope(selected));
    const rq = { ...rqUnsigned, signature: await signMessage(rqUnsigned, reqBodySeed) };
    const rs = { ...rsUnsigned, signature: await signMessage(rsUnsigned, respBodySeed) };
    const card = buildCard(omitVersions ? undefined : advertised, cardEndpoint);
    const req = await signEnvelope(rq, receiverDid, reqSignInputTs ?? rq.timestamp, senderSeed, reqPath);
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
    {
      caseId: "alternate-card-endpoint-path-accepts",
      description: "A receiver that advertises a different inbound path accepts a request signed over that path. INK reserves no fixed inbound path: PATH is the path component of the card's endpoint, so an implementation that hardcodes one spelling rejects a conforming peer.",
      input: await buildTranscript({ cardEndpoint: "https://receiver.example/ink/v1/inbound" }),
      expect: acc("ink/0.1"),
    },
    {
      caseId: "request-path-not-card-endpoint-rejects",
      description: "A request whose signed path is not the path component of the fetched card's endpoint rejects, even though the signature over that path is itself valid. PATH is inside the frozen signature base, so a sender that signs a path from a document instead of from the card it just fetched cannot be verified by the receiver at its real endpoint.",
      input: await buildTranscript({ reqPath: "/ink/v1/intent" }),
      expect: rej,
    },
    {
      caseId: "request-envelope-missing-id-rejects",
      description: "A request envelope with no `id` rejects. §3.1 makes id, correlationId, createdAt and signature MUSTs, so a receiver validates the envelope before it verifies anything; here both signatures verify over the shortened envelope, so the structure step is the only thing that can reject it.",
      input: await buildTranscript({ reqEnvMutate: without("id") }),
      expect: rej,
    },
    {
      caseId: "response-envelope-missing-created-at-rejects",
      description: "The same §3.1 obligation on the response half: an envelope with no `createdAt` rejects even though the response is otherwise a correctly signed accepted connection_response.",
      input: await buildTranscript({ respEnvMutate: without("createdAt") }),
      expect: rej,
    },
    {
      caseId: "request-envelope-unknown-top-level-key-rejects",
      description: "The intent envelope is a strict surface (§3.1, compatibility-policy §3.1): an unknown top-level member rejects. The member is present before signing, so both signatures cover it and only the strict schema can reject.",
      input: await buildTranscript({ reqEnvMutate: (e) => ({ ...e, extension: "x" }) }),
      expect: rej,
    },
    {
      caseId: "request-body-signature-wrong-key-rejects",
      description: "A request envelope whose §3.6 body signature was made with the receiver's key rather than the sender's rejects. The transport signature is valid over the delivered body, so an implementation that verifies only the §3.3 transport signature and treats the envelope `signature` member as opaque accepts a body the named sender never signed.",
      input: await buildTranscript({ reqBodySeed: receiverSeed }),
      expect: rej,
    },
    {
      caseId: "response-body-signature-wrong-key-rejects",
      description: "The same on the response half: the receiver's envelope carries a body signature made with the sender's key, and the sender must reject it.",
      input: await buildTranscript({ respBodySeed: senderSeed }),
      expect: rej,
    },
  ]);
}

// ── discovery-query-envelope ────────────────────────────────────────────────
// An authenticated discovery query envelope (specs/ink-discovery-query.md). The
// requester signs a bounded query addressed to a directory; the directory
// verifies it against the requester's public key and its own verification
// context. Each vector carries the full envelope, the requester's public key
// hex and the context the directory supplies: its own identity (`audience`, a
// string or a list of the spellings it answers to), its clock (`now`) and the
// optional set of already-burned `(from, nonce)` pairs. A verifier accepts iff
// the envelope is structurally valid, the signature verifies, the signed `to`
// is this directory, the signed `timestamp` is inside the freshness window at
// `now` and the signed `nonce` has not been burned for this `from`.
{
  const dqDirectory = "did:web:directory.example";
  const base = {
    from: `tulpa:${mb}`,
    to: dqDirectory,
    nonce: "conformance-discovery-nonce-1",
    timestamp: "2026-07-09T00:00:00.000Z",
    query: { tags: ["go", "typescript"], scope: "public", limit: 10 },
  };
  const env = await buildDiscoveryQueryEnvelope(base, seed);
  const inkEnv = await buildDiscoveryQueryEnvelope({ ...base, type: "network.ink.discovery_query" }, seed);
  const minimalEnv = await buildDiscoveryQueryEnvelope({ ...base, query: {} }, seed);
  const otherPublicKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(9)));

  // A verifier clock offset from the signed timestamp, in milliseconds.
  const dqClock = (offsetMs) => new Date(Date.parse(base.timestamp) + offsetMs).toISOString();
  const dqNow = dqClock(1000);
  // The freshness window, mirroring MAX_DISCOVERY_QUERY_AGE_MS and
  // MAX_DISCOVERY_QUERY_SKEW_MS: five minutes past, thirty seconds future.
  const dqAgeMs = 5 * 60 * 1000;
  const dqSkewMs = 30 * 1000;
  const dqSeen = [{ from: base.from, nonce: base.nonce }];

  // Every case supplies the full context; a case that exercises one check
  // overrides just that part of it.
  const dqe = (caseId, description, input, result, reason) => ({
    caseId,
    description,
    input: { audience: dqDirectory, now: dqNow, ...input },
    expect: reason === undefined ? { result } : { result, reason },
  });

  // Raw-text cases. An envelope is a signed body, so the raw-body gate of
  // specs/ink-signed-string-safety.md applies to it, and every rule that gate
  // enforces is about bytes a parsed value has already lost. A case that needs
  // to express one carries `envelopeRaw`, the exact JSON text a sender put on
  // the wire, instead of `envelope`; a runner decodes it to bytes and verifies
  // those. The shadowed literal is the reason the field exists: JSON member
  // semantics are last-wins, so the out-of-range literal never reaches the
  // parsed object, the envelope canonicalizes to the signed bytes and its
  // signature verifies. A verifier that gates only the value accepts it and one
  // that gates the bytes refuses it, which is an accept-versus-reject split in a
  // signed path, choosable by whoever writes the bytes.
  const envText = JSON.stringify(env);
  const dqShadowedNumber = `{"protocol":1e309,${envText.slice(1)}`;
  const dqLiveNumber = envText.replace(`"limit":10`, `"limit":1e309`);
  const dqLoneSurrogate = envText.replace(`"nonce":"${base.nonce}"`, `"nonce":"\\ud800${base.nonce}"`);
  // The negative control for the same shape: an underflowing exponent is in
  // range (every IEEE-754 parser decodes it to 0), so a shadowed 1e-400 is not
  // gated and the envelope behind it still verifies.
  const dqShadowedUnderflow = `{"protocol":1e-400,${envText.slice(1)}`;
  // Whitespace between tokens is legal JSON and vanishes at canonicalization,
  // so this is the same signed envelope, byte-padded.
  const dqPadded = `{  ${envText.slice(1)}`;

  vectorFile("discovery-query-envelope", [
    dqe("valid-query-accepts", "A requester-signed query with tags, scope and limit verifies against the requester's key, this directory's identity and its clock.", { envelope: env, publicKeyHex }, "accept"),
    dqe("network-ink-spelling-accepts", "The vendor-neutral network.ink.discovery_query spelling is signed and verifies like the legacy spelling.", { envelope: inkEnv, publicKeyHex }, "accept"),
    dqe("empty-query-accepts", "An empty query object (no tags, scope, or limit) is a valid signed request.", { envelope: minimalEnv, publicKeyHex }, "accept"),
    dqe("tampered-to-rejects", "Changing the addressed directory after signing invalidates the signature, and the signature is checked before the audience.", { envelope: { ...env, to: "did:web:evil.example" }, publicKeyHex, audience: "did:web:evil.example" }, "reject", "signature"),
    dqe("relabeled-type-rejects", "Relabeling the wire type from network.tulpa to network.ink after signing invalidates the signature; the spelling is signed, not normalized.", { envelope: { ...env, type: "network.ink.discovery_query" }, publicKeyHex }, "reject", "signature"),
    dqe("tampered-tag-rejects", "Altering a query tag after signing invalidates the signature.", { envelope: { ...env, query: { ...env.query, tags: ["rust", "typescript"] } }, publicKeyHex }, "reject", "signature"),
    dqe("wrong-key-rejects", "Verifying against a different public key fails.", { envelope: env, publicKeyHex: otherPublicKeyHex }, "reject", "signature"),
    dqe("malformed-signature-rejects", "A signature that is not valid base64url of the right length is rejected.", { envelope: { ...env, signature: env.signature.slice(0, 85) + "+" }, publicKeyHex }, "reject", "schema"),
    dqe("unknown-top-level-key-rejects", "An unknown top-level field is rejected by the strict schema before verification.", { envelope: { ...env, extra: 1 }, publicKeyHex }, "reject", "schema"),
    dqe("unknown-query-key-rejects", "An unknown field inside the query object is rejected by the strict schema.", { envelope: { ...env, query: { ...env.query, rank: "best" } }, publicKeyHex }, "reject", "schema"),
    dqe("over-limit-tags-rejects", "A query with more than 32 tags is out of profile and rejects.", { envelope: { ...env, query: { ...env.query, tags: Array.from({ length: 33 }, (_, i) => `t${i}`) } }, publicKeyHex }, "reject", "schema"),
    dqe("limit-over-100-rejects", "A limit above 100 is out of profile and rejects.", { envelope: { ...env, query: { ...env.query, limit: 101 } }, publicKeyHex }, "reject", "schema"),
    dqe("invalid-timestamp-rejects", "A timestamp that is not a strict INK timestamp rejects.", { envelope: { ...env, timestamp: "2026-07-09 00:00" }, publicKeyHex }, "reject", "schema"),
    dqe("short-nonce-rejects", "A nonce shorter than 16 code units is out of profile and rejects.", { envelope: { ...env, nonce: "short" }, publicKeyHex }, "reject", "schema"),
    dqe("missing-signature-rejects", "An envelope with no signature field rejects.", { envelope: (() => { const { signature, ...rest } = env; return rest; })(), publicKeyHex }, "reject", "schema"),
    // Audience binding: the signed `to` is consumed, not just signed over.
    dqe("other-directory-rejects", "A validly signed query addressed to another directory rejects at this one: the signed `to` must be this directory's own identity.", { envelope: env, publicKeyHex, audience: "did:web:other.example" }, "reject", "audience"),
    dqe("audience-alias-accepts", "A directory that answers to several spellings of itself supplies all of them; the signed `to` matching any one accepts.", { envelope: env, publicKeyHex, audience: ["https://directory.example", "directory.example", dqDirectory] }, "accept"),
    dqe("audience-case-mismatch-rejects", "Audience comparison is exact: a case-folded spelling of the same directory does not match.", { envelope: env, publicKeyHex, audience: "DID:WEB:DIRECTORY.EXAMPLE" }, "reject", "audience"),
    dqe("empty-audience-rejects", "An empty audience set is a verifier input error and fails closed rather than admitting every audience.", { envelope: env, publicKeyHex, audience: [] }, "reject", "schema"),
    dqe("signature-before-audience-rejects", "With both the key and the audience wrong the verdict is the signature, so a rejection never reveals whether the audience would have matched.", { envelope: env, publicKeyHex: otherPublicKeyHex, audience: "did:web:other.example" }, "reject", "signature"),
    // Freshness: the signed timestamp is consumed at the verifier clock.
    dqe("stale-timestamp-rejects", "A query older than the five-minute freshness window rejects at the verifier clock.", { envelope: env, publicKeyHex, now: dqClock(dqAgeMs + 1) }, "reject", "expired"),
    dqe("age-bound-accepts", "The age bound is inclusive: a query exactly five minutes old still accepts.", { envelope: env, publicKeyHex, now: dqClock(dqAgeMs) }, "accept"),
    dqe("future-timestamp-rejects", "A query timestamped past the thirty-second skew allowance rejects.", { envelope: env, publicKeyHex, now: dqClock(-(dqSkewMs + 1)) }, "reject", "not_yet_valid"),
    dqe("skew-bound-accepts", "The skew bound is inclusive: a query exactly thirty seconds ahead of the verifier clock still accepts.", { envelope: env, publicKeyHex, now: dqClock(-dqSkewMs) }, "accept"),
    dqe("malformed-clock-rejects", "A verifier clock that is not a strict INK timestamp is an input error and fails closed as schema, not a window verdict.", { envelope: env, publicKeyHex, now: "2026-07-09 00:00" }, "reject", "schema"),
    // Replay: the signed nonce is consumed against the directory's burned set.
    dqe("replayed-nonce-rejects", "A (from, nonce) pair this directory already burned is a replay.", { envelope: env, publicKeyHex, seenNonces: dqSeen }, "reject", "replay"),
    dqe("other-requester-nonce-accepts", "Replay is keyed on the (from, nonce) pair, so an identical nonce burned for a different requester does not reject this one.", { envelope: env, publicKeyHex, seenNonces: [{ from: "tulpa:someone-else", nonce: base.nonce }] }, "accept"),
    dqe("stale-replay-reports-window", "Replay is checked after the window, so a stale replayed query reports the window rather than the replay.", { envelope: env, publicKeyHex, now: dqClock(dqAgeMs + 1), seenNonces: dqSeen }, "reject", "expired"),
    // Raw-body gate: cases carrying `envelopeRaw`, the exact wire text, because
    // the rule under test is about bytes the parsed value no longer carries.
    dqe("raw-envelope-accepts", "The same signed envelope presented as raw wire text verifies: whitespace between tokens is legal JSON and vanishes at canonicalization, so the signature still covers it.", { envelopeRaw: dqPadded, publicKeyHex }, "accept"),
    dqe("shadowed-number-literal-rejects", "An out-of-range number literal shadowed by a later duplicate member rejects. Member semantics are last-wins, so the literal never reaches the parsed envelope and the signature over the canonical form still verifies; only a gate on the raw text sees it, and without one two implementations admit different byte strings for the same signed envelope.", { envelopeRaw: dqShadowedNumber, publicKeyHex }, "reject", "schema"),
    dqe("live-number-literal-rejects", "An out-of-range number literal in a live member rejects at the raw gate, before the schema can rule on the Infinity a lenient parser would hand it.", { envelopeRaw: dqLiveNumber, publicKeyHex }, "reject", "schema"),
    dqe("shadowed-underflow-accepts", "An underflowing exponent is in range: every IEEE-754 parser decodes 1e-400 to 0, so a shadowed one is not gated and the envelope behind it verifies. The gate is a range test, not a ban on exponents.", { envelopeRaw: dqShadowedUnderflow, publicKeyHex }, "accept"),
    dqe("raw-lone-surrogate-escape-rejects", "A lone UTF-16 surrogate escape in the raw text rejects structurally, before the signature: a parser that rewrites it to U+FFFD would canonicalize something other than what was sent.", { envelopeRaw: dqLoneSurrogate, publicKeyHex }, "reject", "schema"),
  ]);
}

// ── authorization-grant ─────────────────────────────────────────────────────
// A scoped signed authorization grant, the "Sign in with INK" primitive
// (specs/ink-authorization-grant.md). An issuer signs a grant bound to one
// subject, one audience, one scope set, and a fixed validity window; a service
// verifies it against the issuer key and its own context. Each vector carries
// the full grant plus the verification context the service supplies: the issuer
// public key hex, the checking service's own audience, its clock (now), and the
// optional replay set, revocation list, and owner status. A verifier accepts iff
// verifyAuthorizationGrant returns ok. The context caps the fields two
// implementations must agree on: signature, audience, window, replay,
// revocation, and the owner-verification requirement.
{
  const grantBase = {
    issuer: `tulpa:${mb}`,
    subject: "did:web:subject.example",
    audience: "did:web:service.example",
    scope: ["profile:read", "messages:send"],
    grantId: "conformance-grant-000000001",
    issuedAt: "2026-07-11T12:00:00.000Z",
    expiresAt: "2026-07-11T12:05:00.000Z",
  };
  const nowInWindow = "2026-07-11T12:02:00.000Z";
  const grant = await buildAuthorizationGrant(grantBase, seed);
  const inkGrant = await buildAuthorizationGrant({ ...grantBase, type: "network.ink.authorization_grant" }, seed);
  const ownerGrant = await buildAuthorizationGrant({ ...grantBase, requireVerifiedOwner: true }, seed);
  const otherPublicKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(9)));
  // A backslash const keeps a literal lone-surrogate escape out of a JSON string
  // the generator would otherwise write as U+FFFD.
  const loneSurrogateSubject = "sub\uD800";
  // A window exactly one second past the ten-minute ceiling. It is signed with a
  // key the vector never verifies against, so the over-long window is the reason
  // it rejects, structurally, before the signature.
  const overCapExpiresAt = new Date(Date.parse(grantBase.issuedAt) + 10 * 60 * 1000 + 1000).toISOString();

  // The verification context every accept case shares: the checking service is
  // did:web:service.example and its clock sits inside the window.
  const ctx = { audience: "did:web:service.example", now: nowInWindow };
  const key = { issuer: grantBase.issuer, grantId: grantBase.grantId };

  const acc = (caseId, description, input) => ({ caseId, description, input, expect: { result: "accept" } });
  const rej = (caseId, description, input, reason) => ({ caseId, description, input, expect: { result: "reject", reason } });

  // Raw-text cases. A grant is a signed body, so the raw-body gate of
  // specs/ink-signed-string-safety.md applies to it, and every rule that gate
  // enforces is about bytes a parsed value has already lost. A case that needs to
  // express one carries `grantRaw`, the exact JSON text a presenter put on the
  // wire, instead of `grant`; a runner decodes it to bytes and verifies those. The
  // shadowed literal is the reason the field exists: JSON member semantics are
  // last-wins, so the out-of-range literal never reaches the parsed object, the
  // grant canonicalizes to the signed bytes and its signature verifies. A verifier
  // that gates only the value accepts it and one that gates the bytes refuses it,
  // which is an accept-versus-reject split in the "Sign in with INK" primitive,
  // choosable by whoever writes the bytes.
  const grantText = JSON.stringify(grant);
  const grShadowedNumber = `{"protocol":1e309,${grantText.slice(1)}`;
  const grLiveNumber = JSON.stringify(ownerGrant).replace(`"requireVerifiedOwner":true`, `"requireVerifiedOwner":1e309`);
  // The negative control for the same shape: an underflowing exponent is in range
  // (every IEEE-754 parser decodes it to 0), so a shadowed 1e-400 is not gated and
  // the grant behind it still verifies.
  const grShadowedUnderflow = `{"protocol":1e-400,${grantText.slice(1)}`;
  const grLoneSurrogate = grantText.replace(`"subject":"${grantBase.subject}"`, `"subject":"\\ud800${grantBase.subject}"`);
  // Whitespace between tokens is legal JSON and vanishes at canonicalization, so
  // this is the same signed grant, byte-padded.
  const grPadded = `{  ${grantText.slice(1)}`;

  vectorFile("authorization-grant", [
    acc("valid-grant-accepts", "A scoped grant verified against the issuer key, for the named audience, inside its window, verifies.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx }),
    acc("network-ink-spelling-accepts", "The vendor-neutral network.ink.authorization_grant spelling is signed and verifies like the legacy spelling.", { grant: inkGrant, issuerPublicKeyHex: publicKeyHex, ...ctx }),
    acc("issued-at-lower-bound-accepts", "A grant presented at exactly issuedAt is inside the window (inclusive lower bound).", { grant, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: grantBase.issuedAt }),
    acc("required-owner-verified-accepts", "A grant that requires a verified owner verifies when the service supplies a verified owner status.", { grant: ownerGrant, issuerPublicKeyHex: publicKeyHex, ...ctx, verifiedOwner: { status: "verified" } }),
    acc("owner-not-required-ignores-status-accepts", "A grant that does not require a verified owner verifies even when the service supplies an unverified owner status; the hook is consulted only when the grant asks for it.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, verifiedOwner: { status: "unverified" } }),
    acc("cross-issuer-same-grant-id-accepts", "A different issuer's seen and revoked entry for the same grantId string does not block this grant; replay and revocation key on the (issuer, grantId) pair.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, seenGrants: [{ issuer: "tulpa:other-issuer", grantId: grantBase.grantId }], revokedGrants: [{ issuer: "tulpa:other-issuer", grantId: grantBase.grantId }] }),
    rej("bad-signature-with-wrong-audience-rejects-signature", "A grant with a broadened scope (bad signature) presented to the wrong audience still rejects on the signature, pinning signature-first ordering ahead of the audience check.", { grant: { ...grant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, audience: "did:web:other-service.example", now: nowInWindow }, "signature"),
    rej("bad-signature-with-expired-rejects-signature", "A grant with a broadened scope presented after expiry still rejects on the signature, not on expiry.", { grant: { ...grant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: "2026-07-11T12:06:00.000Z" }, "signature"),
    rej("bad-signature-with-replay-rejects-signature", "A grant with a broadened scope whose (issuer, grantId) is already seen still rejects on the signature, not on replay.", { grant: { ...grant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, ...ctx, seenGrants: [key] }, "signature"),
    rej("bad-signature-with-revoked-rejects-signature", "A grant with a broadened scope whose (issuer, grantId) is revoked still rejects on the signature, not on revocation.", { grant: { ...grant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, ...ctx, revokedGrants: [key] }, "signature"),
    rej("bad-signature-with-owner-unverified-rejects-signature", "An owner-requiring grant with a broadened scope and an unverified owner still rejects on the signature, not on owner verification.", { grant: { ...ownerGrant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, ...ctx, verifiedOwner: { status: "unverified" } }, "signature"),
    rej("wrong-issuer-key-rejects", "Verifying against a different public key fails the signature check.", { grant, issuerPublicKeyHex: otherPublicKeyHex, ...ctx }, "signature"),
    rej("tampered-scope-rejects", "Broadening the scope after signing invalidates the signature.", { grant: { ...grant, scope: ["profile:read", "admin:all"] }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "signature"),
    rej("tampered-subject-rejects", "Changing the subject after signing invalidates the signature.", { grant: { ...grant, subject: "did:web:attacker.example" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "signature"),
    rej("confused-deputy-rejects", "A grant minted for did:web:service.example presented to a different service is rejected on the audience check even though the signature is valid.", { grant, issuerPublicKeyHex: publicKeyHex, audience: "did:web:other-service.example", now: nowInWindow }, "audience"),
    rej("relabeled-audience-rejects", "Relabeling the grant audience to match the checking service after signing does not help: the signature bound the original audience.", { grant: { ...grant, audience: "did:web:other-service.example" }, issuerPublicKeyHex: publicKeyHex, audience: "did:web:other-service.example", now: nowInWindow }, "signature"),
    acc("presenter-matches-subject-accepts", "A grant presented by the authenticated principal named as its subject verifies; the presentation binding holds.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, presenter: grantBase.subject }),
    acc("presenter-absent-accepts", "A grant with no presenter supplied is a bearer artifact inside its window; the binding check is skipped.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx }),
    acc("presenter-empty-accepts", "An empty-string presenter means no presenter was established, so the binding check is skipped just as when it is absent; Go cannot tell an unset field from an empty one, so an empty presenter is no presenter across implementations.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, presenter: "" }),
    rej("presenter-not-subject-rejects", "A grant presented by a principal other than its signed subject is rejected on the presentation binding, so a stolen grant is not presentable by another principal.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, presenter: "did:web:thief.example" }, "subject"),
    rej("expired-rejects", "A grant presented after expiresAt is rejected.", { grant, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: "2026-07-11T12:06:00.000Z" }, "expired"),
    rej("expiry-upper-bound-rejects", "A grant presented at exactly expiresAt is rejected (exclusive upper bound).", { grant, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: grantBase.expiresAt }, "expired"),
    rej("not-yet-valid-rejects", "A grant presented before issuedAt is rejected; issuer and verifier clock skew must not admit a future grant.", { grant, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: "2026-07-11T11:59:00.000Z" }, "not_yet_valid"),
    rej("replayed-grant-id-rejects", "A grant whose (issuer, grantId) is already in the service's seen set is a replay and is rejected.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, seenGrants: [key] }, "replay"),
    rej("revoked-grant-id-rejects", "A grant whose (issuer, grantId) is on the service's revocation list is rejected even inside the window.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, revokedGrants: [key] }, "revoked"),
    rej("required-owner-unverified-rejects", "A grant that requires a verified owner is rejected when the owner status is unverified.", { grant: ownerGrant, issuerPublicKeyHex: publicKeyHex, ...ctx, verifiedOwner: { status: "unverified" } }, "owner_unverified"),
    rej("required-owner-absent-rejects", "A grant that requires a verified owner is rejected when the service supplies no owner status; absent is not verified.", { grant: ownerGrant, issuerPublicKeyHex: publicKeyHex, ...ctx }, "owner_unverified"),
    rej("unknown-top-level-key-rejects", "An unknown top-level field is rejected by the strict schema before verification.", { grant: { ...grant, extra: 1 }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("lone-surrogate-rejects", "A lone UTF-16 surrogate in a string field is not portable and rejects structurally as schema, before the signature.", { grant: { ...grant, subject: loneSurrogateSubject }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("empty-scope-rejects", "A grant with no scope entries is out of profile and rejects.", { grant: { ...grant, scope: [] }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("duplicate-scope-rejects", "A grant with a repeated scope entry is rejected; scope entries must be distinct so two implementations count the same set.", { grant: { ...grant, scope: ["profile:read", "profile:read"] }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("overbroad-scope-rejects", "A scope array with more than 64 entries is out of profile and rejects.", { grant: { ...grant, scope: Array.from({ length: 65 }, (_, i) => `s${i}`) }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("non-string-scope-entry-rejects", "A scope array with a non-string entry rejects.", { grant: { ...grant, scope: ["profile:read", 1] }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("over-length-scope-entry-rejects", "A scope entry longer than 128 code units is out of profile and rejects.", { grant: { ...grant, scope: ["profile:read", "x".repeat(129)] }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("over-length-issuer-rejects", "An issuer longer than 512 code units is out of profile and rejects.", { grant: { ...grant, issuer: "i".repeat(513) }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("over-length-subject-rejects", "A subject longer than 512 code units is out of profile and rejects.", { grant: { ...grant, subject: "s".repeat(513) }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("over-length-audience-rejects", "An audience longer than 512 code units is out of profile and rejects.", { grant: { ...grant, audience: "a".repeat(513) }, issuerPublicKeyHex: publicKeyHex, audience: "a".repeat(513), now: nowInWindow }, "schema"),
    rej("over-length-grant-id-rejects", "A grantId longer than 256 code units is out of profile and rejects.", { grant: { ...grant, grantId: "g".repeat(257) }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("invalid-protocol-rejects", "A protocol other than ink/0.1 is out of profile and rejects.", { grant: { ...grant, protocol: "ink/0.2" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("invalid-type-rejects", "A type that is neither the network.tulpa nor the network.ink spelling is out of profile and rejects.", { grant: { ...grant, type: "network.tulpa.other" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("inverted-window-rejects", "A grant whose expiresAt is not after issuedAt is malformed and rejects.", { grant: { ...grant, expiresAt: grantBase.issuedAt }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("over-maximum-lifetime-rejects", "A grant whose window exceeds the ten-minute maximum lifetime is out of profile and rejects structurally, before the signature, even against a wrong key.", { grant: { ...grant, expiresAt: overCapExpiresAt }, issuerPublicKeyHex: otherPublicKeyHex, audience: ctx.audience, now: grantBase.issuedAt }, "schema"),
    rej("over-caller-lifetime-rejects", "A grant inside the profile window but longer than a caller-tightened maxLifetimeMs is rejected as schema, after the signature.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, maxLifetimeMs: 60000 }, "schema"),
    acc("caller-lifetime-zero-accepts", "A caller-tightened maxLifetimeMs of exactly 0 means unset and uses the profile default, so a grant inside the profile window still verifies; Go cannot tell a zero-value integer from an unset one, so 0 is no caller cap across implementations.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, maxLifetimeMs: 0 }),
    rej("negative-caller-lifetime-rejects", "A negative caller-tightened maxLifetimeMs is a verifier input error that fails closed as schema, not a policy that admits every window, after the signature.", { grant, issuerPublicKeyHex: publicKeyHex, ...ctx, maxLifetimeMs: -1 }, "schema"),
    rej("invalid-issued-at-rejects", "A grant whose issuedAt is not a strict INK timestamp rejects.", { grant: { ...grant, issuedAt: "2026-07-11 12:00" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("malformed-signature-rejects", "A signature that is not valid base64url of the right length is rejected.", { grant: { ...grant, signature: grant.signature.slice(0, 85) + "+" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("missing-signature-rejects", "A grant with no signature field rejects.", { grant: (() => { const { signature, ...rest } = grant; return rest; })(), issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("short-grant-id-rejects", "A grantId shorter than 16 code units is out of profile and rejects.", { grant: { ...grant, grantId: "short" }, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("invalid-now-rejects", "A verifier clock that is not a strict INK timestamp is a verifier input error and fails closed as schema, not a window verdict.", { grant, issuerPublicKeyHex: publicKeyHex, audience: ctx.audience, now: "not-a-timestamp" }, "schema"),
    // Raw-body gate: cases carrying `grantRaw`, the exact wire text, because the
    // rule under test is about bytes the parsed value no longer carries.
    acc("raw-grant-accepts", "The same signed grant presented as raw wire text verifies: whitespace between tokens is legal JSON and vanishes at canonicalization, so the signature still covers it.", { grantRaw: grPadded, issuerPublicKeyHex: publicKeyHex, ...ctx }),
    rej("shadowed-number-literal-rejects", "An out-of-range number literal shadowed by a later duplicate member rejects. Member semantics are last-wins, so the literal never reaches the parsed grant and the signature over the canonical form still verifies; only a gate on the raw text sees it, and without one two implementations admit different byte strings for the same signed grant.", { grantRaw: grShadowedNumber, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    rej("live-number-literal-rejects", "An out-of-range number literal in a live member rejects at the raw gate, before the schema can rule on the Infinity a lenient parser would hand it.", { grantRaw: grLiveNumber, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
    acc("shadowed-underflow-accepts", "An underflowing exponent is in range: every IEEE-754 parser decodes 1e-400 to 0, so a shadowed one is not gated and the grant behind it verifies. The gate is a range test, not a ban on exponents.", { grantRaw: grShadowedUnderflow, issuerPublicKeyHex: publicKeyHex, ...ctx }),
    rej("raw-lone-surrogate-escape-rejects", "A lone UTF-16 surrogate escape in the raw text rejects structurally, before the signature: a parser that rewrites it to U+FFFD would canonicalize something other than what was sent.", { grantRaw: grLoneSurrogate, issuerPublicKeyHex: publicKeyHex, ...ctx }, "schema"),
  ]);
}

// ── authorization-chain ──────────────────────────────────────────────────────
// A linear authorization chain, the post-1.0 delegation extension on top of the
// grant (specs/ink-authorization-chain.md). A chain is 2 to 4 delegation links,
// each the grant field model plus a network.ink.delegation_link type and a parent
// hash, each hop narrowing the last. Each vector carries the presented chain plus
// the verification context: the per-link resolved issuer keys (aligned root-first
// to `links`, each an active/retired/revoked signing key), the verifying service
// audience, the clock, and the optional presenter, replay set, revocation list,
// and owner status. A verifier accepts iff verifyAuthorizationChain returns ok; a
// reject pins the typed reason so the two implementations agree on verify order.
{
  const enc2 = new TextEncoder();
  const mkKey = async (label) => {
    const s = new Uint8Array(await crypto.subtle.digest("SHA-256", enc2.encode(label)));
    const pub = await ed.getPublicKeyAsync(s);
    return { seed: s, hex: bytesToHex(pub) };
  };
  const kOrigin = await mkKey("ink-conformance-v1-chain-origin");
  const kD1 = await mkKey("ink-conformance-v1-chain-delegate-1");
  const kD2 = await mkKey("ink-conformance-v1-chain-delegate-2");
  const kD3 = await mkKey("ink-conformance-v1-chain-delegate-3");
  const kD4 = await mkKey("ink-conformance-v1-chain-delegate-4");

  const AUD = "did:web:service.example";
  const P_ORIGIN = "did:web:origin.example";
  const P_D1 = "did:web:delegate-1.example";
  const P_D2 = "did:web:delegate-2.example";
  const P_D3 = "did:web:delegate-3.example";
  const P_D4 = "did:web:delegate-4.example";
  const P_D5 = "did:web:delegate-5.example";
  const EXT = "delegation.extend";

  // Build a root-first array of signed delegation links from field specs and the
  // aligned signing seeds, deriving each non-root link's parent hash from the link
  // above it. The wrapper is assembled inline per case.
  const buildLinks = async (specs, seeds) => {
    const links = [];
    let parent = null;
    for (let i = 0; i < specs.length; i++) {
      const link = await buildDelegationLink(specs[i], parent, seeds[i]);
      links.push(link);
      parent = link;
    }
    return links;
  };
  const wrap = (links) => ({ protocol: "ink/0.1", type: "network.ink.authorization_chain", links });
  const activeKeys = (...hexes) => hexes.map((publicKeyHex) => ({ publicKeyHex, status: "active" }));
  // A shallow per-link mutation: clone the links and overlay a patch on one link.
  const patchLink = (links, i, patch) => links.map((l, j) => (j === i ? { ...l, ...patch } : { ...l }));
  const dropParent = (links, i) => links.map((l, j) => {
    if (j !== i) return { ...l };
    const { parent, ...rest } = l;
    return rest;
  });
  // Flip the leading character of an 86-char base64url signature to a different
  // base64url character: a valid shape that no longer verifies. The leading
  // character's bits are all significant (unlike the trailing character, whose low
  // bits are padding), so the decoded signature bytes genuinely change.
  const breakSig = (sig) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);

  // The canonical valid 2-link chain: origin delegates to d1 (carrying the
  // delegation.extend token that seats the re-delegation), d1 re-delegates to d2.
  const twoSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", "messages:send", EXT], grantId: "chain-2link-root-000000001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read"], grantId: "chain-2link-head-000000001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:10:00.000Z" },
  ];
  const twoSeeds = [kOrigin.seed, kD1.seed];
  const two = await buildLinks(twoSpecs, twoSeeds);
  const twoKeys = activeKeys(kOrigin.hex, kD1.hex);
  const nowIn = "2026-07-11T12:06:00.000Z";
  const rootPair = { issuer: P_ORIGIN, grantId: twoSpecs[0].grantId };
  const headPair = { issuer: P_D1, grantId: twoSpecs[1].grantId };

  // The canonical valid 4-link chain: origin -> d1 -> d2 -> d3 -> d4, each
  // intermediate carrying delegation.extend and each window nested in its parent.
  const fourSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", "messages:send", EXT], grantId: "chain-4link-l0-0000000001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read", "messages:send", EXT], grantId: "chain-4link-l1-0000000001", issuedAt: "2026-07-11T12:01:00.000Z", expiresAt: "2026-07-11T12:20:00.000Z" },
    { issuer: P_D2, subject: P_D3, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-4link-l2-0000000001", issuedAt: "2026-07-11T12:02:00.000Z", expiresAt: "2026-07-11T12:15:00.000Z" },
    { issuer: P_D3, subject: P_D4, audience: AUD, scope: ["profile:read"], grantId: "chain-4link-l3-0000000001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:12:00.000Z" },
  ];
  const fourSeeds = [kOrigin.seed, kD1.seed, kD2.seed, kD3.seed];
  const four = await buildLinks(fourSpecs, fourSeeds);
  const fourKeys = activeKeys(kOrigin.hex, kD1.hex, kD2.hex, kD3.hex);

  // A five-link chain, built cleanly so only the depth cap is what rejects it.
  const fiveSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-5link-l0-0000000001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-5link-l1-0000000001", issuedAt: "2026-07-11T12:01:00.000Z", expiresAt: "2026-07-11T12:20:00.000Z" },
    { issuer: P_D2, subject: P_D3, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-5link-l2-0000000001", issuedAt: "2026-07-11T12:02:00.000Z", expiresAt: "2026-07-11T12:15:00.000Z" },
    { issuer: P_D3, subject: P_D4, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-5link-l3-0000000001", issuedAt: "2026-07-11T12:03:00.000Z", expiresAt: "2026-07-11T12:13:00.000Z" },
    { issuer: P_D4, subject: P_D5, audience: AUD, scope: ["profile:read"], grantId: "chain-5link-l4-0000000001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:12:00.000Z" },
  ];
  const five = await buildLinks(fiveSpecs, [kOrigin.seed, kD1.seed, kD2.seed, kD3.seed, kD4.seed]);
  const fiveKeys = activeKeys(kOrigin.hex, kD1.hex, kD2.hex, kD3.hex, kD4.hex);

  // A tokenless-root 2-link chain: the root carries NO delegation.extend, so it
  // cannot seat the re-delegation below it. Built cleanly so structure and
  // signatures pass and only the delegability gate rejects it.
  const tokenlessSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read"], grantId: "chain-tokenless-root-00001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read"], grantId: "chain-tokenless-head-00001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:10:00.000Z" },
  ];
  const tokenless = await buildLinks(tokenlessSpecs, [kOrigin.seed, kD1.seed]);

  // A 3-link chain whose middle link drops delegation.extend, so it cannot seat
  // the third link even though the root seats the middle one.
  const midTokenlessSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-midless-l0-000000001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read"], grantId: "chain-midless-l1-000000001", issuedAt: "2026-07-11T12:01:00.000Z", expiresAt: "2026-07-11T12:20:00.000Z" },
    { issuer: P_D2, subject: P_D3, audience: AUD, scope: ["profile:read"], grantId: "chain-midless-l2-000000001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:12:00.000Z" },
  ];
  const midTokenless = await buildLinks(midTokenlessSpecs, [kOrigin.seed, kD1.seed, kD2.seed]);
  const midTokenlessKeys = activeKeys(kOrigin.hex, kD1.hex, kD2.hex);

  // A chain whose final link names a different audience than the root, built and
  // signed correctly, so structure and signatures pass and the audience check on
  // the mismatched link is what rejects it.
  const splitAudSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-splitaud-root-00001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z" },
    { issuer: P_D1, subject: P_D2, audience: "did:web:evil.example", scope: ["profile:read"], grantId: "chain-splitaud-head-00001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:10:00.000Z" },
  ];
  const splitAud = await buildLinks(splitAudSpecs, [kOrigin.seed, kD1.seed]);

  // A chain whose root requires a verified owner, so the whole chain requires the
  // conjunction, built cleanly so only the owner-verification hook decides.
  const ownerSpecs = [
    { issuer: P_ORIGIN, subject: P_D1, audience: AUD, scope: ["profile:read", EXT], grantId: "chain-owner-root-00000001", issuedAt: "2026-07-11T12:00:00.000Z", expiresAt: "2026-07-11T12:30:00.000Z", requireVerifiedOwner: true },
    { issuer: P_D1, subject: P_D2, audience: AUD, scope: ["profile:read"], grantId: "chain-owner-head-00000001", issuedAt: "2026-07-11T12:05:00.000Z", expiresAt: "2026-07-11T12:10:00.000Z" },
  ];
  const owner = await buildLinks(ownerSpecs, [kOrigin.seed, kD1.seed]);

  const ctx = { audience: AUD, now: nowIn };
  const acc = (caseId, description, input) => ({ caseId, description, input, expect: { result: "accept" } });
  const rej = (caseId, description, input, reason) => ({ caseId, description, input, expect: { result: "reject", reason } });

  // Raw-text cases. Every link is a signed body, so the raw-body gate of
  // specs/ink-signed-string-safety.md applies to the presentation, and every rule
  // that gate enforces is about bytes a parsed value has already lost. A case that
  // needs to express one carries `chainRaw`, the exact JSON text a presenter put
  // on the wire, instead of `chain`; a runner decodes it to bytes and verifies
  // those. The shadowed literal is the reason the field exists: member semantics
  // are last-wins, so the out-of-range literal never reaches the parsed wrapper,
  // every link canonicalizes to its signed bytes and every signature verifies.
  const chainText = JSON.stringify(wrap(two));
  const chShadowedNumber = `{"protocol":1e309,${chainText.slice(1)}`;
  // The wrapper protocol, not a link's: String.replace without a global flag
  // rewrites only the first occurrence, which is the wrapper's own member.
  const chLiveNumber = chainText.replace(`"protocol":"ink/0.1"`, `"protocol":1e309`);
  const chShadowedUnderflow = `{"protocol":1e-400,${chainText.slice(1)}`;
  const chLoneSurrogate = chainText.replace(`"grantId":"${twoSpecs[1].grantId}"`, `"grantId":"\\ud800${twoSpecs[1].grantId}"`);
  const chPadded = `{  ${chainText.slice(1)}`;

  vectorFile("authorization-chain", [
    // ── accepts ──
    acc("valid-2link-accepts", "A 2-link chain whose root carries delegation.extend, whose head scope and window narrow the root, signed by each issuer's active key and presented inside every window to the named audience, verifies.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx }),
    acc("valid-4link-accepts", "A 4-link chain narrowing scope and window at every hop, each intermediate carrying delegation.extend, verifies at the maximum depth.", { chain: wrap(four), issuerKeys: fourKeys, ...ctx }),
    acc("presenter-matches-final-subject-accepts", "A chain presented by the authenticated principal named as the FINAL link's subject verifies; the presentation binding holds across the whole chain.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, presenter: P_D2 }),
    acc("presenter-empty-accepts", "An empty-string presenter means no presenter was established, so the binding check is skipped just as when it is absent.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, presenter: "" }),
    acc("intermediate-seen-not-replay-accepts", "The root (an intermediate link) pair already in the seen set does NOT reject: only the final link is replay-checked, so a shared prefix can seat many distinct chains.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, seenGrants: [rootPair] }),
    acc("cross-issuer-same-grant-id-accepts", "A different issuer's seen and revoked entry for the same grantId string as the head does not block the chain; replay and revocation key on the (issuer, grantId) pair.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, seenGrants: [{ issuer: "did:web:other.example", grantId: twoSpecs[1].grantId }], revokedGrants: [{ issuer: "did:web:other.example", grantId: twoSpecs[1].grantId }] }),
    acc("required-owner-verified-accepts", "A chain whose root requires a verified owner verifies when the service supplies a verified owner status.", { chain: wrap(owner), issuerKeys: twoKeys, ...ctx, verifiedOwner: { status: "verified" } }),
    acc("owner-not-required-ignores-status-accepts", "A chain no link of which requires a verified owner verifies even when the service supplies an unverified owner status.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, verifiedOwner: { status: "unverified" } }),
    acc("issued-at-lower-bound-accepts", "A chain presented at exactly the latest link's issuedAt is inside every window (inclusive lower bound).", { chain: wrap(two), issuerKeys: twoKeys, audience: AUD, now: twoSpecs[1].issuedAt }),

    // ── schema (structure, on signed bytes) ──
    rej("too-few-links-rejects", "A wrapper carrying a single link is not a chain (a one-link grant is verified by the grant verifier) and rejects on the 2-to-4 depth bound.", { chain: wrap([two[0]]), issuerKeys: activeKeys(kOrigin.hex), ...ctx }, "schema"),
    rej("too-many-links-rejects", "A wrapper carrying five links exceeds the depth cap and rejects.", { chain: wrap(five), issuerKeys: fiveKeys, ...ctx }, "schema"),
    rej("wrong-wrapper-type-rejects", "A wrapper type other than network.ink.authorization_chain rejects.", { chain: { ...wrap(two), type: "network.ink.authorization_grant" }, issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("unknown-wrapper-field-rejects", "An unknown top-level wrapper field is rejected by the strict schema.", { chain: { ...wrap(two), extra: 1 }, issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("unknown-link-field-rejects", "An unknown field on a link is rejected by the strict delegation-link schema.", { chain: wrap(patchLink(two, 1, { extra: 1 })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("wrong-link-type-rejects", "A link typed network.ink.authorization_grant is not a delegation link and rejects; a grant is never accepted as a chain link.", { chain: wrap(patchLink(two, 1, { type: "network.ink.authorization_grant" })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("bad-parent-shape-rejects", "A parent that is not 43 base64url characters is a malformed digest and rejects on the delegation-link schema.", { chain: wrap(patchLink(two, 1, { parent: "tooshort" })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("root-with-parent-rejects", "The root link MUST NOT carry a parent; a root that does rejects.", { chain: wrap(patchLink(two, 0, { parent: "A".repeat(43) })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("non-root-missing-parent-rejects", "A non-root link MUST carry a parent; a non-root link with none rejects.", { chain: wrap(dropParent(two, 1)), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("intermediate-over-24h-rejects", "An intermediate (non-final) link whose lifetime exceeds 24 hours is over its position ceiling and rejects structurally on the signed bytes.", { chain: wrap(patchLink(two, 0, { expiresAt: "2026-07-12T13:00:00.000Z" })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("final-over-10min-rejects", "A final link whose lifetime exceeds 10 minutes is over its position ceiling and rejects structurally on the signed bytes.", { chain: wrap(patchLink(two, 1, { expiresAt: "2026-07-11T12:16:00.000Z" })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("empty-scope-rejects", "A link with no scope entries is out of profile and rejects.", { chain: wrap(patchLink(two, 1, { scope: [] })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("duplicate-scope-rejects", "A link with a repeated scope entry rejects; scope entries must be distinct so two implementations count the same set.", { chain: wrap(patchLink(two, 1, { scope: ["profile:read", "profile:read"] })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("inverted-window-rejects", "A link whose expiresAt is not after issuedAt is malformed and rejects.", { chain: wrap(patchLink(two, 1, { expiresAt: twoSpecs[1].issuedAt })), issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("malformed-now-rejects", "A verifier clock that is not a strict INK timestamp is a verifier input error consulted in pass 2 and fails closed as schema, not signature and not a window verdict.", { chain: wrap(two), issuerKeys: twoKeys, audience: AUD, now: "not-a-timestamp" }, "schema"),

    // ── chain (continuity: issuer-subject seam and parent hash) ──
    rej("continuity-seam-mismatch-rejects", "A non-root link whose issuer does not byte-equal its parent's subject breaks continuity and rejects as chain.", { chain: wrap(patchLink(two, 1, { issuer: "did:web:stranger.example" })), issuerKeys: twoKeys, ...ctx }, "chain"),
    rej("spliced-parent-hash-rejects", "A non-root link whose parent hash does not equal the digest of the link above it (a spliced parent) rejects as chain.", { chain: wrap(patchLink(two, 1, { parent: "A".repeat(43) })), issuerKeys: twoKeys, ...ctx }, "chain"),
    rej("edited-parent-breaks-hash-rejects", "Editing a signed ancestor (here the root grantId) changes its canonical bytes, so the child's parent digest no longer matches and the chain rejects as chain before the signature check.", { chain: wrap(patchLink(two, 0, { grantId: "chain-2link-root-000000099" })), issuerKeys: twoKeys, ...ctx }, "chain"),

    // ── attenuation (scope subset, window nesting, delegability) ──
    rej("scope-widening-rejects", "A child scope token absent from its parent is a widening and rejects the chain as attenuation.", { chain: wrap(patchLink(two, 1, { scope: ["profile:read", "admin:all"] })), issuerKeys: twoKeys, ...ctx }, "attenuation"),
    rej("window-not-nested-rejects", "A child whose window starts before its parent's escapes the parent window and rejects as attenuation.", { chain: wrap(patchLink(two, 1, { issuedAt: "2026-07-11T11:58:00.000Z", expiresAt: "2026-07-11T12:06:00.000Z" })), issuerKeys: twoKeys, ...ctx }, "attenuation"),
    rej("window-exceeds-parent-expiry-rejects", "A child whose issuedAt still satisfies parent.issuedAt <= child.issuedAt but whose expiresAt runs past the parent's expiresAt violates the child.expiresAt <= parent.expiresAt conjunct of window nesting; the head keeps a strictly positive window and a 10-minute lifetime so pass-1 schema does not fire first, isolating the upper-bound nesting violation as attenuation.", { chain: wrap(patchLink(two, 1, { issuedAt: "2026-07-11T12:25:00.000Z", expiresAt: "2026-07-11T12:35:00.000Z" })), issuerKeys: twoKeys, ...ctx }, "attenuation"),
    rej("tokenless-root-2link-rejects", "A 2-link chain whose root lacks delegation.extend cannot seat the re-delegation below it and rejects as attenuation; a two-link chain requires the token in the root.", { chain: wrap(tokenless), issuerKeys: twoKeys, ...ctx }, "attenuation"),
    rej("missing-token-mid-seam-rejects", "A 3-link chain whose middle link drops delegation.extend cannot seat the third link, so the deeper seam rejects as attenuation even though the root seats the middle link.", { chain: wrap(midTokenless), issuerKeys: midTokenlessKeys, ...ctx }, "attenuation"),

    // ── signature (pass 2, root to head) ──
    rej("bad-signature-rejects", "A link whose signature does not verify against its resolved issuer key rejects as signature.", { chain: wrap(patchLink(two, 1, { signature: breakSig(two[1].signature) })), issuerKeys: twoKeys, ...ctx }, "signature"),
    rej("retired-key-rejects", "A retired signing key never verifies a link, the chain's fast revocation lever for a compromised delegate; the chain rejects as signature.", { chain: wrap(two), issuerKeys: [{ publicKeyHex: kOrigin.hex, status: "active" }, { publicKeyHex: kD1.hex, status: "retired" }], ...ctx }, "signature"),
    rej("revoked-key-rejects", "A revoked signing key never verifies a link; the chain rejects as signature.", { chain: wrap(two), issuerKeys: [{ publicKeyHex: kOrigin.hex, status: "revoked" }, { publicKeyHex: kD1.hex, status: "active" }], ...ctx }, "signature"),
    rej("wrong-key-rejects", "A link resolved to the wrong active issuer key does not verify and rejects as signature.", { chain: wrap(two), issuerKeys: [{ publicKeyHex: kOrigin.hex, status: "active" }, { publicKeyHex: kD2.hex, status: "active" }], ...ctx }, "signature"),

    // ── audience / subject / window (pass 3) ──
    rej("confused-deputy-audience-rejects", "A chain minted for one service presented to a different verifying service rejects on the audience check even though every signature is valid.", { chain: wrap(two), issuerKeys: twoKeys, audience: "did:web:other-service.example", now: nowIn }, "audience"),
    rej("mismatched-link-audience-rejects", "A chain whose final link names a different audience than the root rejects on the audience check at the mismatched link; the audience is fixed by the origin and identical on every link.", { chain: wrap(splitAud), issuerKeys: twoKeys, ...ctx }, "audience"),
    rej("presenter-not-final-subject-rejects", "A chain presented by a principal other than its final link's subject rejects on the presentation binding.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, presenter: "did:web:thief.example" }, "subject"),
    rej("not-yet-valid-rejects", "A chain presented before the final link's issuedAt is not yet valid at that link and rejects.", { chain: wrap(two), issuerKeys: twoKeys, audience: AUD, now: "2026-07-11T12:04:00.000Z" }, "not_yet_valid"),
    rej("expired-rejects", "A chain presented after the final link's expiresAt is expired at that link and rejects.", { chain: wrap(two), issuerKeys: twoKeys, audience: AUD, now: "2026-07-11T12:11:00.000Z" }, "expired"),
    rej("presented-at-expiry-upper-bound-rejects", "A chain presented at exactly the final link's expiresAt is expired: the validity window is [issuedAt, expiresAt), so now == expiresAt is outside it. This pins the exclusive upper bound, the symmetric counterpart to issued-at-lower-bound-accepts pinning the inclusive lower bound.", { chain: wrap(two), issuerKeys: twoKeys, audience: AUD, now: twoSpecs[1].expiresAt }, "expired"),

    // ── replay / revoked / owner (pass 3) ──
    rej("final-pair-seen-replay-rejects", "The final link's (issuer, grantId) pair already in the seen set is a replay and rejects.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, seenGrants: [headPair] }, "replay"),
    rej("final-seen-and-revoked-rejects-replay", "The final link's (issuer, grantId) pair is both in the seen set and on the revocation denylist; because pass 3 reads replay before revocation under first-failure-wins, a final link that is both replayed and revoked rejects as replay, not revoked.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, seenGrants: [headPair], revokedGrants: [headPair] }, "replay"),
    rej("head-revoked-rejects", "The final link's (issuer, grantId) pair on the revocation list rejects the chain even inside its window; an unseen head that passes the replay read still rejects on revocation and nothing is recorded.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, revokedGrants: [headPair] }, "revoked"),
    rej("intermediate-revoked-rejects", "A revoked intermediate (root) pair rejects the whole chain; every link is revocation-checked even though only the head is replay-checked.", { chain: wrap(two), issuerKeys: twoKeys, ...ctx, revokedGrants: [rootPair] }, "revoked"),
    rej("required-owner-unverified-rejects", "A chain whose root requires a verified owner rejects when the owner status is unverified.", { chain: wrap(owner), issuerKeys: twoKeys, ...ctx, verifiedOwner: { status: "unverified" } }, "owner_unverified"),
    rej("required-owner-absent-rejects", "A chain whose root requires a verified owner rejects when the service supplies no owner status; absent is not verified.", { chain: wrap(owner), issuerKeys: twoKeys, ...ctx }, "owner_unverified"),

    // ── ordering (two defects coexist; the earlier pass wins) ──
    rej("bad-sig-and-wrong-audience-rejects-signature", "A chain with a bad final signature presented to the wrong audience rejects on the signature (pass 2) ahead of the audience check (pass 3).", { chain: wrap(patchLink(two, 1, { signature: breakSig(two[1].signature) })), issuerKeys: twoKeys, audience: "did:web:other-service.example", now: nowIn }, "signature"),
    rej("scope-widen-and-expired-rejects-attenuation", "A chain that both widens scope and is presented after expiry rejects on attenuation (pass 1) ahead of the expiry check (pass 3).", { chain: wrap(patchLink(two, 1, { scope: ["profile:read", "admin:all"] })), issuerKeys: twoKeys, audience: AUD, now: "2026-07-11T12:11:00.000Z" }, "attenuation"),
    rej("malformed-now-and-bad-sig-rejects-schema", "A malformed clock with a bad signature rejects as schema: the clock is consulted at the start of pass 2, ahead of the per-link signature check.", { chain: wrap(patchLink(two, 1, { signature: breakSig(two[1].signature) })), issuerKeys: twoKeys, audience: AUD, now: "not-a-timestamp" }, "schema"),

    // ── raw-body gate (pass 0, on the presented bytes) ──
    acc("raw-chain-accepts", "The same signed chain presented as raw wire text verifies: whitespace between tokens is legal JSON and vanishes at canonicalization, so every link signature still covers it.", { chainRaw: chPadded, issuerKeys: twoKeys, ...ctx }),
    rej("shadowed-number-literal-rejects", "An out-of-range number literal shadowed by a later duplicate wrapper member rejects. Member semantics are last-wins, so the literal never reaches the parsed chain and every link signature still verifies; only a gate on the raw text sees it, and without one two implementations admit different byte strings for the same presented chain.", { chainRaw: chShadowedNumber, issuerKeys: twoKeys, ...ctx }, "schema"),
    rej("live-number-literal-rejects", "An out-of-range number literal in a live wrapper member rejects at the raw gate, before the schema can rule on the Infinity a lenient parser would hand it.", { chainRaw: chLiveNumber, issuerKeys: twoKeys, ...ctx }, "schema"),
    acc("shadowed-underflow-accepts", "An underflowing exponent is in range: every IEEE-754 parser decodes 1e-400 to 0, so a shadowed one is not gated and the chain behind it verifies. The gate is a range test, not a ban on exponents.", { chainRaw: chShadowedUnderflow, issuerKeys: twoKeys, ...ctx }),
    rej("raw-lone-surrogate-escape-rejects", "A lone UTF-16 surrogate escape in the raw text rejects structurally, before any signature: a parser that rewrites it to U+FFFD would canonicalize something other than what was sent.", { chainRaw: chLoneSurrogate, issuerKeys: twoKeys, ...ctx }, "schema"),
  ]);
}

// ── agent-authorization ──────────────────────────────────────────────────────
// The sign-in challenge artifact the Agent Authorization flow profile adds on top
// of the grant (specs/ink-agent-authorization.md). An RP signs a challenge; the
// user's agent verifies it against an active RP signing key before minting the
// grant that answers it. Each verify case carries the challenge, the RP card's
// candidate signing keys, and the verifier clock; a verifier accepts iff
// verifyAuthorizationChallenge returns ok, and a reject pins the typed reason so
// two implementations agree on verify order (schema -> signature -> window). A
// case with no `keys` is a derive-only case: it pins the exact challenge-derived
// grantId for fixed inputs, the cross-impl contract for the nonce-binding
// derivation. Accept cases also pin the derived id.
{
  const challengeBase = {
    rp: "did:web:rp.example",
    nonce: "nonce-challenge-000000001",
    requestedScope: ["identity.assert", "profile.read"],
    redirectUri: "https://rp.example/callback",
    issuedAt: "2026-07-16T12:00:00.000Z",
    expiresAt: "2026-07-16T12:05:00.000Z",
  };
  const nowInWindow = "2026-07-16T12:02:00.000Z";
  const challenge = await buildAuthorizationChallenge(challengeBase, seed);
  const portBase = {
    ...challengeBase,
    rp: "did:web:rp.example%3A8443",
    redirectUri: "https://rp.example:8443/callback",
  };
  const portChallenge = await buildAuthorizationChallenge(portBase, seed);
  // A redirectUri that is the origin plus / plus a query only (no path segment):
  // the literal prefix rule admits it because the path and query after the / are
  // optional.
  const queryRedirectChallenge = await buildAuthorizationChallenge({ ...challengeBase, redirectUri: "https://rp.example/?ref=xyz" }, seed);
  const otherPublicKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(9)));

  // The RP card's active signing key set. Every accept case shares it; the
  // signature cases vary the status or window to pin the active-key-only rule.
  const activeKeys = [{ keyId: "rp-active", publicKeyHex, status: "active" }];

  // A backslash const keeps a literal lone-surrogate escape out of a JSON string
  // the generator would otherwise write as U+FFFD.
  const loneSurrogateNonce = "nonce-\uD800-000000001";
  // A window exactly one second past the ten-minute ceiling, signed with a key the
  // vector never verifies against, so the over-long window is the reason it rejects
  // structurally, before the signature.
  const overCapExpiresAt = new Date(Date.parse(challengeBase.issuedAt) + 10 * 60 * 1000 + 1000).toISOString();
  // A redirectUri carrying a literal U+0001 control character, kept out of the
  // source text via fromCharCode so the generator file stays control-char clean.
  const controlCharRedirect = "https://rp.example/call" + String.fromCharCode(1) + "back";

  // The derived grantId is the base64url-nopad SHA-256 over the domain string, a
  // newline, and the JCS of the four binding fields. Pinned for fixed inputs so
  // both implementations compute the identical id.
  const idBase = await deriveChallengeGrantId(challengeBase);
  const idDiffRp = await deriveChallengeGrantId({ ...challengeBase, rp: "did:web:rp2.example" });
  const idDiffNonce = await deriveChallengeGrantId({ ...challengeBase, nonce: "nonce-challenge-000000002" });
  const idDiffWindow = await deriveChallengeGrantId({ ...challengeBase, expiresAt: "2026-07-16T12:06:00.000Z" });

  // Raw-text cases. A challenge is a signed body, so the raw-body gate of
  // specs/ink-signed-string-safety.md applies to it, and every rule that gate
  // enforces is about bytes a parsed value has already lost. A case that needs to
  // express one carries `challengeRaw`, the exact JSON text the RP put on the
  // wire, instead of `challenge`; a runner decodes it to bytes and verifies those.
  // The shadowed literal is the reason the field exists: member semantics are
  // last-wins, so the out-of-range literal never reaches the parsed challenge, the
  // challenge canonicalizes to the signed bytes and its signature verifies.
  const challengeText = JSON.stringify(challenge);
  const chalShadowedNumber = `{"protocol":1e309,${challengeText.slice(1)}`;
  const chalLiveNumber = challengeText.replace(`"protocol":"ink/0.1"`, `"protocol":1e309`);
  const chalShadowedUnderflow = `{"protocol":1e-400,${challengeText.slice(1)}`;
  const chalLoneSurrogate = challengeText.replace(`"nonce":"${challengeBase.nonce}"`, `"nonce":"\\ud800${challengeBase.nonce}"`);
  const chalPadded = `{  ${challengeText.slice(1)}`;

  const ctx = { keys: activeKeys, now: nowInWindow };
  const acc = (caseId, description, input, derivedGrantId) => ({ caseId, description, input, expect: derivedGrantId ? { result: "accept", derivedGrantId } : { result: "accept" } });
  const rej = (caseId, description, input, reason) => ({ caseId, description, input, expect: { result: "reject", reason } });
  const der = (caseId, description, challengeObj, derivedGrantId) => ({ caseId, description, input: { challenge: challengeObj }, expect: { result: "accept", derivedGrantId } });

  vectorFile("agent-authorization", [
    acc("valid-challenge-accepts", "A challenge signed by the RP's active key, verified at a clock inside its window, verifies and derives its grantId.", { challenge, ...ctx }, idBase),
    acc("issued-at-lower-bound-accepts", "A challenge verified at exactly issuedAt is inside the window (inclusive lower bound).", { challenge, keys: activeKeys, now: challengeBase.issuedAt }, idBase),
    acc("bare-host-with-port-accepts", "A bare-host did:web rp carrying a non-default port derives an origin with that port, and a redirectUri under it verifies.", { challenge: portChallenge, ...ctx }),
    acc("in-window-active-key-accepts", "An active key whose validFrom/validUntil bracket the verifier clock verifies the challenge.", { challenge, keys: [{ keyId: "rp-active", publicKeyHex, status: "active", validFrom: "2026-07-16T11:00:00.000Z", validUntil: "2026-07-16T13:00:00.000Z" }], now: nowInWindow }, idBase),

    rej("retired-key-rejects-signature", "A retired RP key MUST NOT verify a live challenge, so the signature step rejects even though the key material matches.", { challenge, keys: [{ keyId: "rp-retired", publicKeyHex, status: "retired" }], now: nowInWindow }, "signature"),
    rej("revoked-key-rejects-signature", "A revoked RP key never verifies a challenge.", { challenge, keys: [{ keyId: "rp-revoked", publicKeyHex, status: "revoked" }], now: nowInWindow }, "signature"),
    rej("expired-active-key-rejects-signature", "An active key whose validUntil precedes the verifier clock is out of window and does not verify; usability is evaluated at now, not at the RP-chosen issuedAt.", { challenge, keys: [{ keyId: "rp-active", publicKeyHex, status: "active", validUntil: "2026-07-16T11:00:00.000Z" }], now: nowInWindow }, "signature"),
    rej("not-yet-valid-active-key-rejects-signature", "An active key whose validFrom is after the verifier clock is not yet usable and does not verify.", { challenge, keys: [{ keyId: "rp-active", publicKeyHex, status: "active", validFrom: "2026-07-16T13:00:00.000Z" }], now: nowInWindow }, "signature"),
    rej("wrong-key-rejects-signature", "A candidate active key that is not the signing key cannot verify the signature.", { challenge, keys: [{ keyId: "rp-wrong", publicKeyHex: otherPublicKeyHex, status: "active" }], now: nowInWindow }, "signature"),
    rej("no-usable-key-rejects-signature", "An empty candidate key set yields no usable active signing key, so the signature step rejects.", { challenge, keys: [], now: nowInWindow }, "signature"),
    rej("tampered-redirect-rejects-signature", "Changing redirectUri after signing to another value under the same origin keeps the schema valid but breaks the signature.", { challenge: { ...challenge, redirectUri: "https://rp.example/other" }, ...ctx }, "signature"),
    rej("tampered-nonce-rejects-signature", "Changing the nonce after signing breaks the signature.", { challenge: { ...challenge, nonce: "nonce-challenge-999999999" }, ...ctx }, "signature"),

    rej("unknown-top-level-key-rejects", "An unknown top-level field is rejected by the strict schema before verification.", { challenge: { ...challenge, extra: 1 }, ...ctx }, "schema"),
    rej("legacy-grant-type-rejects", "The challenge type is a single new spelling; the grant type is not accepted.", { challenge: { ...challenge, type: "network.ink.authorization_grant" }, ...ctx }, "schema"),
    rej("tulpa-challenge-type-rejects", "There is no legacy network.tulpa spelling of the challenge type; only network.ink.authorization_challenge is accepted.", { challenge: { ...challenge, type: "network.tulpa.authorization_challenge" }, ...ctx }, "schema"),
    rej("invalid-protocol-rejects", "A protocol other than ink/0.1 is out of profile and rejects.", { challenge: { ...challenge, protocol: "ink/0.2" }, ...ctx }, "schema"),
    rej("lone-surrogate-rejects", "A lone UTF-16 surrogate in a string field is not portable and rejects as schema before the signature.", { challenge: { ...challenge, nonce: loneSurrogateNonce }, ...ctx }, "schema"),

    rej("rp-path-segment-rejects", "A path-bearing did:web has no unambiguous origin and rejects as schema before the signature.", { challenge: { ...challenge, rp: "did:web:rp.example:path" }, ...ctx }, "schema"),
    rej("rp-uppercase-host-rejects", "An uppercase host label is not a bytewise-comparable A-label and rejects.", { challenge: { ...challenge, rp: "did:web:RP.example" }, ...ctx }, "schema"),
    rej("rp-all-digit-final-label-rejects", "A final label that is all digits is excluded, matching the hostname rule that a top-level label is never all-numeric.", { challenge: { ...challenge, rp: "did:web:rp.123" }, ...ctx }, "schema"),
    rej("rp-ipv4-literal-rejects", "A dotted-quad IPv4 literal fails the label grammar (its final label is all-numeric) and rejects.", { challenge: { ...challenge, rp: "did:web:192.168.0.1", redirectUri: "https://192.168.0.1/callback" }, ...ctx }, "schema"),
    rej("rp-explicit-443-rejects", "An explicit port 443 is out of profile because its derived origin would collide with the default.", { challenge: { ...challenge, rp: "did:web:rp.example%3A443", redirectUri: "https://rp.example:443/callback" }, ...ctx }, "schema"),
    rej("rp-lowercase-port-marker-rejects", "The port marker MUST be an uppercase %3A; a lowercase %3a leaves a percent in the host and rejects.", { challenge: { ...challenge, rp: "did:web:rp.example%3a8443", redirectUri: "https://rp.example:8443/callback" }, ...ctx }, "schema"),

    rej("scope-missing-identity-assert-rejects", "A requestedScope that does not include identity.assert is not a sign-in request and rejects.", { challenge: { ...challenge, requestedScope: ["profile.read"] }, ...ctx }, "schema"),
    rej("scope-unregistered-token-rejects", "A requestedScope entry outside the registry is malformed on the request side and rejects.", { challenge: { ...challenge, requestedScope: ["identity.assert", "admin:all"] }, ...ctx }, "schema"),
    rej("scope-duplicate-rejects", "A repeated requestedScope entry is rejected; entries must be distinct so two implementations count the same set.", { challenge: { ...challenge, requestedScope: ["identity.assert", "identity.assert"] }, ...ctx }, "schema"),
    rej("scope-empty-rejects", "A requestedScope with no entries is out of profile and rejects.", { challenge: { ...challenge, requestedScope: [] }, ...ctx }, "schema"),
    rej("scope-non-string-entry-rejects", "A requestedScope with a non-string entry rejects.", { challenge: { ...challenge, requestedScope: ["identity.assert", 1] }, ...ctx }, "schema"),

    rej("redirect-non-prefix-rejects", "A redirectUri that is not the derived RP origin plus / rejects under the literal prefix rule.", { challenge: { ...challenge, redirectUri: "https://evil.example/callback" }, ...ctx }, "schema"),
    rej("redirect-host-suffix-extension-rejects", "A redirectUri whose host merely extends the RP host is not the origin plus /, because the / defeats suffix extension, and rejects.", { challenge: { ...challenge, redirectUri: "https://rp.example.evil.com/callback" }, ...ctx }, "schema"),
    rej("redirect-no-slash-rejects", "A redirectUri equal to the origin with no trailing / rejects; the prefix is the origin followed immediately by /.", { challenge: { ...challenge, redirectUri: "https://rp.example" }, ...ctx }, "schema"),
    rej("redirect-fragment-rejects", "A redirectUri containing # is malformed: a fragment never reaches the completion endpoint.", { challenge: { ...challenge, redirectUri: "https://rp.example/callback#frag" }, ...ctx }, "schema"),
    rej("redirect-backslash-rejects", "A redirectUri containing a backslash is rejected; parsers disagree on backslash normalization.", { challenge: { ...challenge, redirectUri: "https://rp.example/call\\back" }, ...ctx }, "schema"),
    rej("redirect-control-char-rejects", "A redirectUri containing an ASCII control character is rejected; a control char that survives into a Location header is an injection primitive.", { challenge: { ...challenge, redirectUri: controlCharRedirect }, ...ctx }, "schema"),
    rej("redirect-whitespace-rejects", "A redirectUri containing ASCII whitespace is rejected; the string is not trimmed first.", { challenge: { ...challenge, redirectUri: "https://rp.example/call back" }, ...ctx }, "schema"),

    rej("nonce-too-short-rejects", "A nonce shorter than 16 code units is out of profile and rejects.", { challenge: { ...challenge, nonce: "short-nonce" }, ...ctx }, "schema"),
    rej("inverted-window-rejects", "A challenge whose expiresAt is not after issuedAt is malformed and rejects.", { challenge: { ...challenge, expiresAt: challengeBase.issuedAt }, ...ctx }, "schema"),
    rej("over-maximum-lifetime-rejects", "A window exceeding the ten-minute maximum lifetime is out of profile and rejects structurally, before the signature, even against a wrong key.", { challenge: { ...challenge, expiresAt: overCapExpiresAt }, keys: [{ keyId: "rp-wrong", publicKeyHex: otherPublicKeyHex, status: "active" }], now: challengeBase.issuedAt }, "schema"),
    rej("malformed-signature-rejects", "A signature that is not valid base64url of the right length is rejected.", { challenge: { ...challenge, signature: challenge.signature.slice(0, 85) + "+" }, ...ctx }, "schema"),
    rej("missing-signature-rejects", "A challenge with no signature field rejects.", { challenge: (() => { const { signature, ...rest } = challenge; return rest; })(), ...ctx }, "schema"),
    rej("invalid-issued-at-rejects", "A challenge whose issuedAt is not a strict INK timestamp rejects.", { challenge: { ...challenge, issuedAt: "2026-07-16 12:00" }, ...ctx }, "schema"),

    rej("expired-rejects", "A challenge verified after expiresAt is rejected.", { challenge, keys: activeKeys, now: "2026-07-16T12:06:00.000Z" }, "expired"),
    rej("expiry-upper-bound-rejects", "A challenge verified at exactly expiresAt is rejected (exclusive upper bound).", { challenge, keys: activeKeys, now: challengeBase.expiresAt }, "expired"),
    rej("not-yet-valid-rejects", "A challenge verified before issuedAt is rejected.", { challenge, keys: activeKeys, now: "2026-07-16T11:59:00.000Z" }, "not_yet_valid"),
    rej("invalid-now-rejects", "A verifier clock that is not a strict INK timestamp is a verifier input error and fails closed as schema, not a window verdict.", { challenge, keys: activeKeys, now: "not-a-timestamp" }, "schema"),

    // Verify-order pins: the signature is checked before the window, so a bad
    // signature outranks a window verdict. Paired with expired-rejects and
    // not-yet-valid-rejects (good signature) above, these prove signature precedes
    // window in both directions.
    rej("expired-with-bad-signature-rejects-signature", "A challenge with a tampered body verified after expiry rejects on the signature, not on expiry, pinning signature-before-window order.", { challenge: { ...challenge, nonce: "nonce-challenge-999999999" }, keys: activeKeys, now: "2026-07-16T12:06:00.000Z" }, "signature"),
    rej("not-yet-valid-with-bad-signature-rejects-signature", "A challenge with a tampered body verified before issuedAt rejects on the signature, not on the window.", { challenge: { ...challenge, nonce: "nonce-challenge-999999999" }, keys: activeKeys, now: "2026-07-16T11:59:00.000Z" }, "signature"),

    // Key-window boundary pins. The active-key validity window is inclusive at
    // both ends, evaluated at the verifier clock, matching the rotation verifier;
    // this is deliberately distinct from the challenge validity window, whose
    // upper bound is exclusive (expiry-upper-bound-rejects above).
    acc("key-valid-until-equals-now-accepts", "An active signing key whose validUntil equals the verifier clock is still usable (inclusive upper bound), so the challenge verifies.", { challenge, keys: [{ keyId: "rp-active", publicKeyHex, status: "active", validUntil: nowInWindow }], now: nowInWindow }, idBase),
    acc("key-valid-from-equals-now-accepts", "An active signing key whose validFrom equals the verifier clock is usable (inclusive lower bound), so the challenge verifies.", { challenge, keys: [{ keyId: "rp-active", publicKeyHex, status: "active", validFrom: nowInWindow }], now: nowInWindow }, idBase),

    // RP bare-host did:web parser edges. Each rejects as schema on the signed bytes
    // alone, by explicit string rules with no URL parsing, and TS and Go decide
    // identically (a divergence here would be a real interop bug).
    rej("rp-trailing-dot-host-rejects", "A trailing dot leaves an empty final label, which fails the label grammar, so the rp rejects.", { challenge: { ...challenge, rp: "did:web:rp.example." }, ...ctx }, "schema"),
    rej("rp-repeated-port-marker-rejects", "A second %3A in the port position is a malformed identifier and rejects.", { challenge: { ...challenge, rp: "did:web:rp.example%3A8443%3A9000" }, ...ctx }, "schema"),
    rej("rp-port-zero-rejects", "Port 0 is out of the 1..65535 range and rejects.", { challenge: { ...challenge, rp: "did:web:rp.example%3A0" }, ...ctx }, "schema"),
    rej("rp-port-65536-rejects", "Port 65536 is one past the maximum and rejects.", { challenge: { ...challenge, rp: "did:web:rp.example%3A65536" }, ...ctx }, "schema"),
    rej("rp-ipv6-bracket-rejects", "A bracketed IPv6 literal fails the label grammar (brackets and colons are not LDH), so it rejects without a separate exclusion.", { challenge: { ...challenge, rp: "did:web:[2001:db8::1]" }, ...ctx }, "schema"),
    rej("rp-percent-encoded-host-rejects", "A percent escape in the host (a percent-encoded dot) is malformed: the host carries no percent-encoding, so it rejects.", { challenge: { ...challenge, rp: "did:web:rp%2Eexample" }, ...ctx }, "schema"),

    // redirectUri parser edges under the literal-prefix rule with no URL parsing.
    rej("redirect-uppercase-origin-rejects", "The literal-prefix match is case-sensitive: an uppercase host in the redirectUri does not equal the derived lowercase origin and rejects.", { challenge: { ...challenge, redirectUri: "https://RP.EXAMPLE/callback" }, ...ctx }, "schema"),
    rej("redirect-trailing-dot-host-rejects", "A trailing dot on the redirectUri host breaks the literal prefix (the character after the origin is a dot, not /) and rejects.", { challenge: { ...challenge, redirectUri: "https://rp.example./callback" }, ...ctx }, "schema"),
    acc("redirect-query-only-accepts", "A redirectUri that is the origin plus / plus a query only (no path segment) satisfies the prefix rule and verifies.", { challenge: queryRedirectChallenge, ...ctx }),

    // Raw-body gate: cases carrying `challengeRaw`, the exact wire text, because
    // the rule under test is about bytes the parsed value no longer carries.
    acc("raw-challenge-accepts", "The same signed challenge presented as raw wire text verifies: whitespace between tokens is legal JSON and vanishes at canonicalization, so the signature still covers it.", { challengeRaw: chalPadded, ...ctx }),
    rej("shadowed-number-literal-rejects", "An out-of-range number literal shadowed by a later duplicate member rejects. Member semantics are last-wins, so the literal never reaches the parsed challenge and the signature over the canonical form still verifies; only a gate on the raw text sees it, and without one two implementations admit different byte strings for the same signed challenge.", { challengeRaw: chalShadowedNumber, ...ctx }, "schema"),
    rej("live-number-literal-rejects", "An out-of-range number literal in a live member rejects at the raw gate, before the schema can rule on the Infinity a lenient parser would hand it.", { challengeRaw: chalLiveNumber, ...ctx }, "schema"),
    acc("shadowed-underflow-accepts", "An underflowing exponent is in range: every IEEE-754 parser decodes 1e-400 to 0, so a shadowed one is not gated and the challenge behind it verifies. The gate is a range test, not a ban on exponents.", { challengeRaw: chalShadowedUnderflow, ...ctx }),
    rej("raw-lone-surrogate-escape-rejects", "A lone UTF-16 surrogate escape in the raw text rejects structurally, before the signature: a parser that rewrites it to U+FFFD would canonicalize something other than what was sent.", { challengeRaw: chalLoneSurrogate, ...ctx }, "schema"),

    der("derived-id-determinism", "The derived grantId over the four binding fields is deterministic and matches the pinned base64url-nopad SHA-256 digest.", challengeBase, idBase),
    der("derived-id-ignores-other-fields", "A challenge sharing the four binding fields but differing in requestedScope and redirectUri derives the identical id, so the binding is over exactly rp, nonce, issuedAt, and expiresAt.", { ...challengeBase, requestedScope: ["identity.assert"], redirectUri: "https://rp.example/other" }, idBase),
    der("derived-id-differs-on-rp", "A challenge differing only in rp derives a distinct id, so the same nonce at two RPs cannot collide.", { ...challengeBase, rp: "did:web:rp2.example" }, idDiffRp),
    der("derived-id-differs-on-nonce", "A challenge differing only in nonce derives a distinct id.", { ...challengeBase, nonce: "nonce-challenge-000000002" }, idDiffNonce),
    der("derived-id-differs-on-window", "A challenge differing only in its window derives a distinct id, so a reused nonce in a fresh window cannot collide.", { ...challengeBase, expiresAt: "2026-07-16T12:06:00.000Z" }, idDiffWindow),
  ]);
}

// ── authorization-header ───────────────────────────────────────────────────
// The INK-Ed25519 transport Authorization-header grammar (§3.3):
//   INK-Ed25519 <base64url(signature)> [keyId=<keyId>]
// The signature is exactly 86 base64url chars; keyId is optional, 1-128 chars
// from [A-Za-z0-9_:.-]. A runner parses the raw header value with the pure
// parser (parseInkAuthHeader / ParseInkAuthHeader) and pins the accept/reject
// decision, and on accept the extracted signature and any keyId. Both parsers
// use the identical anchored regex, so every input is decided byte for byte the
// same. `authSig` reuses the 86-char signature minted above; the variants below
// perturb exactly one aspect of the grammar so each vector isolates one rule.
const authSig = signature;
const authKeyId = "rp-2026-07";
const authKeyIdPunct = "did:web:rp.example.com_key-2026.07";
const authKeyId128 = "k".repeat(128);
const authKeyId129 = "k".repeat(129);
vectorFile("authorization-header", [
  {
    caseId: "valid-no-keyid-accepts",
    description: "A well-formed header with no keyId parameter parses; the 86-char base64url signature is extracted.",
    input: { header: `INK-Ed25519 ${authSig}` },
    expect: { result: "accept", signature: authSig },
  },
  {
    caseId: "valid-with-keyid-accepts",
    description: "A well-formed header with a keyId parameter extracts both the signature and the keyId.",
    input: { header: `INK-Ed25519 ${authSig} keyId=${authKeyId}` },
    expect: { result: "accept", signature: authSig, keyId: authKeyId },
  },
  {
    caseId: "keyid-with-allowed-punctuation-accepts",
    description: "A keyId using every allowed punctuation class ([_:.-]) is accepted and extracted verbatim.",
    input: { header: `INK-Ed25519 ${authSig} keyId=${authKeyIdPunct}` },
    expect: { result: "accept", signature: authSig, keyId: authKeyIdPunct },
  },
  {
    caseId: "keyid-128-chars-accepts",
    description: "A keyId of exactly 128 characters is at the upper bound and is accepted.",
    input: { header: `INK-Ed25519 ${authSig} keyId=${authKeyId128}` },
    expect: { result: "accept", signature: authSig, keyId: authKeyId128 },
  },
  {
    caseId: "empty-header-rejects",
    description: "An empty header value carries no authorization and is rejected as missing_authorization, distinct from a malformed scheme.",
    input: { header: "" },
    expect: { result: "reject", reason: "missing_authorization" },
  },
  {
    caseId: "wrong-scheme-bearer-rejects",
    description: "A Bearer scheme is not INK-Ed25519 and is rejected.",
    input: { header: `Bearer ${authSig}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "lowercase-scheme-rejects",
    description: "The scheme is case-sensitive; lowercase ink-ed25519 does not match and is rejected.",
    input: { header: `ink-ed25519 ${authSig}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "signature-85-chars-rejects",
    description: "A signature one character short of 86 is the wrong length and is rejected before any verification.",
    input: { header: `INK-Ed25519 ${authSig.slice(0, 85)}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "signature-87-chars-rejects",
    description: "A signature one character over 86 is the wrong length and is rejected; the anchors forbid a longer run.",
    input: { header: `INK-Ed25519 ${authSig}${authSig.slice(0, 1)}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "signature-plus-char-rejects",
    description: "A '+' is base64 but not base64url; an 86-char value containing it is rejected.",
    input: { header: `INK-Ed25519 ${authSig.slice(0, 85)}+` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "signature-slash-char-rejects",
    description: "A '/' is base64 but not base64url; an 86-char value containing it is rejected.",
    input: { header: `INK-Ed25519 ${authSig.slice(0, 85)}/` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "signature-padding-equals-rejects",
    description: "A '=' padding character is not part of the unpadded base64url alphabet and is rejected.",
    input: { header: `INK-Ed25519 ${authSig.slice(0, 85)}=` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "missing-space-rejects",
    description: "The scheme and signature run together with no separating space; the grammar requires a single space and rejects.",
    input: { header: `INK-Ed25519${authSig}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "double-space-rejects",
    description: "Two spaces between the scheme and signature is not the single-space grammar and is rejected.",
    input: { header: `INK-Ed25519  ${authSig}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "leading-space-rejects",
    description: "A leading space before the scheme breaks the start anchor and is rejected; the value is not trimmed first.",
    input: { header: ` INK-Ed25519 ${authSig}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "trailing-space-rejects",
    description: "A trailing space after the signature breaks the end anchor and is rejected.",
    input: { header: `INK-Ed25519 ${authSig} ` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "trailing-data-rejects",
    description: "Unparsed trailing data after the signature is rejected; the end anchor admits no extra tokens.",
    input: { header: `INK-Ed25519 ${authSig} extra` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "keyid-empty-rejects",
    description: "A keyId= parameter with no value is below the 1-char minimum and is rejected.",
    input: { header: `INK-Ed25519 ${authSig} keyId=` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "keyid-illegal-char-rejects",
    description: "A keyId containing a '/' is outside [A-Za-z0-9_:.-] and is rejected.",
    input: { header: `INK-Ed25519 ${authSig} keyId=bad/id` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "keyid-129-chars-rejects",
    description: "A keyId of 129 characters is one over the maximum and is rejected.",
    input: { header: `INK-Ed25519 ${authSig} keyId=${authKeyId129}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "embedded-lf-rejects",
    description: "A line feed embedded after the signature is rejected: the header is single-line and the end anchor does not match before a newline, so a parser cannot be tricked into a multiline value.",
    input: { header: `INK-Ed25519 ${authSig}\nkeyId=${authKeyId}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "embedded-cr-rejects",
    description: "A carriage return after the signature is rejected; CR is not admitted by the single-space grammar or the end anchor.",
    input: { header: `INK-Ed25519 ${authSig}\rkeyId=${authKeyId}` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
  {
    caseId: "second-unknown-param-rejects",
    description: "A second, unknown key=value parameter after a valid keyId is rejected; the grammar admits only the one optional keyId.",
    input: { header: `INK-Ed25519 ${authSig} keyId=${authKeyId} foo=bar` },
    expect: { result: "reject", reason: "invalid_auth_scheme" },
  },
]);


// ── attestation ─────────────────────────────────────────────────────────────
// The evidence primitive (specs/ink-attestation.md): an issuer signs a typed,
// bounded claim about a subject, valid for a window, verified from raw bytes.
// Each vector carries the attestation (or its exact wire text for raw-gate
// cases), the issuer public key hex, and the verifier clock. Base verification
// makes no policy judgment: signature, shape and window are the whole
// cross-implementation contract, and subject binding to a presenting card is a
// receiver-side rule pinned by the spec, not by these vectors.
{
  const attBase = {
    issuer: `ink:${mb}`,
    subject: "did:web:subject.example",
    claimType: "example.owner.verified_human",
    claim: { method: "in_person" },
    attestationId: "conformance-att-000000001",
    issuedAt: "2026-08-01T00:00:00.000Z",
    expiresAt: "2027-08-01T00:00:00.000Z",
  };
  const nowInWindow = "2026-09-01T00:00:00.000Z";
  const attestation = await buildAttestation(attBase, seed);
  const selfAtt = await buildAttestation({ ...attBase, subject: attBase.issuer, attestationId: "conformance-att-000000002" }, seed);
  const emptyClaim = await buildAttestation({ ...attBase, claim: {}, attestationId: "conformance-att-000000003" }, seed);
  const longWindow = await buildAttestation({ ...attBase, expiresAt: "2031-08-01T00:00:00.000Z", attestationId: "conformance-att-000000004" }, seed);
  const otherPublicKeyHex = bytesToHex(await ed.getPublicKeyAsync(new Uint8Array(32).fill(9)));

  const ctx = { issuerPublicKeyHex: publicKeyHex, now: nowInWindow };
  const acc = (caseId, description, input) => ({ caseId, description, input, expect: { result: "accept" } });
  const rej = (caseId, description, input, reason) => ({ caseId, description, input, expect: { result: "reject", reason } });

  // Raw-text cases mirror the grant category: the raw-body gate rules are about
  // bytes a parsed value has already lost, so these cases carry attestationRaw.
  const attText = JSON.stringify(attestation);
  const atShadowedNumber = `{"protocol":1e309,${attText.slice(1)}`;
  const atShadowedUnderflow = `{"protocol":1e-400,${attText.slice(1)}`;
  const atLoneSurrogate = attText.replace(`"subject":"${attBase.subject}"`, `"subject":"\\ud800${attBase.subject}"`);
  const atPadded = `{  ${attText.slice(1)}`;

  vectorFile("attestation", [
    acc("valid-attestation-accepts", "An attestation verified against the issuer key inside its window verifies.", { attestation, ...ctx }),
    acc("issued-at-lower-bound-accepts", "An attestation checked at exactly issuedAt is inside the window (inclusive lower bound).", { attestation, issuerPublicKeyHex: publicKeyHex, now: attBase.issuedAt }),
    acc("empty-claim-accepts", "An empty claim object is a well-formed claim; its meaning is the claim type's business.", { attestation: emptyClaim, ...ctx }),
    acc("self-attestation-accepts", "An attestation whose subject is its issuer is well-formed; what it is worth is receiver policy, not verification.", { attestation: selfAtt, ...ctx }),
    acc("multi-year-window-accepts", "A multi-year window verifies: unlike a grant, no maximum lifetime applies, and receivers discount long windows as policy.", { attestation: longWindow, ...ctx }),
    rej("wrong-issuer-key-rejects", "Verifying against a different public key fails the signature check.", { attestation, issuerPublicKeyHex: otherPublicKeyHex, now: nowInWindow }, "signature"),
    rej("tampered-subject-rejects", "Changing the subject after signing invalidates the signature; evidence cannot be re-pointed at another agent.", { attestation: { ...attestation, subject: "did:web:attacker.example" }, ...ctx }, "signature"),
    rej("tampered-claim-rejects", "Changing the claim payload after signing invalidates the signature; the payload is opaque to verification but fully covered by it.", { attestation: { ...attestation, claim: { method: "forged" } }, ...ctx }, "signature"),
    rej("bad-signature-with-expired-rejects-signature", "A tampered attestation presented after expiry still rejects on the signature, pinning signature-before-window ordering.", { attestation: { ...attestation, subject: "did:web:attacker.example" }, issuerPublicKeyHex: publicKeyHex, now: "2028-01-01T00:00:00.000Z" }, "signature"),
    rej("legacy-spelling-rejects", "network.tulpa.attestation is not a wire type: the attestation postdates the namespace migration and is single-spelling by design, unlike the dual-accept object types.", { attestation: { ...attestation, type: "network.tulpa.attestation" }, ...ctx }, "schema"),
    rej("unknown-type-rejects", "Any type other than network.ink.attestation rejects.", { attestation: { ...attestation, type: "network.ink.other" }, ...ctx }, "schema"),
    rej("unknown-top-level-key-rejects", "An unknown top-level member is rejected by the strict schema.", { attestation: { ...attestation, extra: 1 }, ...ctx }, "schema"),
    rej("short-attestation-id-rejects", "An attestationId shorter than 16 code units is out of profile.", { attestation: { ...attestation, attestationId: "short" }, ...ctx }, "schema"),
    rej("over-length-attestation-id-rejects", "An attestationId longer than 256 code units is out of profile.", { attestation: { ...attestation, attestationId: "a".repeat(257) }, ...ctx }, "schema"),
    rej("attestation-id-grammar-rejects", "An attestationId outside the [A-Za-z0-9_-] nonce grammar rejects.", { attestation: { ...attestation, attestationId: "bad!chars#in.this.id" }, ...ctx }, "schema"),
    rej("undotted-claim-type-rejects", "A claimType with no dot is outside the reverse-DNS-style grammar.", { attestation: { ...attestation, claimType: "nodots" }, ...ctx }, "schema"),
    rej("uppercase-claim-type-rejects", "A claimType with uppercase characters is outside the lowercase grammar.", { attestation: { ...attestation, claimType: "Example.Owner.Verified" }, ...ctx }, "schema"),
    rej("over-length-claim-type-rejects", "A claimType longer than 128 code units is out of profile.", { attestation: { ...attestation, claimType: "a." + "b".repeat(127) }, ...ctx }, "schema"),
    rej("non-object-claim-rejects", "A claim that is not a JSON object rejects; the payload slot is an object by shape.", { attestation: { ...attestation, claim: "string" }, ...ctx }, "schema"),
    rej("array-claim-rejects", "A claim that is a JSON array rejects; an array is not the object shape the slot pins.", { attestation: { ...attestation, claim: ["x"] }, ...ctx }, "schema"),
    rej("over-length-issuer-rejects", "An issuer longer than 512 code units is out of profile.", { attestation: { ...attestation, issuer: "i".repeat(513) }, ...ctx }, "schema"),
    rej("over-length-subject-rejects", "A subject longer than 512 code units is out of profile.", { attestation: { ...attestation, subject: "s".repeat(513) }, ...ctx }, "schema"),
    rej("inverted-window-rejects", "An attestation whose expiresAt is not strictly after issuedAt is malformed.", { attestation: { ...attestation, expiresAt: attBase.issuedAt }, ...ctx }, "schema"),
    rej("invalid-issued-at-rejects", "An issuedAt that is not a strict INK timestamp rejects.", { attestation: { ...attestation, issuedAt: "2026-08-01 00:00" }, ...ctx }, "schema"),
    rej("malformed-signature-rejects", "A signature that is not 86 base64url characters rejects structurally.", { attestation: { ...attestation, signature: attestation.signature.slice(0, 85) + "+" }, ...ctx }, "schema"),
    rej("missing-signature-rejects", "An attestation with no signature member rejects.", { attestation: (() => { const { signature, ...rest } = attestation; return rest; })(), ...ctx }, "schema"),
    rej("expiry-upper-bound-rejects", "An attestation checked at exactly expiresAt is rejected (exclusive upper bound).", { attestation, issuerPublicKeyHex: publicKeyHex, now: attBase.expiresAt }, "expired"),
    rej("expired-rejects", "An attestation checked after expiresAt is rejected as expired.", { attestation, issuerPublicKeyHex: publicKeyHex, now: "2028-01-01T00:00:00.000Z" }, "expired"),
    rej("not-yet-valid-rejects", "An attestation checked before issuedAt is rejected as not yet valid.", { attestation, issuerPublicKeyHex: publicKeyHex, now: "2026-07-31T23:59:59.000Z" }, "not_yet_valid"),
    rej("invalid-now-rejects", "A verifier clock that is not a strict INK timestamp is a verifier input error and fails closed as schema.", { attestation, issuerPublicKeyHex: publicKeyHex, now: "not-a-timestamp" }, "schema"),
    acc("raw-padded-accepts", "The same signed attestation presented as raw wire text with token whitespace verifies; whitespace vanishes at canonicalization.", { attestationRaw: atPadded, ...ctx }),
    rej("shadowed-number-literal-rejects", "An out-of-range number literal shadowed by a later duplicate member rejects at the raw gate; the parsed value never sees it and the signature still verifies, so only a byte gate refuses it.", { attestationRaw: atShadowedNumber, ...ctx }, "schema"),
    acc("shadowed-underflow-accepts", "A shadowed underflowing exponent decodes to 0 in every IEEE-754 parser, so it is in range and not gated.", { attestationRaw: atShadowedUnderflow, ...ctx }),
    rej("raw-lone-surrogate-escape-rejects", "A lone UTF-16 surrogate escape in the raw text rejects structurally before the signature.", { attestationRaw: atLoneSurrogate, ...ctx }, "schema"),
  ]);
}

writeManifest();
writeSchema();

console.log(`Wrote conformance/v1/vectors + manifest + schema for principal (key ${mb.slice(0, 12)}...).`);
