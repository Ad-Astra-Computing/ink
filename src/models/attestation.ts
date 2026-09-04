import { z } from "zod";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";
import { hasUnpairedSurrogate } from "../crypto/surrogate.js";
import { parseSignedBodyBytes } from "../crypto/parse-signed-body.js";
import { verifyDetachedSignatureWithKeys, type MultiKeyVerifyResult } from "../crypto/multi-key-verify.js";
import type { CandidateKey } from "./key-entry.js";

// A signed claim by one principal about another, the evidence primitive of
// specs/ink-attestation.md. It is not a capability: it binds no audience, no
// presenter and no scope, and base verification passes no judgment on the
// issuer or the claim. Whether a verified attestation means anything is the
// receiver's policy decision, made after verification.

const ID_MAX = 512;
const ATTESTATION_ID_MIN = 16;
const ATTESTATION_ID_MAX = 256;
const CLAIM_TYPE_MIN = 3;
const CLAIM_TYPE_MAX = 128;

// Grammar per the spec: a lowercase reverse-DNS-style dotted name for claim
// types, the shared nonce grammar for attestation ids.
const CLAIM_TYPE_RE = /^[a-z0-9]+(\.[a-z0-9_]+)+$/;
const ATTESTATION_ID_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Byte-length ceiling on a raw attestation body, enforced before decoding, in
 * the same position and for the same reason as the grant cap: JSON permits
 * unbounded whitespace between tokens and whitespace vanishes at
 * canonicalization, so a padded body still carries a verifying signature and
 * must be refused on size alone.
 */
export const MAX_ATTESTATION_BODY_BYTES = 65536;

// The window must be strictly positive. Unlike a grant there is no maximum
// lifetime: a claim about a subject is not a capability, and a receiver
// discounts long windows as policy rather than the schema refusing them.
function isWindowPositive(a: { issuedAt: string; expiresAt: string }): boolean {
  const start = parseInkTimestampMs(a.issuedAt);
  const end = parseInkTimestampMs(a.expiresAt);
  if (start === null || end === null) return false;
  return end > start;
}

export const AttestationSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    // Single spelling by design: the object postdates the namespace migration,
    // so no legacy network.tulpa.* form exists to accept.
    type: z.literal("network.ink.attestation"),
    issuer: z.string().min(1).max(ID_MAX),
    subject: z.string().min(1).max(ID_MAX),
    claimType: z.string().min(CLAIM_TYPE_MIN).max(CLAIM_TYPE_MAX).regex(CLAIM_TYPE_RE),
    // Opaque to the base verifier: bounds-checked and canonicalized, never
    // interpreted. Meaning belongs to the claim type.
    claim: z.record(z.string(), z.unknown()),
    attestationId: z
      .string()
      .min(ATTESTATION_ID_MIN)
      .max(ATTESTATION_ID_MAX)
      .regex(ATTESTATION_ID_RE),
    issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict()
  .refine(isWindowPositive, { message: "expiresAt must be strictly after issuedAt" });

const UnsignedAttestationSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: z.literal("network.ink.attestation"),
    issuer: z.string().min(1).max(ID_MAX),
    subject: z.string().min(1).max(ID_MAX),
    claimType: z.string().min(CLAIM_TYPE_MIN).max(CLAIM_TYPE_MAX).regex(CLAIM_TYPE_RE),
    claim: z.record(z.string(), z.unknown()),
    attestationId: z
      .string()
      .min(ATTESTATION_ID_MIN)
      .max(ATTESTATION_ID_MAX)
      .regex(ATTESTATION_ID_RE),
    issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
  })
  .strict()
  .refine(isWindowPositive, { message: "expiresAt must be strictly after issuedAt" });

export type Attestation = z.infer<typeof AttestationSchema>;

export const ClaimTypeSchema = z
  .string()
  .min(CLAIM_TYPE_MIN)
  .max(CLAIM_TYPE_MAX)
  .regex(CLAIM_TYPE_RE);

// A claim-type array is a set: distinct entries, satisfied by one credited
// attestation of the type, never by a count.
const ClaimTypeSetSchema = z
  .array(ClaimTypeSchema)
  .min(1)
  .max(32)
  .refine((s) => new Set(s).size === s.length, { message: "claim types must be distinct" });

// The receiver's advance evidence statement on its card. Unknown members pass
// through so the card proof covers them; they carry no meaning here.
export const EvidencePolicySchema = z
  .object({
    required: ClaimTypeSetSchema.optional(),
    preferred: ClaimTypeSetSchema.optional(),
  })
  .passthrough();

export type EvidencePolicy = z.infer<typeof EvidencePolicySchema>;

// The structured refusal a receiver returns when required evidence is missing:
// the standard endpoint error body carrying the policy:evidence_required code
// and the conjunctive residual set of missing claim types. A sender parses it
// from an arbitrary receiver, so unknown members pass through.
export const EvidenceRefusalSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    error: z.literal(true),
    code: z.literal("policy:evidence_required"),
    requiredClaimTypes: ClaimTypeSetSchema,
    message: z.string().max(500).optional(),
  })
  .passthrough();

export type EvidenceRefusal = z.infer<typeof EvidenceRefusalSchema>;

export type EvidenceRefusalParseResult =
  | { ok: true; refusal: EvidenceRefusal }
  | { ok: false };

/** Parse a candidate evidence refusal body. Never throws. */
export function parseEvidenceRefusal(value: unknown): EvidenceRefusalParseResult {
  const parsed = EvidenceRefusalSchema.safeParse(value);
  return parsed.success ? { ok: true, refusal: parsed.data } : { ok: false };
}

export interface AttestationInput {
  issuer: string;
  subject: string;
  claimType: string;
  claim: Record<string, unknown>;
  attestationId: string;
  issuedAt: string;
  expiresAt: string;
}

export type AttestationVerifyResult =
  | { ok: true; attestation: Attestation }
  | { ok: false; reason: "schema" | "signature" | "not_yet_valid" | "expired" };

export interface AttestationVerifyContext {
  /** The verifier clock, a strict INK timestamp. */
  now: string;
}

/**
 * Build a signed attestation. The unsigned object is validated before signing,
 * so an out-of-grammar claim type or an inverted window is refused at build
 * time rather than producing a signature over an out-of-profile document.
 */
export async function buildAttestation(
  input: AttestationInput,
  issuerPrivateKey: Uint8Array,
): Promise<Attestation> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: "network.ink.attestation" as const,
    issuer: input.issuer,
    subject: input.subject,
    claimType: input.claimType,
    claim: input.claim,
    attestationId: input.attestationId,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  };
  UnsignedAttestationSchema.parse(unsigned);
  if (!isWithinBounds(unsigned)) {
    throw new Error("attestation exceeds the signed-body structural bounds");
  }
  const signature = await signMessage(unsigned, issuerPrivateKey);
  return { ...unsigned, signature };
}

export type AttestationVerifyWithKeysResult = AttestationVerifyResult & Partial<MultiKeyVerifyResult>;

/**
 * Shared raw-bytes gate, schema parse, surrogate scan, signature step
 * (delegated to `verifySignature`), and validity-window check for an
 * attestation. `beforeSignature`, when given, runs after the surrogate scan
 * and before the signature step; returning a non-null reason fails closed
 * without trying the signature. `verifyAttestation` and
 * `verifyAttestationWithKeys` differ only in how the signature is checked
 * (and, for the WithKeys path, the extra `beforeSignature` artifact-clock
 * gate), so both delegate here.
 */
async function verifyAttestationCore(
  raw: Uint8Array,
  context: AttestationVerifyContext,
  verifySignature: (attestation: Attestation) => Promise<MultiKeyVerifyResult>,
  beforeSignature?: (attestation: Attestation) => "schema" | null,
): Promise<AttestationVerifyWithKeysResult> {
  try {
    if (!ArrayBuffer.isView(raw) || !(raw instanceof Uint8Array)) {
      return { ok: false, reason: "schema" };
    }
    if (raw.length > MAX_ATTESTATION_BODY_BYTES) {
      return { ok: false, reason: "schema" };
    }
    let value: unknown;
    try {
      value = parseSignedBodyBytes(raw);
    } catch {
      return { ok: false, reason: "schema" };
    }
    if (!isWithinBounds(value)) {
      return { ok: false, reason: "schema" };
    }
    const parsed = AttestationSchema.safeParse(value);
    if (!parsed.success) {
      return { ok: false, reason: "schema" };
    }
    const attestation = parsed.data;
    if (hasUnpairedSurrogate(attestation)) {
      return { ok: false, reason: "schema" };
    }
    if (beforeSignature) {
      const problem = beforeSignature(attestation);
      if (problem !== null) {
        return { ok: false, reason: problem };
      }
    }
    const result = await verifySignature(attestation);
    if (!result.verified) {
      return { ok: false, reason: "signature" };
    }
    const start = parseInkTimestampMs(attestation.issuedAt);
    const end = parseInkTimestampMs(attestation.expiresAt);
    if (start === null || end === null) {
      return { ok: false, reason: "schema" };
    }
    const nowMs = parseInkTimestampMs(context.now);
    if (nowMs === null) {
      return { ok: false, reason: "schema" };
    }
    if (nowMs < start) {
      return { ok: false, reason: "not_yet_valid" };
    }
    if (nowMs >= end) {
      return { ok: false, reason: "expired" };
    }
    return result.keyId !== undefined
      ? {
          ok: true,
          attestation,
          keyId: result.keyId,
          keyStatus: result.keyStatus,
          usedRetiredKey: result.usedRetiredKey,
        }
      : { ok: true, attestation };
  } catch {
    return { ok: false, reason: "schema" };
  }
}

/**
 * Verify an attestation from its raw bytes against the resolved issuer key.
 * The input is the raw body, never a parsed value: the raw-body gate of
 * ink-signed-string-safety.md runs on bytes that no longer exist after
 * parsing. Check order per the spec, first failure wins: raw gate and parse,
 * structural bounds and grammar, signature, validity window (lower bound
 * inclusive, upper bound exclusive). Deliberately absent: audience, replay
 * and any judgment about the issuer or the claim. Never throws.
 */
export async function verifyAttestation(
  raw: Uint8Array,
  issuerPublicKey: Uint8Array,
  context: AttestationVerifyContext,
): Promise<AttestationVerifyResult> {
  return verifyAttestationCore(raw, context, async (attestation) => ({
    verified: await verifyMessage(attestation, issuerPublicKey),
  }));
}

/**
 * Verify an attestation from its raw bytes against a rotation-aware
 * candidate issuer key set. Security considerations §"Issuer key rotation"
 * (ink-attestation.md): an attestation verifies under the same rotation
 * rules as any other signed body, a retired issuer key still verifies an
 * attestation issued inside that key's validity window, and a revoked
 * issuer key never verifies, even for an attestation whose `issuedAt`
 * predates the revocation.
 *
 * The artifact clock is `issuedAt`, the moment the issuer signed the
 * claim, i.e. the same field the validity-window check below uses as its
 * lower bound, not `context.now` (the verifier's clock, used only to
 * judge freshness against `expiresAt`). Mirrors `verifyAttestation` byte
 * for byte otherwise; only the signature step is rotation-aware.
 */
export async function verifyAttestationWithKeys(
  raw: Uint8Array,
  keys: CandidateKey[],
  context: AttestationVerifyContext,
  opts?: { hintKeyId?: string },
): Promise<AttestationVerifyWithKeysResult> {
  return verifyAttestationCore(
    raw,
    context,
    (attestation) => {
      // Non-null: `beforeSignature` below already rejected a null parse.
      const artifactMs = parseInkTimestampMs(attestation.issuedAt)!;
      return verifyDetachedSignatureWithKeys(
        (publicKey) => verifyMessage(attestation, publicKey),
        keys,
        artifactMs,
        opts?.hintKeyId,
      );
    },
    (attestation) => (parseInkTimestampMs(attestation.issuedAt) === null ? "schema" : null),
  );
}
