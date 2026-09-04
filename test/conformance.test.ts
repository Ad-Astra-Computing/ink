import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  canonicalAgentPrincipal,
  verifyInkSignature,
  verifyInkSignatureWithKeys,
  decryptInkPayload,
  jcsCanonicalize,
  checkReplay,
  parseInkTimestampMs,
  containsLoneSurrogateEscape,
  containsEscapedMemberName,
  parseSignedBodyBytes,
  verifyInclusionProof,
  verifyConsistencyProof,
  parseCheckpoint,
  formatCheckpoint,
  computeAuditMerkleLeafHash,
  verifyInclusionReceipt,
  verifyAuditQueryResponse,
  verifyAuditEventSignature,
  InkChallengeSchema,
  InkRejectionSchema,
  InkResolutionSchema,
  ConnectionRequestPayloadSchema,
  ConnectionResponsePayloadSchema,
  AgentCardSchema,
  evaluateAgentCardFetch,
  isPrivateHostname,
  agentSupportedProtocolVersions,
  hexToBytes,
  verifyDiscoveryQueryEnvelope,
  verifyAuthorizationGrant,
  verifyAttestation,
  parseEvidenceRefusal,
  verifyAuthorizationChain,
  verifyAuthorizationChallenge,
  deriveChallengeGrantId,
  verifyAgentCardSignature,
  parseInkAuthHeader,
  verifyInkAuth,
  buildAuthHeader,
  MessageEnvelopeSchema,
  verifyMessage,
} from "../src/index.js";
import type { AgentCard, AgentCardVerifyOptions } from "../src/index.js";
import type { VerifiedOwnerStatus, GrantKey, DiscoveryQueryKey } from "../src/index.js";
import type { ChainIssuerKey } from "../src/index.js";
import type { AgentCardFetchInput } from "../src/index.js";
import type { CandidateKey } from "../src/index.js";

// Runs the versioned ink/1 conformance vectors against this reference
// implementation. The vectors are the cross-implementation contract: a second
// implementation must make the same accept/reject decisions on the same bytes.
// See conformance/v1/README.md.
const v1Dir = fileURLToPath(new URL("../conformance/v1/", import.meta.url).href);
const vectorsDir = v1Dir + "vectors/";

interface OptionalBehavior {
  id: string;
  alternative: "accept" | "reject";
  spec: string;
  rationale: string;
}

// Which branch of each optional behavior THIS implementation takes. A case
// carrying `optionalBehavior` pins a decision the spec leaves to the
// implementation: `expect.result` is the branch the reference takes and
// `optionalBehavior.alternative` is the other conformant outcome. Every id in
// the corpus MUST appear here, and the runner asserts the declared branch
// exactly, so the category keeps its full discriminating power while a
// conformant implementation that takes the other branch stays conformant by
// editing one line here. A conformance report SHOULD publish this map.
const OPTIONAL_BEHAVIOR_POLICY: Record<string, "pinned" | "alternative"> = {
  // §4.2: a warm did:web verifier MAY continue when the resolver is
  // unreachable. The reference continues and emits card.anchor_unverified.
  "didweb-warm-resolver-unavailable": "pinned",
  // §6: cold acceptance of a forged chain extension is a documented residual,
  // not an obligation. The reference accepts and documents the residual.
  "cold-chain-extension-residual": "pinned",
};

interface VectorCase {
  caseId: string;
  description: string;
  optionalBehavior?: OptionalBehavior;
  input: Record<string, unknown>;
  expect: { result: "accept" | "reject"; reason?: string; auditEvent?: string; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; signature?: string; epochMs?: number; canonicalString?: string; leafHash?: string; derivedGrantId?: string };
}

type Outcome = { result: "accept" | "reject"; reason?: string; auditEvents?: string[]; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; signature?: string; epochMs?: number; canonicalString?: string; leafHash?: string; derivedGrantId?: string };

async function evaluate(category: string, input: Record<string, unknown>): Promise<Outcome> {
  switch (category) {
    case "principal-normalization": {
      try {
        return { result: "accept", canonicalPrincipal: canonicalAgentPrincipal(input.agentId as string) };
      } catch {
        return { result: "reject" };
      }
    }
    case "signature-base": {
      const { signInput, signature, publicKeyHex } = input as {
        signInput: Parameters<typeof verifyInkSignature>[0];
        signature: string;
        publicKeyHex: string;
      };
      const ok = await verifyInkSignature(signInput, signature, hexToBytes(publicKeyHex));
      return { result: ok ? "accept" : "reject" };
    }
    case "discovery-query-envelope": {
      const { envelope, envelopeRaw, publicKeyHex, audience, now, seenNonces } = input as {
        envelope?: unknown;
        envelopeRaw?: string;
        publicKeyHex: string;
        audience: string | string[];
        now: string;
        seenNonces?: DiscoveryQueryKey[];
      };
      // The verifier takes the raw body bytes, because the raw-body gate is a
      // rule about bytes a parsed value has already lost. A case that exercises
      // that gate carries `envelopeRaw`, the exact wire text; every other case
      // carries the envelope as a value and is serialized here the way a sender
      // would.
      const bodyText = envelopeRaw ?? JSON.stringify(envelope);
      // The directory context comes straight from the vector: its own identity
      // (one spelling or several), its clock and the (from, nonce) pairs it has
      // already burned. A verifier accepts iff the result is ok; on reject the
      // typed reason is pinned too.
      const result = await verifyDiscoveryQueryEnvelope(new TextEncoder().encode(bodyText), hexToBytes(publicKeyHex), {
        audience,
        now,
        seenNonces,
      });
      return result.ok ? { result: "accept" } : { result: "reject", reason: result.reason };
    }
    case "authorization-grant": {
      const {
        grant,
        grantRaw,
        issuerPublicKeyHex,
        audience,
        now,
        presenter,
        seenGrants,
        revokedGrants,
        verifiedOwner,
        maxLifetimeMs,
      } = input as {
        grant?: unknown;
        grantRaw?: string;
        issuerPublicKeyHex: string;
        audience: string;
        now: string;
        presenter?: string;
        seenGrants?: GrantKey[];
        revokedGrants?: GrantKey[];
        verifiedOwner?: VerifiedOwnerStatus;
        maxLifetimeMs?: number;
      };
      // Reconstruct the receiver context from the vector: the revocation list
      // becomes a denylist predicate keyed by the (issuer, grantId) pair, and the
      // seen set, presenter, and owner status pass through. A verifier accepts iff
      // the result is ok; on reject the typed reason is pinned too.
      // The verifier takes the raw body bytes, because the raw-body gate is a
      // rule about bytes a parsed value has already lost. A case that exercises
      // that gate carries `grantRaw`, the exact wire text; every other case
      // carries the grant as a value and is serialized here the way a presenter
      // would.
      const revoked = revokedGrants ?? [];
      const grantBody = new TextEncoder().encode(grantRaw ?? JSON.stringify(grant));
      const result = await verifyAuthorizationGrant(grantBody, hexToBytes(issuerPublicKeyHex), {
        audience,
        now,
        presenter,
        seenGrants,
        isRevoked: (key) => revoked.some((r) => r.issuer === key.issuer && r.grantId === key.grantId),
        verifiedOwner,
        maxLifetimeMs,
      });
      return result.ok ? { result: "accept" } : { result: "reject", reason: result.reason };
    }
    case "attestation": {
      const { attestation, attestationRaw, issuerPublicKeyHex, now } = input as {
        attestation?: unknown;
        attestationRaw?: string;
        issuerPublicKeyHex: string;
        now: string;
      };
      // Raw bytes in, same as the grant: raw-gate cases carry the exact wire
      // text, every other case serializes the value the way a presenter would.
      const attBody = new TextEncoder().encode(attestationRaw ?? JSON.stringify(attestation));
      const result = await verifyAttestation(attBody, hexToBytes(issuerPublicKeyHex), { now });
      return result.ok ? { result: "accept" } : { result: "reject", reason: result.reason };
    }
    case "agent-card-evidence": {
      // A case with an agentId exercises card-proof coverage of the evidence
      // members through the card-signature verifier; a case without one pins
      // clockless shape validation of attestations and evidencePolicy.
      if (input.agentId !== undefined) {
        const { card, agentId, options } = input as { card: AgentCard; agentId: string; options: AgentCardVerifyOptions };
        const r = await verifyAgentCardSignature(card, agentId, options);
        return { result: r.rejected ? "reject" : "accept", reason: r.reason };
      }
      return { result: AgentCardSchema.safeParse(input.card).success ? "accept" : "reject" };
    }
    case "evidence-refusal": {
      return { result: parseEvidenceRefusal(input.refusal).ok ? "accept" : "reject" };
    }
    case "authorization-chain": {
      const {
        chain,
        chainRaw,
        issuerKeys,
        audience,
        now,
        presenter,
        seenGrants,
        revokedGrants,
        verifiedOwner,
      } = input as {
        chain?: unknown;
        chainRaw?: string;
        issuerKeys: Array<{ publicKeyHex: string; status: ChainIssuerKey["status"] }>;
        audience: string;
        now: string;
        presenter?: string;
        seenGrants?: GrantKey[];
        revokedGrants?: GrantKey[];
        verifiedOwner?: VerifiedOwnerStatus;
      };
      // Reconstruct the receiver context: each link's resolved issuer key is
      // aligned root-first to `links`, the revocation list becomes a denylist
      // predicate keyed by the (issuer, grantId) pair, and the seen set, presenter,
      // and owner status pass through. A verifier accepts iff the result is ok; on
      // reject the typed reason is pinned too. The verifier takes the raw body
      // bytes: a case that exercises the raw-body gate carries `chainRaw`, the
      // exact wire text, and every other case carries the chain as a value.
      const keys: ChainIssuerKey[] = issuerKeys.map((k) => ({ publicKey: hexToBytes(k.publicKeyHex), status: k.status }));
      const revoked = revokedGrants ?? [];
      const chainBody = new TextEncoder().encode(chainRaw ?? JSON.stringify(chain));
      const result = await verifyAuthorizationChain(chainBody, {
        audience,
        now,
        issuerKeys: keys,
        presenter,
        seenGrants,
        isRevoked: (key) => revoked.some((r) => r.issuer === key.issuer && r.grantId === key.grantId),
        verifiedOwner,
      });
      return result.ok ? { result: "accept" } : { result: "reject", reason: result.reason };
    }
    case "agent-authorization": {
      // The verifier takes the raw body bytes: a case that exercises the
      // raw-body gate carries `challengeRaw`, the exact wire text, and every
      // other case carries the challenge as a value.
      const { challenge, challengeRaw } = input as {
        challenge?: Record<string, unknown>;
        challengeRaw?: string;
      };
      // A case with no `keys` is a derive-only case: it pins the exact
      // challenge-derived grantId for fixed inputs, independent of signature.
      if (input.keys === undefined) {
        const derivedGrantId = await deriveChallengeGrantId(
          challenge as { rp: string; nonce: string; issuedAt: string; expiresAt: string },
        );
        return { result: "accept", derivedGrantId };
      }
      const { keys, now } = input as {
        keys: Array<{ keyId: string; publicKeyHex: string; status: CandidateKey["status"]; validFrom?: string; validUntil?: string; revokedAt?: string }>;
        now: string;
      };
      const candidates: CandidateKey[] = keys.map((k) => ({
        keyId: k.keyId,
        publicKey: hexToBytes(k.publicKeyHex),
        status: k.status,
        validFrom: k.validFrom,
        validUntil: k.validUntil,
        revokedAt: k.revokedAt,
      }));
      const challengeBody = new TextEncoder().encode(challengeRaw ?? JSON.stringify(challenge));
      const result = await verifyAuthorizationChallenge(challengeBody, candidates, { now });
      if (!result.ok) return { result: "reject", reason: result.reason };
      // On accept, also derive the grantId so a vector can pin it: the answering
      // identity assertion adopts exactly this id as its grantId.
      const derivedGrantId = await deriveChallengeGrantId(result.challenge);
      return { result: "accept", derivedGrantId };
    }
    case "authorization-header": {
      const parsed = parseInkAuthHeader(input.header as string);
      if (!parsed.ok) return { result: "reject", reason: parsed.reason };
      return parsed.keyId !== undefined
        ? { result: "accept", signature: parsed.signature, keyId: parsed.keyId }
        : { result: "accept", signature: parsed.signature };
    }
    case "jcs-number": {
      try {
        // Through the signed-body gate, not a bare JSON.parse: the raw-text
        // rules (UTF-8, lone surrogates, out-of-range number literals) run
        // before parsing on a real signed body, and one of them decides a case
        // in this category that the value profile cannot see.
        const parsed = parseSignedBodyBytes(new TextEncoder().encode(input.bodyRaw as string));
        return { result: "accept", canonicalString: jcsCanonicalize(parsed) };
      } catch {
        return { result: "reject" };
      }
    }
    case "key-rotation": {
      const { signInput, signature, keys, hintKeyId, liveAuth, liveAuthAllowRetired } = input as {
        signInput: Parameters<typeof verifyInkSignatureWithKeys>[0];
        signature: string;
        keys: Array<{ keyId: string; publicKeyHex: string; status: CandidateKey["status"]; validFrom?: string; validUntil?: string; revokedAt?: string }>;
        hintKeyId?: string;
        liveAuth?: boolean;
        liveAuthAllowRetired?: boolean;
      };
      const candidates: CandidateKey[] = keys.map((k) => ({
        keyId: k.keyId,
        publicKey: hexToBytes(k.publicKeyHex),
        status: k.status,
        validFrom: k.validFrom,
        validUntil: k.validUntil,
        revokedAt: k.revokedAt,
      }));
      if (liveAuth) {
        // Live transport auth runs the production middleware, not the bare
        // primitive, so the retired-key default of §3.3 is exercised where it
        // actually lives. The vector timestamps are fixed, so the clock the
        // freshness check reads is pinned to the message instant; nothing else
        // about the middleware is stubbed.
        const messageMs = parseInkTimestampMs(signInput.timestamp);
        const realNow = Date.now;
        Date.now = () => messageMs ?? realNow();
        try {
          const auth = await verifyInkAuth({
            authHeader: buildAuthHeader(signature, hintKeyId),
            method: signInput.method,
            path: signInput.path,
            recipientAgentId: signInput.recipientDid,
            body: signInput.body as Record<string, unknown>,
            resolveKeySet: () => candidates,
            requireActiveKey: liveAuthAllowRetired ? false : undefined,
            nonceStore: "deferred",
          });
          return auth.valid
            ? { result: "accept", keyStatus: auth.keyStatus, keyId: auth.keyId }
            : { result: "reject", reason: auth.error };
        } finally {
          Date.now = realNow;
        }
      }
      const r = await verifyInkSignatureWithKeys(signInput, signature, candidates, hintKeyId);
      return { result: r.verified ? "accept" : "reject", keyStatus: r.keyStatus, keyId: r.keyId };
    }
    case "replay-freshness": {
      const r = checkReplay(input.replay as Parameters<typeof checkReplay>[0]);
      return { result: r.accepted ? "accept" : "reject" };
    }
    case "timestamp-validity": {
      const ms = parseInkTimestampMs(input.timestamp);
      if (ms === null) return { result: "reject" };
      return { result: "accept", epochMs: ms };
    }
    case "jcs-string-safety": {
      const reject = containsLoneSurrogateEscape(input.bodyRaw as string);
      return { result: reject ? "reject" : "accept" };
    }
    case "signed-body-member-name": {
      const reject = containsEscapedMemberName(input.bodyRaw as string);
      return { result: reject ? "reject" : "accept" };
    }
    case "signed-body-utf8": {
      try {
        parseSignedBodyBytes(hexToBytes(input.bodyHex as string));
        return { result: "accept" };
      } catch {
        return { result: "reject" };
      }
    }
    case "merkle-inclusion": {
      const { leafHash, inclusionProof, leafIndex, treeSize, rootHash } = input as {
        leafHash: string;
        inclusionProof: string[];
        leafIndex: number;
        treeSize: number;
        rootHash: string;
      };
      const ok = await verifyInclusionProof(leafHash, inclusionProof, leafIndex, treeSize, rootHash);
      return { result: ok ? "accept" : "reject" };
    }
    case "merkle-consistency": {
      const { first, firstRoot, second, secondRoot, proof } = input as {
        first: number;
        firstRoot: string;
        second: number;
        secondRoot: string;
        proof: string[];
      };
      const ok = await verifyConsistencyProof(first, firstRoot, second, secondRoot, proof);
      return { result: ok ? "accept" : "reject" };
    }
    case "merkle-checkpoint": {
      const parsed = parseCheckpoint(input.body as string);
      if (!parsed) return { result: "reject" };
      return { result: "accept", canonicalString: formatCheckpoint(parsed) };
    }
    case "merkle-leaf": {
      try {
        if (containsLoneSurrogateEscape(input.eventRaw as string)) return { result: "reject" };
        const parsed = JSON.parse(input.eventRaw as string);
        return { result: "accept", leafHash: await computeAuditMerkleLeafHash(parsed) };
      } catch {
        return { result: "reject" };
      }
    }
    case "handshake-message": {
      const message = input.message as { type?: unknown };
      const t = typeof message?.type === "string" ? message.type : "";
      // Dispatch on the type SUFFIX so both the legacy network.tulpa.* and the
      // vendor-neutral network.ink.* spellings route to the same schema, which
      // itself dual-accepts (ink/0.4). Mirrors the Go ValidateHandshakeMessage.
      const suffix = t.startsWith("network.tulpa.") ? t.slice("network.tulpa.".length)
        : t.startsWith("network.ink.") ? t.slice("network.ink.".length) : "";
      const schema =
        suffix === "challenge" ? InkChallengeSchema :
        suffix === "rejection" ? InkRejectionSchema :
        suffix === "resolution" ? InkResolutionSchema : null;
      if (schema === null) return { result: "reject" };
      return { result: schema.safeParse(message).success ? "accept" : "reject" };
    }
    case "connection-payload": {
      const { kind, payload } = input as { kind: string; payload: unknown };
      const schema =
        kind === "connection_request" ? ConnectionRequestPayloadSchema :
        kind === "connection_response" ? ConnectionResponsePayloadSchema : null;
      if (schema === null) return { result: "reject" };
      return { result: schema.safeParse(payload).success ? "accept" : "reject" };
    }
    case "agent-card": {
      return { result: AgentCardSchema.safeParse(input.card).success ? "accept" : "reject" };
    }
    case "agent-card-fetch": {
      return { result: evaluateAgentCardFetch(input as unknown as AgentCardFetchInput).accepted ? "accept" : "reject" };
    }
    case "agent-card-signature":
    case "agent-card-signature-phase-c": {
      const { card, agentId, options } = input as { card: AgentCard; agentId: string; options: AgentCardVerifyOptions };
      const r = await verifyAgentCardSignature(card, agentId, options);
      return { result: r.rejected ? "reject" : "accept", reason: r.reason, auditEvents: r.auditEvents };
    }
    case "private-hostname": {
      // accept = public/safe (isPrivateHostname false); reject = private/unsafe.
      return { result: isPrivateHostname(input.hostname as string) ? "reject" : "accept" };
    }
    case "audit-query-response": {
      const { response, witnessPublicKeyHex, expectedRequester, expectedMessageId, expectedServiceDid, laterCheckpoint, agentKeysHex } = input as {
        response: Parameters<typeof verifyAuditQueryResponse>[0]["response"];
        witnessPublicKeyHex: string;
        expectedRequester: string;
        expectedMessageId: string;
        expectedServiceDid?: string;
        laterCheckpoint?: { treeSize: number; rootHash: string };
        agentKeysHex: Record<string, string>;
      };
      const r = await verifyAuditQueryResponse({
        response,
        witnessPublicKey: hexToBytes(witnessPublicKeyHex),
        expectedRequester,
        expectedMessageId,
        expectedServiceDid,
        laterCheckpoint,
        verifyEventSignature: async (event) => {
          const agentId = (event as { agentId?: unknown }).agentId;
          if (typeof agentId !== "string") return false;
          const keyHex = agentKeysHex[agentId];
          if (typeof keyHex !== "string") return false;
          return verifyAuditEventSignature(event, hexToBytes(keyHex));
        },
      });
      return { result: r.valid ? "accept" : "reject" };
    }
    case "inclusion-receipt": {
      const { receipt, witnessPublicKeyHex, event, eventHash, laterCheckpoint } = input as {
        receipt: Parameters<typeof verifyInclusionReceipt>[0]["receipt"];
        witnessPublicKeyHex: string;
        event?: Record<string, unknown>;
        eventHash?: string;
        laterCheckpoint?: { treeSize: number; rootHash: string };
      };
      const r = await verifyInclusionReceipt({
        receipt,
        witnessPublicKey: hexToBytes(witnessPublicKeyHex),
        event,
        eventHash,
        laterCheckpoint,
      });
      return { result: r.valid ? "accept" : "reject" };
    }
    case "payload-encryption": {
      const { envelope, recipientPrivateKeyHex, recipientDid } = input as {
        envelope: Parameters<typeof decryptInkPayload>[0];
        recipientPrivateKeyHex: string;
        recipientDid?: string;
      };
      try {
        // recipientDid is required; a vector that omits it passes "" so the
        // mandatory-recipient reject fires (matches a nil pointer in the Go port).
        const plaintext = await decryptInkPayload(envelope, recipientPrivateKeyHex, recipientDid ?? "");
        // Accept pins the exact decrypted plaintext as canonical bytes, so a
        // verifier that decrypts to different bytes (or accepts a tampered
        // envelope) diverges. Reject is any thrown error.
        return { result: "accept", canonicalString: jcsCanonicalize(plaintext) };
      } catch {
        return { result: "reject" };
      }
    }
    case "first-contact-transcript": {
      const t = input as {
        cardFetch: AgentCardFetchInput;
        clientSupportedVersions: string[];
        receiverClock: string;
        seenNonces: string[];
        request: { signInput: Parameters<typeof verifyInkSignature>[0]; signature: string; senderPublicKeyHex: string };
        response: { signInput: Parameters<typeof verifyInkSignature>[0]; signature: string; receiverPublicKeyHex: string };
      };
      // Compose the pinned primitives in order; any failed step rejects the
      // whole transcript. See specs/ink-first-contact-transcript.md.
      const reject = { result: "reject" } as const;
      // 1. discovery
      const fetched = evaluateAgentCardFetch(t.cardFetch);
      if (!fetched.accepted || fetched.card === null) return reject;
      // 2. version selection
      const advertised = agentSupportedProtocolVersions(fetched.card);
      const selected = t.clientSupportedVersions.find((v) => advertised.includes(v));
      if (selected === undefined) return reject;
      // 3. request agreement
      const reqEnv = t.request.signInput.body as Record<string, unknown>;
      // 3a. envelope structure (§3.1): every intent envelope carries protocol,
      // id, correlationId, createdAt, from, to, intent, payload and signature,
      // and no unknown top-level member. A receiver validates this before it
      // spends any signature work, so the transcript pins it here.
      if (!MessageEnvelopeSchema.safeParse(reqEnv).success) return reject;
      if (reqEnv.protocol !== selected) return reject;
      if (reqEnv.intent !== "connection_request") return reject;
      if (!ConnectionRequestPayloadSchema.safeParse(reqEnv.payload).success) return reject;
      if (t.request.signInput.timestamp !== reqEnv.timestamp) return reject;
      // 3b. endpoint binding: the signed PATH is the path component of the
      // card's endpoint. INK reserves no fixed inbound path, so the card is
      // the only thing binding sender and receiver to one spelling.
      let cardPath: string;
      try {
        cardPath = new URL(fetched.card.endpoint).pathname;
      } catch {
        return reject;
      }
      if (t.request.signInput.path !== cardPath) return reject;
      // 4. request signatures: the §3.3 transport signature over the delivered
      // body, and the §3.6 body signature the envelope carries, both against the
      // sender's key.
      const reqOk = await verifyInkSignature(t.request.signInput, t.request.signature, hexToBytes(t.request.senderPublicKeyHex));
      if (!reqOk) return reject;
      if (!(await verifyMessage(reqEnv, hexToBytes(t.request.senderPublicKeyHex)))) return reject;
      // 5. replay / freshness
      const replay = checkReplay({
        messageTimestamp: reqEnv.timestamp as string,
        receiverClock: t.receiverClock,
        nonce: reqEnv.nonce as string,
        previouslySeenNonces: t.seenNonces,
      });
      if (!replay.accepted) return reject;
      // 6. response agreement
      const respEnv = t.response.signInput.body as Record<string, unknown>;
      if (!MessageEnvelopeSchema.safeParse(respEnv).success) return reject;
      if (respEnv.protocol !== selected) return reject;
      if (respEnv.intent !== "connection_response") return reject;
      const respPayload = ConnectionResponsePayloadSchema.safeParse(respEnv.payload);
      if (!respPayload.success || respPayload.data.status !== "accepted") return reject;
      if (t.response.signInput.timestamp !== respEnv.timestamp) return reject;
      // 7. response signatures, transport and body, against the receiver's key.
      const respOk = await verifyInkSignature(t.response.signInput, t.response.signature, hexToBytes(t.response.receiverPublicKeyHex));
      if (!respOk) return reject;
      if (!(await verifyMessage(respEnv, hexToBytes(t.response.receiverPublicKeyHex)))) return reject;
      return { result: "accept", canonicalString: selected };
    }
    default:
      throw new Error(`unknown conformance category: ${category}`);
  }
}

const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();
const docs = files.map((f) => JSON.parse(readFileSync(vectorsDir + f, "utf8")) as { format: string; category: string; cases: VectorCase[] });

// A `staged` category is anchored in the manifest but is not yet a conformance
// obligation: it pins a rule that becomes required on a scheduled date. It runs
// only in the dedicated staged job, so a default `npm test` exercises exactly
// the categories it exercised before the staged category existed. Staged-ness is
// read from the manifest rather than from a hardcoded category name, so retagging
// the category to `base` at the flip is all it takes to fold it into every run.
const manifest = JSON.parse(readFileSync(v1Dir + "manifest.json", "utf8")) as {
  categories: { id: string; profile: string }[];
};
const stagedCategories = new Set(manifest.categories.filter((c) => c.profile === "staged").map((c) => c.id));
const runStaged = process.env.INK_STAGED_CONFORMANCE === "1";
const runnable = docs.filter((d) => runStaged || !stagedCategories.has(d.category));

describe("ink/1 conformance vectors", () => {
  // A real tripwire, not a comment: it binds the mode to what actually got
  // registered, so neither a staged category leaking into a default run nor a
  // staged category silently skipping in the staged job can pass unnoticed.
  it("registers the staged categories only under INK_STAGED_CONFORMANCE=1", () => {
    expect(stagedCategories.size).toBeGreaterThan(0);
    const registered = new Set(runnable.map((d) => d.category));
    for (const id of stagedCategories) {
      expect(registered.has(id), id).toBe(runStaged);
    }
  });

  for (const doc of runnable) {
    describe(doc.category, () => {
      it("declares the ink.conformance.v1 format", () => {
        expect(doc.format).toBe("ink.conformance.v1");
      });
      for (const c of doc.cases) {
        it(`${c.caseId}: ${c.description}`, async () => {
          const actual = await evaluate(doc.category, c.input);
          if (c.optionalBehavior !== undefined) {
            const branch = OPTIONAL_BEHAVIOR_POLICY[c.optionalBehavior.id];
            // An undeclared optional behavior is a drift failure, not a pass:
            // an implementation must state which branch it takes.
            expect(branch, `${c.caseId}: undeclared optional behavior ${c.optionalBehavior.id}`).toBeDefined();
            expect(c.optionalBehavior.alternative, c.caseId).not.toBe(c.expect.result);
            if (branch === "alternative") {
              // This implementation takes the other conformant branch: the
              // outcome is pinned to the alternative and the reference's
              // reason/audit expectations do not apply.
              expect(actual.result, c.caseId).toBe(c.optionalBehavior.alternative);
              return;
            }
          }
          expect(actual.result, c.caseId).toBe(c.expect.result);
          if (c.expect.reason !== undefined) {
            expect(actual.reason, c.caseId).toBe(c.expect.reason);
          }
          if (c.expect.auditEvent !== undefined) {
            expect(actual.auditEvents ?? [], c.caseId).toContain(c.expect.auditEvent);
          }
          if (c.expect.canonicalPrincipal !== undefined) {
            expect(actual.canonicalPrincipal, c.caseId).toBe(c.expect.canonicalPrincipal);
          }
          if (c.expect.keyStatus !== undefined) {
            expect(actual.keyStatus, c.caseId).toBe(c.expect.keyStatus);
          }
          if (c.expect.keyId !== undefined) {
            expect(actual.keyId, c.caseId).toBe(c.expect.keyId);
          }
          if (c.expect.signature !== undefined) {
            expect(actual.signature, c.caseId).toBe(c.expect.signature);
          }
          if (c.expect.epochMs !== undefined) {
            expect(actual.epochMs, c.caseId).toBe(c.expect.epochMs);
          }
          if (c.expect.canonicalString !== undefined) {
            expect(actual.canonicalString, c.caseId).toBe(c.expect.canonicalString);
          }
          if (c.expect.leafHash !== undefined) {
            expect(actual.leafHash, c.caseId).toBe(c.expect.leafHash);
          }
          if (c.expect.derivedGrantId !== undefined) {
            expect(actual.derivedGrantId, c.caseId).toBe(c.expect.derivedGrantId);
          }
        });
      }
    });
  }

  // Only the runners that consult OPTIONAL_BEHAVIOR_POLICY can honor the tag.
  // Tagging a case in any other category would silently pin one branch again, so
  // the honoring set is frozen here and grows only with a runner that reads it.
  const OPTIONAL_BEHAVIOR_CATEGORIES = new Set(["agent-card-signature", "agent-card-signature-phase-c"]);

  it("declares every optional behavior in the corpus and tags it only where a runner honors it", () => {
    const seen = new Set<string>();
    for (const doc of docs) {
      for (const c of doc.cases) {
        if (c.optionalBehavior === undefined) continue;
        expect(OPTIONAL_BEHAVIOR_CATEGORIES.has(doc.category), `${doc.category}/${c.caseId}`).toBe(true);
        expect(OPTIONAL_BEHAVIOR_POLICY[c.optionalBehavior.id], c.caseId).toBeDefined();
        expect(c.optionalBehavior.alternative, c.caseId).not.toBe(c.expect.result);
        seen.add(c.optionalBehavior.id);
      }
    }
    // No stale declaration either: a policy entry with no case left in the
    // corpus is a decision recorded about nothing.
    for (const id of Object.keys(OPTIONAL_BEHAVIOR_POLICY)) {
      expect(seen.has(id), id).toBe(true);
    }
  });

  it("covers the kernel categories", () => {
    const categories = new Set(docs.map((d) => d.category));
    for (const required of ["principal-normalization", "signature-base", "jcs-number"]) {
      expect(categories.has(required), required).toBe(true);
    }
  });
});
