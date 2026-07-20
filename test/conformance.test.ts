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
  verifyAuthorizationChain,
  verifyAuthorizationChallenge,
  deriveChallengeGrantId,
  verifyAgentCardSignature,
  parseInkAuthHeader,
} from "../src/index.js";
import type { AgentCard, AgentCardVerifyOptions } from "../src/index.js";
import type { VerifiedOwnerStatus, GrantKey } from "../src/index.js";
import type { ChainIssuerKey } from "../src/index.js";
import type { AgentCardFetchInput } from "../src/index.js";
import type { CandidateKey } from "../src/index.js";

// Runs the versioned ink/1 conformance vectors against this reference
// implementation. The vectors are the cross-implementation contract: a second
// implementation must make the same accept/reject decisions on the same bytes.
// See conformance/v1/README.md.
const vectorsDir = fileURLToPath(new URL("../conformance/v1/vectors/", import.meta.url).href);

interface VectorCase {
  caseId: string;
  description: string;
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
      const { envelope, publicKeyHex } = input as { envelope: unknown; publicKeyHex: string };
      const ok = await verifyDiscoveryQueryEnvelope(envelope, hexToBytes(publicKeyHex));
      return { result: ok ? "accept" : "reject" };
    }
    case "authorization-grant": {
      const {
        grant,
        issuerPublicKeyHex,
        audience,
        now,
        presenter,
        seenGrants,
        revokedGrants,
        verifiedOwner,
        maxLifetimeMs,
      } = input as {
        grant: unknown;
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
      const revoked = revokedGrants ?? [];
      const result = await verifyAuthorizationGrant(grant, hexToBytes(issuerPublicKeyHex), {
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
    case "authorization-chain": {
      const {
        chain,
        issuerKeys,
        audience,
        now,
        presenter,
        seenGrants,
        revokedGrants,
        verifiedOwner,
      } = input as {
        chain: unknown;
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
      // reject the typed reason is pinned too.
      const keys: ChainIssuerKey[] = issuerKeys.map((k) => ({ publicKey: hexToBytes(k.publicKeyHex), status: k.status }));
      const revoked = revokedGrants ?? [];
      const result = await verifyAuthorizationChain(chain, {
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
      const { challenge } = input as { challenge: Record<string, unknown> };
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
      const result = await verifyAuthorizationChallenge(challenge, candidates, { now });
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
        const parsed = JSON.parse(input.bodyRaw as string);
        return { result: "accept", canonicalString: jcsCanonicalize(parsed) };
      } catch {
        return { result: "reject" };
      }
    }
    case "key-rotation": {
      const { signInput, signature, keys, hintKeyId } = input as {
        signInput: Parameters<typeof verifyInkSignatureWithKeys>[0];
        signature: string;
        keys: Array<{ keyId: string; publicKeyHex: string; status: CandidateKey["status"]; validFrom?: string; validUntil?: string; revokedAt?: string }>;
        hintKeyId?: string;
      };
      const candidates: CandidateKey[] = keys.map((k) => ({
        keyId: k.keyId,
        publicKey: hexToBytes(k.publicKeyHex),
        status: k.status,
        validFrom: k.validFrom,
        validUntil: k.validUntil,
        revokedAt: k.revokedAt,
      }));
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
    case "agent-card-signature": {
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
      if (reqEnv.protocol !== selected) return reject;
      if (reqEnv.intent !== "connection_request") return reject;
      if (!ConnectionRequestPayloadSchema.safeParse(reqEnv.payload).success) return reject;
      if (t.request.signInput.timestamp !== reqEnv.timestamp) return reject;
      // 4. request signature
      const reqOk = await verifyInkSignature(t.request.signInput, t.request.signature, hexToBytes(t.request.senderPublicKeyHex));
      if (!reqOk) return reject;
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
      if (respEnv.protocol !== selected) return reject;
      if (respEnv.intent !== "connection_response") return reject;
      const respPayload = ConnectionResponsePayloadSchema.safeParse(respEnv.payload);
      if (!respPayload.success || respPayload.data.status !== "accepted") return reject;
      if (t.response.signInput.timestamp !== respEnv.timestamp) return reject;
      // 7. response signature
      const respOk = await verifyInkSignature(t.response.signInput, t.response.signature, hexToBytes(t.response.receiverPublicKeyHex));
      if (!respOk) return reject;
      return { result: "accept", canonicalString: selected };
    }
    default:
      throw new Error(`unknown conformance category: ${category}`);
  }
}

const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();
const docs = files.map((f) => JSON.parse(readFileSync(vectorsDir + f, "utf8")) as { format: string; category: string; cases: VectorCase[] });

describe("ink/1 conformance vectors", () => {
  for (const doc of docs) {
    describe(doc.category, () => {
      it("declares the ink.conformance.v1 format", () => {
        expect(doc.format).toBe("ink.conformance.v1");
      });
      for (const c of doc.cases) {
        it(`${c.caseId}: ${c.description}`, async () => {
          const actual = await evaluate(doc.category, c.input);
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

  it("covers the kernel categories", () => {
    const categories = new Set(docs.map((d) => d.category));
    for (const required of ["principal-normalization", "signature-base", "jcs-number"]) {
      expect(categories.has(required), required).toBe(true);
    }
  });
});
