import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  canonicalAgentPrincipal,
  verifyInkSignature,
  verifyInkSignatureWithKeys,
  jcsCanonicalize,
  checkReplay,
  parseInkTimestampMs,
  containsLoneSurrogateEscape,
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
  hexToBytes,
} from "../src/index.js";
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
  expect: { result: "accept" | "reject"; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; epochMs?: number; canonicalString?: string; leafHash?: string };
}

type Outcome = { result: "accept" | "reject"; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; epochMs?: number; canonicalString?: string; leafHash?: string };

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
      const schema =
        t === "network.tulpa.challenge" ? InkChallengeSchema :
        t === "network.tulpa.rejection" ? InkRejectionSchema :
        t === "network.tulpa.resolution" ? InkResolutionSchema : null;
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
          if (c.expect.canonicalPrincipal !== undefined) {
            expect(actual.canonicalPrincipal, c.caseId).toBe(c.expect.canonicalPrincipal);
          }
          if (c.expect.keyStatus !== undefined) {
            expect(actual.keyStatus, c.caseId).toBe(c.expect.keyStatus);
          }
          if (c.expect.keyId !== undefined) {
            expect(actual.keyId, c.caseId).toBe(c.expect.keyId);
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
