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
  hexToBytes,
} from "../src/index.js";
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
  expect: { result: "accept" | "reject"; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; epochMs?: number; canonicalString?: string };
}

type Outcome = { result: "accept" | "reject"; canonicalPrincipal?: string; keyStatus?: string; keyId?: string; epochMs?: number; canonicalString?: string };

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
