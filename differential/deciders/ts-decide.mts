// The TypeScript decider.
//
// Reads NDJSON cases on stdin, one `{caseId, surface, input}` per line, and
// writes one NDJSON decision per line. It is a batch runner rather than a
// subprocess per case: process startup dominates the cost of every one of these
// decisions, so batching is what makes a million-case budget tractable.
//
// It calls only the package's public entry point, the same surface an adopter
// gets from `import ... from "@ink/..."`. It never reaches into a module that
// `src/index.ts` does not export, because a divergence found through a private
// path is a divergence no adopter can hit.
//
// Decoding rules that must match the Go decider byte for byte are marked
// MIRRORED. They are input plumbing, never a security decision: an input that
// cannot be decoded is failed closed to `reject` on both sides.

import { createInterface } from "node:readline";
import {
  canonicalAgentPrincipal,
  parseInkTimestampMs,
  parseInkAuthHeader,
  parseSignedBodyBytes,
  jcsCanonicalize,
  verifyInkSignature,
  AgentCardSchema,
  evaluateAgentCardFetch,
  isPrivateHostname,
  parseCheckpoint,
  formatCheckpoint,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyDiscoveryQueryEnvelope,
} from "../../src/index.js";
import type { AgentCardFetchInput, DiscoveryQueryKey } from "../../src/index.js";

type Decision = {
  caseId: string;
  result: "accept" | "reject";
  reason?: string;
  canonicalPrincipal?: string;
  canonicalString?: string;
  epochMs?: number;
  signature?: string;
  keyId?: string;
};

const REJECT = { result: "reject" } as const;

/** MIRRORED: hex to bytes.
 *
 * This is bridge decoding, so it uses the platform decoder rather than the
 * library's own hexToBytes. hexToBytes carries an encode-size cap that Go's
 * encoding/hex does not, and a cap on the transport would show up as a
 * disagreement about a payload neither library ever saw. Deliberately the same
 * rule as Go's hex.DecodeString: even length, hex alphabet, or nothing. */
function fromHex(hex: unknown): Uint8Array | null {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/** MIRRORED: a JSON number is usable as an index only when it is integral. */
function asInt(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) ? v : null;
}

async function decide(surface: string, input: Record<string, unknown>): Promise<Omit<Decision, "caseId">> {
  switch (surface) {
    case "signed-body-canonical": {
      try {
        const parsed = parseSignedBodyBytes(new TextEncoder().encode(input.bodyRaw as string));
        return { result: "accept", canonicalString: jcsCanonicalize(parsed) };
      } catch {
        return REJECT;
      }
    }
    case "signed-body-utf8": {
      try {
        parseSignedBodyBytes(fromHex(input.bodyHex) ?? new Uint8Array());
        return { result: "accept" };
      } catch {
        return REJECT;
      }
    }
    case "signature-base": {
      const key = fromHex(input.publicKeyHex);
      if (key === null) return REJECT;
      const si = input.signInput as Parameters<typeof verifyInkSignature>[0];
      try {
        const ok = await verifyInkSignature(si, input.signature as string, key);
        return ok ? { result: "accept" } : REJECT;
      } catch {
        return REJECT;
      }
    }
    case "principal-normalization": {
      try {
        return { result: "accept", canonicalPrincipal: canonicalAgentPrincipal(input.agentId as string) };
      } catch {
        return REJECT;
      }
    }
    case "timestamp-validity": {
      const ms = parseInkTimestampMs(input.timestamp as string);
      return ms === null ? REJECT : { result: "accept", epochMs: ms };
    }
    case "authorization-header": {
      const parsed = parseInkAuthHeader(input.header as string);
      if (!parsed.ok) return { result: "reject", reason: parsed.reason };
      return parsed.keyId !== undefined
        ? { result: "accept", signature: parsed.signature, keyId: parsed.keyId }
        : { result: "accept", signature: parsed.signature };
    }
    case "agent-card": {
      return { result: AgentCardSchema.safeParse(input.card).success ? "accept" : "reject" };
    }
    case "agent-card-fetch": {
      const fetchInput: AgentCardFetchInput = {
        status: input.status as number,
        contentType: (input.contentType ?? null) as string | null,
        contentLength: (input.contentLength ?? null) as string | null,
        bodyRaw: input.bodyRaw as string,
        requestedAgentId: input.requestedAgentId as string,
        resolutionDid: (input.resolutionDid ?? null) as string | null,
      };
      try {
        return { result: evaluateAgentCardFetch(fetchInput).accepted ? "accept" : "reject" };
      } catch {
        return REJECT;
      }
    }
    case "private-hostname": {
      // accept means the destination is public, matching the conformance category.
      return { result: isPrivateHostname(input.hostname as string) ? "reject" : "accept" };
    }
    case "merkle-checkpoint": {
      const parsed = parseCheckpoint(input.body as string);
      if (!parsed) return REJECT;
      return { result: "accept", canonicalString: formatCheckpoint(parsed) };
    }
    case "merkle-inclusion": {
      const leafIndex = asInt(input.leafIndex);
      const treeSize = asInt(input.treeSize);
      if (leafIndex === null || treeSize === null) return REJECT;
      try {
        const ok = await verifyInclusionProof(
          input.leafHash as string,
          input.inclusionProof as string[],
          leafIndex,
          treeSize,
          input.rootHash as string,
        );
        return ok ? { result: "accept" } : REJECT;
      } catch {
        return REJECT;
      }
    }
    case "merkle-consistency": {
      const first = asInt(input.first);
      const second = asInt(input.second);
      if (first === null || second === null) return REJECT;
      try {
        const ok = await verifyConsistencyProof(
          first,
          input.firstRoot as string,
          second,
          input.secondRoot as string,
          input.proof as string[],
        );
        return ok ? { result: "accept" } : REJECT;
      } catch {
        return REJECT;
      }
    }
    case "discovery-query-envelope": {
      const key = fromHex(input.publicKeyHex);
      if (key === null) return REJECT;
      // Both entry points take the raw body bytes, so both see the same input
      // and the reason code is comparable on every case, including a body that
      // is not JSON at all.
      const envelope = new TextEncoder().encode(input.envelopeRaw as string);
      try {
        const r = await verifyDiscoveryQueryEnvelope(envelope, key, {
          audience: input.audience as string | string[],
          now: input.now as string,
          seenNonces: input.seenNonces as DiscoveryQueryKey[] | undefined,
        });
        return r.ok ? { result: "accept" } : { result: "reject", reason: r.reason };
      } catch {
        return REJECT;
      }
    }
    default:
      throw new Error(`ts-decide: unknown surface ${surface}`);
  }
}

// Fault injection for the harness's own negative control. When INK_DIFF_MUTANT
// names a surface, this decider inverts its answer on that surface only. It
// exists so `run.mjs --self-test` can prove the comparison actually reports a
// disagreement: a differential harness that has never seen one is
// indistinguishable from a broken one. It is off unless the variable is set.
const MUTANT = process.env.INK_DIFF_MUTANT ?? "";

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
const out: string[] = [];
for await (const line of rl) {
  if (line.trim() === "") continue;
  const c = JSON.parse(line) as { caseId: string; surface: string; input: Record<string, unknown> };
  let decision: Omit<Decision, "caseId">;
  try {
    decision = await decide(c.surface, c.input);
  } catch (err) {
    // A throw the surface did not model is reported, never silently rejected:
    // an unhandled crash on one side is itself a divergence worth seeing.
    decision = { result: "reject", reason: `__harness_error:${(err as Error).message}` };
  }
  if (MUTANT !== "" && c.surface === MUTANT) {
    decision = { ...decision, result: decision.result === "accept" ? "reject" : "accept" };
  }
  out.push(JSON.stringify({ caseId: c.caseId, ...decision }));
  if (out.length >= 512) {
    process.stdout.write(out.join("\n") + "\n");
    out.length = 0;
  }
}
if (out.length > 0) process.stdout.write(out.join("\n") + "\n");
