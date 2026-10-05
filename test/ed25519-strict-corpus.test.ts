/**
 * `verifyStrictEd25519` (src/crypto/ed25519-strict.ts, re-exported from
 * bin/ed25519-strict.mjs, the canonical implementation) against the
 * conformance corpus's own cofactor-confusion and non-canonical vectors.
 *
 * test/ed25519-strict-verify.test.ts builds its own small fixtures and
 * checks the function's logic directly; this file instead proves the
 * corpus vectors this package ships to other implementations (Go, a third
 * party) are themselves rejected by the function they are meant to pin.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";
import { buildSignatureBase } from "../src/index.js";
import { verifyStrictEd25519 } from "../src/crypto/ed25519-strict.js";

const CONFORMANCE_CASE_IDS = [
  "non-canonical-s-rejects",
  "non-canonical-public-key-encoding-rejects",
  "mixed-order-public-key-rejects",
];

const HERE = dirname(fileURLToPath(import.meta.url));

function loadConformanceCases() {
  const manifest = JSON.parse(
    readFileSync(join(HERE, "../conformance/v1/vectors/signature-base.json"), "utf-8"),
  ) as { cases: Array<{ caseId: string; input: { signInput: unknown; signature: string; publicKeyHex: string } }> };
  return manifest.cases.filter((c) => CONFORMANCE_CASE_IDS.includes(c.caseId));
}

describe("verifyStrictEd25519 against the conformance corpus", () => {
  const cases = loadConformanceCases();

  it("the corpus's cofactor-confusion and non-canonical vectors are present", () => {
    // If this is empty, the manifest was regenerated and lost the case IDs
    // this test keys on: a silent gap, not a pass.
    expect(cases.length).toBe(CONFORMANCE_CASE_IDS.length);
  });

  for (const c of cases) {
    it(`rejects ${c.caseId}`, async () => {
      const message = new TextEncoder().encode(buildSignatureBase(c.input.signInput as never));
      const signature = Buffer.from(c.input.signature, "base64url");
      const publicKey = Buffer.from(c.input.publicKeyHex, "hex");
      expect(await verifyStrictEd25519(signature, message, publicKey)).toBe(false);
    });
  }
});
