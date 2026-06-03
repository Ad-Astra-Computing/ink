/**
 * Conformance: every body-signature vector verifies exactly as declared.
 *
 * Runs test-vectors/body-signature.json through the real verifyMessage so
 * the published vectors and the implementation can never drift. These are
 * the permanent regression + cross-version + tamper cases for the
 * version-keyed body-signature domain.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyMessage, hexToBytes } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "test-vectors", "body-signature.json");

interface Vector {
  description: string;
  input: { body: Record<string, unknown>; signerPublicKeyHex: string };
  expected: { signatureVerifies: boolean };
}

const doc = JSON.parse(readFileSync(vectorsPath, "utf-8")) as { vectors: Vector[] };

describe("body-signature.json conformance", () => {
  it("has the expected coverage (valid + cross-version + tamper)", () => {
    expect(doc.vectors.length).toBeGreaterThanOrEqual(7);
    expect(doc.vectors.some((v) => v.expected.signatureVerifies)).toBe(true);
    expect(doc.vectors.some((v) => !v.expected.signatureVerifies)).toBe(true);
  });

  for (const v of doc.vectors) {
    it(v.description, async () => {
      const publicKey = hexToBytes(v.input.signerPublicKeyHex);
      const result = await verifyMessage(v.input.body, publicKey);
      expect(result).toBe(v.expected.signatureVerifies);
    });
  }
});
