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
import { signMessage, verifyMessage, hexToBytes } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "test-vectors", "body-signature.json");
const goGoldensPath = join(here, "..", "go", "ink", "testdata", "body-signature-producer.json");

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

/**
 * The Go producer goldens are this implementation's output, committed as Go
 * testdata so the second implementation's signer can be compared byte for byte.
 * They are only meaningful while they still equal what signMessage emits today,
 * so this suite regenerates each signature and pins it. A change to signing that
 * did not regenerate the goldens fails here rather than silently making the Go
 * comparison test a check against a stale file.
 */
interface ProducerGolden {
  description: string;
  body: Record<string, unknown>;
  signature: string;
}

const goldens = JSON.parse(readFileSync(goGoldensPath, "utf-8")) as {
  signerPrivateKeySeedHex: string;
  signerPublicKeyHex: string;
  cases: ProducerGolden[];
};

describe("body-signature producer goldens (Go testdata)", () => {
  const privateKey = hexToBytes(goldens.signerPrivateKeySeedHex);

  it("covers both body-signature domains", () => {
    const isV02 = (c: ProducerGolden) => c.body.protocol === "ink/0.2";
    expect(goldens.cases.some(isV02)).toBe(true);
    expect(goldens.cases.some((c) => !isV02(c))).toBe(true);
  });

  for (const c of goldens.cases) {
    it(`reproduces: ${c.description}`, async () => {
      expect(await signMessage(c.body, privateKey)).toBe(c.signature);
      const { signature: _drop, ...unsigned } = c.body;
      expect(await verifyMessage({ ...unsigned, signature: c.signature }, hexToBytes(goldens.signerPublicKeyHex))).toBe(
        true,
      );
    });
  }
});
