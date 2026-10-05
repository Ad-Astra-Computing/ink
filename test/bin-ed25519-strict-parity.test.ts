/**
 * `bin/ed25519-strict.mjs` is a second copy of the shared RFC 8032 strict
 * Ed25519 verifier. It exists because the CLI must run from a git checkout
 * with no `dist/`, so it cannot import the library's copy. A second copy of
 * a security-critical verifier is exactly the drift this release fixed
 * elsewhere (two CLI call sites in bin/verify-inclusion-impl.mjs called the
 * library's cofactored check directly until this was caught), so it is held
 * in step here rather than by care: the two copies are run against one
 * table, including the conformance corpus's own cofactor-confusion vectors,
 * and must agree on every case.
 *
 * If this fails, one side was changed and the other was not. Fix the copy,
 * do not relax the test.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { buildSignatureBase } from "../src/index.js";
import { verifyStrictEd25519 as libVerify } from "../src/crypto/ed25519-strict.js";
import * as binEd25519Strict from "../bin/ed25519-strict.mjs";

const binVerify = binEd25519Strict.verifyStrictEd25519;

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

describe("bin/ed25519-strict.mjs matches the library verifier", () => {
  const cases = loadConformanceCases();

  it("the conformance corpus's cofactor-confusion vectors are present", () => {
    // If this is empty, the manifest was regenerated and lost the case IDs
    // this test keys on: a silent gap, not a pass.
    expect(cases.length).toBe(CONFORMANCE_CASE_IDS.length);
  });

  for (const c of cases) {
    it(`agrees on ${c.caseId}`, async () => {
      const message = new TextEncoder().encode(buildSignatureBase(c.input.signInput as never));
      const signature = Buffer.from(c.input.signature, "base64url");
      const publicKey = Buffer.from(c.input.publicKeyHex, "hex");

      const libResult = await libVerify(signature, message, publicKey);
      const binResult = await binVerify(signature, message, publicKey);

      expect(binResult).toBe(libResult);
      // Every case in CONFORMANCE_CASE_IDS is a rejection vector; a flipped
      // expectation here would mean the fixture changed under this test.
      expect(libResult).toBe(false);
    });
  }

  it("agrees on an ordinary valid signature", async () => {
    const seed = ed.utils.randomSecretKey();
    const publicKey = await ed.getPublicKeyAsync(seed);
    const message = new TextEncoder().encode("bin/src ed25519-strict parity, ordinary signature");
    const signature = await ed.signAsync(message, seed);

    expect(await binVerify(signature, message, publicKey)).toBe(true);
    expect(await libVerify(signature, message, publicKey)).toBe(true);
  });

  it("agrees on a tampered signature", async () => {
    const seed = ed.utils.randomSecretKey();
    const publicKey = await ed.getPublicKeyAsync(seed);
    const message = new TextEncoder().encode("bin/src ed25519-strict parity, tampered signature");
    const signature = await ed.signAsync(message, seed);
    const tampered = new Uint8Array(signature);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;

    expect(await binVerify(tampered, message, publicKey)).toBe(false);
    expect(await libVerify(tampered, message, publicKey)).toBe(false);
  });
});
