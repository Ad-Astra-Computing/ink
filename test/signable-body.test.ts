import { describe, it, expect } from "vitest";
import {
  buildSignatureBase,
  signInkMessage,
  verifyInkSignature,
  computeMessageHash,
  signMessage,
  verifyMessage,
  generateKeypair,
} from "../src/index.js";

/** An interface, not a Record. Declared interfaces have no index signature,
 * so this is the shape that used to need a cast at every call site. */
interface Receiptish {
  protocol: "ink/0.1";
  type: "network.tulpa.receipt";
  messageId: string;
  nonce: string;
  timestamp: string;
}

const receipt: Receiptish = {
  protocol: "ink/0.1",
  type: "network.tulpa.receipt",
  messageId: "01JABCDEF0123456789ABCDEFG",
  nonce: "5f3a9c1d",
  timestamp: "2026-09-05T00:00:00.000Z",
};

const base = {
  method: "POST",
  path: "/ink/v1/submit",
  recipientDid: "did:web:example.com",
  timestamp: receipt.timestamp,
};

describe("signing accepts the package's own declared types", () => {
  it("builds a signature base from an interface-typed body without a cast", () => {
    const sigBase = buildSignatureBase({ ...base, body: receipt });
    expect(sigBase.startsWith("ink/0.1\nPOST\n")).toBe(true);
    expect(sigBase).toContain('"messageId":"01JABCDEF0123456789ABCDEFG"');
  });

  it("signs and verifies an interface-typed body", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const sig = await signInkMessage({ ...base, body: receipt }, privateKey);
    expect(await verifyInkSignature({ ...base, body: receipt }, sig, publicKey)).toBe(true);
  });

  it("hashes an interface-typed body", async () => {
    expect(await computeMessageHash(receipt)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("signs and verifies an interface-typed message", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const sig = await signMessage(receipt, privateKey);
    expect(await verifyMessage({ ...receipt, signature: sig }, publicKey)).toBe(true);
  });
});

describe("a widened body type still rejects what is not a JSON object", () => {
  const notObjects: unknown[] = [[], [1, 2, 3], new Date(0), new Map(), () => 1];

  it("refuses a non-object signature-base body", () => {
    for (const body of notObjects) {
      expect(() => buildSignatureBase({ ...base, body: body as object })).toThrow(
        /signature-base body/i,
      );
    }
  });

  it("refuses a non-object message hash body", async () => {
    for (const body of notObjects) {
      await expect(computeMessageHash(body as object)).rejects.toThrow(/message body/i);
    }
  });

  it("refuses a non-object signed message", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    for (const message of notObjects) {
      await expect(signMessage(message as object, privateKey)).rejects.toThrow();
      expect(await verifyMessage(message as object, publicKey)).toBe(false);
    }
  });
});
