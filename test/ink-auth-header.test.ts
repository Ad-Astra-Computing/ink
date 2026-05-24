import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { buildAuthHeader, signInkMessage, type InkSignInput } from "../src/crypto/ink.js";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { MessageEnvelopeSchema } from "../src/models/intent.js";
import type { CandidateKey } from "../src/models/key-entry.js";

async function makeKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

const testInput: InkSignInput = {
  method: "POST",
  path: "/ink/v1/test/intent",
  recipientDid: "tulpa:zRecipient",
  body: { from: "tulpa:zSender", type: "connection_request", timestamp: new Date().toISOString() },
  timestamp: new Date().toISOString(),
};

// Ed25519 signatures are 64 bytes = exactly 86 unpadded base64url chars.
// buildAuthHeader now validates this length, so tests must use a valid-length placeholder.
const MOCK_SIG_86 = "A".repeat(86);

describe("INK Auth Header — keyId extension", () => {
  it("buildAuthHeader without keyId returns legacy format", () => {
    const header = buildAuthHeader(MOCK_SIG_86);
    expect(header).toBe(`INK-Ed25519 ${MOCK_SIG_86}`);
    expect(header).not.toContain("keyId=");
  });

  it("buildAuthHeader with keyId includes keyId parameter", () => {
    const header = buildAuthHeader(MOCK_SIG_86, "sig-2026-03");
    expect(header).toBe(`INK-Ed25519 ${MOCK_SIG_86} keyId=sig-2026-03`);
  });

  it("verifyInkAuth parses keyId from extended auth header", async () => {
    const kp = await makeKeypair();
    const body = {
      from: "tulpa:zSender",
      type: "connection_request",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };
    const sig = await signInkMessage(input, kp.privateKey);
    const header = buildAuthHeader(sig, "sig-new");

    const result = await verifyInkAuth({
      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-new", publicKey: kp.publicKey, status: "active" as const },
      ],
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.keyId).toBe("sig-new");
    }
  });

  it("hintKeyId tries hinted key first (optimization)", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const sig = await signInkMessage(testInput, keyB.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "active" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
    ];

    // With hintKeyId="key-b", should find key-b directly
    const result = await verifyInkSignatureWithKeys(testInput, sig, keys, "key-b");
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("key-b");
  });

  it("legacy auth header (no keyId) still works", async () => {
    const kp = await makeKeypair();
    const body = {
      from: "tulpa:zSender",
      type: "connection_request",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };
    const sig = await signInkMessage(input, kp.privateKey);
    // Legacy header — no keyId
    const header = `INK-Ed25519 ${sig}`;

    const result = await verifyInkAuth({
      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-only", publicKey: kp.publicKey, status: "active" as const },
      ],
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.keyId).toBe("sig-only");
    }
  });

  it("MessageEnvelopeSchema accepts signingKeyId as optional field", () => {
    const validEnvelope = {
      protocol: "ink/0.1",
      id: "test-id",
      correlationId: "corr-id",
      createdAt: new Date().toISOString(),
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      intent: "ping",
      payload: {},
      signature: "sig-data",
      signingKeyId: "sig-2026-03",
    };
    const parsed = MessageEnvelopeSchema.parse(validEnvelope);
    expect(parsed.signingKeyId).toBe("sig-2026-03");

    // Without signingKeyId should also work
    const { signingKeyId, ...withoutKeyId } = validEnvelope;
    const parsedLegacy = MessageEnvelopeSchema.parse(withoutKeyId);
    expect(parsedLegacy.signingKeyId).toBeUndefined();
  });
});
