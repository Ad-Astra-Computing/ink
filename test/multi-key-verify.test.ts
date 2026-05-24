import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import { signInkMessage, type InkSignInput } from "../src/crypto/ink.js";
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
  body: { from: "tulpa:zSender", type: "connection_request", timestamp: "2026-03-25T00:00:00Z" },
  timestamp: "2026-03-25T00:00:00Z",
};

describe("verifyInkSignatureWithKeys", () => {
  it("verifies signature by current active key", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-a", publicKey: kp.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("sig-a");
  });

  it("verifies signature by retired key", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-old", publicKey: kp.publicKey, status: "retired" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("sig-old");
    expect(result.usedRetiredKey).toBe(true);
  });

  it("rejects signature by revoked key", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-revoked", publicKey: kp.publicKey, status: "revoked" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects signature by unknown key", async () => {
    const signerKp = await makeKeypair();
    const otherKp = await makeKeypair();
    const signature = await signInkMessage(testInput, signerKp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-other", publicKey: otherKp.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(false);
  });

  it("returns { verified: false } for empty key set", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const result = await verifyInkSignatureWithKeys(testInput, signature, []);
    expect(result.verified).toBe(false);
  });

  it("tries active keys before retired keys", async () => {
    const activeKp = await makeKeypair();
    const retiredKp = await makeKeypair();
    const signature = await signInkMessage(testInput, activeKp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-retired", publicKey: retiredKp.publicKey, status: "retired" },
      { keyId: "sig-active", publicKey: activeKp.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("sig-active");
  });

  it("falls through to retired key when active keys dont match", async () => {
    const retiredKp = await makeKeypair();
    const activeKp = await makeKeypair();
    const signature = await signInkMessage(testInput, retiredKp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-active", publicKey: activeKp.publicKey, status: "active" },
      { keyId: "sig-retired", publicKey: retiredKp.publicKey, status: "retired" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("sig-retired");
    expect(result.usedRetiredKey).toBe(true);
  });

  it("sets usedRetiredKey false when verified with active key", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-a", publicKey: kp.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.usedRetiredKey).toBe(false);
  });

  it("sets usedRetiredKey true when verified via hinted retired key", async () => {
    const kp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-old", publicKey: kp.publicKey, status: "retired" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys, "sig-old");
    expect(result.verified).toBe(true);
    expect(result.usedRetiredKey).toBe(true);
  });

  it("skips revoked keys even if signature would match", async () => {
    const kp = await makeKeypair();
    const otherKp = await makeKeypair();
    const signature = await signInkMessage(testInput, kp.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "sig-revoked", publicKey: kp.publicKey, status: "revoked" },
      { keyId: "sig-active", publicKey: otherKp.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(false);
  });
});
