/**
 * Security regression tests — round 7.
 *
 * Findings:
 *  1. decryptInkPayload: no AES-GCM nonce (IV) length validation — non-12-byte nonce
 *     causes an unhandled exception rather than a clean rejection
 *  2. InkAuditSubmitSchema: `from` and `to` fields have no .max() cap, enabling
 *     storage-DoS via oversized strings that pass schema validation
 */
import { describe, it, expect } from "vitest";
import {
  encryptInkPayload,
  decryptInkPayload,
  type InkEncryptedEnvelope,
} from "../src/crypto/ink.js";
import { generateEncryptionKeypair, deriveAgentId } from "../src/crypto/keys.js";
import * as ed from "@noble/ed25519";
import { InkAuditSubmitSchema } from "../src/models/ink-audit.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Finding 1: decryptInkPayload AES nonce length validation ──

describe("decryptInkPayload: AES nonce length validation", () => {
  it("rejects envelope with AES nonce that is not 12 bytes (too short)", async () => {
    const encKp = generateEncryptionKeypair();
    const sigKp = ed.utils.randomPrivateKey();
    const sigPub = await ed.getPublicKeyAsync(sigKp);
    const agentId = deriveAgentId(sigPub);

    // Encrypt a real envelope first so we have valid outer fields
    const recipientPubHex = toHex(encKp.publicKey);
    const { envelope } = await encryptInkPayload(
      { from: agentId, to: "tulpa:zRecipient" },
      agentId,
      recipientPubHex,
      new Date().toISOString(),
      "testnonce12345678",
    );

    // Replace the nonce with a non-12-byte value (e.g. 8 bytes)
    const shortNonce = new Uint8Array(8);
    const tampered: InkEncryptedEnvelope = { ...envelope, nonce: base64urlEncode(shortNonce) };

    // Must throw/reject cleanly rather than allowing a crypto exception to propagate unpredictably
    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey)),
    ).rejects.toThrow(/nonce|iv/i);
  });

  it("rejects envelope with AES nonce that is not 12 bytes (too long)", async () => {
    const encKp = generateEncryptionKeypair();
    const sigKp = ed.utils.randomPrivateKey();
    const sigPub = await ed.getPublicKeyAsync(sigKp);
    const agentId = deriveAgentId(sigPub);

    const recipientPubHex = toHex(encKp.publicKey);
    const { envelope } = await encryptInkPayload(
      { from: agentId, to: "tulpa:zRecipient" },
      agentId,
      recipientPubHex,
      new Date().toISOString(),
      "testnonce12345678",
    );

    // Replace the nonce with a non-12-byte value (e.g. 16 bytes)
    const longNonce = new Uint8Array(16);
    const tampered: InkEncryptedEnvelope = { ...envelope, nonce: base64urlEncode(longNonce) };

    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey)),
    ).rejects.toThrow(/nonce|iv/i);
  });

  it("accepts a valid envelope with correct 12-byte AES nonce", async () => {
    const encKp = generateEncryptionKeypair();
    const sigKp = ed.utils.randomPrivateKey();
    const sigPub = await ed.getPublicKeyAsync(sigKp);
    const agentId = deriveAgentId(sigPub);

    const recipientPubHex = toHex(encKp.publicKey);
    const { envelope } = await encryptInkPayload(
      { from: agentId, to: "tulpa:zRecipient" },
      agentId,
      recipientPubHex,
      new Date().toISOString(),
      "testnonce12345678",
    );

    const decrypted = await decryptInkPayload(envelope, toHex(encKp.privateKey), "tulpa:zRecipient");
    expect(decrypted.from).toBe(agentId);
  });
});

// ── Finding 2: InkAuditSubmitSchema from/to field length caps ──

describe("InkAuditSubmitSchema: from/to field length caps", () => {
  const validBase = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_submit" as const,
    from: "tulpa:zABCDEF0123456",
    to: "did:web:witness.tulpa.network",
    event: {
      id: "evt-001",
      version: "ink-audit/1" as const,
      agentId: "tulpa:zABCDEF0123456",
      agentSignature: "dGVzdA",
      sequence: 1,
      previousEventHash: null,
      eventType: "message.sent" as const,
      timestamp: new Date().toISOString(),
    },
    nonce: "testnonce1234567890",
    timestamp: new Date().toISOString(),
  };

  it("rejects submit body with oversized from field", () => {
    const oversized = { ...validBase, from: "tulpa:z" + "A".repeat(300) };
    const result = InkAuditSubmitSchema.safeParse(oversized);
    expect(result.success).toBe(false);
  });

  it("rejects submit body with oversized to field", () => {
    const oversized = { ...validBase, to: "did:web:" + "b".repeat(300) };
    const result = InkAuditSubmitSchema.safeParse(oversized);
    expect(result.success).toBe(false);
  });

  it("accepts submit body with valid from/to fields", () => {
    const result = InkAuditSubmitSchema.safeParse(validBase);
    expect(result.success).toBe(true);
  });
});
