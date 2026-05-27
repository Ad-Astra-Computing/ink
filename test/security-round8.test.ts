/**
 * Security regression tests — round 8.
 *
 * Findings from Codex review:
 *  1. buildSignatureBase: newline injection in scalar fields (method, path,
 *     recipientDid, timestamp) can produce signing-base collisions.
 *  2. decryptInkPayload: envelope.type is not validated and not included in
 *     AES-GCM AAD — type-confusion risk if callers route on envelope.type.
 */
import { describe, it, expect } from "vitest";
import {
  buildSignatureBase,
  signInkMessage,
  verifyInkSignature,
  encryptInkPayload,
  decryptInkPayload,
  type InkSignInput,
  type InkEncryptedEnvelope,
} from "../src/crypto/ink.js";
import { generateEncryptionKeypair, deriveAgentId } from "../src/crypto/keys.js";
import * as ed from "@noble/ed25519";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Finding 1: newline injection in buildSignatureBase ──

describe("buildSignatureBase: newline injection rejection", () => {
  const baseInput: InkSignInput = {
    method: "POST",
    path: "/ink/v1/message",
    recipientDid: "tulpa:zRecipient",
    body: { from: "tulpa:zSender", timestamp: new Date().toISOString() },
    timestamp: new Date().toISOString(),
  };

  it("rejects newline in method", () => {
    const bad: InkSignInput = { ...baseInput, method: "POST\nGET" };
    expect(() => buildSignatureBase(bad)).toThrow(/newline|CR|LF|invalid/i);
  });

  it("rejects newline in path", () => {
    const bad: InkSignInput = { ...baseInput, path: "/a\n/b" };
    expect(() => buildSignatureBase(bad)).toThrow(/newline|CR|LF|invalid/i);
  });

  it("rejects newline in recipientDid", () => {
    const bad: InkSignInput = { ...baseInput, recipientDid: "tulpa:zR\nxxx" };
    expect(() => buildSignatureBase(bad)).toThrow(/newline|CR|LF|invalid/i);
  });

  it("rejects newline in timestamp", () => {
    const bad: InkSignInput = { ...baseInput, timestamp: "2026-01-01T00:00:00Z\nextra" };
    expect(() => buildSignatureBase(bad)).toThrow(/newline|CR|LF|invalid/i);
  });

  it("rejects carriage return in path", () => {
    const bad: InkSignInput = { ...baseInput, path: "/a\r/b" };
    expect(() => buildSignatureBase(bad)).toThrow(/newline|CR|LF|invalid/i);
  });

  it("accepts normal inputs without throwing", () => {
    expect(() => buildSignatureBase(baseInput)).not.toThrow();
  });

  it("newline injection does not produce a cross-field collision", async () => {
    // Ensure that path="/x\nrecip" does NOT yield the same signature base
    // as path="/x", recipientDid="recip" (by verifying they each fail to verify against the other)
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const input1: InkSignInput = {
      method: "POST",
      path: "/x",
      recipientDid: "tulpa:zRecip",
      body: {},
      timestamp: "2026-01-01T00:00:00Z",
    };

    // Both should now throw because they contain newlines after validation is added
    const input2: InkSignInput = {
      method: "POST",
      path: "/x\ntulpa:zRecip",
      recipientDid: "ignored",
      body: {},
      timestamp: "2026-01-01T00:00:00Z",
    };

    // Sign with input1 (valid)
    const sig = await signInkMessage(input1, kp);

    // input2 has a newline in path — must be rejected by buildSignatureBase
    await expect(signInkMessage(input2, kp)).rejects.toThrow(/newline|CR|LF|invalid/i);
    // Verify with input1 still works
    const valid = await verifyInkSignature(input1, sig, pub);
    expect(valid).toBe(true);
  });
});

// ── Finding 3: buildAuthHeader header injection and signature length validation ──

import { buildAuthHeader, verifyAuditEventSignature, verifyAuditResponseSignature } from "../src/crypto/ink.js";

describe("buildAuthHeader: header injection rejection", () => {
  // Helper: 86-char valid base64url string (correct Ed25519 sig length)
  const sig86 = "A".repeat(86);

  it("rejects newline in signatureBase64url", () => {
    // Newline breaks the 86-char exact match and is invalid
    const withNewline = "A".repeat(42) + "\n" + "A".repeat(43);
    expect(() => buildAuthHeader(withNewline)).toThrow(/invalid|injection|header|Ed25519/i);
  });

  it("rejects carriage return in signatureBase64url", () => {
    const withCr = "A".repeat(42) + "\r" + "A".repeat(43);
    expect(() => buildAuthHeader(withCr)).toThrow(/invalid|injection|header|Ed25519/i);
  });

  it("rejects newline in keyId", () => {
    expect(() => buildAuthHeader(sig86, "key1\ninjected")).toThrow(/invalid|injection|header/i);
  });

  it("rejects invalid characters in signatureBase64url", () => {
    expect(() => buildAuthHeader("bad sig!")).toThrow(/invalid|injection|header|Ed25519/i);
  });

  it("rejects invalid characters in keyId", () => {
    expect(() => buildAuthHeader(sig86, "key with spaces")).toThrow(/invalid|injection|header/i);
  });

  it("accepts valid 86-char signature without keyId", () => {
    expect(() => buildAuthHeader(sig86)).not.toThrow();
  });

  it("accepts valid 86-char signature with valid keyId", () => {
    expect(() => buildAuthHeader(sig86, "key-001:v1")).not.toThrow();
  });

  it("rejects a signature shorter than 86 chars (not a valid Ed25519 sig)", () => {
    // Ed25519 = 64 bytes = exactly 86 unpadded base64url chars
    const shortSig = "A".repeat(85);
    expect(() => buildAuthHeader(shortSig)).toThrow(/invalid|signature/i);
  });

  it("rejects a signature longer than 86 chars", () => {
    const longSig = "A".repeat(87);
    expect(() => buildAuthHeader(longSig)).toThrow(/invalid|signature/i);
  });

  it("accepts a signature of exactly 86 base64url chars", () => {
    const validLenSig = "A".repeat(86);
    expect(() => buildAuthHeader(validLenSig)).not.toThrow();
  });
});

// ── Finding 5: verifyInkSignature must return false instead of throwing
//    for malformed or wrong-length signatures ──

describe("verifyInkSignature: malformed input returns false", () => {
  const goodInput: InkSignInput = {
    method: "POST",
    path: "/ink/v1/message",
    recipientDid: "tulpa:zRecipient",
    body: { from: "tulpa:zSender", timestamp: new Date().toISOString() },
    timestamp: new Date().toISOString(),
  };

  it("returns false for invalid base64url (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const result = await verifyInkSignature(goodInput, "!!!not-base64url!!!", pub);
    expect(result).toBe(false);
  });

  it("returns false for wrong-length signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const shortSig = base64urlEncode(new Uint8Array(10));
    const result = await verifyInkSignature(goodInput, shortSig, pub);
    expect(result).toBe(false);
  });
});

// ── Finding 4: verifyAuditEventSignature and verifyAuditResponseSignature
//    must return false instead of throwing for malformed signatures ──

describe("verifyAuditEventSignature: malformed input returns false", () => {
  it("returns false for a non-base64url agentSignature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: "!!!not-base64url!!!",
      eventType: "message.sent",
    };
    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });

  it("returns false for a wrong-length signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const event = {
      id: "e1",
      agentId: "tulpa:z123",
      agentSignature: base64urlEncode(new Uint8Array(10)), // 10 bytes, not 64
      eventType: "message.sent",
    };
    const result = await verifyAuditEventSignature(event, pub);
    expect(result).toBe(false);
  });
});

describe("verifyAuditResponseSignature: malformed input returns false", () => {
  it("returns false for a non-base64url signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const result = await verifyAuditResponseSignature([], "!!!not-base64url!!!", pub);
    expect(result).toBe(false);
  });

  it("returns false for a wrong-length signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();
    const result = await verifyAuditResponseSignature([], base64urlEncode(new Uint8Array(10)), pub);
    expect(result).toBe(false);
  });
});

// ── Finding 2: decryptInkPayload envelope.type validation and AAD binding ──

describe("decryptInkPayload: envelope.type validation", () => {
  it("rejects envelope with incorrect type field", async () => {
    const encKp = generateEncryptionKeypair();
    const { secretKey: sigKp, publicKey: sigPub } = await ed.keygenAsync();
    const agentId = deriveAgentId(sigPub);
    const recipientPubHex = toHex(encKp.publicKey);

    const { envelope } = await encryptInkPayload(
      { from: agentId, to: "tulpa:zRecipient" },
      agentId,
      recipientPubHex,
      new Date().toISOString(),
      "testnonce12345678",
    );

    // Tamper with type
    const tampered: InkEncryptedEnvelope = {
      ...envelope,
      type: "network.tulpa.FAKE" as "network.tulpa.encrypted",
    };

    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey)),
    ).rejects.toThrow(/type/i);
  });

  it("accepts envelope with correct type field", async () => {
    const encKp = generateEncryptionKeypair();
    const { secretKey: sigKp, publicKey: sigPub } = await ed.keygenAsync();
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
