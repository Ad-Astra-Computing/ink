/**
 * Rotation-aware non-transport artifact verification (spec §6.2/§6.3/§12).
 *
 * Every artifact verifier historically took a single raw Ed25519 key, so a
 * retired key inside its validity window could not verify historical
 * artifacts, and a revoked key could not be reliably excluded. These tests
 * pin the rotation-aware `...WithKeys` siblings across every non-transport
 * artifact: audit events, receipts, inclusion receipts, checkpoints, and
 * attestations.
 */
import { describe, it, expect } from "vitest";
import canonicalize from "canonicalize";
import * as ed from "@noble/ed25519";
import {
  generateKeypair,
  base64urlEncode,
  signAuditEvent,
  verifyAuditEventSignatureWithKeys,
  buildReceipt,
  verifyReceiptWithKeys,
  verifyInclusionReceiptWithKeys,
  verifyCheckpointWithKeys,
  buildAttestation,
  verifyAttestationWithKeys,
  computeMessageHash,
  signMessage,
  type InclusionReceipt,
  type CandidateKey,
} from "../src/index.js";

async function makeKeypair() {
  return generateKeypair();
}

function candidateKey(overrides: Partial<CandidateKey> & { keyId: string; publicKey: Uint8Array }): CandidateKey {
  return { status: "active", ...overrides } as CandidateKey;
}

// ── Audit event ──

describe("verifyAuditEventSignatureWithKeys", () => {
  async function signedEvent(privateKey: Uint8Array, timestamp: string, extra: Record<string, unknown> = {}) {
    const event: Record<string, unknown> = {
      id: "01JBTEST00000001",
      type: "message.sent",
      agentId: "tulpa:zAgent",
      timestamp,
      ...extra,
    };
    const signature = await signAuditEvent(event, privateKey);
    return { ...event, agentSignature: signature };
  }

  it("verifies with the active key", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("k1");
    expect(result.usedRetiredKey).toBeFalsy();
  });

  it("verifies with a retired key inside its window", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-03-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-04-01T00:00:00Z",
      }),
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(true);
    expect(result.usedRetiredKey).toBe(true);
  });

  it("rejects a retired key outside its window", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-05-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-04-01T00:00:00Z",
      }),
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("never verifies with a revoked key, even for events predating revokedAt", async () => {
    const kp = await makeKeypair();
    // Event timestamp is well before the revocation.
    const event = await signedEvent(kp.privateKey, "2026-01-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-revoked",
        publicKey: kp.publicKey,
        status: "revoked",
        validFrom: "2025-01-01T00:00:00Z",
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects a key whose status is active but which carries a revokedAt field", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-01-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-mixed",
        publicKey: kp.publicKey,
        status: "active",
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("fails closed on a malformed window field", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-03-01T00:00:00.000Z");
    const keys: CandidateKey[] = [
      {
        keyId: "k-malformed",
        publicKey: kp.publicKey,
        status: "retired",
        // Not a string: present-but-malformed must fail closed.
        validUntil: 12345 as unknown as string,
      },
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("fails closed when the event timestamp is missing", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-03-01T00:00:00.000Z");
    delete (event as Record<string, unknown>).timestamp;
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey })];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("fails closed when the event timestamp is malformed", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-03-01T00:00:00.000Z");
    (event as Record<string, unknown>).timestamp = "not-a-timestamp";
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey })];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("defaults the hint to event.signingKeyId and takes the fast path", async () => {
    const kp = await makeKeypair();
    const other = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z", { signingKeyId: "k1" });
    const keys = [
      candidateKey({ keyId: "k-other", publicKey: other.publicKey, status: "active" }),
      candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("k1");
  });

  it("falls through when opts.hintKeyId names the wrong key", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyAuditEventSignatureWithKeys(event, keys, { hintKeyId: "wrong-hint" });
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("k1");
  });

  it("bounds candidate keys at MAX_CANDIDATE_KEYS (20)", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const decoys = await Promise.all(Array.from({ length: 20 }, () => makeKeypair()));
    const keys: CandidateKey[] = [
      ...decoys.map((d, i) => candidateKey({ keyId: `decoy-${i}`, publicKey: d.publicKey, status: "active" })),
      candidateKey({ keyId: "real", publicKey: kp.publicKey, status: "active" }),
    ];
    // The real key is candidate #21 (index 20), past the 20-key bound.
    const result = await verifyAuditEventSignatureWithKeys(event, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects an empty key array", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const result = await verifyAuditEventSignatureWithKeys(event, []);
    expect(result.verified).toBe(false);
  });

  it("rejects a non-array keys argument", async () => {
    const kp = await makeKeypair();
    const event = await signedEvent(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const result = await verifyAuditEventSignatureWithKeys(event, null as unknown as CandidateKey[]);
    expect(result.verified).toBe(false);
  });
});

// ── Receipt (ink/receipts.ts) ──

describe("verifyReceiptWithKeys", () => {
  const from = "tulpa:zSender";
  const to = "tulpa:zRecipient";
  const messageId = "msg-1";
  const messageBody = { hello: "world" };

  async function signedReceipt(privateKey: Uint8Array, timestamp: string) {
    const messageHash = await computeMessageHash(messageBody);
    const unsigned = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.receipt" as const,
      from,
      to,
      messageId,
      disposition: "received" as const,
      dispositionAt: timestamp,
      messageHash,
      nonce: "n".repeat(8),
      timestamp,
    };
    const signature = await signMessage(unsigned as unknown as Record<string, unknown>, privateKey);
    return { ...unsigned, signature };
  }

  const expected = { from, to, messageId, messageBody };

  it("verifies with the active key", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("k1");
  });

  it("verifies with a retired key inside its window", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-02-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(true);
    expect(result.usedRetiredKey).toBe(true);
  });

  it("rejects a retired key outside its window", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-05-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(false);
  });

  it("never verifies with a revoked key, even predating revokedAt", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-01-01T00:00:00.000Z");
    const keys = [
      candidateKey({
        keyId: "k-revoked",
        publicKey: kp.publicKey,
        status: "revoked",
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    ];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(false);
  });

  it("fails closed on a malformed window field", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-02-01T00:00:00.000Z");
    const keys: CandidateKey[] = [
      { keyId: "k1", publicKey: kp.publicKey, status: "retired", validFrom: "" },
    ];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(false);
  });

  it("fails closed when the receipt timestamp is malformed", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-02-01T00:00:00.000Z");
    (receipt as unknown as Record<string, unknown>).timestamp = "garbage";
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey })];
    const result = await verifyReceiptWithKeys({ receipt, keys, expected });
    expect(result.valid).toBe(false);
  });

  it("hint fast path picks the hinted key", async () => {
    const kp = await makeKeypair();
    const other = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const keys = [
      candidateKey({ keyId: "k-other", publicKey: other.publicKey, status: "active" }),
      candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyReceiptWithKeys({ receipt, keys, hintKeyId: "k1", expected });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("k1");
  });

  it("falls through on a wrong hint", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const keys = [candidateKey({ keyId: "k1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyReceiptWithKeys({ receipt, keys, hintKeyId: "nope", expected });
    expect(result.valid).toBe(true);
  });

  it("rejects an empty key array", async () => {
    const kp = await makeKeypair();
    const receipt = await signedReceipt(kp.privateKey, "2026-06-01T00:00:00.000Z");
    const result = await verifyReceiptWithKeys({ receipt, keys: [], expected });
    expect(result.valid).toBe(false);
  });
});

// ── Inclusion receipt ──

describe("verifyInclusionReceiptWithKeys", () => {
  async function signedInclusionReceipt(
    privateKey: Uint8Array,
    overrides: Partial<InclusionReceipt> = {},
  ): Promise<InclusionReceipt> {
    const base = {
      eventId: "01JBTEST00000001",
      leafIndex: 0,
      treeSize: 1,
      rootHash: "a".repeat(64),
      inclusionProof: [],
      timestamp: "2026-05-27T00:00:00.000Z",
      serviceSignature: "",
      ...overrides,
    };
    const signed = {
      eventId: base.eventId,
      leafIndex: base.leafIndex,
      treeSize: base.treeSize,
      rootHash: base.rootHash,
      timestamp: base.timestamp,
    };
    const sigBase = `ink/audit-inclusion/v1\n${canonicalize(signed)}`;
    const sig = await ed.signAsync(new TextEncoder().encode(sigBase), privateKey);
    return { ...base, serviceSignature: base64urlEncode(sig) };
  }

  it("verifies with the active witness key", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey);
    const keys = [candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("w1");
  });

  it("verifies with a retired witness key inside its window", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey, { timestamp: "2026-02-01T00:00:00.000Z" });
    const keys = [
      candidateKey({
        keyId: "w-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(true);
    expect(result.usedRetiredKey).toBe(true);
  });

  it("rejects a retired witness key outside its window", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey, { timestamp: "2026-05-01T00:00:00.000Z" });
    const keys = [
      candidateKey({
        keyId: "w-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(false);
  });

  it("never verifies with a revoked witness key, even predating revokedAt", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey, { timestamp: "2026-01-01T00:00:00.000Z" });
    const keys = [
      candidateKey({
        keyId: "w-revoked",
        publicKey: kp.publicKey,
        status: "revoked",
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(false);
  });

  it("fails closed on a malformed window field", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey, { timestamp: "2026-02-01T00:00:00.000Z" });
    const keys: CandidateKey[] = [
      { keyId: "w1", publicKey: kp.publicKey, status: "retired", validUntil: "not-a-date" },
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(false);
  });

  it("fails closed when receipt.timestamp is malformed", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey);
    (receipt as unknown as Record<string, unknown>).timestamp = "not-a-timestamp";
    const keys = [candidateKey({ keyId: "w1", publicKey: kp.publicKey })];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(false);
  });

  it("hint fast path picks the hinted key", async () => {
    const kp = await makeKeypair();
    const other = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey);
    const keys = [
      candidateKey({ keyId: "w-other", publicKey: other.publicKey, status: "active" }),
      candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys, hintKeyId: "w1" });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("w1");
  });

  it("bounds candidate keys at MAX_CANDIDATE_KEYS (20)", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey);
    const decoys = await Promise.all(Array.from({ length: 20 }, () => makeKeypair()));
    const keys: CandidateKey[] = [
      ...decoys.map((d, i) => candidateKey({ keyId: `decoy-${i}`, publicKey: d.publicKey, status: "active" })),
      candidateKey({ keyId: "real", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys });
    expect(result.valid).toBe(false);
  });

  it("rejects empty keys array", async () => {
    const kp = await makeKeypair();
    const receipt = await signedInclusionReceipt(kp.privateKey);
    const result = await verifyInclusionReceiptWithKeys({ receipt, keys: [] });
    expect(result.valid).toBe(false);
  });
});

// ── Checkpoint ──

describe("verifyCheckpointWithKeys", () => {
  const ORIGIN = "witness.example";
  const ROOT = "a".repeat(64);

  async function signCheckpoint(
    origin: string,
    treeSize: number,
    rootHash: string,
    privateKey: Uint8Array,
  ): Promise<string> {
    const body = `${origin}\n${treeSize}\n${rootHash}`;
    const sig = await ed.signAsync(new TextEncoder().encode(body), privateKey);
    return `${body}\n\n-- ${origin} ${base64urlEncode(sig)}\n`;
  }

  const ARTIFACT_MS = Date.parse("2026-06-01T00:00:00.000Z");

  it("verifies with the active key and preserves origin matching", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, ARTIFACT_MS);
    expect(result).not.toBeNull();
    expect(result?.origin).toBe(ORIGIN);
    expect(result?.treeSize).toBe(42);
    expect(result?.keyId).toBe("w1");
  });

  it("rejects when the origin does not match, regardless of key set", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyCheckpointWithKeys(signed, keys, "other.example", ARTIFACT_MS);
    expect(result).toBeNull();
  });

  it("verifies with a retired key inside its window", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [
      candidateKey({
        keyId: "w-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-07-01T00:00:00Z",
      }),
    ];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, ARTIFACT_MS);
    expect(result).not.toBeNull();
    expect(result?.usedRetiredKey).toBe(true);
  });

  it("rejects a retired key outside its window", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [
      candidateKey({
        keyId: "w-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-02-01T00:00:00Z",
      }),
    ];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, ARTIFACT_MS);
    expect(result).toBeNull();
  });

  it("never verifies with a revoked key, even for an artifact clock predating revokedAt", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [
      candidateKey({
        keyId: "w-revoked",
        publicKey: kp.publicKey,
        status: "revoked",
        revokedAt: "2026-12-01T00:00:00Z",
      }),
    ];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, ARTIFACT_MS);
    expect(result).toBeNull();
  });

  it("fails closed on a non-finite artifactMs", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, Number.NaN);
    expect(result).toBeNull();
  });

  it("hint fast path picks the hinted key", async () => {
    const kp = await makeKeypair();
    const other = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const keys = [
      candidateKey({ keyId: "w-other", publicKey: other.publicKey, status: "active" }),
      candidateKey({ keyId: "w1", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyCheckpointWithKeys(signed, keys, ORIGIN, ARTIFACT_MS, "w1");
    expect(result?.keyId).toBe("w1");
  });

  it("rejects empty key array", async () => {
    const kp = await makeKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const result = await verifyCheckpointWithKeys(signed, [], ORIGIN, ARTIFACT_MS);
    expect(result).toBeNull();
  });
});

// ── Attestation ──

describe("verifyAttestationWithKeys", () => {
  const NOW = "2026-06-15T00:00:00Z";

  async function makeAttestation(privateKey: Uint8Array, issuedAt: string, expiresAt: string) {
    const attestation = await buildAttestation(
      {
        issuer: "tulpa:zIssuer",
        subject: "tulpa:zSubject",
        claimType: "trust.verified",
        claim: {},
        attestationId: "attn-0000000000000001",
        issuedAt,
        expiresAt,
      },
      privateKey,
    );
    return new TextEncoder().encode(JSON.stringify(attestation));
  }

  it("verifies with the active issuer key", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z");
    const keys = [candidateKey({ keyId: "i1", publicKey: kp.publicKey, status: "active" })];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(true);
  });

  it("verifies with a retired issuer key inside its window", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-02-01T00:00:00Z", "2026-12-01T00:00:00Z");
    const keys = [
      candidateKey({
        keyId: "i-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(true);
    expect(result.usedRetiredKey).toBe(true);
  });

  it("rejects a retired issuer key outside its window", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z");
    const keys = [
      candidateKey({
        keyId: "i-old",
        publicKey: kp.publicKey,
        status: "retired",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
      }),
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(false);
  });

  it("never verifies with a revoked issuer key, even for issuedAt predating revokedAt", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z");
    const keys = [
      candidateKey({
        keyId: "i-revoked",
        publicKey: kp.publicKey,
        status: "revoked",
        revokedAt: "2026-12-31T00:00:00Z",
      }),
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects a key that is active but carries a revokedAt field", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z");
    const keys = [
      candidateKey({
        keyId: "i-mixed",
        publicKey: kp.publicKey,
        status: "active",
        revokedAt: "2026-12-31T00:00:00Z",
      }),
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(false);
  });

  it("fails closed on a malformed window field", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-02-01T00:00:00Z", "2026-12-01T00:00:00Z");
    const keys: CandidateKey[] = [
      { keyId: "i1", publicKey: kp.publicKey, status: "retired", validFrom: "" },
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW });
    expect(result.ok).toBe(false);
  });

  it("hint fast path picks the hinted key", async () => {
    const kp = await makeKeypair();
    const other = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z");
    const keys = [
      candidateKey({ keyId: "i-other", publicKey: other.publicKey, status: "active" }),
      candidateKey({ keyId: "i1", publicKey: kp.publicKey, status: "active" }),
    ];
    const result = await verifyAttestationWithKeys(raw, keys, { now: NOW }, { hintKeyId: "i1" });
    expect(result.ok).toBe(true);
    expect(result.keyId).toBe("i1");
  });

  it("rejects an empty key array", async () => {
    const kp = await makeKeypair();
    const raw = await makeAttestation(kp.privateKey, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z");
    const result = await verifyAttestationWithKeys(raw, [], { now: NOW });
    expect(result.ok).toBe(false);
  });
});
