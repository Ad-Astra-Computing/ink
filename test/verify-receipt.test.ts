import { describe, it, expect } from "vitest";
import { buildReceipt, verifyReceipt, generateKeypair, deriveAgentId } from "../src/index.js";

async function setup() {
  const issuer = await generateKeypair();
  const from = deriveAgentId(issuer.publicKey);
  const to = "tulpa:zRecipient";
  const messageId = "msg-1";
  const messageBody = { protocol: "ink/0.1", hello: "world" };
  const receipt = await buildReceipt({
    from,
    to,
    messageId,
    messageBody,
    disposition: "received",
    privateKey: issuer.privateKey,
  });
  return { issuer, from, to, messageId, messageBody, receipt };
}

describe("verifyReceipt", () => {
  it("accepts a receipt that matches its message and is signed by the issuer", async () => {
    const { issuer, from, to, messageId, messageBody, receipt } = await setup();
    const r = await verifyReceipt({
      receipt,
      senderPublicKey: issuer.publicKey,
      expected: { from, to, messageId, messageBody },
    });
    expect(r.valid).toBe(true);
  });

  it("rejects a receipt signed by a different key", async () => {
    const { from, to, messageId, messageBody, receipt } = await setup();
    const other = await generateKeypair();
    const r = await verifyReceipt({
      receipt,
      senderPublicKey: other.publicKey,
      expected: { from, to, messageId, messageBody },
    });
    expect(r).toEqual({ valid: false, reason: "invalid_signature" });
  });

  it("rejects when the message body differs from what the receipt acknowledges", async () => {
    const { issuer, from, to, messageId, receipt } = await setup();
    const r = await verifyReceipt({
      receipt,
      senderPublicKey: issuer.publicKey,
      expected: { from, to, messageId, messageBody: { protocol: "ink/0.1", hello: "TAMPERED" } },
    });
    expect(r).toEqual({ valid: false, reason: "message_hash_mismatch" });
  });

  it("rejects when from / to / messageId do not match the expectation", async () => {
    const { issuer, from, to, messageId, messageBody, receipt } = await setup();
    const base = { receipt, senderPublicKey: issuer.publicKey };
    expect((await verifyReceipt({ ...base, expected: { from: "tulpa:zX", to, messageId, messageBody } })).reason).toBe("from_mismatch");
    expect((await verifyReceipt({ ...base, expected: { from, to: "tulpa:zX", messageId, messageBody } })).reason).toBe("to_mismatch");
    expect((await verifyReceipt({ ...base, expected: { from, to, messageId: "other", messageBody } })).reason).toBe("message_id_mismatch");
  });

  it("pins the disposition when requested", async () => {
    const { issuer, from, to, messageId, messageBody, receipt } = await setup();
    // The receipt's disposition is "received"; requiring "delivered" must fail
    // even though the signature is valid, while requiring "received" passes.
    const wrong = await verifyReceipt({
      receipt,
      senderPublicKey: issuer.publicKey,
      expected: { from, to, messageId, messageBody, disposition: "delivered" },
    });
    expect(wrong).toEqual({ valid: false, reason: "disposition_mismatch" });
    const right = await verifyReceipt({
      receipt,
      senderPublicKey: issuer.publicKey,
      expected: { from, to, messageId, messageBody, disposition: "received" },
    });
    expect(right.valid).toBe(true);
  });

  it("rejects a malformed receipt object", async () => {
    const { issuer, from, to, messageId, messageBody } = await setup();
    const r = await verifyReceipt({
      receipt: { not: "a receipt" },
      senderPublicKey: issuer.publicKey,
      expected: { from, to, messageId, messageBody },
    });
    expect(r).toEqual({ valid: false, reason: "malformed_receipt" });
  });
});
