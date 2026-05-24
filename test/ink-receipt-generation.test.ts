import { describe, it, expect, vi, beforeEach } from "vitest";
import { computeMessageHash } from "../src/crypto/ink.js";
import { generateKeypair } from "../src/crypto/keys.js";

describe("Receipt generation helpers", () => {
  describe("buildReceipt", () => {
    it("builds a valid signed receipt envelope", async () => {
      const { buildReceipt } = await import("../src/ink/receipts.js");
      const keypair = await generateKeypair();

      const receipt = await buildReceipt({
        from: "did:plc:bob123",
        to: "did:plc:alice123",
        messageId: "msg-001",
        messageBody: { intent: "schedule_meeting", payload: { date: "2026-03-20" } },
        disposition: "received",
        privateKey: keypair.privateKey,
      });

      expect(receipt.protocol).toBe("ink/0.1");
      expect(receipt.type).toBe("network.tulpa.receipt");
      expect(receipt.from).toBe("did:plc:bob123");
      expect(receipt.to).toBe("did:plc:alice123");
      expect(receipt.messageId).toBe("msg-001");
      expect(receipt.disposition).toBe("received");
      expect(receipt.messageHash).toBeTruthy();
      expect(receipt.nonce).toBeTruthy();
      expect(receipt.timestamp).toBeTruthy();
      expect(receipt.dispositionAt).toBeTruthy();
      expect(receipt.signature).toBeTruthy();
    });

    it("computes correct messageHash from body", async () => {
      const { buildReceipt } = await import("../src/ink/receipts.js");
      const keypair = await generateKeypair();
      const body = { intent: "ping", payload: "hello" };

      const receipt = await buildReceipt({
        from: "did:plc:bob",
        to: "did:plc:alice",
        messageId: "msg-002",
        messageBody: body,
        disposition: "delivered",
        privateKey: keypair.privateKey,
      });

      const expectedHash = await computeMessageHash(body as Record<string, unknown>);
      expect(receipt.messageHash).toBe(expectedHash);
    });
  });

  describe("shouldSendReceipt", () => {
    it("returns true for normal messages", async () => {
      const { shouldSendReceipt } = await import("../src/ink/receipts.js");
      expect(shouldSendReceipt("schedule_meeting")).toBe(true);
      expect(shouldSendReceipt("ping")).toBe(true);
    });

    it("returns false for receipt type messages (loop prevention)", async () => {
      const { shouldSendReceipt } = await import("../src/ink/receipts.js");
      expect(shouldSendReceipt("network.tulpa.receipt")).toBe(false);
    });

    it("returns false for audit messages (no receipts for audit)", async () => {
      const { shouldSendReceipt } = await import("../src/ink/receipts.js");
      expect(shouldSendReceipt("network.tulpa.audit_query")).toBe(false);
      expect(shouldSendReceipt("network.tulpa.audit_response")).toBe(false);
    });
  });

  describe("sendReceiptFireAndForget", () => {
    it("calls fetch with the receipt endpoint and INK auth header", async () => {
      const { sendReceiptFireAndForget } = await import("../src/ink/receipts.js");
      const keypair = await generateKeypair();
      const mockFetch = vi.fn().mockRejectedValue(new Error("network error"));

      const receipt = {
        protocol: "ink/0.1" as const,
        type: "network.tulpa.receipt" as const,
        from: "did:plc:bob",
        to: "did:plc:alice",
        messageId: "msg-1",
        disposition: "received" as const,
        dispositionAt: "2026-03-25T12:00:00Z",
        messageHash: "abc",
        nonce: "nonce1",
        timestamp: "2026-03-25T12:00:00Z",
        signature: "sig",
      };

      // Should not throw even when fetch fails
      await expect(
        sendReceiptFireAndForget(
          "https://example.com/ink/v1/alice/receipt",
          receipt,
          keypair.privateKey,
          mockFetch,
        ),
      ).resolves.toBeUndefined();

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/ink/v1/alice/receipt",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            "Authorization": expect.stringMatching(/^INK-Ed25519 /),
          }),
        }),
      );
    });

    it("uses global fetch by default", async () => {
      const { sendReceiptFireAndForget } = await import("../src/ink/receipts.js");
      const keypair = await generateKeypair();
      const originalFetch = globalThis.fetch;
      const mockFetch = vi.fn().mockResolvedValue(new Response("ok"));
      globalThis.fetch = mockFetch;
      try {
        await sendReceiptFireAndForget(
          "https://example.com/receipt",
          {
            protocol: "ink/0.1",
            type: "network.tulpa.receipt",
            from: "did:plc:bob",
            to: "did:plc:alice",
            messageId: "msg-1",
            disposition: "received",
            dispositionAt: "2026-03-25T12:00:00Z",
            messageHash: "abc",
            nonce: "n1",
            timestamp: "2026-03-25T12:00:00Z",
            signature: "sig",
          } as any,
          keypair.privateKey,
        );
        expect(mockFetch).toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
