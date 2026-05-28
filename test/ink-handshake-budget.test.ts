import { describe, it, expect, beforeEach } from "vitest";
import { HandshakeBudgetTracker } from "../src/ink/handshake-budget.js";

describe("HandshakeBudgetTracker", () => {
  let tracker: HandshakeBudgetTracker;

  beforeEach(() => {
    tracker = new HandshakeBudgetTracker();
  });

  const sender = "did:plc:sender123";
  const correlationId = "corr:abc";

  // ── Per-correlation budgets ──

  describe("per-correlation challenge budget", () => {
    it("accepts 3 challenges on the same correlationId", () => {
      for (let i = 0; i < 3; i++) {
        const result = tracker.checkAndRecord({
          correlationId,
          fromDid: sender,
          messageType: "challenge",
        });
        expect(result.allowed, `challenge ${i + 1} should be allowed`).toBe(true);
      }
    });

    it("rejects the 4th challenge on the same correlationId", () => {
      for (let i = 0; i < 3; i++) {
        tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "challenge" });
      }
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("handshake_budget_exhausted");
    });
  });

  describe("terminal states", () => {
    it("rejection is terminal — no further messages accepted", () => {
      tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "rejection" });
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("handshake_budget_exhausted");
    });

    it("resolution is terminal — no further messages accepted", () => {
      tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "resolution" });
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("handshake_budget_exhausted");
    });
  });

  describe("total state transitions cap", () => {
    it("caps total state transitions at 5", () => {
      // 3 challenges + 1 intent + 1 challenge (should be 5th = last allowed)
      for (let i = 0; i < 5; i++) {
        const result = tracker.checkAndRecord({
          correlationId,
          fromDid: sender,
          messageType: i < 3 ? "challenge" : "intent",
        });
        expect(result.allowed, `transition ${i + 1} should be allowed`).toBe(true);
      }
      // 6th should be rejected
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "intent",
      });
      expect(result.allowed).toBe(false);
    });
  });

  describe("handshake TTL", () => {
    it("rejects messages after intent expiry", () => {
      const pastExpiry = new Date(Date.now() - 1000).toISOString();
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
        intentExpiresAt: pastExpiry,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("handshake_budget_exhausted");
    });

    it("accepts messages before intent expiry", () => {
      const futureExpiry = new Date(Date.now() + 60_000).toISOString();
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
        intentExpiresAt: futureExpiry,
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── Per-sender rate limits ──

  describe("per-sender rate limits", () => {
    it("rejects after exceeding per-minute intent limit", () => {
      const limit = 10;
      for (let i = 0; i < limit; i++) {
        const result = tracker.checkAndRecord({
          correlationId: `corr:${i}`,
          fromDid: sender,
          messageType: "intent",
        });
        expect(result.allowed, `intent ${i + 1} should be allowed`).toBe(true);
      }
      const result = tracker.checkAndRecord({
        correlationId: "corr:overflow",
        fromDid: sender,
        messageType: "intent",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("sender_rate_limited");
    });

    it("allows different senders independently", () => {
      for (let i = 0; i < 10; i++) {
        tracker.checkAndRecord({
          correlationId: `corr:a${i}`,
          fromDid: "did:plc:senderA",
          messageType: "intent",
        });
      }
      // senderB should still have budget
      const result = tracker.checkAndRecord({
        correlationId: "corr:b0",
        fromDid: "did:plc:senderB",
        messageType: "intent",
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── First violation vs repeated violation ──

  describe("first violation vs repeated violation", () => {
    it("first violation returns typed rejection with backoff hint", () => {
      // exhaust challenge budget
      for (let i = 0; i < 3; i++) {
        tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "challenge" });
      }
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("handshake_budget_exhausted");
      expect(result.backoffHint).toBeDefined();
      expect(result.silentDrop).toBe(false);
    });

    it("subsequent violations are silent drops", () => {
      for (let i = 0; i < 3; i++) {
        tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "challenge" });
      }
      // First violation — typed rejection
      tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "challenge" });

      // Second violation — silent drop
      const result = tracker.checkAndRecord({
        correlationId,
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(false);
      expect(result.silentDrop).toBe(true);
    });
  });

  // ── Different correlationIds are independent ──

  describe("correlation isolation", () => {
    it("separate correlationIds have independent budgets", () => {
      for (let i = 0; i < 3; i++) {
        tracker.checkAndRecord({
          correlationId: "corr:first",
          fromDid: sender,
          messageType: "challenge",
        });
      }
      // Different correlationId should have full budget
      const result = tracker.checkAndRecord({
        correlationId: "corr:second",
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── Pruning ──

  describe("pruning", () => {
    it("prunes expired correlation state", () => {
      // Record with an already-expired TTL
      const pastExpiry = new Date(Date.now() - 1000).toISOString();
      tracker.checkAndRecord({
        correlationId: "corr:old",
        fromDid: sender,
        messageType: "challenge",
        intentExpiresAt: pastExpiry,
      });

      tracker.pruneExpired();

      // Internal state should be cleaned (we can't directly inspect,
      // but a new message on the same correlationId should work fresh)
      const result = tracker.checkAndRecord({
        correlationId: "corr:old",
        fromDid: sender,
        messageType: "challenge",
        intentExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── Memory bounds ──

  describe("memory bounds", () => {
    it("evicts oldest entries when exceeding max tracked correlations", () => {
      // Use a smaller tracker with high sender limits so we only test eviction
      const smallTracker = new HandshakeBudgetTracker({
        maxCorrelations: 100,
        maxHandshakeMsgsPerMinute: 200,
      });
      for (let i = 0; i < 100; i++) {
        smallTracker.checkAndRecord({
          correlationId: `corr:${i}`,
          fromDid: sender,
          messageType: "challenge",
        });
      }
      // One more should succeed (evicts oldest)
      const result = smallTracker.checkAndRecord({
        correlationId: "corr:overflow",
        fromDid: sender,
        messageType: "challenge",
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── check() / recordAccepted() split ──

  describe("check() vs recordAccepted()", () => {
    it("check() alone does not mutate correlation or sender state", () => {
      // Repeatedly check rejections — none of these should commit terminal,
      // mark transitions, or consume the per-sender activity budget.
      for (let i = 0; i < 20; i++) {
        const r = tracker.check({ correlationId, fromDid: sender, messageType: "rejection" });
        expect(r.allowed, `check #${i + 1} should still be allowed`).toBe(true);
      }
      // A subsequent committing call should still succeed.
      const committed = tracker.recordAccepted({ correlationId, fromDid: sender, messageType: "rejection" });
      expect(committed.allowed).toBe(true);
    });

    it("recordAccepted() of a terminal type blocks further check() for that correlation", () => {
      tracker.recordAccepted({ correlationId, fromDid: sender, messageType: "rejection" });
      const followup = tracker.check({ correlationId, fromDid: sender, messageType: "challenge" });
      expect(followup.allowed).toBe(false);
      expect(followup.reason).toBe("handshake_budget_exhausted");
    });

    it("check() on an unknown correlation does not create a row", () => {
      // Exhaust nothing — just probe many distinct correlations.
      for (let i = 0; i < 100; i++) {
        tracker.check({ correlationId: `corr:probe-${i}`, fromDid: sender, messageType: "intent" });
      }
      // A committing call on a fresh correlation must still succeed,
      // confirming the prior probes left no per-sender state behind.
      const r = tracker.recordAccepted({ correlationId: "corr:real", fromDid: sender, messageType: "intent" });
      expect(r.allowed).toBe(true);
    });

    it("check() does not burn the typed-rejection budget for a pairKey", () => {
      // Drive the correlation to terminal via a committed rejection.
      tracker.recordAccepted({ correlationId, fromDid: sender, messageType: "rejection" });

      // check() the same pairKey: this would normally trigger a typed
      // first-rejection if it mutated rejectionsSent. The split must
      // observe the rejection without advancing the silent-drop state
      // machine — otherwise check() would burn the typed rejection on
      // behalf of a sender that never reached this code.
      const r1 = tracker.check({ correlationId, fromDid: sender, messageType: "challenge" });
      expect(r1.allowed).toBe(false);
      // The first real eager-commit caller should still see a typed
      // rejection (silentDrop: false) — i.e. check() did not poison
      // the rejection-bookkeeping by claiming the typed response first.
      const r2 = tracker.checkAndRecord({ correlationId, fromDid: sender, messageType: "challenge" });
      expect(r2.allowed).toBe(false);
      expect(r2.silentDrop).toBe(false);
    });
  });
});
