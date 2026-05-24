/**
 * Handshake flood resistance — per-correlation and per-sender budget tracking.
 *
 * Implements §5 of the INK Containment spec:
 * - Per-correlation budgets: max challenges, terminal states, total transitions, TTL
 * - Per-sender rate limits: sliding window for intents and total handshake messages
 * - First violation returns typed rejection with backoff hint
 * - Subsequent violations are silent drops
 */

import type { InkBackoffHint } from "../models/ink-handshake.js";

// ── Budget constants ──

const DEFAULT_MAX_CHALLENGES = 3;
const DEFAULT_MAX_TOTAL_TRANSITIONS = 5;
const DEFAULT_MAX_INTENTS_PER_MINUTE = 10;
const DEFAULT_MAX_HANDSHAKE_MSGS_PER_MINUTE = 30;
const DEFAULT_MAX_CORRELATIONS = 10_000;
const DEFAULT_MAX_SENDERS = 1_000;
const DEFAULT_MAX_REJECTION_ENTRIES = 5_000;
const DEFAULT_PRUNE_INTERVAL = 100;
const DEFAULT_HANDSHAKE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
// Cap correlationId and fromDid lengths to prevent memory exhaustion via large IDs.
// Real correlation IDs are UUIDs (~36 chars); agent DIDs are ~50-100 chars.
// 256 is generous headroom while bounding per-entry memory cost.
const MAX_ID_LENGTH = 256;
const SENDER_REJECTION_WINDOW_MS = 60_000;

const TERMINAL_TYPES = new Set(["rejection", "resolution"]);

// ── Types ──

interface CorrelationState {
  challenges: number;
  totalTransitions: number;
  terminal: boolean;
  expiresAt: number; // epoch ms
  createdAt: number;
}

interface SenderState {
  intentTimestamps: number[];
  handshakeTimestamps: number[];
  lastActivity: number; // epoch ms — used for LRU eviction
}

export interface BudgetCheckResult {
  allowed: boolean;
  reason?: string;
  backoffHint?: InkBackoffHint;
  silentDrop?: boolean;
}

export interface HandshakeBudgetConfig {
  maxChallenges?: number;
  maxTotalTransitions?: number;
  maxIntentsPerMinute?: number;
  maxHandshakeMsgsPerMinute?: number;
  maxCorrelations?: number;
  maxSenders?: number;
  maxRejectionEntries?: number;
}

// ── Budget tracker ──

export class HandshakeBudgetTracker {
  private correlations = new Map<string, CorrelationState>();
  private senders = new Map<string, SenderState>();
  private rejectionsSent = new Set<string>(); // "${correlationId}:${fromDid}"
  // Tracks when a sender last received a rate-limit rejection. Subsequent
  // violations within SENDER_REJECTION_WINDOW_MS are silent-dropped to prevent
  // an over-limit sender from forcing repeated reject/backoff responses.
  private senderRejectionsSent = new Map<string, number>();

  private readonly maxChallenges: number;
  private readonly maxTotalTransitions: number;
  private readonly maxIntentsPerMinute: number;
  private readonly maxHandshakeMsgsPerMinute: number;
  private readonly maxCorrelations: number;
  private readonly maxSenders: number;
  private readonly maxRejectionEntries: number;
  private checkCounter = 0;

  constructor(config: HandshakeBudgetConfig = {}) {
    const pos = (v: number | undefined, def: number, cap: number): number => {
      if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return def;
      return Math.min(Math.floor(v), cap);
    };
    this.maxChallenges = pos(config.maxChallenges, DEFAULT_MAX_CHALLENGES, 1_000);
    this.maxTotalTransitions = pos(config.maxTotalTransitions, DEFAULT_MAX_TOTAL_TRANSITIONS, 10_000);
    this.maxIntentsPerMinute = pos(config.maxIntentsPerMinute, DEFAULT_MAX_INTENTS_PER_MINUTE, 100_000);
    this.maxHandshakeMsgsPerMinute = pos(config.maxHandshakeMsgsPerMinute, DEFAULT_MAX_HANDSHAKE_MSGS_PER_MINUTE, 100_000);
    this.maxCorrelations = pos(config.maxCorrelations, DEFAULT_MAX_CORRELATIONS, 1_000_000);
    this.maxSenders = pos(config.maxSenders, DEFAULT_MAX_SENDERS, 1_000_000);
    this.maxRejectionEntries = pos(config.maxRejectionEntries, DEFAULT_MAX_REJECTION_ENTRIES, 1_000_000);
  }

  checkAndRecord(params: {
    correlationId: string;
    fromDid: string;
    messageType: "intent" | "challenge" | "rejection" | "resolution";
    intentExpiresAt?: string;
  }): BudgetCheckResult {
    const { correlationId, fromDid, messageType, intentExpiresAt } = params;
    const now = Date.now();
    // Reject unbounded IDs before they hit Map keys / Set entries — caps the
    // per-entry memory cost regardless of the maxCorrelations / maxSenders
    // count caps. Stringifying the whole pair amplifies the attack surface.
    if (typeof correlationId !== "string" || correlationId.length > MAX_ID_LENGTH ||
        typeof fromDid !== "string" || fromDid.length > MAX_ID_LENGTH) {
      return { allowed: false, reason: "handshake_budget_exhausted", silentDrop: true };
    }
    // Use JSON encoding to prevent key collisions when IDs contain colons.
    // e.g. correlationId="a:b", fromDid="c" vs correlationId="a", fromDid="b:c"
    // would both produce "a:b:c" with naive string concatenation.
    const pairKey = JSON.stringify([correlationId, fromDid]);

    // Periodic pruning of expired state
    this.checkCounter++;
    if (this.checkCounter >= DEFAULT_PRUNE_INTERVAL) {
      this.checkCounter = 0;
      this.pruneExpired();
    }

    // Check per-sender rate limits first (applies across all correlations)
    const senderResult = this.checkSenderLimits(fromDid, messageType, now);
    if (!senderResult.allowed) {
      return senderResult;
    }

    // Record sender activity FIRST so per-sender limits accumulate on every
    // syntactically valid attempt — including ones that fail downstream
    // budget checks. Otherwise an attacker varying correlationId can trigger
    // unlimited typed rejections without ever hitting the per-sender cap.
    this.recordSenderActivity(fromDid, messageType, now);

    // Check TTL from intent expiry.
    // Distinguish "field absent" (undefined) from "field present but
    // malformed/empty". An intent that supplies `intentExpiresAt: ""`
    // is malformed — treat it as a rejected handshake instead of
    // falling through to the default 24h TTL (which would let
    // attacker-supplied empty expiries retain state longer than the
    // sender's claimed window). Also guard against NaN: new
    // Date("garbage").getTime() returns NaN and NaN <= now is false.
    let parsedExpiryMs: number | null = null;
    if (intentExpiresAt !== undefined) {
      // Length cap matches the timestamp cap used everywhere else in
      // INK (64 chars, well above any real ISO 8601 string). Without
      // this, a sender can submit a multi-megabyte expiry string and
      // force the JS engine into a long Date parser run before the
      // budget tracker rejects.
      if (
        typeof intentExpiresAt !== "string" ||
        intentExpiresAt.length === 0 ||
        intentExpiresAt.length > 64
      ) {
        return this.makeRejection(pairKey, "handshake_budget_exhausted", {
          backoffClass: "intent_ref",
        });
      }
      const expiryMs = new Date(intentExpiresAt).getTime();
      if (!Number.isFinite(expiryMs) || expiryMs <= now) {
        return this.makeRejection(pairKey, "handshake_budget_exhausted", {
          backoffClass: "intent_ref",
        });
      }
      parsedExpiryMs = expiryMs;
    }

    // Get or create correlation state. KEY BY pairKey, not correlationId,
    // so two senders that happen to use the same correlationId can't
    // consume each other's transitions or set terminal state on each
    // other's handshake.
    let state = this.correlations.get(pairKey);
    if (!state) {
      // Enforce memory bounds before creating new entry
      this.enforceMemoryBounds();

      // Reuse the parsed expiry from above instead of re-parsing.
      const ttl = parsedExpiryMs !== null
        ? Math.min(parsedExpiryMs, now + DEFAULT_HANDSHAKE_TTL_MS)
        : now + DEFAULT_HANDSHAKE_TTL_MS;

      state = {
        challenges: 0,
        totalTransitions: 0,
        terminal: false,
        expiresAt: ttl,
        createdAt: now,
      };
      this.correlations.set(pairKey, state);
    }

    // Check if correlation has expired
    if (state.expiresAt <= now) {
      return this.makeRejection(pairKey, "handshake_budget_exhausted", {
        backoffClass: "intent_ref",
      });
    }

    // Check if terminal state was already reached
    if (state.terminal) {
      return this.makeRejection(pairKey, "handshake_budget_exhausted", {
        backoffClass: "intent_ref",
      });
    }

    // Check total transitions
    if (state.totalTransitions >= this.maxTotalTransitions) {
      return this.makeRejection(pairKey, "handshake_budget_exhausted", {
        backoffClass: "intent_ref",
      });
    }

    // Check per-type limits
    if (messageType === "challenge" && state.challenges >= this.maxChallenges) {
      return this.makeRejection(pairKey, "handshake_budget_exhausted", {
        backoffClass: "intent_ref",
      });
    }

    // Record the message
    state.totalTransitions++;
    if (messageType === "challenge") {
      state.challenges++;
    }
    if (TERMINAL_TYPES.has(messageType)) {
      state.terminal = true;
    }

    // Sender activity was already recorded above (before the budget checks)
    // so per-sender limits accumulate even on rejected attempts.

    return { allowed: true };
  }

  pruneExpired(): void {
    const now = Date.now();
    for (const [pairKey, state] of this.correlations) {
      if (state.expiresAt <= now) {
        this.correlations.delete(pairKey);
        // Rejection tracking is keyed by the same pairKey, so we can drop
        // it directly.
        this.rejectionsSent.delete(pairKey);
      }
    }

    // Prune stale sender windows
    const oneMinuteAgo = now - 60_000;
    for (const [did, state] of this.senders) {
      state.intentTimestamps = state.intentTimestamps.filter((t) => t > oneMinuteAgo);
      state.handshakeTimestamps = state.handshakeTimestamps.filter((t) => t > oneMinuteAgo);
      if (state.intentTimestamps.length === 0 && state.handshakeTimestamps.length === 0) {
        this.senders.delete(did);
      }
    }

    // Prune sender-rejection records older than the silent-drop window.
    for (const [did, ts] of this.senderRejectionsSent) {
      if (now - ts >= SENDER_REJECTION_WINDOW_MS) {
        this.senderRejectionsSent.delete(did);
      }
    }
  }

  private checkSenderLimits(
    fromDid: string,
    messageType: string,
    now: number,
  ): BudgetCheckResult {
    const state = this.senders.get(fromDid);
    if (!state) return { allowed: true };

    const oneMinuteAgo = now - 60_000;

    // Check per-minute intent limit
    if (messageType === "intent") {
      const recentIntents = state.intentTimestamps.filter((t) => t > oneMinuteAgo);
      if (recentIntents.length >= this.maxIntentsPerMinute) {
        return this.makeSenderRejection(fromDid, now);
      }
    }

    // Check per-minute total handshake message limit
    const recentHandshake = state.handshakeTimestamps.filter((t) => t > oneMinuteAgo);
    if (recentHandshake.length >= this.maxHandshakeMsgsPerMinute) {
      return this.makeSenderRejection(fromDid, now);
    }

    return { allowed: true };
  }

  // Sender-level rate-limit rejection. Sends a typed reject (with backoff hint)
  // the first time a sender crosses the limit in the current window; silent-drops
  // subsequent violations until the window resets. Mirrors the per-correlation
  // makeRejection pattern from §5 of the INK Containment spec.
  private makeSenderRejection(fromDid: string, now: number): BudgetCheckResult {
    const lastSent = this.senderRejectionsSent.get(fromDid);
    if (lastSent !== undefined && now - lastSent < SENDER_REJECTION_WINDOW_MS) {
      return { allowed: false, reason: "sender_rate_limited", silentDrop: true };
    }
    // Bound the map by maxSenders to prevent attacker-driven growth. Evict the
    // oldest record if at capacity; the pruneExpired pass also cleans up
    // records older than the silent-drop window.
    if (this.senderRejectionsSent.size >= this.maxSenders &&
        !this.senderRejectionsSent.has(fromDid)) {
      let oldestDid: string | null = null;
      let oldestTs = Infinity;
      for (const [d, t] of this.senderRejectionsSent) {
        if (t < oldestTs) { oldestTs = t; oldestDid = d; }
      }
      if (oldestDid) this.senderRejectionsSent.delete(oldestDid);
    }
    this.senderRejectionsSent.set(fromDid, now);
    return {
      allowed: false,
      reason: "sender_rate_limited",
      backoffHint: { retryAfterSeconds: 60, backoffClass: "sender" },
      silentDrop: false,
    };
  }

  private recordSenderActivity(fromDid: string, messageType: string, now: number): void {
    let state = this.senders.get(fromDid);
    if (!state) {
      // Enforce sender cap before adding a new entry
      this.enforceSenderBounds();
      state = { intentTimestamps: [], handshakeTimestamps: [], lastActivity: now };
      this.senders.set(fromDid, state);
    }

    state.lastActivity = now;
    if (messageType === "intent") {
      state.intentTimestamps.push(now);
    }
    state.handshakeTimestamps.push(now);
  }

  private makeRejection(
    pairKey: string,
    reason: string,
    backoffHint: InkBackoffHint,
  ): BudgetCheckResult {
    if (this.rejectionsSent.has(pairKey)) {
      return { allowed: false, reason, silentDrop: true };
    }
    this.rejectionsSent.add(pairKey);
    this.enforceRejectionBounds();
    return { allowed: false, reason, backoffHint, silentDrop: false };
  }

  private enforceRejectionBounds(): void {
    if (this.rejectionsSent.size <= this.maxRejectionEntries) return;

    // Prune rejection entries whose backing correlation no longer exists
    // (already expired or evicted). Rejection keys and correlation keys are
    // both pairKeys now, so the lookup is direct.
    const now = Date.now();
    for (const key of this.rejectionsSent) {
      const state = this.correlations.get(key);
      if (!state || state.expiresAt <= now) {
        this.rejectionsSent.delete(key);
      }
    }

    // If still over limit, clear the oldest half (Set maintains insertion order)
    if (this.rejectionsSent.size > this.maxRejectionEntries) {
      const entries = [...this.rejectionsSent];
      const keepFrom = Math.floor(entries.length / 2);
      this.rejectionsSent.clear();
      for (let i = keepFrom; i < entries.length; i++) {
        this.rejectionsSent.add(entries[i]!);
      }
    }
  }

  private enforceSenderBounds(): void {
    if (this.senders.size < this.maxSenders) return;

    // Evict sender with oldest lastActivity
    let oldestDid: string | null = null;
    let oldestTime = Infinity;
    for (const [did, state] of this.senders) {
      if (state.lastActivity < oldestTime) {
        oldestTime = state.lastActivity;
        oldestDid = did;
      }
    }
    if (oldestDid) {
      this.senders.delete(oldestDid);
    }
  }

  private enforceMemoryBounds(): void {
    if (this.correlations.size < this.maxCorrelations) return;

    // Evict oldest entry (by createdAt)
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [key, state] of this.correlations) {
      if (state.createdAt < oldestTime) {
        oldestTime = state.createdAt;
        oldestKey = key;
      }
    }
    if (oldestKey) {
      this.correlations.delete(oldestKey);
      // Rejection tracking is keyed by the same pairKey, so drop directly.
      this.rejectionsSent.delete(oldestKey);
    }
  }
}
