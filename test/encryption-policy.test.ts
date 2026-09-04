import { describe, it, expect } from "vitest";
import {
  CONFIDENTIAL_INTENTS,
  intentRequiresEncryption,
  checkEncryptionRequired,
} from "../src/ink/encryption-policy.js";
import { IntentTypeSchema } from "../src/models/intent.js";

describe("CONFIDENTIAL_INTENTS", () => {
  it("names exactly the §3.4 set, every member an allocated intent", () => {
    expect([...CONFIDENTIAL_INTENTS].sort()).toEqual(["context_share", "multi_party_sync", "schedule_meeting"]);
    for (const intent of CONFIDENTIAL_INTENTS) {
      expect(IntentTypeSchema.safeParse(intent).success).toBe(true);
    }
  });

  it("intentRequiresEncryption agrees with the set", () => {
    for (const intent of IntentTypeSchema.options) {
      expect(intentRequiresEncryption(intent)).toBe((CONFIDENTIAL_INTENTS as readonly string[]).includes(intent));
    }
    expect(intentRequiresEncryption("telepathy")).toBe(false);
    expect(intentRequiresEncryption("")).toBe(false);
  });
});

describe("checkEncryptionRequired", () => {
  it("refuses every confidential intent in plaintext with encryption_required", () => {
    for (const intent of CONFIDENTIAL_INTENTS) {
      expect(checkEncryptionRequired({ intent })).toEqual({ allowed: false, reason: "encryption_required", intent });
    }
  });

  it("allows every other allocated intent", () => {
    for (const intent of IntentTypeSchema.options) {
      if ((CONFIDENTIAL_INTENTS as readonly string[]).includes(intent)) continue;
      expect(checkEncryptionRequired({ intent })).toEqual({ allowed: true });
    }
  });

  it("does not match by prefix, case or surrounding whitespace", () => {
    for (const intent of ["Schedule_Meeting", " schedule_meeting", "schedule_meeting_response", "context_share2"]) {
      expect(checkEncryptionRequired({ intent })).toEqual({ allowed: true });
    }
  });

  it("passes an envelope with no string intent to the schema, not the gate", () => {
    expect(checkEncryptionRequired({})).toEqual({ allowed: true });
    expect(checkEncryptionRequired({ intent: 7 })).toEqual({ allowed: true });
    expect(checkEncryptionRequired({ intent: null })).toEqual({ allowed: true });
    expect(checkEncryptionRequired(null)).toEqual({ allowed: true });
    expect(checkEncryptionRequired(undefined)).toEqual({ allowed: true });
  });

  it("lets a receiver widen the set with intents of its own", () => {
    const opts = { extraConfidentialIntents: ["opportunity"] };
    expect(checkEncryptionRequired({ intent: "opportunity" }, opts)).toEqual({
      allowed: false,
      reason: "encryption_required",
      intent: "opportunity",
    });
    expect(checkEncryptionRequired({ intent: "ping" }, opts)).toEqual({ allowed: true });
  });

  it("never lets a receiver narrow the protocol set", () => {
    const opts = { extraConfidentialIntents: ["opportunity"] };
    for (const intent of CONFIDENTIAL_INTENTS) {
      expect(checkEncryptionRequired({ intent }, opts)).toEqual({ allowed: false, reason: "encryption_required", intent });
      expect(checkEncryptionRequired({ intent }, { extraConfidentialIntents: [] })).toEqual({
        allowed: false,
        reason: "encryption_required",
        intent,
      });
    }
  });
});
