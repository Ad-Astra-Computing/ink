import { describe, it, expect } from "vitest";
import {
  CONFIDENTIAL_INTENTS,
  intentRequiresEncryption,
  checkEncryptionRequired,
  checkIntentDisposition,
} from "../src/ink/encryption-policy.js";
import { IntentTypeSchema, REGISTERED_INTENTS } from "../src/models/intent.js";

describe("CONFIDENTIAL_INTENTS", () => {
  it("names exactly the §3.4 set, every member a registered intent", () => {
    expect([...CONFIDENTIAL_INTENTS].sort()).toEqual(["context_share", "multi_party_sync", "schedule_meeting"]);
    for (const intent of CONFIDENTIAL_INTENTS) {
      expect(IntentTypeSchema.safeParse(intent).success).toBe(true);
    }
  });

  it("intentRequiresEncryption agrees with the set", () => {
    for (const intent of REGISTERED_INTENTS) {
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

  it("allows every other registered intent", () => {
    for (const intent of REGISTERED_INTENTS) {
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

describe("checkIntentDisposition", () => {
  // Two receivers with different installed support, proving the decision is
  // keyed on the RECEIVER's own set, not a single shared global one.
  const narrowReceiver = { supportedIntents: ["ping", "ask"] };
  const widerReceiver = { supportedIntents: ["ping", "ask", "schedule_meeting", "context_share"] };

  it("refuses unsupported_intent before ever consulting confidentiality", () => {
    // schedule_meeting is protocol-confidential, but narrowReceiver does not
    // support it at all: the receiver that never acts on an intent has
    // nothing to demand encryption for.
    expect(checkIntentDisposition({ intent: "schedule_meeting" }, narrowReceiver)).toEqual({
      allowed: false,
      reason: "unsupported_intent",
      intent: "schedule_meeting",
    });
  });

  it("refuses encryption_required only once the receiver supports the intent", () => {
    expect(checkIntentDisposition({ intent: "schedule_meeting" }, widerReceiver)).toEqual({
      allowed: false,
      reason: "encryption_required",
      intent: "schedule_meeting",
    });
    expect(checkIntentDisposition({ intent: "context_share" }, widerReceiver)).toEqual({
      allowed: false,
      reason: "encryption_required",
      intent: "context_share",
    });
  });

  it("allows a supported, non-confidential intent", () => {
    expect(checkIntentDisposition({ intent: "ping" }, narrowReceiver)).toEqual({ allowed: true });
    expect(checkIntentDisposition({ intent: "ask" }, widerReceiver)).toEqual({ allowed: true });
  });

  it("refuses unsupported_intent for a well-formed vendor intent nobody installed", () => {
    expect(checkIntentDisposition({ intent: "com.example.custom_intent" }, narrowReceiver)).toEqual({
      allowed: false,
      reason: "unsupported_intent",
      intent: "com.example.custom_intent",
    });
  });

  it("treats a vendor intent's own confidentiality as the receiver's to install, not the protocol's", () => {
    const vendorReceiver = {
      supportedIntents: ["ping", "com.example.custom_intent"],
      extraConfidentialIntents: ["com.example.custom_intent"],
    };
    expect(checkIntentDisposition({ intent: "com.example.custom_intent" }, vendorReceiver)).toEqual({
      allowed: false,
      reason: "encryption_required",
      intent: "com.example.custom_intent",
    });
    // The same vendor intent, installed but NOT widened into confidentiality,
    // passes: the protocol's three names are the only ones required by default.
    expect(
      checkIntentDisposition({ intent: "com.example.custom_intent" }, { supportedIntents: ["com.example.custom_intent"] }),
    ).toEqual({ allowed: true });
  });

  it("treats connection_request and connection_response as always supported, listed or not", () => {
    const noSupportedIntents = { supportedIntents: [] };
    expect(checkIntentDisposition({ intent: "connection_request" }, noSupportedIntents)).toEqual({ allowed: true });
    expect(checkIntentDisposition({ intent: "connection_response" }, noSupportedIntents)).toEqual({ allowed: true });
    // A core intent is never, itself, protocol-confidential, so this stays an
    // allow even once the gate runs; nothing here claims otherwise.
  });

  it("extraConfidentialIntents can only widen, never narrow, the composed decision", () => {
    const opts = { supportedIntents: ["schedule_meeting"], extraConfidentialIntents: [] };
    expect(checkIntentDisposition({ intent: "schedule_meeting" }, opts)).toEqual({
      allowed: false,
      reason: "encryption_required",
      intent: "schedule_meeting",
    });
  });

  it("passes an envelope with no string intent through, as the schema's job", () => {
    expect(checkIntentDisposition({}, narrowReceiver)).toEqual({ allowed: true });
    expect(checkIntentDisposition({ intent: 7 }, narrowReceiver)).toEqual({ allowed: true });
    expect(checkIntentDisposition(null, narrowReceiver)).toEqual({ allowed: true });
  });
});
