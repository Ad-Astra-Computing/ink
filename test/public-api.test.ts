/**
 * Smoke test for the package's public entry point (src/index.ts).
 *
 * Regression guard for the README rewrite: README documents importing
 * the public API from "@adastracomputing/ink" (the package root,
 * which resolves to src/index.ts via package.json `main`). If any
 * documented export disappears or breaks, this test fails immediately
 * instead of silently shipping a misleading README.
 */
import { describe, it, expect } from "vitest";
import * as ink from "../src/index.js";

describe("public API surface (src/index.ts → package root)", () => {
  it("re-exports the documented crypto primitives", () => {
    expect(typeof ink.signInkMessage).toBe("function");
    expect(typeof ink.verifyInkSignature).toBe("function");
    expect(typeof ink.buildSignatureBase).toBe("function");
    expect(typeof ink.buildAuthHeader).toBe("function");
    expect(typeof ink.signMessage).toBe("function");
    expect(typeof ink.verifyMessage).toBe("function");
    expect(typeof ink.encryptInkPayload).toBe("function");
    expect(typeof ink.decryptInkPayload).toBe("function");
    expect(typeof ink.checkReplay).toBe("function");
  });

  it("re-exports the documented key utilities", () => {
    expect(typeof ink.generateKeypair).toBe("function");
    expect(typeof ink.deriveAgentId).toBe("function");
    expect(typeof ink.encodePublicKeyMultibase).toBe("function");
    expect(typeof ink.decodePublicKeyMultibase).toBe("function");
    expect(typeof ink.extractPublicKeyFromAgentId).toBe("function");
    expect(typeof ink.canonicalAgentPrincipal).toBe("function");
  });

  it("re-exports the documented discovery and middleware functions", () => {
    expect(typeof ink.fetchAgentCard).toBe("function");
    expect(typeof ink.extractCandidateKeys).toBe("function");
    expect(typeof ink.verifyInkAuth).toBe("function");
  });

  it("re-exports audit/handshake helpers", () => {
    expect(typeof ink.signAuditEvent).toBe("function");
    expect(typeof ink.verifyAuditEventSignature).toBe("function");
    expect(typeof ink.signAuditResponse).toBe("function");
    expect(typeof ink.verifyAuditResponseSignature).toBe("function");
    expect(typeof ink.HandshakeBudgetTracker).toBe("function");
  });

  it("exports the documented freshness-window constants", () => {
    // README claims "5 minutes past, 30 seconds future". Verify the
    // constants match so a future change forces a docs update.
    expect(ink.MAX_TIMESTAMP_AGE_MS).toBe(5 * 60 * 1000);
    expect(ink.MAX_FUTURE_TIMESTAMP_MS).toBe(30 * 1000);
  });
});
