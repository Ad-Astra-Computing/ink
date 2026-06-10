import { describe, it, expect } from "vitest";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";

describe("Authorization header separator", () => {
  it("rejects a header that uses a tab, newline, CR, or doubled space as the separator", async () => {
    const sig = "A".repeat(86);
    for (const sep of ["\t", "\n", "\r", "  ", " \t"]) {
      const result = await verifyInkAuth({
        nonceStore: "deferred",
        authHeader: `INK-Ed25519${sep}${sig}`,
        method: "POST",
        path: "/x",
        recipientAgentId: "tulpa:zR",
        body: { from: "tulpa:zS", timestamp: new Date().toISOString() },
      });
      expect(result.valid, JSON.stringify(sep)).toBe(false);
      if (!result.valid) expect(result.error).toBe("invalid_auth_scheme");
    }
  });

  it("accepts the canonical single-space header grammar", async () => {
    const sig = "A".repeat(86);
    // A single space passes the scheme regex (it fails later at signature
    // verification, not at scheme parsing).
    const result = await verifyInkAuth({
      nonceStore: "deferred",
      authHeader: `INK-Ed25519 ${sig}`,
      method: "POST",
      path: "/x",
      recipientAgentId: "tulpa:zR",
      body: { from: "tulpa:zS", timestamp: new Date().toISOString() },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).not.toBe("invalid_auth_scheme");
  });
});
