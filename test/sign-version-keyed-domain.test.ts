/**
 * Version-keyed body-signature domain separation.
 *
 * The body signature is computed over `<domain>\n` + JCS(body), where the
 * domain is selected from the signed `protocol` field:
 *   ink/0.1 (and any non-ink/0.2 object) -> "tulpa/sign\n" (legacy, kept
 *     forever for backward compatibility)
 *   ink/0.2 -> "ink/sign\n"
 *
 * These tests pin both the backward-compatible legacy behavior and the
 * new ink/0.2 domain, and prove the two domains do not cross-verify, so a
 * signature made under one version cannot be replayed under another.
 */

import { describe, it, expect } from "vitest";
import { generateKeypair, signMessage, verifyMessage } from "../src/index.js";

async function kp() {
  return generateKeypair();
}

const baseBody = () => ({
  protocol: "ink/0.1",
  id: "01ABCDEF",
  from: "did:key:zSender",
  to: "did:key:zRecipient",
  intent: "connection_request",
  timestamp: "2026-06-03T00:00:00Z",
  nonce: "abcdef0123456789",
});

describe("version-keyed body signature domain", () => {
  it("ink/0.1 message round-trips under the legacy domain", async () => {
    const k = await kp();
    const body: Record<string, unknown> = { ...baseBody(), protocol: "ink/0.1" };
    const signature = await signMessage(body, k.privateKey);
    expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
  });

  it("ink/0.2 message round-trips under the new domain", async () => {
    const k = await kp();
    const body: Record<string, unknown> = { ...baseBody(), protocol: "ink/0.2" };
    const signature = await signMessage(body, k.privateKey);
    expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
  });

  it("a protocol-less object round-trips under the legacy domain", async () => {
    const k = await kp();
    const body: Record<string, unknown> = { hello: "world", n: 1 };
    const signature = await signMessage(body, k.privateKey);
    expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
  });

  it("the two domains differ: an ink/0.2 signature differs from an ink/0.1 signature over the same other fields", async () => {
    const k = await kp();
    const rest = { ...baseBody() };
    delete (rest as Record<string, unknown>).protocol;
    const sig01 = await signMessage({ ...rest, protocol: "ink/0.1" }, k.privateKey);
    const sig02 = await signMessage({ ...rest, protocol: "ink/0.2" }, k.privateKey);
    expect(sig01).not.toBe(sig02);
  });

  describe("cross-version replay is rejected (tamper-evidence)", () => {
    it("an ink/0.2 body relabelled ink/0.1 fails to verify", async () => {
      const k = await kp();
      const body: Record<string, unknown> = { ...baseBody(), protocol: "ink/0.2" };
      const signature = await signMessage(body, k.privateKey);
      const tampered = { ...body, protocol: "ink/0.1", signature };
      expect(await verifyMessage(tampered, k.publicKey)).toBe(false);
    });

    it("an ink/0.1 body relabelled ink/0.2 fails to verify", async () => {
      const k = await kp();
      const body: Record<string, unknown> = { ...baseBody(), protocol: "ink/0.1" };
      const signature = await signMessage(body, k.privateKey);
      const tampered = { ...body, protocol: "ink/0.2", signature };
      expect(await verifyMessage(tampered, k.publicKey)).toBe(false);
    });

    it("an ink/0.2 body with protocol removed (-> legacy domain) fails to verify", async () => {
      const k = await kp();
      const body: Record<string, unknown> = { ...baseBody(), protocol: "ink/0.2" };
      const signature = await signMessage(body, k.privateKey);
      const stripped: Record<string, unknown> = { ...body, signature };
      delete stripped.protocol;
      expect(await verifyMessage(stripped, k.publicKey)).toBe(false);
    });
  });

  describe("only the exact string ink/0.2 switches domains", () => {
    for (const sneaky of ["ink/0.2 ", " ink/0.2", "INK/0.2", "ink/0.20", "ink/0.3", "ink/2.0"]) {
      it(`protocol ${JSON.stringify(sneaky)} uses the legacy domain (not the v0.2 domain)`, async () => {
        const k = await kp();
        const body: Record<string, unknown> = { ...baseBody(), protocol: sneaky };
        // Signed under the legacy domain (it is not exactly "ink/0.2").
        const signature = await signMessage(body, k.privateKey);
        // Verifies as itself (legacy domain on both sides)...
        expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
        // ...and a real ink/0.2 signature would NOT verify for this body,
        // confirming these strings did not select the v0.2 domain.
        const v2sig = await signMessage({ ...body, protocol: "ink/0.2" }, k.privateKey);
        expect(await verifyMessage({ ...body, signature: v2sig }, k.publicKey)).toBe(false);
      });
    }

    it("a non-string protocol uses the legacy domain", async () => {
      const k = await kp();
      const body: Record<string, unknown> = { ...baseBody(), protocol: { nested: "ink/0.2" } };
      const signature = await signMessage(body, k.privateKey);
      expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
    });

    it("a boxed String('ink/0.2') object does NOT select the v0.2 domain (strict ===)", async () => {
      const k = await kp();
      // eslint-disable-next-line no-new-wrappers
      const body: Record<string, unknown> = { ...baseBody(), protocol: new String("ink/0.2") };
      const signature = await signMessage(body, k.privateKey);
      // Signs + verifies under legacy; a true v0.2 signature would not verify.
      expect(await verifyMessage({ ...body, signature }, k.publicKey)).toBe(true);
      const v2sig = await signMessage({ ...body, protocol: "ink/0.2" }, k.privateKey);
      expect(await verifyMessage({ ...body, signature: v2sig }, k.publicKey)).toBe(false);
    });
  });
});
