/**
 * Seal-time inner/outer binding for the ECIES payload envelope (§3.4).
 *
 * Every conformant decrypter requires the sealed plaintext to carry `from`
 * equal to the outer envelope sender and `to` equal to the recipient identity
 * the decrypter asserts. The seal path did not check that, so a producer could
 * mint an envelope no conformant decrypter would ever open. The other
 * encrypt-side guards (scalar caps, plaintext bounds, the all-zero ECDH secret)
 * are all written so encrypt cannot mint what decrypt refuses; these tests pin
 * the same rule for the inner binding.
 */
import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import { encryptInkPayload, decryptInkPayload } from "../src/crypto/ink.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function recipient() {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  return { privHex: bytesToHex(priv), pubHex: bytesToHex(x25519.getPublicKey(priv)) };
}

const SENDER = "did:web:sender.example";
const RECIPIENT = "did:web:recipient.example";
const TS = "2026-04-01T00:00:00.000Z";
const NONCE = "01HENCNONCE00000000000000";

describe("encryptInkPayload: inner/outer binding is enforced at seal time", () => {
  it("seals and round-trips when the inner binding matches", async () => {
    const r = recipient();
    const { envelope } = await encryptInkPayload(
      { from: SENDER, to: RECIPIENT, note: "hello" },
      SENDER,
      r.pubHex,
      TS,
      NONCE,
      { recipientDid: RECIPIENT },
    );
    const out = await decryptInkPayload(envelope, r.privHex, RECIPIENT);
    expect(out.note).toBe("hello");
  });

  it("rejects a plaintext whose `from` disagrees with the outer sender", async () => {
    const r = recipient();
    await expect(
      encryptInkPayload(
        { from: "did:web:someone-else.example", to: RECIPIENT },
        SENDER,
        r.pubHex,
        TS,
        NONCE,
      ),
    ).rejects.toThrow(/inner .*from|from.*sender/i);
  });

  it("rejects a plaintext with no `from` at all", async () => {
    const r = recipient();
    await expect(
      encryptInkPayload({ to: RECIPIENT, note: "hi" }, SENDER, r.pubHex, TS, NONCE),
    ).rejects.toThrow(/from/i);
  });

  it("rejects a plaintext whose `to` disagrees with the asserted recipient", async () => {
    const r = recipient();
    await expect(
      encryptInkPayload({ from: SENDER, to: "did:web:elsewhere.example" }, SENDER, r.pubHex, TS, NONCE, {
        recipientDid: RECIPIENT,
      }),
    ).rejects.toThrow(/to/i);
  });

  it("rejects a plaintext with a missing or non-string `to`", async () => {
    const r = recipient();
    await expect(
      encryptInkPayload({ from: SENDER, note: "hi" }, SENDER, r.pubHex, TS, NONCE),
    ).rejects.toThrow(/to/i);
    await expect(
      encryptInkPayload({ from: SENDER, to: "" }, SENDER, r.pubHex, TS, NONCE),
    ).rejects.toThrow(/to/i);
    await expect(
      encryptInkPayload({ from: SENDER, to: 42 }, SENDER, r.pubHex, TS, NONCE),
    ).rejects.toThrow(/to/i);
  });

  it("rejects an asserted EMPTY recipientDid rather than treating it as omitted", async () => {
    // Supplying `recipientDid: ""` is an assertion no inner `to` can satisfy,
    // since `to` must itself be non-empty. Treating it as "not asserted" would
    // silently seal an envelope whose intended recipient the caller got wrong.
    // The Go port carries the same rule with a *string field, so the two
    // implementations agree on the empty-string case.
    const r = recipient();
    await expect(
      encryptInkPayload({ from: SENDER, to: RECIPIENT }, SENDER, r.pubHex, TS, NONCE, {
        recipientDid: "",
      }),
    ).rejects.toThrow(/to/i);
  });

  it("still seals when options are supplied without a recipientDid", async () => {
    const r = recipient();
    const { envelope } = await encryptInkPayload(
      { from: SENDER, to: RECIPIENT, note: "hi" },
      SENDER,
      r.pubHex,
      TS,
      NONCE,
      { messageType: "network.ink.encrypted" },
    );
    const out = await decryptInkPayload(envelope, r.privHex, RECIPIENT);
    expect(out.note).toBe("hi");
  });

  it("still seals without an asserted recipientDid, and the envelope opens for the inner `to`", async () => {
    const r = recipient();
    const { envelope } = await encryptInkPayload(
      { from: SENDER, to: RECIPIENT, note: "hi" },
      SENDER,
      r.pubHex,
      TS,
      NONCE,
    );
    const out = await decryptInkPayload(envelope, r.privHex, RECIPIENT);
    expect(out.note).toBe("hi");
  });
});
