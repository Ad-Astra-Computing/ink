import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyCheckpoint, generateKeypair } from "../src/index.js";

const ORIGIN = "witness.example";
const ROOT = "a".repeat(64);

/**
 * Reproduce the witness's signed-checkpoint format exactly (witness-log.ts
 * handleCheckpoint): the signature covers the body bytes
 * `<origin>\n<treeSize>\n<rootHash>` with no trailing newline, base64url
 * encoded, then `\n\n-- <origin> <sig>\n` is appended.
 */
async function signCheckpoint(
  origin: string,
  treeSize: number,
  rootHash: string,
  privateKey: Uint8Array,
  opts: { sigOrigin?: string } = {},
): Promise<string> {
  const body = `${origin}\n${treeSize}\n${rootHash}`;
  const sig = await ed.signAsync(new TextEncoder().encode(body), privateKey);
  const sigB64 = Buffer.from(sig).toString("base64url");
  return `${body}\n\n-- ${opts.sigOrigin ?? origin} ${sigB64}\n`;
}

describe("verifyCheckpoint", () => {
  it("accepts a correctly signed checkpoint and returns its parsed body", async () => {
    const kp = await generateKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    const result = await verifyCheckpoint(signed, kp.publicKey, ORIGIN);
    expect(result).not.toBeNull();
    expect(result).toEqual({ origin: ORIGIN, treeSize: 42, rootHash: ROOT });
  });

  it("rejects a checkpoint whose body was tampered after signing", async () => {
    const kp = await generateKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    // Flip the tree size in the signed text without re-signing.
    const tampered = signed.replace(`${ORIGIN}\n42\n`, `${ORIGIN}\n99\n`);
    expect(await verifyCheckpoint(tampered, kp.publicKey, ORIGIN)).toBeNull();
  });

  it("rejects a checkpoint signed by a different key", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    expect(await verifyCheckpoint(signed, other.publicKey, ORIGIN)).toBeNull();
  });

  it("rejects a checkpoint whose origin does not match the expected origin", async () => {
    const kp = await generateKeypair();
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey);
    expect(await verifyCheckpoint(signed, kp.publicKey, "other.witness")).toBeNull();
  });

  it("rejects when the signature-line origin disagrees with the body origin", async () => {
    const kp = await generateKeypair();
    // Body says ORIGIN, signature line claims a different origin.
    const signed = await signCheckpoint(ORIGIN, 42, ROOT, kp.privateKey, { sigOrigin: "evil.witness" });
    expect(await verifyCheckpoint(signed, kp.publicKey, ORIGIN)).toBeNull();
  });

  it("rejects an unsigned checkpoint body", async () => {
    const kp = await generateKeypair();
    const body = `${ORIGIN}\n42\n${ROOT}\n`;
    expect(await verifyCheckpoint(body, kp.publicKey, ORIGIN)).toBeNull();
  });

  it("rejects a malformed or oversized input", async () => {
    const kp = await generateKeypair();
    expect(await verifyCheckpoint("", kp.publicKey, ORIGIN)).toBeNull();
    expect(await verifyCheckpoint("x".repeat(5000), kp.publicKey, ORIGIN)).toBeNull();
  });
});
