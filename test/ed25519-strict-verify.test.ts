import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signMessage, verifyMessage, generateKeypair } from "../src/index.js";
import { decodePublicKeyMultibase, encodePublicKeyMultibase } from "../src/crypto/keys.js";

/**
 * Small-order public-key forgery vector.
 *
 * With the public key A = the identity point (a small-order element), the
 * signature (R = basepoint, S = 1) satisfies the cofactored ZIP-215
 * verification equation [S]B = R + [k]A for ANY message, because [k]A is the
 * identity for every scalar k. RFC 8032 strict verification (zip215:false)
 * rejects the small-order public key outright, closing the forgery.
 */
function smallOrderForgery(): { pub: Uint8Array; sigB64: string } {
  const pub = ed.Point.ZERO.toBytes(); // identity, small-order
  const R = ed.Point.BASE.toBytes(); // basepoint
  const S = new Uint8Array(32);
  S[0] = 1; // scalar 1, little-endian
  const sig = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(S, 32);
  return { pub, sigB64: Buffer.from(sig).toString("base64url") };
}

describe("Ed25519 strict (RFC 8032) verification", () => {
  it("the forgery vector is accepted by noble's default ZIP-215 mode (proves the vector is real)", async () => {
    const { pub, sigB64 } = smallOrderForgery();
    const sig = Buffer.from(sigB64, "base64url");
    const acceptedZip215 = await ed.verifyAsync(
      sig,
      new TextEncoder().encode("any message at all"),
      pub,
      { zip215: true },
    );
    expect(acceptedZip215).toBe(true);
    const rejectedStrict = await ed.verifyAsync(
      sig,
      new TextEncoder().encode("any message at all"),
      pub,
      { zip215: false },
    );
    expect(rejectedStrict).toBe(false);
  });

  it("verifyMessage rejects a signature made under a small-order public key", async () => {
    const { pub, sigB64 } = smallOrderForgery();
    const message = { protocol: "ink/0.2", hello: "world", signature: sigB64 };
    expect(await verifyMessage(message, pub)).toBe(false);
  });

  it("legitimate signatures still verify (no regression from strict mode)", async () => {
    const kp = await generateKeypair();
    const unsigned = { protocol: "ink/0.2", note: "a real signed message" };
    const sig = await signMessage(unsigned, kp.privateKey);
    expect(await verifyMessage({ ...unsigned, signature: sig }, kp.publicKey)).toBe(true);
  });
});

describe("multibase agentId canonical-form", () => {
  it("round-trips a valid key to its canonical encoding", async () => {
    const kp = await generateKeypair();
    const mb = encodePublicKeyMultibase(kp.publicKey);
    const decoded = decodePublicKeyMultibase(mb);
    expect(encodePublicKeyMultibase(decoded)).toBe(mb);
  });

  it("rejects a non-canonical encoding that prepends a leading '1' (extra zero byte)", async () => {
    const kp = await generateKeypair();
    const mb = encodePublicKeyMultibase(kp.publicKey); // "z" + base58(0xed01 || key)
    // Inject a non-canonical leading "1" into the base58 body: it decodes to a
    // leading 0x00 byte, shifting the multicodec prefix, and must be rejected.
    const nonCanonical = "z1" + mb.slice(1);
    expect(() => decodePublicKeyMultibase(nonCanonical)).toThrow();
  });
});
