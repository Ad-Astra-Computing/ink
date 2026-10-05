import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signMessage, verifyMessage, generateKeypair } from "../src/index.js";
import { decodePublicKeyMultibase, encodePublicKeyMultibase } from "../src/crypto/keys.js";
import { verifyStrictEd25519 } from "../src/crypto/ed25519-strict.js";

const SUBGROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i] ?? 0);
  }
  return value;
}

function numberToBytesLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Scalar multiplication by raw doubling and adding, using only Point.add().
 * Bypasses Point.multiply()'s `1 <= n < subgroupOrder` range guard, needed
 * here to multiply by the subgroup order itself when deriving the order-8
 * torsion point below.
 */
function rawMultiply(point: InstanceType<typeof ed.Point>, scalar: bigint): InstanceType<typeof ed.Point> {
  let result = ed.Point.ZERO;
  let addend = point;
  let n = scalar;
  while (n > 0n) {
    if (n & 1n) result = result.add(addend);
    addend = addend.add(addend);
    n >>= 1n;
  }
  return result;
}

/**
 * The Ed25519 curve group has order 8L (L = the prime subgroup order). It is
 * cyclic, so a random valid point not in the prime-order subgroup has order
 * dividing 8L but not L; multiplying it by L yields the unique order-8
 * element. This is the "T8" the mixed-order forgery adds to an honest key.
 */
function findOrder8Point(): InstanceType<typeof ed.Point> {
  for (let attempt = 0; attempt < 200; attempt++) {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = (attempt * 7 + i * 13 + 1) & 0xff;
    let candidate: InstanceType<typeof ed.Point>;
    try {
      candidate = ed.Point.fromBytes(seed, false);
    } catch {
      continue;
    }
    const t8 = rawMultiply(candidate, SUBGROUP_ORDER);
    if (t8.is0()) continue; // candidate was already in the prime-order subgroup
    const two = t8.add(t8);
    const four = two.add(two);
    if (!four.add(four).is0()) throw new Error("expected 8*T == 0");
    if (two.is0() || four.is0()) continue; // unlucky: order divides 4, keep searching
    return t8;
  }
  throw new Error("failed to find an order-8 point");
}

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

describe("cofactorless verification (RFC 8032 / spec §3.3 Frozen equation)", () => {
  it("rejects a signature under a mixed-order public key that a cofactored check would accept", async () => {
    // A = A0 + T8: canonical, NOT small-order, built from an honest key A0
    // plus an order-8 torsion point T8. @noble/ed25519's {zip215:false} mode
    // checks the COFACTORED equation [8](R+[k]A-[S]B)==0; Go's bare
    // crypto/ed25519.Verify checks the COFACTORLESS [S]B==R+[k]A. The two
    // diverge whenever k mod 8 != 0, which is the fork the spec closes.
    const t8 = findOrder8Point();
    const seed = ed.utils.randomSecretKey();
    const ext = await ed.utils.getExtendedPublicKeyAsync(seed);
    const a0 = ext.scalar;
    const mixedOrderKey = ext.point.add(t8);
    const publicKeyBytes = mixedOrderKey.toBytes();
    expect(mixedOrderKey.isSmallOrder()).toBe(false);

    const message = new TextEncoder().encode("mixed-order forgery test message");

    let forged: { R: Uint8Array; s: bigint } | null = null;
    for (let attempt = 0; attempt < 500 && forged === null; attempt++) {
      const rSeed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) rSeed[i] = (attempt * 11 + i * 5 + 3) & 0xff;
      const r = bytesToNumberLE(rSeed) % SUBGROUP_ORDER;
      if (r === 0n) continue;
      const R = ed.Point.BASE.multiply(r, false);
      const Rbytes = R.toBytes();
      const hashed = await ed.hashes.sha512Async(concatBytes(Rbytes, publicKeyBytes, message));
      const k = bytesToNumberLE(hashed) % SUBGROUP_ORDER;
      if (k % 8n === 0n) continue; // need the cofactored/cofactorless equations to diverge
      const s = (r + k * a0) % SUBGROUP_ORDER;
      forged = { R: Rbytes, s };
    }
    if (forged === null) throw new Error("could not grind a k with k mod 8 != 0");

    const sig = concatBytes(forged.R, numberToBytesLE(forged.s, 32));

    // Proves the fork is real: the library's own zip215:false mode still
    // accepts it (cofactored check).
    expect(await ed.verifyAsync(sig, message, publicKeyBytes, { zip215: false })).toBe(true);
    // The shared strict verifier rejects it (cofactorless check, per spec).
    expect(await verifyStrictEd25519(sig, message, publicKeyBytes)).toBe(false);

    // Control: an honest signature under A0 alone (no torsion component)
    // still verifies under both, so this isn't a general regression.
    const honestSig = await ed.signAsync(message, seed);
    expect(await verifyStrictEd25519(honestSig, message, ext.pointBytes)).toBe(true);
  });

  it("rejects a signature whose S scalar is non-canonical (S + subgroup order)", async () => {
    const kp = await generateKeypair();
    const message = new TextEncoder().encode("non-canonical S test message");
    const sig = await ed.signAsync(message, kp.privateKey);
    expect(await verifyStrictEd25519(sig, message, kp.publicKey)).toBe(true);

    const s = bytesToNumberLE(sig.subarray(32, 64));
    const nonCanonicalS = numberToBytesLE(s + SUBGROUP_ORDER, 32);
    const tampered = concatBytes(sig.subarray(0, 32), nonCanonicalS);
    expect(await verifyStrictEd25519(tampered, message, kp.publicKey)).toBe(false);
  });

  it("rejects a non-canonical public-key encoding (identity encoded as y = p + 1)", async () => {
    // p = 2^255 - 19. Encoding y = p + 1 as little-endian bytes with the sign
    // bit clear decodes, after the strict `y < p` range check, to a value
    // outside the field: bytes 0xee, then 30 bytes of 0xff, then 0x7f.
    const nonCanonical = new Uint8Array(32);
    nonCanonical[0] = 0xee;
    for (let i = 1; i < 31; i++) nonCanonical[i] = 0xff;
    nonCanonical[31] = 0x7f;

    // R = basepoint, S = 1: only the public-key encoding under test matters,
    // since a strict verifier must reject before ever reaching the equation.
    const R = ed.Point.BASE.toBytes();
    const S = new Uint8Array(32);
    S[0] = 1;
    const sig = concatBytes(R, S);
    const message = new TextEncoder().encode("any message at all");

    expect(await verifyStrictEd25519(sig, message, nonCanonical)).toBe(false);
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

describe("single verification path", () => {
  it("no source or published CLI file calls the library verifier directly", async () => {
    const { readdirSync, readFileSync, statSync } = await import("node:fs");
    const { join } = await import("node:path");
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (
          (path.endsWith(".ts") || path.endsWith(".mjs")) &&
          !path.endsWith("ed25519-strict.ts") &&
          !path.endsWith("ed25519-strict.mjs")
        ) {
          const text = readFileSync(path, "utf-8");
          if (/\bverifyAsync\s*\(|\bed\.verify\s*\(/.test(text)) offenders.push(path);
        }
      }
    };
    walk(new URL("../src", import.meta.url).pathname);
    // bin/ is published and has no dist/ to import from at CLI runtime, so it
    // carries its own copy (ed25519-strict.mjs) rather than importing src/.
    // This caught two direct library-verify calls that slipped past the
    // src/-only version of this guard (bin/verify-inclusion-impl.mjs).
    walk(new URL("../bin", import.meta.url).pathname);
    expect(offenders).toEqual([]);
  });
});
