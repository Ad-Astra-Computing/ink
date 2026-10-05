/**
 * The shared Ed25519 verifier, self-contained.
 *
 * `bin/` is published so its shebang resolves on any supported Node install
 * without a TypeScript toolchain, and a git checkout has no `dist/` until
 * someone builds it, so the CLI cannot import the library's copy. It carries
 * its own, matching `src/crypto/ed25519-strict.ts`.
 *
 * A second copy of a security-critical verifier is exactly the drift this
 * release fixed elsewhere, so it is not left to care: `test/bin-ed25519-strict-parity.test.ts`
 * runs both copies against one shared table and fails if they ever disagree.
 * Change one, change the other, or the test says so.
 *
 * specs/ink-protocol.md (Frozen for 1.0) requires RFC 8032 strict
 * verification: canonical, non-small-order points, and the cofactorless
 * equation `[S]B == R + [k]A`. @noble/ed25519's `verifyAsync(..., { zip215:
 * false })` gets the decode and small-order checks right but still checks
 * the cofactored equation `[8](R + [k]A - [S]B) == 0` internally
 * (`clearCofactor()` in its `_verify`). A mixed-order public key `A = A0 +
 * T8` (canonical, not itself small-order, where `T8` is an order-8 point)
 * lets a signature with `k mod 8 != 0` pass that cofactored check while
 * failing the cofactorless one, so a signature Go's `crypto/ed25519.Verify`
 * (which is cofactorless) rejects would still verify here. This function
 * closes that gap by computing the cofactorless equation directly, with no
 * `clearCofactor()` anywhere in the path.
 *
 * Every verification call in `bin/` MUST go through this function instead of
 * calling `ed.verifyAsync` (or `ed.verify`) directly.
 */

import * as ed from "@noble/ed25519";

/** Order of the Ed25519 base-point subgroup (RFC 8032, section 5.1). */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function bytesToNumberLE(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i] ?? 0);
  }
  return value;
}

function concatBytes(...parts) {
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
 * RFC 8032 strict Ed25519 verification using the cofactorless equation.
 *
 * Returns false (never throws) for any malformed input: wrong-length
 * signature or key, non-canonical point encoding, a small-order public key,
 * a non-canonical (unreduced) scalar `S`, or a failed equation check.
 */
export async function verifyStrictEd25519(signature, message, publicKey) {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const rBytes = signature.subarray(0, 32);
  const sBytes = signature.subarray(32, 64);
  const s = bytesToNumberLE(sBytes);
  // Canonical scalar: S MUST be reduced mod the subgroup order.
  if (s >= L) return false;

  let A;
  let R;
  try {
    // Strict (non-ZIP-215) decode: canonical y < p, canonical sign-bit form.
    A = ed.Point.fromBytes(publicKey, false);
    R = ed.Point.fromBytes(rBytes, false);
  } catch {
    return false;
  }
  // Reject a small-order public key outright (identity included).
  if (A.isSmallOrder()) return false;

  let hashed;
  try {
    hashed = await ed.hashes.sha512Async(concatBytes(rBytes, publicKey, message));
  } catch {
    return false;
  }
  const k = bytesToNumberLE(hashed) % L;

  try {
    const SB = ed.Point.BASE.multiply(s, false);
    const kA = A.multiply(k, false);
    // Cofactorless equation: [S]B == R + [k]A. No clearCofactor() anywhere
    // in this path, unlike the library's zip215:false mode.
    return SB.equals(R.add(kA));
  } catch {
    return false;
  }
}
