// A key-holding generator for the card-signature surface, so the accept side of
// a composite verifier is reachable. See differential/README.md.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";

ed.hashes.sha512 = sha512;

const ED25519_MULTICODEC = [0xed, 0x01];
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += BASE58[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58[digits[i]];
  return out;
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

/** A deterministic key, so a seed replays the same card. */
export function keyFromRng(rng) {
  const secret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) secret[i] = rng.between(0, 255);
  const publicKey = ed.getPublicKey(secret);
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKey, ED25519_MULTICODEC.length);
  return { secret, publicKey, multibase: "z" + encodeBase58(prefixed) };
}

/** `ink/agent-card\n` + JCS(card without cardSignature), per the card spec. */
export function cardSignatureBase(card) {
  const { cardSignature: _omit, ...rest } = card;
  return `ink/agent-card\n${canonicalize(rest)}`;
}

export function signCard(card, secret) {
  const bytes = new TextEncoder().encode(cardSignatureBase(card));
  return base64url(ed.sign(bytes, secret));
}

/**
 * A card whose agent id is derived from the signing key, with no cached card
 * and no did:web resolution. Those are the two constructs the corpus marks as
 * spec-optional, and a fuzzer that wandered into them would report a
 * disagreement the spec permits.
 */
export function buildSignedCard(rng, key = keyFromRng(rng)) {
  const validFrom = new Date(Date.UTC(2026, 0, 1 + rng.between(0, 200))).toISOString();
  const card = {
    protocol: "ink/0.1",
    agentId: `tulpa:${key.multibase}`,
    handle: `agent${rng.between(0, 999)}`,
    displayName: "Agent",
    endpoint: `https://example${rng.between(0, 9)}.com/ink`,
    publicKeyMultibase: key.multibase,
    capabilities: { intentsAccepted: [], intentsSent: [] },
    availability: { timezone: "UTC" },
    keys: {
      signing: [
        {
          keyId: "g1",
          algorithm: "Ed25519",
          publicKeyMultibase: key.multibase,
          status: "active",
          validFrom,
        },
      ],
      encryption: [],
    },
    currentSigningKeyId: "g1",
    keySetVersion: 1,
    updatedAt: new Date(Date.UTC(2026, 6, 1 + rng.between(0, 100))).toISOString(),
  };
  // An optional member a mutation can never introduce is a member the surface
  // cannot fuzz. Emitting it sometimes is what lets the wrong-type arm reach
  // the branches that read it.
  if (rng.bool(0.3)) {
    // An empty chain reaches only the no-chain branch. A one-link chain is what
    // reaches the per-link checks, and it does not need to verify to do that.
    // A chain link with a real entry, so the committed-set members are
    // reachable. An empty signing array reaches nothing inside the loop.
    card.rotationChain = rng.bool(0.4)
      ? []
      : [{
          keySetVersion: 1,
          signing: [{ keyId: "g1", algorithm: "Ed25519", publicKeyMultibase: key.multibase, status: "active", validFrom }],
          prevKeyId: "g1",
          signature: "A".repeat(86),
        }];
  }
  return { card: { ...card, cardSignature: buildSignature(card, key) }, key };
}

function buildSignature(card, key) {
  return { keyId: "g1", signature: signCard(card, key.secret) };
}

/**
 * Re-sign a card after a mutation, so the mutation is what is under test.
 *
 * A mutation can produce a card the canonicalizer refuses, a lone surrogate for
 * one. The runner already skips a case whose generator throws, so the choice
 * here is between skipping that case and deciding it with the signature it
 * already had. The second is worth more: a card whose signature no longer
 * covers its bytes is exactly what a verifier has to reject.
 *
 * Only the canonicalizer's own refusals are caught. Anything else, a bad secret
 * for instance, is a harness fault, and swallowing it would leave every
 * re-signed case silently failing its signature while the run still reported
 * green.
 */
const CANONICALIZER_REFUSALS = /Lone surrogate|not allowed|NaN|Infinity/i;

export function resign(card, key) {
  const { cardSignature, ...rest } = card;
  if (!cardSignature || typeof cardSignature !== "object") return card;
  try {
    return { ...card, cardSignature: { ...cardSignature, signature: signCard(rest, key.secret) } };
  } catch (error) {
    if (error instanceof Error && CANONICALIZER_REFUSALS.test(error.message)) return card;
    throw error;
  }
}
