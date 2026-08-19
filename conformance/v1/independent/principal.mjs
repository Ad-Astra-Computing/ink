// Principal normalization, written from specs/ink-protocol.md §7 rather than
// from `src/`. This is the function that decides which sender a security
// decision keys on, so a divergence here is an identity bug, not a formatting
// one, and the corpus must not be produced by the code it is checking.
import { base58Decode, encodePublicKeyMultibase } from "./multibase.mjs";

// §7: the multicodec prefixes are 0xed 0x01 for Ed25519 signing keys and
// 0xec 0x01 for X25519 encryption keys. Both decode their tail identically, so
// a malformed tail is rejected the same way for each; the prefix is identity
// syntax, not a capability grant.
const ED25519_PUB = [0xed, 0x01];
const X25519_PUB = [0xec, 0x01];

// §7: normalization is DECODE-then-re-encode, not a prefix rewrite. Replacing
// `tulpa:`/`ink:` with `key:` textually would map a malformed, truncated,
// non-canonically encoded or wrongly-typed body to a `key:` principal that no
// key can authenticate, handing it a security scope of its own.
export function canonicalPrincipal(agentId) {
  if (typeof agentId !== "string") throw new Error("§7: agentId is not a string");

  // §7: a raw `key:` input is never a legitimate agentId, so it is escaped
  // rather than passed through, or it could forge a collision with a
  // canonicalized key principal.
  if (agentId.startsWith("key:")) return `raw:${agentId}`;

  const prefix = ["tulpa:", "ink:"].find((p) => agentId.startsWith(p));
  if (prefix === undefined) return agentId;

  const tail = agentId.slice(prefix.length);
  if (!tail.startsWith("z")) return `raw:${agentId}`;

  let raw;
  try {
    raw = base58Decode(tail.slice(1));
  } catch {
    // §7: a malformed multibase body is escaped to `raw:<agentId>`. The
    // function stays total rather than throwing.
    return `raw:${agentId}`;
  }

  const isEd = raw.length === 34 && raw[0] === ED25519_PUB[0] && raw[1] === ED25519_PUB[1];
  const isX = raw.length === 34 && raw[0] === X25519_PUB[0] && raw[1] === X25519_PUB[1];
  if (!isEd && !isX) return `raw:${agentId}`;

  // Re-encode from the decoded key, so a non-canonical encoding of the same key
  // collapses onto the same principal and a sender cannot re-encode to dodge a
  // block or split a rate-limit window.
  return `key:${encodePublicKeyMultibase(raw.slice(2))}`;
}
