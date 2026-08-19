// Principal normalization, written from specs/ink-protocol.md §7 rather than
// from `src/`. This is the function that decides which sender a security
// decision keys on, so a divergence here is an identity bug, not a formatting
// one, and the corpus must not be produced by the code it is checking.
import { base58Decode, encodePublicKeyMultibase } from "./multibase.mjs";

// §7: a signing principal decodes to a 32-byte Ed25519 public key, multicodec
// 0xed 0x01. The X25519 multicodec 0xec 0x01 appears in a card's key set but is
// not a principal.
const ED25519_PUB = [0xed, 0x01];

// §7: normalization is DECODE-then-re-encode, not a prefix rewrite. Replacing
// `tulpa:`/`ink:` with `key:` textually would map a malformed, truncated,
// non-canonically encoded or wrongly-typed body to a `key:` principal that no
// key can authenticate, handing it a security scope of its own.
export function canonicalPrincipal(agentId) {
  if (typeof agentId !== "string")
    throw new Error("§7: agentId is not a string");

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

  // §7: "A signing principal decodes to a 32-byte Ed25519 public key that
  // verifies the sender's transport and body signatures." An X25519 body
  // (0xec 0x01) is well formed but is an encryption key, so it is not a signing
  // principal and is kept opaque. Canonicalizing it would be worse than useless:
  // re-encoding the decoded bytes under the Ed25519 multicodec maps the
  // encryption spelling of a key onto the SIGNING principal of the same bytes,
  // collapsing two distinct agentIds into one security bucket.
  const isEd =
    raw.length === 34 && raw[0] === ED25519_PUB[0] && raw[1] === ED25519_PUB[1];
  if (!isEd) return `raw:${agentId}`;

  // Re-encode from the decoded key, so a non-canonical encoding of the same key
  // collapses onto the same principal and a sender cannot re-encode to dodge a
  // block or split a rate-limit window.
  return `key:${encodePublicKeyMultibase(raw.slice(2))}`;
}
