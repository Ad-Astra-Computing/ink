// The remaining fixed signing domains and the RFC 6962 leaf hash, written from
// their normative sections rather than from `src/`. See README.md here.
import { createHash } from "node:crypto";
import { jcs } from "./jcs.mjs";

// Protocol §3.6 "Other signing domains": the audit and witness sub-protocols
// use fixed prefixes over JCS of their payloads, each excluding the signature
// member it is about to produce.
const AUDIT_EVENT = "ink/audit-event\n";
const AUDIT_RESPONSE = "ink/audit-response\n";
const AUDIT_QUERY_RESPONSE = "ink/audit-query-response/v1\n";
// ink-authorization-chain.md: the parent hash uses the same domain-then-newline
// pattern as the body-signature scheme.
const DELEGATION_LINK = "ink/delegation-link\n";

function without(object, member) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) {
    throw new Error("expected a JSON object");
  }
  const out = {};
  for (const key of Object.keys(object)) {
    if (key !== member) out[key] = object[key];
  }
  return out;
}

export function auditEventSignatureBase(event) {
  return `${AUDIT_EVENT}${jcs(without(event, "agentSignature"))}`;
}

// Protocol §3.6: a bilateral audit slice signs over JCS of the events array.
export function auditResponseSignatureBase(events) {
  return `${AUDIT_RESPONSE}${jcs(events)}`;
}

export function auditQueryResponseSignatureBase(response) {
  return `${AUDIT_QUERY_RESPONSE}${jcs(without(response, "serviceSignature"))}`;
}

// ink-merkle-leaf.md: SHA-256(0x00 || JCS(event without agentSignature)),
// returned as 64 lowercase hex characters. The 0x00 prefix is RFC 6962's leaf
// domain separator, which is what stops a leaf being reinterpreted as an
// interior node.
export function merkleLeafHash(event) {
  const canonical = jcs(without(event, "agentSignature"));
  const hash = createHash("sha256");
  hash.update(Uint8Array.from([0x00]));
  hash.update(Buffer.from(canonical, "utf8"));
  return hash.digest("hex");
}

// ink-authorization-chain.md: the parent hash is base64url without padding of
// SHA-256 over the domain, a newline, and the JCS of the FULL parent link
// INCLUDING its signature. Including the signature is the point: the child
// commits to the parent as it was actually signed and presented, not to an
// unsigned skeleton of it.
export function delegationLinkParentHash(parentLink) {
  const digest = createHash("sha256")
    .update(Buffer.from(`${DELEGATION_LINK}${jcs(parentLink)}`, "utf8"))
    .digest();
  return digest
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ink-inclusion-receipt.md §2: the witness signature covers
// "ink/audit-inclusion/v1\n" plus the JCS of exactly five members. The
// `inclusionProof` is deliberately NOT signed: the verifier authenticates the
// committed (leafIndex, treeSize, rootHash) and re-derives the proof's validity
// separately, so tampering the proof cannot make a forged leaf verify.
// Signing a named-field subset is unusual in INK and easy to get wrong by
// canonicalizing the whole receipt, which is why the members are listed here
// rather than stripped.
const AUDIT_INCLUSION = "ink/audit-inclusion/v1\n";

export function inclusionReceiptSignatureBase(receipt) {
  const { eventId, leafIndex, rootHash, timestamp, treeSize } = receipt;
  return `${AUDIT_INCLUSION}${jcs({ eventId, leafIndex, rootHash, timestamp, treeSize })}`;
}

// ink-merkle-inclusion.md: an interior node is SHA-256(0x01 || l || r) over the
// raw 32-byte child hashes. The 0x01 prefix is what stops a leaf being
// reinterpreted as an interior node, the mirror of the leaf rule's 0x00.
function hashPair(left, right) {
  const h = createHash("sha256");
  h.update(Uint8Array.from([0x01]));
  h.update(left);
  h.update(right);
  return h.digest();
}

const fromHex = (s) => Buffer.from(s, "hex");
const largestPowerOf2LessThan = (n) => {
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
};

// RFC 6962 §2.1.1 index-space walk. Returns the recomputed root as lowercase
// hex, or null when the proof is structurally impossible for the given
// (leafIndex, treeSize), which a verifier must treat as a rejection rather than
// an exception.
export function recomputeMerkleRoot(
  leafHashHex,
  proofHex,
  leafIndex,
  treeSize,
) {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize))
    return null;
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return null;
  // A hostile receipt commits to treeSize but not to the proof array, so the
  // walk is bounded independently of it.
  if (proofHex.length > 64) return null;

  let hash = fromHex(leafHashHex);
  if (hash.length !== 32) return null;

  // The subtree split is decided from the ROOT DOWN, but the hashing runs from
  // the LEAF UP. Those are two different directions and doing both in one pass
  // silently mispairs every leaf that is not at index 0. So descend first,
  // recording which side our node fell on at each level, then combine upward.
  const onLeft = [];
  let index = leafIndex;
  let size = treeSize;
  while (size > 1) {
    const split = largestPowerOf2LessThan(size);
    if (index < split) {
      onLeft.push(true);
      size = split;
    } else {
      onLeft.push(false);
      index -= split;
      size -= split;
    }
  }

  // ink-merkle-inclusion.md orders proof elements TOP-DOWN: the first element is
  // the sibling just below the root, the last is the sibling adjacent to the
  // leaf. That is the reverse of RFC 6962's PATH, which gives the leaf-adjacent
  // sibling first. `onLeft` came out top-down too, so the two line up
  // positionally, and both are walked backwards to hash from the leaf upward.
  // A proof with a different number of entries than the tree has levels does not
  // describe this tree: too short cannot be completed, and a padded one would
  // let an attacker add an unused entry.
  if (proofHex.length !== onLeft.length) return null;

  for (let level = onLeft.length - 1; level >= 0; level--) {
    const sibling = fromHex(proofHex[level]);
    if (sibling.length !== 32) return null;
    hash = onLeft[level] ? hashPair(hash, sibling) : hashPair(sibling, hash);
  }

  return hash.toString("hex");
}

// ink-merkle-consistency.md: the empty tree's root is SHA-256("").
const EMPTY_TREE_ROOT_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);

// ink-merkle-consistency.md: the RFC 6962 §2.1.2 imperative consistency walk.
// Boolean rather than throwing: a verifier facing malformed input rejects it,
// it does not except on it.
export function verifyConsistencyProof(first, firstRoot, second, secondRoot, proof) {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second)) return false;
  if (first < 0 || second < 0 || first > second) return false;
  if (!isHex64(firstRoot) || !isHex64(secondRoot)) return false;
  if (!Array.isArray(proof) || !proof.every(isHex64)) return false;

  if (first === second) {
    return proof.length === 0 && firstRoot === secondRoot;
  }
  if (first === 0) {
    return proof.length === 0 && firstRoot === EMPTY_TREE_ROOT_HEX;
  }

  // Shift down to the first node on the rightmost path of the `first` tree
  // that the two trees do not share.
  let node = first - 1;
  let last = second - 1;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    last = Math.floor(last / 2);
  }

  let idx = 0;
  let firstHash;
  let secondHash;
  if (node > 0) {
    // `first` is not an exact power of two: the walk starts from a proof node.
    if (proof.length === 0) return false;
    firstHash = secondHash = fromHex(proof[idx]);
    idx++;
  } else {
    // `first` is an exact power of two: the old subtree hash is `firstRoot`.
    firstHash = secondHash = fromHex(firstRoot);
  }

  while (node > 0) {
    if (node % 2 === 1) {
      // Odd node: the left sibling is shared and feeds both reconstructions.
      if (idx >= proof.length) return false;
      const sibling = fromHex(proof[idx]);
      idx++;
      firstHash = hashPair(sibling, firstHash);
      secondHash = hashPair(sibling, secondHash);
    } else if (node < last) {
      // Even node still short of `last`: the right sibling exists only in
      // the second tree and feeds the new reconstruction alone.
      if (idx >= proof.length) return false;
      const sibling = fromHex(proof[idx]);
      idx++;
      secondHash = hashPair(secondHash, sibling);
    }
    node = Math.floor(node / 2);
    last = Math.floor(last / 2);
  }

  if (firstHash.toString("hex") !== firstRoot) return false;

  // Any remaining proof nodes extend the second tree on up to its root.
  while (last > 0) {
    if (idx >= proof.length) return false;
    const sibling = fromHex(proof[idx]);
    idx++;
    secondHash = hashPair(secondHash, sibling);
    last = Math.floor(last / 2);
  }

  // Unused proof nodes mean a padded proof, which must not verify.
  if (idx !== proof.length) return false;
  return secondHash.toString("hex") === secondRoot;
}
