// The surfaces under differential test.
//
// A surface is one decision both implementations expose to an ordinary caller:
// same input, same accept-or-reject, and where the decision carries a value (a
// canonical principal, an epoch, canonical bytes) the same value. The input
// shape of each surface is the input shape of the matching conformance category,
// so a divergence found here can be promoted into the corpus without a
// translation step.
//
// Ranking. The surfaces are tiered by how much damage a disagreement does:
//
//   tier 1  the signature path. If the two sides canonicalize differently or
//           admit different bytes as a signed body, a message signed by one is
//           unverifiable by the other, or worse, a body one side refuses is
//           accepted by the other under a signature over different bytes. This
//           is the only class where a divergence is a security bug outright.
//   tier 2  identity and freshness. A principal that normalizes two ways is
//           attribution confusion; a timestamp or Authorization header that
//           parses two ways is a replay or smuggling window.
//   tier 3  admission. Card schema, discovery fetch, host safety and the Merkle
//           walks decide what gets in. A divergence is an interop break and
//           sometimes an SSRF or a forged-inclusion gap.
//
// Deliberately not covered, with reasons, in README.md.

import {
  UNICODE_EDGES, NUMBER_EDGES, TIMESTAMP_EDGES, B64URL_EDGES, PRINCIPAL_EDGES,
  HOSTNAME_EDGES, MEMBER_NAME_EDGES, ORDERING_PAIRS,
  mutateString, mutateJson, mutateJsonText, mutateHex,
  randomJsonText, randomHex, randomString, orderingObjectText,
} from "./mutators.mjs";
import { jsonTextShrinkCandidates } from "./shrink.mjs";
import { buildSignedCard, keyFromRng, resign } from "./card-signer.mjs";

const isStr = (v) => typeof v === "string";
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const isStrArray = (v) => Array.isArray(v) && v.every(isStr);

/** Requires every listed key to be a string. */
const strings = (...keys) => (input) => isObj(input) && keys.every((k) => isStr(input[k]));

const utf8Hex = (s) => Buffer.from(s, "utf8").toString("hex");

// ── surface definitions ──

/** A surface whose whole input is one string field. */
function stringSurface({ id, tier, why, field, bank, seedFrom, randomize }) {
  return {
    id,
    tier,
    why,
    wellFormed: strings(field),
    seedFrom,
    mutate(input, rng) {
      const base = rng.bool(0.25) ? rng.pick(bank) : input[field];
      let s = base;
      const rounds = rng.between(1, 3);
      for (let i = 0; i < rounds; i++) s = mutateString(s, rng);
      return { [field]: s };
    },
    random(rng) {
      return { [field]: randomize ? randomize(rng) : randomString(rng) };
    },
  };
}


const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (text) => Uint8Array.from(Buffer.from(text, "hex"));

/**
 * Mutate the card, then decide whether the signature still covers it. Breaking
 * the signature is one case; keeping it valid over a mutated card is the other,
 * and only the second reaches the checks past the signature.
 */
/**
 * Members whose type decides which branch a verifier takes, and the values that
 * are present but not the declared shape. Text mutation reaches these only by
 * accident and cannot introduce a member that is absent, which is how a whole
 * bug class stayed invisible: every one of its instances was a member read as
 * absent because it was present with the wrong type.
 */
const CARD_STRUCTURAL_MEMBERS = [
  ["keys"], ["keys", "signing"], ["keys", "encryption"], ["rotationChain"],
  ["cardSignature"], ["cardSignature", "keyId"], ["cardSignature", "signature"],
  ["currentSigningKeyId"], ["keySetVersion"], ["capabilities"], ["availability"],
  // Inside the arrays. A member list that stops at the top level fuzzes only
  // the half of the verifier that reads the top level, and the entry and link
  // members are where the two implementations read a value without checking
  // its type.
  ["keys", "signing", 0], ["keys", "signing", 0, "keyId"],
  ["keys", "signing", 0, "publicKeyMultibase"], ["keys", "signing", 0, "status"],
  ["keys", "signing", 0, "validFrom"], ["keys", "signing", 1, "keyId"],
  ["rotationChain", 0], ["rotationChain", 0, "signing"],
  ["rotationChain", 0, "signing", 0], ["rotationChain", 0, "signing", 0, "keyId"],
  ["rotationChain", 0, "signing", 0, "status"],
  ["rotationChain", 0, "signing", 0, "publicKeyMultibase"],
  ["rotationChain", 0, "keySetVersion"], ["rotationChain", 0, "prevKeyId"],
  ["rotationChain", 0, "signature"],
];

const WRONG_TYPED = [
  null, false, true, 0, 7, -1, "", "x", [], {}, { bad: true }, [1, 2], [{}],
  [null], ["x"], [[]], [{ keyId: 7 }], [{ keyId: null }],
];

/** Set a member to a value of the wrong type, adding it when it is absent. */
function setWrongType(card, rng) {
  const path = rng.pick(CARD_STRUCTURAL_MEMBERS);
  // Clone it. The bank holds shared objects, and assigning one by reference
  // lets a later mutation descend into the bank itself and eventually assign a
  // value into its own descendant, which builds a cycle the runner then
  // recurses into forever.
  const value = structuredClone(rng.pick(WRONG_TYPED));
  let node = card;
  for (const step of path.slice(0, -1)) {
    const wantArray = typeof step === "number";
    const container = wantArray ? Array.isArray(node) : isObj(node);
    if (!container) return; // the parent is already the malformed thing
    if (node[step] === undefined || (typeof node[step] !== "object" || node[step] === null)) {
      if (rng.bool(0.5)) return; // leave the parent malformed and stop
      node[step] = {};
    }
    node = node[step];
  }
  const last = path[path.length - 1];
  if (typeof last === "number" ? !Array.isArray(node) : !isObj(node)) return;
  node[last] = value;
}

function mutateCardInput(input, rng) {
  // A share of the arm goes to the structural mutation, and the rest stays on
  // text mutation, which finds the encoding and canonicalization cases.
  if (isObj(input.card) && rng.bool(0.35)) {
    const card = structuredClone(input.card);
    // Sometimes two, because a disagreement can need one malformed member to
    // collide with another, and one mutation per case can never build that.
    setWrongType(card, rng);
    if (rng.bool(0.3)) setWrongType(card, rng);
    const next = { ...input, card };
    if (input.signerSecretHex && rng.bool(0.5)) {
      const key = keyFromRng({ between: () => 0 });
      key.secret = unhex(input.signerSecretHex);
      next.card = resign(card, key);
    }
    return next;
  }
  let text = JSON.stringify(input.card);
  for (let i = 0, n = rng.between(1, 3); i < n; i++) text = mutateJsonText(text, rng);
  let card;
  try {
    card = JSON.parse(text);
  } catch {
    return { ...input, card: { broken: text } };
  }
  const next = { ...input, card, agentId: rng.bool(0.8) ? input.agentId : String(card.agentId ?? "") };
  if (input.signerSecretHex && isObj(card) && rng.bool(0.5)) {
    const key = keyFromRng({ between: () => 0 });
    key.secret = unhex(input.signerSecretHex);
    next.card = resign(card, key);
  }
  return next;
}

export const SURFACES = [
  // ── tier 1: the signature path ──
  {
    id: "signed-body-canonical",
    tier: 1,
    why:
      "The whole signed-body admission gate plus canonicalization: raw JSON text " +
      "in, canonical bytes out. A disagreement on the accepted set is a signature " +
      "bypass; a disagreement on the bytes is a signature that cannot cross.",
    wellFormed: strings("bodyRaw"),
    // The value the two sides must also agree on, not just accept-or-reject.
    valueFields: ["canonicalString"],
    seedFrom: [
      { category: "jcs-number", map: (i) => ({ bodyRaw: i.bodyRaw }) },
      { category: "jcs-string-safety", map: (i) => ({ bodyRaw: i.bodyRaw }) },
      { category: "signed-body-member-name", map: (i) => ({ bodyRaw: i.bodyRaw }) },
      { category: "merkle-leaf", map: (i) => ({ bodyRaw: i.eventRaw }) },
      { category: "signature-base", map: (i) => ({ bodyRaw: JSON.stringify(i.signInput?.body ?? {}) }) },
      { category: "agent-card", map: (i) => ({ bodyRaw: JSON.stringify(i.card ?? {}) }) },
    ],
    mutate(input, rng) {
      let text = input.bodyRaw;
      for (let i = 0, n = rng.between(1, 4); i < n; i++) text = mutateJsonText(text, rng);
      return { bodyRaw: text };
    },
    // Member ordering is a decision this surface makes on every object and the
    // only one an all-ASCII body cannot exercise, so a share of the arm is spent
    // on bodies built to force it. The rest is unbiased random JSON.
    random(rng) {
      return { bodyRaw: rng.bool(0.3) ? orderingObjectText(rng) : randomJsonText(rng) };
    },
    shrink(input) {
      return jsonTextShrinkCandidates(input.bodyRaw).map((t) => ({ bodyRaw: t }));
    },
  },
  {
    id: "signed-body-utf8",
    tier: 1,
    why:
      "The same gate one layer lower, on raw bytes a JSON string cannot express. " +
      "A lenient UTF-8 decode substitutes U+FFFD and verifies a signature over " +
      "bytes the signer never signed, so the two decoders must be fatal alike.",
    wellFormed: (input) => isObj(input) && isStr(input.bodyHex) && /^([0-9a-f]{2})*$/.test(input.bodyHex),
    seedFrom: [
      { category: "signed-body-utf8", map: (i) => ({ bodyHex: i.bodyHex }) },
      { category: "jcs-number", map: (i) => ({ bodyHex: utf8Hex(i.bodyRaw) }) },
      { category: "jcs-string-safety", map: (i) => ({ bodyHex: utf8Hex(i.bodyRaw) }) },
    ],
    mutate(input, rng) {
      let hex = input.bodyHex;
      for (let i = 0, n = rng.between(1, 4); i < n; i++) hex = mutateHex(hex, rng);
      return { bodyHex: hex };
    },
    random(rng) {
      if (rng.bool(0.5)) return { bodyHex: randomHex(rng) };
      return { bodyHex: utf8Hex(rng.bool(0.2) ? orderingObjectText(rng) : randomJsonText(rng)) };
    },
    // The generic shrinker works on the hex text and would produce odd-length
    // strings that are not byte sequences at all, so this surface shrinks the
    // bytes: delete a run, halve, truncate, keep one member of a container.
    shrink(input) {
      const bytes = [];
      for (let i = 0; i + 1 < input.bodyHex.length; i += 2) bytes.push(parseInt(input.bodyHex.slice(i, i + 2), 16));
      const toHex = (b) => ({ bodyHex: b.map((x) => x.toString(16).padStart(2, "0")).join("") });
      const out = [];
      if (bytes.length === 0) return out;
      out.push(toHex([]));
      out.push(toHex(bytes.slice(0, Math.floor(bytes.length / 2))));
      out.push(toHex(bytes.slice(Math.floor(bytes.length / 2))));
      const step = Math.max(1, Math.floor(bytes.length / 48));
      for (const run of [1, 2, 4, 8, 32, 128]) {
        for (let i = 0; i < bytes.length; i += step) {
          out.push(toHex([...bytes.slice(0, i), ...bytes.slice(i + run)]));
        }
      }
      // A JSON body is usually a container: offer each balanced group and each
      // scalar token in the text as a body on its own.
      const text = Buffer.from(input.bodyHex, "hex").toString("utf8");
      for (const t of jsonTextShrinkCandidates(text)) out.push({ bodyHex: utf8Hex(t) });
      return out;
    },
  },
  {
    id: "signature-base",
    tier: 1,
    why:
      "The §3.3 envelope verification an ordinary receiver runs: build the " +
      "signature base from method, path, recipient, canonical body and timestamp, " +
      "then verify. A divergence here accepts or refuses a real message.",
    wellFormed: (input) =>
      isObj(input) && isObj(input.signInput) && isStr(input.signature) && isStr(input.publicKeyHex) &&
      isStr(input.signInput.method) && isStr(input.signInput.path) &&
      isStr(input.signInput.recipientDid) && isStr(input.signInput.timestamp),
    seedFrom: [
      { category: "signature-base", map: (i) => ({ signInput: i.signInput, signature: i.signature, publicKeyHex: i.publicKeyHex }) },
      { category: "key-rotation", map: (i) => ({ signInput: i.signInput, signature: i.signature, publicKeyHex: i.keys?.[0]?.publicKeyHex ?? "" }) },
    ],
    mutate(input, rng) {
      const next = structuredClone(input);
      const op = rng.pick(["body", "scalar", "signature", "key"]);
      if (op === "body") {
        next.signInput.body = mutateJson(next.signInput.body ?? {}, rng) ?? {};
      } else if (op === "scalar") {
        const f = rng.pick(["method", "path", "recipientDid", "timestamp"]);
        next.signInput[f] = f === "timestamp" && rng.bool(0.5)
          ? rng.pick(TIMESTAMP_EDGES)
          : mutateString(String(next.signInput[f] ?? ""), rng);
      } else if (op === "signature") {
        next.signature = rng.bool(0.4) ? rng.pick(B64URL_EDGES) : mutateString(next.signature, rng);
      } else {
        next.publicKeyHex = rng.bool(0.5)
          ? rng.pick([
              "", "00".repeat(32), "01".repeat(32), "ff".repeat(32),
              // Ed25519 small-order and non-canonical points, which strict
              // verification must refuse on both sides.
              "0000000000000000000000000000000000000000000000000000000000000000",
              "0100000000000000000000000000000000000000000000000000000000000000",
              "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              "00".repeat(31), "00".repeat(33),
            ])
          : mutateString(next.publicKeyHex, rng);
      }
      return next;
    },
    random(rng) {
      return {
        signInput: {
          method: rng.pick(["POST", "GET", "post", "", "POST ", "POST\n"]),
          path: rng.pick(["/ink/v1/message", "/", "", "/a\n/b", "/%2e%2e/", randomString(rng)]),
          recipientDid: rng.pick(PRINCIPAL_EDGES),
          body: JSON.parse(randomJsonText(rng).startsWith("{") ? randomJsonText(rng) : "{}"),
          timestamp: rng.pick(TIMESTAMP_EDGES),
        },
        signature: rng.pick(B64URL_EDGES),
        publicKeyHex: randomHex(rng),
      };
    },
  },

  // ── tier 2: identity and freshness ──
  stringSurface({
    id: "principal-normalization",
    tier: 2,
    why:
      "Two spellings of one key must collapse to one principal and a literal " +
      "key: id must not be confusable with it. If the two sides normalize " +
      "differently, one attributes a message to an identity the other does not.",
    field: "agentId",
    bank: PRINCIPAL_EDGES,
    seedFrom: [
      { category: "principal-normalization", map: (i) => ({ agentId: i.agentId }) },
    ],
    randomize: (rng) => (rng.bool(0.5) ? rng.pick(PRINCIPAL_EDGES) : rng.pick(["key:", "ink:", "did:web:", ""]) + randomString(rng)),
  }),
  stringSurface({
    id: "timestamp-validity",
    tier: 2,
    why:
      "One strict RFC 3339 millisecond grammar decides the replay window. A " +
      "lenient parser on either side widens that window silently.",
    field: "timestamp",
    bank: TIMESTAMP_EDGES,
    seedFrom: [
      { category: "timestamp-validity", map: (i) => ({ timestamp: i.timestamp }) },
    ],
    randomize: (rng) => (rng.bool(0.7) ? mutateString(rng.pick(TIMESTAMP_EDGES), rng) : randomString(rng)),
  }),
  stringSurface({
    id: "authorization-header",
    tier: 2,
    why:
      "The transport header parser is the classic differential target: whitespace, " +
      "a second parameter, an embedded CR/LF. Two parsers that split it differently " +
      "let one side verify a signature the other never saw.",
    field: "header",
    bank: [
      `INK-Ed25519 ${"A".repeat(86)}`,
      `INK-Ed25519 ${"A".repeat(86)} keyId=k1`,
      `INK-Ed25519  ${"A".repeat(86)}`,
      `ink-ed25519 ${"A".repeat(86)}`,
      `INK-Ed25519\t${"A".repeat(86)}`,
      `INK-Ed25519 ${"A".repeat(86)} keyId=k1 keyId=k2`,
      `INK-Ed25519 ${"A".repeat(86)}\r\nX: y`,
      `Bearer ${"A".repeat(86)}`,
      "", " ", "INK-Ed25519", "INK-Ed25519 ",
    ],
    seedFrom: [
      { category: "authorization-header", map: (i) => ({ header: i.header }) },
    ],
    randomize: (rng) =>
      rng.bool(0.6)
        ? `${rng.pick(["INK-Ed25519", "ink-ed25519", "INK-ED25519", "Bearer", ""])}${rng.pick([" ", "  ", "\t", "", "\r\n"])}${rng.pick(B64URL_EDGES)}${rng.pick(["", ` keyId=${randomString(rng)}`, " keyId=", " x=y"])}`
        : randomString(rng),
  }),

  // ── tier 3: admission ──
  {
    id: "agent-card",
    tier: 3,
    why:
      "Discovery schema validation. A card one side admits and the other refuses " +
      "splits the network into agents that can be reached and agents that cannot.",
    wellFormed: (input) => isObj(input) && isObj(input.card),
    seedFrom: [
      { category: "agent-card", map: (i) => ({ card: i.card }) },
      { category: "agent-card-signature", map: (i) => ({ card: i.card }) },
    ],
    mutate(input, rng) {
      let card = input.card;
      for (let i = 0, n = rng.between(1, 3); i < n; i++) {
        const next = mutateJson(card, rng);
        card = isObj(next) ? next : card;
      }
      return { card };
    },
    random(rng) {
      const text = randomJsonText(rng);
      let card;
      try {
        card = JSON.parse(text);
      } catch {
        card = {};
      }
      if (!isObj(card)) card = {};
      // Half the random arm starts from the required shape, so it reaches past
      // the first required-field check often enough to be worth running.
      if (rng.bool(0.5)) {
        card.protocol = rng.pick(["ink/0.1", "ink/0.2", "ink/1.0", "", 1]);
        card.agentId = rng.pick(PRINCIPAL_EDGES);
        card.endpoint = rng.pick([
          "https://example.com/ink", "http://example.com/ink", "https://u:p@example.com/",
          "https://example.com/#f", "javascript:alert(1)", "mailto:a@b.c", "ftp://example.com/",
          "https://example.com:0/", "https://example.com:99999/", "https://[::1]/", "https:///",
        ]);
      }
      return { card };
    },
  },
  {
    id: "agent-card-fetch",
    tier: 3,
    why:
      "The response-handling contract in front of the card: status, content type, " +
      "the size caps and the identity binding. A divergence admits a substituted " +
      "card on one side.",
    wellFormed: (input) =>
      isObj(input) && isNum(input.status) && isStr(input.bodyRaw) && isStr(input.requestedAgentId) &&
      (input.contentType === undefined || input.contentType === null || isStr(input.contentType)) &&
      (input.contentLength === undefined || input.contentLength === null || isStr(input.contentLength)) &&
      (input.resolutionDid === undefined || input.resolutionDid === null || isStr(input.resolutionDid)),
    seedFrom: [{ category: "agent-card-fetch", map: (i) => i }],
    mutate(input, rng) {
      const next = structuredClone(input);
      const op = rng.pick(["status", "contentType", "contentLength", "body", "id", "did"]);
      if (op === "status") next.status = rng.pick([0, 200, 201, 204, 301, 302, 304, 400, 404, 500, -1, 1e9, 200.5]);
      else if (op === "contentType") {
        next.contentType = rng.pick([
          "application/json", "application/json; charset=utf-8", "application/json;charset=UTF-8",
          "application/json; charset=utf-16", "APPLICATION/JSON", "text/json", "application/json+ld",
          "application/jsonx", " application/json", "application/json ;", "", null,
          "application/json; charset=utf-8; boundary=x",
        ]);
      } else if (op === "contentLength") {
        next.contentLength = rng.pick(["0", "1", "65536", "65537", "99999999999999999999", "-1", "+1", "1.0", " 1", "1 ", "0x10", "", null]);
      } else if (op === "body") {
        next.bodyRaw = rng.bool(0.5) ? mutateJsonText(next.bodyRaw || "{}", rng) : randomJsonText(rng);
      } else if (op === "id") {
        next.requestedAgentId = rng.bool(0.5) ? rng.pick(PRINCIPAL_EDGES) : mutateString(next.requestedAgentId, rng);
      } else {
        next.resolutionDid = rng.pick([undefined, null, "did:web:example.com", "did:web:EXAMPLE.com", "", ...PRINCIPAL_EDGES]);
      }
      return next;
    },
    random(rng) {
      return {
        status: rng.pick([200, 200, 301, 404, 500, 0]),
        contentType: rng.pick(["application/json", "application/json; charset=utf-8", "text/html", null]),
        contentLength: rng.pick([null, "10", "65537", "-1"]),
        bodyRaw: randomJsonText(rng),
        requestedAgentId: rng.pick(PRINCIPAL_EDGES),
        resolutionDid: rng.pick([undefined, null, "did:web:example.com"]),
      };
    },
  },
  stringSurface({
    id: "private-hostname",
    tier: 3,
    why:
      "The SSRF gate. Accept means the destination is public. If one side calls a " +
      "name public that the other calls private, one implementation will make the " +
      "request the other refuses.",
    field: "hostname",
    bank: HOSTNAME_EDGES,
    seedFrom: [{ category: "private-hostname", map: (i) => ({ hostname: i.hostname }) }],
    randomize: (rng) =>
      rng.bool(0.6)
        ? mutateString(rng.pick(HOSTNAME_EDGES), rng)
        : Array.from({ length: rng.between(1, 8) }, () => rng.pick(["0", "1", "10", "127", "192", "168", "255", "256", "ff", "::", ":", ".", "a", "0x1", "01"])).join(rng.pick(["", ".", ":"])),
  }),
  stringSurface({
    id: "merkle-checkpoint",
    tier: 3,
    why:
      "The checkpoint body grammar a witness publishes its log head under. A " +
      "parser differential here lets a malformed or ambiguous head through one " +
      "implementation, which is the input to every consistency check downstream.",
    field: "body",
    bank: [
      "origin\n1\n" + "ab".repeat(32) + "\n",
      "origin\n1\n" + "ab".repeat(32),
      "origin\n1\n" + "AB".repeat(32) + "\n",
      "origin\n01\n" + "ab".repeat(32) + "\n",
      "origin\n+1\n" + "ab".repeat(32) + "\n",
      "origin\n-1\n" + "ab".repeat(32) + "\n",
      "origin\n1\n" + "ab".repeat(32) + "\n\n",
      "\n1\n" + "ab".repeat(32) + "\n",
      "origin\r\n1\r\n" + "ab".repeat(32) + "\r\n",
      "origin\n99999999999999999999\n" + "ab".repeat(32) + "\n",
      "",
    ],
    seedFrom: [{ category: "merkle-checkpoint", map: (i) => ({ body: i.body }) }],
    randomize: (rng) =>
      [
        rng.pick(["origin", "", "a b", "origin\u0000", randomString(rng)]),
        rng.pick(["0", "1", "10", "01", "+1", "-1", "1e2", " 1", "9007199254740993", "18446744073709551616", ""]),
        rng.pick(["ab".repeat(32), "AB".repeat(32), "ab".repeat(31), "ab".repeat(33), "zz".repeat(32), ""]),
      ].join("\n") + rng.pick(["\n", "", "\n\n", "\r\n"]),
  }),
  {
    id: "merkle-inclusion",
    tier: 3,
    why:
      "The RFC 6962 inclusion walk, and the sharpest JavaScript-versus-Go numeric " +
      "boundary in the protocol: a tree size past the safe-integer range is an " +
      "int64 in Go and a lossy double in JavaScript.",
    wellFormed: (input) =>
      isObj(input) && isStr(input.leafHash) && isStr(input.rootHash) && isStrArray(input.inclusionProof) &&
      isNum(input.leafIndex) && isNum(input.treeSize),
    seedFrom: [{ category: "merkle-inclusion", map: (i) => i }],
    mutate(input, rng) {
      const next = structuredClone(input);
      const op = rng.pick(["index", "size", "proof", "hash"]);
      const NUMS = [0, 1, -1, 2, 3, 7, 8, 1e9, 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 2, -(2 ** 53), 1.5, 0.1];
      if (op === "index") next.leafIndex = rng.pick(NUMS);
      else if (op === "size") next.treeSize = rng.pick(NUMS);
      else if (op === "proof") {
        const p = next.inclusionProof.slice();
        const at = rng.int(p.length + 1);
        const what = rng.pick(["drop", "dup", "add", "tamper"]);
        if (what === "drop") p.splice(at, 1);
        else if (what === "dup" && p.length) p.splice(at, 0, p[Math.max(0, at - 1)]);
        else if (what === "add") p.splice(at, 0, rng.pick(["ab".repeat(32), "AB".repeat(32), "", "zz".repeat(32), "ab".repeat(31)]));
        else if (p.length) p[at % p.length] = mutateString(p[at % p.length], rng);
        next.inclusionProof = p;
      } else {
        const f = rng.pick(["leafHash", "rootHash"]);
        next[f] = rng.bool(0.5) ? mutateString(next[f], rng) : rng.pick(["", "ab".repeat(32), "AB".repeat(32), "ab".repeat(31), "ab".repeat(33)]);
      }
      return next;
    },
    random(rng) {
      return {
        leafHash: rng.pick(["ab".repeat(32), "00".repeat(32), "AB".repeat(32), ""]),
        inclusionProof: Array.from({ length: rng.between(0, 5) }, () => rng.pick(["ab".repeat(32), "cd".repeat(32), "", "zz".repeat(32)])),
        leafIndex: rng.pick([0, 1, 2, 5, -1, 2 ** 53, 1.5]),
        treeSize: rng.pick([0, 1, 2, 5, 8, -1, 2 ** 53, 2 ** 53 + 2, 1.5]),
        rootHash: rng.pick(["ab".repeat(32), "00".repeat(32), ""]),
      };
    },
  },
  {
    id: "merkle-consistency",
    tier: 3,
    why:
      "The append-only check that detects a forked log. Same numeric boundary as " +
      "the inclusion walk, plus a prefix-size relation both sides must bound the " +
      "same way.",
    wellFormed: (input) =>
      isObj(input) && isStr(input.firstRoot) && isStr(input.secondRoot) && isStrArray(input.proof) &&
      isNum(input.first) && isNum(input.second),
    seedFrom: [{ category: "merkle-consistency", map: (i) => i }],
    mutate(input, rng) {
      const next = structuredClone(input);
      const op = rng.pick(["first", "second", "proof", "root"]);
      const NUMS = [0, 1, 2, 3, 4, 7, 8, -1, 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 2, 1.5];
      if (op === "first") next.first = rng.pick(NUMS);
      else if (op === "second") next.second = rng.pick(NUMS);
      else if (op === "proof") {
        const p = next.proof.slice();
        const at = rng.int(p.length + 1);
        const what = rng.pick(["drop", "dup", "add", "tamper"]);
        if (what === "drop") p.splice(at, 1);
        else if (what === "dup" && p.length) p.splice(at, 0, p[Math.max(0, at - 1)]);
        else if (what === "add") p.splice(at, 0, rng.pick(["ab".repeat(32), "", "AB".repeat(32)]));
        else if (p.length) p[at % p.length] = mutateString(p[at % p.length], rng);
        next.proof = p;
      } else {
        const f = rng.pick(["firstRoot", "secondRoot"]);
        next[f] = rng.bool(0.5) ? mutateString(next[f], rng) : rng.pick(["", "ab".repeat(32), "AB".repeat(32)]);
      }
      return next;
    },
    random(rng) {
      return {
        first: rng.pick([0, 1, 2, 3, 4, 8, -1, 2 ** 53]),
        firstRoot: rng.pick(["ab".repeat(32), "", "00".repeat(32)]),
        second: rng.pick([0, 1, 2, 4, 8, 2 ** 53]),
        secondRoot: rng.pick(["ab".repeat(32), "", "00".repeat(32)]),
        proof: Array.from({ length: rng.between(0, 5) }, () => rng.pick(["ab".repeat(32), "cd".repeat(32), ""])),
      };
    },
  },
  {
    id: "discovery-query-envelope",
    tier: 3,
    why:
      "A composite: strict schema, then signature, then audience, then freshness, " +
      "then replay, in that order. It is the one surface where the order of the " +
      "checks is itself the contract, so a reordered verifier diverges on reason.",
    wellFormed: (input) =>
      isObj(input) && isStr(input.envelopeRaw) && isStr(input.publicKeyHex) && isStr(input.now) &&
      (isStr(input.audience) || isStrArray(input.audience)) &&
      (input.seenNonces === undefined || Array.isArray(input.seenNonces)),
    valueFields: ["reason"],
    seedFrom: [
      {
        category: "discovery-query-envelope",
        map: (i) => ({
          envelopeRaw: JSON.stringify(i.envelope),
          publicKeyHex: i.publicKeyHex,
          audience: i.audience,
          now: i.now,
          ...(i.seenNonces === undefined ? {} : { seenNonces: i.seenNonces }),
        }),
      },
    ],
    mutate(input, rng) {
      const next = structuredClone(input);
      const op = rng.pick(["envelope", "key", "audience", "now", "seen"]);
      if (op === "envelope") {
        for (let i = 0, n = rng.between(1, 3); i < n; i++) next.envelopeRaw = mutateJsonText(next.envelopeRaw, rng);
      } else if (op === "key") {
        next.publicKeyHex = rng.bool(0.5) ? randomHex(rng) : mutateString(next.publicKeyHex, rng);
      } else if (op === "audience") {
        next.audience = rng.pick([
          next.audience, [], [""], "", "did:web:directory.example",
          "DID:WEB:directory.example", ["did:web:a", "did:web:b"], "did:web:directory.example.",
        ]);
      } else if (op === "now") {
        next.now = rng.pick(TIMESTAMP_EDGES);
      } else {
        next.seenNonces = rng.pick([
          undefined, [], [{ from: "a", nonce: "b" }],
          [{ from: "", nonce: "" }],
        ]);
        if (next.seenNonces === undefined) delete next.seenNonces;
      }
      return next;
    },
    random(rng) {
      return {
        envelopeRaw: randomJsonText(rng),
        publicKeyHex: randomHex(rng),
        audience: rng.pick(["did:web:directory.example", [], [""], "" ]),
        now: rng.pick(TIMESTAMP_EDGES),
      };
    },
  },
  {
    id: "agent-card-signature",
    tier: 3,
    why:
      "The first composite verifier the harness can reach: a card is admitted, a " +
      "signature is checked against a key the card itself declares, and the agent " +
      "id is bound to that key. A disagreement is a card one side trusts and the " +
      "other does not, which is an identity split rather than a parse difference.",
    // The generator holds the key, so a mutation can be re-signed and the accept
    // side stays reachable. `signerSecretHex` is harness state and neither
    // decider reads it; a decision that depended on it would be a finding.
    wellFormed: (input) => isObj(input) && isObj(input.card) && isStr(input.agentId),
    valueFields: ["reason"],
    seedFrom: [
      {
        category: "agent-card-signature",
        map: (i) => {
          // Two corpus cases pin a decision the spec leaves open, and both need
          // a cached card or a did:web resolution to reach. Seeding from them
          // would fuzz toward a disagreement the spec permits.
          const options = i.options ?? {};
          if (options.cachedCard || options.didVerificationKeys) return undefined;
          return { card: i.card, agentId: i.agentId, options };
        },
      },
    ],
    random(rng) {
      const { card, key } = buildSignedCard(rng);
      const input = { card, agentId: card.agentId, options: { profile: "1.0" }, signerSecretHex: hex(key.secret) };
      return rng.bool(0.5) ? input : mutateCardInput(input, rng);
    },
    mutate(input, rng) {
      return mutateCardInput(input, rng);
    },
    shrink(input) {
      return jsonTextShrinkCandidates(JSON.stringify(input.card))
        .map((text) => {
          try {
            return { ...input, card: JSON.parse(text) };
          } catch {
            return undefined;
          }
        })
        .filter((candidate) => candidate !== undefined);
    },
  },
];

export const SURFACE_BY_ID = new Map(SURFACES.map((s) => [s.id, s]));

/** Numeric edges re-exported so the runner can report bank coverage. */
export const BANKS = {
  UNICODE_EDGES, NUMBER_EDGES, TIMESTAMP_EDGES, B64URL_EDGES, PRINCIPAL_EDGES,
  HOSTNAME_EDGES, MEMBER_NAME_EDGES, ORDERING_PAIRS,
};
