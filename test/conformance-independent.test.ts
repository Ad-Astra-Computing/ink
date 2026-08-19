// Re-verify every signature the corpus records against bases built from the
// spec text rather than from the implementation. See README.md in this
// directory for why the corpus alone cannot report this failure.
//
// This test lives in test/ rather than beside those modules because tsconfig
// and eslint only reach src/, test/ and scripts/. A check the typechecker and
// linter cannot see is the kind that rots quietly.
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";
// Untyped by design; see test/independent-modules.d.ts.
// dependency on this package's types, so they cannot drift toward src/.
import { transportSignatureBase } from "../conformance/v1/independent/signature-base.mjs";
import { bodySignatureBase } from "../conformance/v1/independent/body-signature.mjs";
import {
  cardSignatureBase,
  rotationLinkSignatureBase,
} from "../conformance/v1/independent/card-signature.mjs";
import { decodePublicKeyMultibase } from "../conformance/v1/independent/multibase.mjs";
import { canonicalPrincipal } from "../conformance/v1/independent/principal.mjs";
import { jcs } from "../conformance/v1/independent/jcs.mjs";
import {
  merkleLeafHash,
  auditQueryResponseSignatureBase,
  auditEventSignatureBase,
  inclusionReceiptSignatureBase,
  recomputeMerkleRoot,
} from "../conformance/v1/independent/audit-and-chain.mjs";

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "conformance",
  "v1",
  "vectors",
);
const enc = new TextEncoder();
const b64u = (s: string) =>
  Uint8Array.from(
    Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
  );
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

type Case = { caseId: string; input: any; expect: any };
function cases(category: string): Case[] {
  const out: Case[] = [];
  for (const file of readdirSync(VECTORS).filter((f) => f.endsWith(".json"))) {
    const doc = JSON.parse(readFileSync(join(VECTORS, file), "utf8"));
    if (doc.category === category) out.push(...(doc.cases ?? []));
  }
  return out;
}

const verify = (sig: string, base: string, key: Uint8Array) =>
  ed.verifyAsync(b64u(sig), enc.encode(base), key);

describe("transport signature base, protocol §3.3", () => {
  it("verifies every signature the corpus accepts", async () => {
    const failures: string[] = [];
    let exercised = 0;
    for (const c of cases("signature-base")) {
      const { signInput, signature, publicKeyHex } = c.input ?? {};
      if (!signInput || !signature || !publicKeyHex) {
        // An accept case missing its artifacts cannot be checked, and silently
        // skipping it is how a check goes hollow. Fail instead.
        expect(
          c.expect.result,
          `${c.caseId}: accept case is missing signInput, signature or key`,
        ).not.toEqual("accept");
        continue;
      }
      exercised++;
      let ok = false;
      try {
        ok = await verify(
          signature,
          transportSignatureBase(signInput),
          fromHex(publicKeyHex),
        );
      } catch {
        // A scalar carrying CR or LF cannot build a base at all, which is how
        // §3.3 rejects it. That is the expected path for those cases.
        if (c.expect.result === "reject") continue;
        throw new Error(
          `${c.caseId}: base construction threw on an accept case`,
        );
      }
      if (c.expect.result === "accept" && !ok) failures.push(c.caseId);
    }
    expect(
      exercised,
      "no signature-base vectors were exercised",
    ).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });
});

describe("agent card signature base, card spec §3.2", () => {
  it("verifies every card signature the corpus accepts", async () => {
    const failures: string[] = [];
    let exercised = 0;
    let unsigned = 0;
    for (const c of cases("agent-card-signature")) {
      if (c.expect.result !== "accept") continue;
      const card = c.input?.card;
      const cs = card?.cardSignature;
      if (typeof cs?.signature !== "string") {
        // An unsigned card is a legitimate accept until Phase C makes the
        // signature mandatory (ink-agent-card-signature.md §10). That is a real
        // protocol state, not missing fixture data, so it is counted and
        // skipped rather than asserted away.
        unsigned++;
        continue;
      }
      // Card spec §3.3 admits exactly two forms. A key-set card MUST resolve
      // cardSignature.keyId inside keys.signing; only a legacy card with no
      // keys.signing may use the top-level publicKeyMultibase, and then only
      // under the literal keyId "bootstrap". A blanket fallback would let an
      // accepted vector whose key-set signer is absent verify anyway, which is
      // the case this check exists to catch.
      const signing = Array.isArray(card.keys?.signing)
        ? card.keys.signing
        : null;
      const mb =
        signing === null
          ? cs.keyId === "bootstrap"
            ? card.publicKeyMultibase
            : undefined
          : signing.find((k: any) => k?.keyId === cs.keyId)?.publicKeyMultibase;
      expect(
        typeof mb,
        `${c.caseId}: cardSignature.keyId ${cs.keyId} resolves to no key under §3.3`,
      ).toEqual("string");
      exercised++;
      if (
        !(await verify(
          cs.signature,
          cardSignatureBase(card),
          decodePublicKeyMultibase(mb),
        ))
      ) {
        failures.push(c.caseId);
      }
    }
    expect(
      exercised,
      "no accepted agent-card-signature vectors were exercised",
    ).toBeGreaterThan(0);
    expect(
      unsigned,
      "every accepted card was unsigned, so nothing was verified",
    ).toBeLessThan(exercised);
    expect(failures).toEqual([]);
  });

  it("verifies every rotation link on an accepted card", async () => {
    const failures: string[] = [];
    let exercised = 0;
    let didWebRooted = 0;
    for (const c of cases("agent-card-signature")) {
      if (c.expect.result !== "accept") continue;
      const chain = c.input?.card?.rotationChain;
      if (!Array.isArray(chain)) continue;
      for (const [index, link] of chain.entries()) {
        expect(
          typeof link?.signature,
          `${c.caseId}: chain link on an accepted card is unsigned`,
        ).toEqual("string");
        // A link is signed by prevKeyId as it stood in the set committed by the
        // PREVIOUS link, not by any key that appears anywhere in the chain.
        // Pooling every link's set would verify a link against a key that was
        // not active when it was made.
        const priorSet: any[] =
          index === 0 ? [] : (chain[index - 1].signing ?? []);
        const fromPriorSet = priorSet.find(
          (k: any) => k?.keyId === link.prevKeyId,
        )?.publicKeyMultibase;
        // Only link 1 roots outside the chain, and it roots in the IDENTITY
        // ROOT, not in a card field. For a key-derived card that root is the
        // multibase inside the agentId itself, which no card edit can move.
        // Rooting in card.publicKeyMultibase instead would let an accepted
        // vector sign link 1 with a mutable field and still pass here.
        //
        // NOT currently exercised: no vector has a card.publicKeyMultibase that
        // differs from the agentId's key, so swapping this back to the card
        // field leaves the suite green. The rule is right, the corpus just
        // cannot tell the two apart yet. Tracked as a coverage gap.
        const agentId: unknown = c.input.card.agentId;
        const keyDerivedRoot =
          typeof agentId === "string" &&
          (agentId.startsWith("tulpa:") || agentId.startsWith("ink:"))
            ? agentId.slice(agentId.indexOf(":") + 1)
            : undefined;
        if (index === 0 && keyDerivedRoot === undefined) {
          // A did:web chain roots in the resolved DID verification keys, which
          // this vector does not carry. Nothing to check rather than something
          // weak to check.
          didWebRooted++;
          continue;
        }
        const mb = fromPriorSet ?? (index === 0 ? keyDerivedRoot : undefined);
        expect(
          typeof mb,
          `${c.caseId}: link ${index} prevKeyId ${link.prevKeyId} resolves to no key in the prior set`,
        ).toEqual("string");
        exercised++;
        if (
          !(await verify(
            link.signature,
            rotationLinkSignatureBase(link),
            decodePublicKeyMultibase(mb),
          ))
        ) {
          failures.push(`${c.caseId} v${link.keySetVersion}`);
        }
      }
    }
    expect(
      exercised,
      `no rotation links were exercised (${didWebRooted} skipped as did:web rooted)`,
    ).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });
});

describe("first contact transcript, protocol §3.3 and §3.6", () => {
  it("verifies both legs of every accepted transcript on both bases", async () => {
    const failures: string[] = [];
    let exercised = 0;
    for (const c of cases("first-contact-transcript")) {
      if (c.expect.result !== "accept") continue;
      for (const [leg, keyField] of [
        [c.input?.request, "senderPublicKeyHex"],
        [c.input?.response, "receiverPublicKeyHex"],
      ] as const) {
        if (
          !leg?.signInput ||
          typeof leg.signature !== "string" ||
          typeof leg[keyField] !== "string"
        )
          continue;
        exercised++;
        const key = fromHex(leg[keyField]);
        if (
          !(await verify(
            leg.signature,
            transportSignatureBase(leg.signInput),
            key,
          ))
        ) {
          failures.push(`${c.caseId} ${keyField} transport`);
        }
        const body = leg.signInput.body;
        if (body && typeof body.signature === "string") {
          if (!(await verify(body.signature, bodySignatureBase(body), key))) {
            failures.push(`${c.caseId} ${keyField} body`);
          }
        }
      }
    }
    expect(exercised, "no transcript legs were exercised").toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });
});

describe("principal normalization, protocol §7", () => {
  it("derives the same principal the corpus records", () => {
    const accepted = cases("principal-normalization").filter(
      (c) => c.expect.result === "accept",
    );
    expect(
      accepted.length,
      "no accept cases found; the category was renamed or dropped",
    ).toBeGreaterThan(0);
    const failures: string[] = [];
    for (const c of accepted) {
      if (canonicalPrincipal(c.input.agentId) !== c.expect.canonicalPrincipal)
        failures.push(c.caseId);
    }
    expect(failures).toEqual([]);
  });
});

// The corpus cannot exercise every rule the oracle enforces. Mutation testing
// showed a lone surrogate in a MEMBER NAME and several §3.2 bounds have no
// vector at all, so removing those checks left the suite green. These assert
// the oracle's own rules directly, otherwise the oracle silently loosens.
describe("the oracle enforces the §3.2 profile itself", () => {
  it("refuses a number outside the safe-integer profile", () => {
    expect(() => jcs({ n: 1.5 })).toThrow(/safe integer/);
    expect(() => jcs({ n: 2 ** 53 })).toThrow(/safe integer/);
    expect(() => jcs({ n: Number.NaN })).toThrow(/safe integer/);
    expect(() => jcs({ n: Number.POSITIVE_INFINITY })).toThrow(/safe integer/);
    expect(() => jcs({ n: -0 })).toThrow(/negative zero/);
    expect(jcs({ n: 100 })).toEqual('{"n":100}');
  });

  it("refuses a lone surrogate in a value and in a member name", () => {
    expect(() => jcs({ s: "\ud800" })).toThrow(
      /lone surrogate in a string value/,
    );
    expect(() => jcs({ "\ud800": 1 })).toThrow(
      /lone surrogate in a member name/,
    );
    // A properly paired surrogate is ordinary text and must survive.
    expect(jcs({ s: "\ud83d\ude00" })).toEqual('{"s":"😀"}');
  });

  it("bounds the walk", () => {
    let deep: any = 1;
    for (let i = 0; i < 40; i++) deep = { a: deep };
    expect(() => jcs(deep)).toThrow(/depth exceeds/);
    expect(() => jcs(Array.from({ length: 10001 }, (_, i) => i))).toThrow(
      /node count exceeds/,
    );
    expect(() => jcs({ s: "x".repeat(1200001) })).toThrow(
      /aggregate string length/,
    );
  });

  it("caps the canonical output in code units and, separately, in bytes", () => {
    // Under the 1.2M aggregate-string ceiling but over the 1 MiB output.
    expect(() => jcs({ s: "x".repeat(1_100_000) })).toThrow(
      /code units exceeds/,
    );
    // Under BOTH the aggregate ceiling and the code-unit output cap, but three
    // bytes per character in UTF-8, so only the byte cap can catch it.
    expect(() => jcs({ s: "\u4f60".repeat(600_000) })).toThrow(/bytes exceeds/);
  });

  it("sorts members by UTF-16 code unit, not by insertion", () => {
    expect(jcs({ b: 1, a: 2, "\u00e9": 3, A: 4 })).toEqual(
      '{"A":4,"a":2,"b":1,"é":3}',
    );
  });
});

// The base profile is 16 of the 29 categories. These cover the signed bytes in
// the rest: grants and agent authorization reuse the §3.6 body base, so they
// need no new construction, while the audit query response and the RFC 6962
// leaf hash have their own domains.
describe("non-base profiles", () => {
  // A vector with no signature at all is out of scope for a signature oracle
  // and is skipped. A vector that HAS a signature whose key will not resolve is
  // a different thing entirely: it means the oracle could not check something it
  // was supposed to check, so that count must be zero. Collapsing the two into
  // one `continue` is how an oracle quietly stops testing.
  type Tally = {
    exercised: number;
    noSignature: string[];
    unresolved: string[];
  };
  const tally = (): Tally => ({
    exercised: 0,
    noSignature: [],
    unresolved: [],
  });
  function settle(t: Tally, label: string, failures: string[]) {
    expect(
      t.unresolved,
      `${label}: signed vectors whose key did not resolve`,
    ).toEqual([]);
    expect(
      t.exercised,
      `${label}: nothing exercised (${t.noSignature.length} unsigned)`,
    ).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }

  // Confirmed with the spec authors' text: grants, authorization challenges and
  // discovery envelopes sign under the §3.6 body base and have no domain of
  // their own.
  const bodySigned: Array<
    [string, string, (c: Case) => { obj: any; keyHex: unknown }]
  > = [
    [
      "authorization-grant",
      "grants",
      (c) => ({
        obj: c.input?.grant,
        keyHex: c.input?.publicKeyHex ?? c.input?.issuerPublicKeyHex,
      }),
    ],
    [
      "discovery-query-envelope",
      "discovery envelopes",
      (c) => ({ obj: c.input?.envelope, keyHex: c.input?.publicKeyHex }),
    ],
  ];

  for (const [category, label, pick] of bodySigned) {
    it(`verifies every accepted ${label} on the §3.6 body base`, async () => {
      const t = tally();
      const failures: string[] = [];
      for (const c of cases(category)) {
        if (c.expect.result !== "accept") continue;
        const { obj, keyHex } = pick(c);
        if (typeof obj?.signature !== "string") {
          t.noSignature.push(c.caseId);
          continue;
        }
        if (typeof keyHex !== "string") {
          t.unresolved.push(c.caseId);
          continue;
        }
        t.exercised++;
        if (
          !(await verify(
            obj.signature,
            bodySignatureBase(obj),
            fromHex(keyHex),
          ))
        )
          failures.push(c.caseId);
      }
      settle(t, label, failures);
    });
  }

  it("verifies every accepted authorization challenge on the §3.6 body base", async () => {
    const t = tally();
    const failures: string[] = [];
    for (const c of cases("agent-authorization")) {
      if (c.expect.result !== "accept") continue;
      const ch = c.input?.challenge;
      if (typeof ch?.signature !== "string") {
        t.noSignature.push(c.caseId);
        continue;
      }
      const keys = c.input.keys;
      const list: any[] = Array.isArray(keys)
        ? keys
        : keys && typeof keys === "object"
          ? Object.entries(keys).map(([keyId, v]) =>
              typeof v === "string"
                ? { keyId, publicKeyHex: v }
                : { keyId, ...(v as object) },
            )
          : [];
      // The challenge carries no keyId: it is signed by an ACTIVE relying-party
      // signing key. Key rotation permits overlapping active keys, so any one
      // of them may be the signer and the oracle tries each. What it will not
      // do is fall back to a key that is not active, which would verify a
      // challenge signed by a retired or revoked key.
      //
      // NOT currently exercised: no vector carries a non-active RP key that
      // would verify, so dropping the status filter leaves the suite green.
      // The rule is right, the corpus cannot yet tell. Tracked with the other
      // coverage gaps.
      const candidates = list.filter(
        (k) => k?.status === "active" && typeof k.publicKeyHex === "string",
      );
      if (candidates.length === 0) {
        t.unresolved.push(c.caseId);
        continue;
      }
      t.exercised++;
      let verified = false;
      for (const k of candidates) {
        if (
          await verify(
            ch.signature,
            bodySignatureBase(ch),
            fromHex(k.publicKeyHex),
          )
        ) {
          verified = true;
          break;
        }
      }
      if (!verified) failures.push(c.caseId);
    }
    settle(t, "authorization challenges", failures);
  });

  it("verifies every accepted audit query response on its own domain", async () => {
    const t = tally();
    const failures: string[] = [];
    for (const c of cases("audit-query-response")) {
      if (c.expect.result !== "accept") continue;
      const r = c.input?.response;
      if (typeof r?.serviceSignature !== "string") {
        t.noSignature.push(c.caseId);
        continue;
      }
      if (typeof c.input.witnessPublicKeyHex !== "string") {
        t.unresolved.push(c.caseId);
        continue;
      }
      t.exercised++;
      if (
        !(await verify(
          r.serviceSignature,
          auditQueryResponseSignatureBase(r),
          fromHex(c.input.witnessPublicKeyHex),
        ))
      ) {
        failures.push(c.caseId);
      }
    }
    settle(t, "audit query responses", failures);
  });

  it("reproduces every RFC 6962 leaf hash from the raw event bytes", () => {
    const t = tally();
    const failures: string[] = [];
    for (const c of cases("merkle-leaf")) {
      if (typeof c.expect.leafHash !== "string") {
        t.noSignature.push(c.caseId);
        continue;
      }
      if (typeof c.input?.eventRaw !== "string") {
        t.unresolved.push(c.caseId);
        continue;
      }
      t.exercised++;
      if (merkleLeafHash(JSON.parse(c.input.eventRaw)) !== c.expect.leafHash)
        failures.push(c.caseId);
    }
    settle(t, "merkle leaves", failures);
  });
});

describe("audit and delegation profiles", () => {
  it("verifies every accepted inclusion receipt over its five committed members", async () => {
    let exercised = 0;
    const failures: string[] = [];
    for (const c of cases("inclusion-receipt")) {
      if (c.expect.result !== "accept") continue;
      const r = c.input?.receipt;
      if (
        typeof r?.serviceSignature !== "string" ||
        typeof c.input.witnessPublicKeyHex !== "string"
      )
        continue;
      exercised++;
      if (
        !(await verify(
          r.serviceSignature,
          inclusionReceiptSignatureBase(r),
          fromHex(c.input.witnessPublicKeyHex),
        ))
      ) {
        failures.push(c.caseId);
      }
    }
    expect(exercised, "no inclusion receipts were exercised").toBeGreaterThan(
      0,
    );
    expect(failures).toEqual([]);
  });

  it("recomputes the RFC 6962 root for every inclusion proof, accept and reject alike", () => {
    let exercised = 0;
    const failures: string[] = [];
    for (const c of cases("merkle-inclusion")) {
      const i = c.input;
      if (typeof i?.leafHash !== "string") continue;
      exercised++;
      const got = recomputeMerkleRoot(
        i.leafHash,
        i.inclusionProof ?? [],
        i.leafIndex,
        i.treeSize,
      );
      // Reject cases matter as much as accepts here: a walk that accepts a
      // padded or short proof is exactly the bug this pins.
      const ok =
        c.expect.result === "accept" ? got === i.rootHash : got !== i.rootHash;
      if (!ok) failures.push(`${c.caseId} (${c.expect.result})`);
    }
    expect(exercised, "no inclusion proofs were exercised").toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });

  it("verifies the per-event agentSignature carried inside a query response", async () => {
    let exercised = 0;
    const failures: string[] = [];
    for (const c of cases("audit-query-response")) {
      if (c.expect.result !== "accept") continue;
      const events = c.input?.response?.events;
      const keys = c.input?.agentKeysHex;
      if (!Array.isArray(events) || !keys) continue;
      for (const ev of events) {
        if (typeof ev?.agentSignature !== "string") continue;
        const key = keys[ev.agentId];
        if (typeof key !== "string") continue;
        exercised++;
        if (
          !(await verify(
            ev.agentSignature,
            auditEventSignatureBase(ev),
            fromHex(key),
          ))
        ) {
          failures.push(`${c.caseId} ${ev.id}`);
        }
      }
    }
    expect(exercised, "no per-event signatures were exercised").toBeGreaterThan(
      0,
    );
    expect(failures).toEqual([]);
  });

  it("verifies every delegation link on the §3.6 body base", async () => {
    let exercised = 0;
    const failures: string[] = [];
    for (const c of cases("authorization-chain")) {
      if (c.expect.result !== "accept") continue;
      const links = c.input?.chain?.links;
      // Only active issuer keys are candidates. Any link that verifies under a
      // non-active key would be a finding, not a pass.
      const keys = (c.input?.issuerKeys ?? []).filter(
        (k: any) =>
          k?.status === "active" && typeof k.publicKeyHex === "string",
      );
      if (!Array.isArray(links) || keys.length === 0) continue;
      for (const link of links) {
        if (typeof link?.signature !== "string") continue;
        exercised++;
        let ok = false;
        for (const k of keys) {
          if (
            await verify(
              link.signature,
              bodySignatureBase(link),
              fromHex(k.publicKeyHex),
            )
          ) {
            ok = true;
            break;
          }
        }
        if (!ok) failures.push(`${c.caseId} ${link.grantId}`);
      }
    }
    expect(exercised, "no delegation links were exercised").toBeGreaterThan(0);
    expect(failures).toEqual([]);
  });
});
