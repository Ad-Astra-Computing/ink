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
// @ts-expect-error the independent modules are deliberately plain .mjs with no
// dependency on this package's types, so they cannot drift toward src/.
import { transportSignatureBase } from "../conformance/v1/independent/signature-base.mjs";
// @ts-expect-error see above
import { bodySignatureBase } from "../conformance/v1/independent/body-signature.mjs";
// @ts-expect-error see above
import { cardSignatureBase, rotationLinkSignatureBase } from "../conformance/v1/independent/card-signature.mjs";
// @ts-expect-error see above
import { decodePublicKeyMultibase } from "../conformance/v1/independent/multibase.mjs";
// @ts-expect-error see above
import { canonicalPrincipal } from "../conformance/v1/independent/principal.mjs";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "conformance", "v1", "vectors");
const enc = new TextEncoder();
const b64u = (s: string) => Uint8Array.from(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
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
        expect(c.expect.result, `${c.caseId}: accept case is missing signInput, signature or key`).not.toEqual("accept");
        continue;
      }
      exercised++;
      let ok = false;
      try {
        ok = await verify(signature, transportSignatureBase(signInput), fromHex(publicKeyHex));
      } catch {
        // A scalar carrying CR or LF cannot build a base at all, which is how
        // §3.3 rejects it. That is the expected path for those cases.
        if (c.expect.result === "reject") continue;
        throw new Error(`${c.caseId}: base construction threw on an accept case`);
      }
      if (c.expect.result === "accept" && !ok) failures.push(c.caseId);
    }
    expect(exercised, "no signature-base vectors were exercised").toBeGreaterThan(0);
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
      const signing = Array.isArray(card.keys?.signing) ? card.keys.signing : [];
      const mb = signing.find((k: any) => k?.keyId === cs.keyId)?.publicKeyMultibase ?? card.publicKeyMultibase;
      expect(typeof mb, `${c.caseId}: no public key resolves for cardSignature.keyId`).toEqual("string");
      exercised++;
      if (!(await verify(cs.signature, cardSignatureBase(card), decodePublicKeyMultibase(mb)))) {
        failures.push(c.caseId);
      }
    }
    expect(exercised, "no accepted agent-card-signature vectors were exercised").toBeGreaterThan(0);
    expect(unsigned, "every accepted card was unsigned, so nothing was verified").toBeLessThan(exercised);
    expect(failures).toEqual([]);
  });

  it("verifies every rotation link on an accepted card", async () => {
    const failures: string[] = [];
    let exercised = 0;
    for (const c of cases("agent-card-signature")) {
      if (c.expect.result !== "accept") continue;
      const chain = c.input?.card?.rotationChain;
      if (!Array.isArray(chain)) continue;
      const known = [...chain.flatMap((l: any) => l.signing ?? []), ...(c.input.card.keys?.signing ?? [])];
      for (const link of chain) {
        expect(typeof link?.signature, `${c.caseId}: chain link on an accepted card is unsigned`).toEqual("string");
        // The first link is signed by the genesis key, which on a key-derived
        // card is the embedded publicKeyMultibase rather than a member of any
        // committed set, so it carries no keyId to match on.
        const mb =
          known.find((k: any) => k?.keyId === link.prevKeyId)?.publicKeyMultibase ??
          c.input.card.publicKeyMultibase;
        expect(typeof mb, `${c.caseId}: link prevKeyId ${link.prevKeyId} resolves to no key`).toEqual("string");
        exercised++;
        if (!(await verify(link.signature, rotationLinkSignatureBase(link), decodePublicKeyMultibase(mb)))) {
          failures.push(`${c.caseId} v${link.keySetVersion}`);
        }
      }
    }
    expect(exercised, "no rotation links were exercised").toBeGreaterThan(0);
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
        if (!leg?.signInput || typeof leg.signature !== "string" || typeof leg[keyField] !== "string") continue;
        exercised++;
        const key = fromHex(leg[keyField]);
        if (!(await verify(leg.signature, transportSignatureBase(leg.signInput), key))) {
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
    const accepted = cases("principal-normalization").filter((c) => c.expect.result === "accept");
    expect(accepted.length, "no accept cases found; the category was renamed or dropped").toBeGreaterThan(0);
    const failures: string[] = [];
    for (const c of accepted) {
      if (canonicalPrincipal(c.input.agentId) !== c.expect.canonicalPrincipal) failures.push(c.caseId);
    }
    expect(failures).toEqual([]);
  });
});
