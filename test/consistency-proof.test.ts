import { describe, it, expect } from "vitest";
import { verifyConsistencyProof } from "../src/index.js";

// ---------------------------------------------------------------------------
// Independent reference implementation, deliberately NOT the production code.
// The production verifier is an imperative RFC 6962 walk; this reference is a
// recursive SUBPROOF generator plus a recursive Merkle tree hash. If they
// agree across the boundary matrix and random sizes, an off-by-one or
// power-of-two mistake in either would have to be present in both, in opposite
// directions, to go unnoticed. Plus the explicit literal vector below pins the
// exact bytes.
// ---------------------------------------------------------------------------
const enc = new TextEncoder();
const EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
function fromHex(s: string): Uint8Array {
  const a = new Uint8Array(s.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return a;
}
async function sha256(b: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
}
async function leafHash(data: string): Promise<string> {
  const d = enc.encode(data);
  const buf = new Uint8Array(1 + d.length);
  buf[0] = 0x00;
  buf.set(d, 1);
  return sha256(buf);
}
async function nodeHash(l: string, r: string): Promise<string> {
  const buf = new Uint8Array(65);
  buf[0] = 0x01;
  buf.set(fromHex(l), 1);
  buf.set(fromHex(r), 33);
  return sha256(buf);
}
function lp2(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
async function mth(leaves: string[], start: number, size: number): Promise<string> {
  if (size === 0) return EMPTY;
  if (size === 1) return leaves[start]!;
  const k = lp2(size);
  return nodeHash(await mth(leaves, start, k), await mth(leaves, start + k, size - k));
}
async function subproof(leaves: string[], m: number, start: number, size: number, b: boolean): Promise<string[]> {
  if (m === size) return b ? [] : [await mth(leaves, start, size)];
  const k = lp2(size);
  if (m <= k) return [...(await subproof(leaves, m, start, k, b)), await mth(leaves, start + k, size - k)];
  return [...(await subproof(leaves, m - k, start + k, size - k, false)), await mth(leaves, start, k)];
}
async function genProof(leaves: string[], m: number, n: number): Promise<string[]> {
  if (m === 0 || m === n) return [];
  return subproof(leaves, m, 0, n, true);
}
async function makeLeaves(n: number): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(await leafHash(`leaf-${i}`));
  return out;
}

describe("verifyConsistencyProof — known-answer vector", () => {
  it("accepts the literal 1 -> 2 proof", async () => {
    const firstRoot = "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7";
    const secondRoot = "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc";
    const proof = ["3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f"];
    expect(await verifyConsistencyProof(1, firstRoot, 2, secondRoot, proof)).toBe(true);
    // A different second root must not verify against the same proof.
    expect(await verifyConsistencyProof(1, firstRoot, 2, "f".repeat(64), proof)).toBe(false);
  });
});

describe("verifyConsistencyProof — boundary matrix (reference generator)", () => {
  const cases: Array<[number, number]> = [
    [1, 2], [1, 3], [2, 3], [2, 4], [3, 4], [4, 5], [4, 8], [7, 8], [8, 9],
    [1, 8], [5, 8], [6, 7], [1, 1], [8, 8],
  ];
  for (const [m, n] of cases) {
    it(`verifies a ${m} -> ${n} proof`, async () => {
      const leaves = await makeLeaves(n);
      const firstRoot = await mth(leaves, 0, m);
      const secondRoot = await mth(leaves, 0, n);
      const proof = await genProof(leaves, m, n);
      expect(await verifyConsistencyProof(m, firstRoot, n, secondRoot, proof)).toBe(true);
    });
  }
});

describe("verifyConsistencyProof — exhaustive small + pseudo-random", () => {
  it("verifies every 1 <= m <= n <= 24", async () => {
    const N = 24;
    const leaves = await makeLeaves(N);
    const roots: string[] = [];
    for (let s = 0; s <= N; s++) roots.push(await mth(leaves, 0, s));
    for (let n = 1; n <= N; n++) {
      for (let m = 1; m <= n; m++) {
        const proof = await genProof(leaves, m, n);
        const ok = await verifyConsistencyProof(m, roots[m]!, n, roots[n]!, proof);
        expect(ok, `${m} -> ${n}`).toBe(true);
      }
    }
  });

  it("rejects every wrong (m, n') pairing it is not a proof for", async () => {
    // A proof generated for m -> n must not verify m -> n+1 (wrong second root).
    const leaves = await makeLeaves(16);
    const roots: string[] = [];
    for (let s = 0; s <= 16; s++) roots.push(await mth(leaves, 0, s));
    for (let n = 2; n < 16; n++) {
      const m = Math.max(1, n - 1);
      const proof = await genProof(leaves, m, n);
      expect(await verifyConsistencyProof(m, roots[m]!, n + 1, roots[n + 1]!, proof)).toBe(false);
    }
  });
});

describe("verifyConsistencyProof — edge cases", () => {
  it("same size requires equal roots and an empty proof", async () => {
    const leaves = await makeLeaves(5);
    const root = await mth(leaves, 0, 5);
    expect(await verifyConsistencyProof(5, root, 5, root, [])).toBe(true);
    expect(await verifyConsistencyProof(5, root, 5, "a".repeat(64), [])).toBe(false);
    expect(await verifyConsistencyProof(5, root, 5, root, ["b".repeat(64)])).toBe(false);
  });

  it("empty first tree is a prefix of any tree, with an empty proof and the empty-tree root", async () => {
    const leaves = await makeLeaves(5);
    const root5 = await mth(leaves, 0, 5);
    expect(await verifyConsistencyProof(0, EMPTY, 5, root5, [])).toBe(true);
    expect(await verifyConsistencyProof(0, "c".repeat(64), 5, root5, [])).toBe(false);
    expect(await verifyConsistencyProof(0, EMPTY, 5, root5, ["d".repeat(64)])).toBe(false);
  });
});

describe("verifyConsistencyProof — negative and tamper cases", () => {
  async function fixture(m: number, n: number) {
    const leaves = await makeLeaves(n);
    return {
      firstRoot: await mth(leaves, 0, m),
      secondRoot: await mth(leaves, 0, n),
      proof: await genProof(leaves, m, n),
    };
  }

  it("rejects first > second", async () => {
    const { firstRoot, secondRoot } = await fixture(3, 7);
    expect(await verifyConsistencyProof(7, secondRoot, 3, firstRoot, [])).toBe(false);
  });

  it("rejects a wrong first root", async () => {
    const { secondRoot, proof } = await fixture(3, 7);
    expect(await verifyConsistencyProof(3, "0".repeat(64), 7, secondRoot, proof)).toBe(false);
  });

  it("rejects a wrong second root", async () => {
    const { firstRoot, proof } = await fixture(3, 7);
    expect(await verifyConsistencyProof(3, firstRoot, 7, "0".repeat(64), proof)).toBe(false);
  });

  it("rejects a reordered proof node", async () => {
    const { firstRoot, secondRoot, proof } = await fixture(3, 7);
    expect(proof.length).toBeGreaterThanOrEqual(2);
    const swapped = [...proof];
    [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, swapped)).toBe(false);
  });

  it("rejects a tampered proof node", async () => {
    const { firstRoot, secondRoot, proof } = await fixture(3, 7);
    const tampered = [...proof];
    tampered[0] = tampered[0]!.replace(/./, (c) => (c === "a" ? "b" : "a"));
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, tampered)).toBe(false);
  });

  it("rejects a truncated proof", async () => {
    const { firstRoot, secondRoot, proof } = await fixture(3, 7);
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, proof.slice(0, -1))).toBe(false);
  });

  it("rejects a proof with an appended extra node", async () => {
    const { firstRoot, secondRoot, proof } = await fixture(3, 7);
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, [...proof, "e".repeat(64)])).toBe(false);
  });

  it("rejects malformed inputs", async () => {
    const { firstRoot, secondRoot, proof } = await fixture(3, 7);
    expect(await verifyConsistencyProof(3.5, firstRoot, 7, secondRoot, proof)).toBe(false);
    expect(await verifyConsistencyProof(-1, firstRoot, 7, secondRoot, proof)).toBe(false);
    expect(await verifyConsistencyProof(3, "XYZ", 7, secondRoot, proof)).toBe(false);
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, [...proof, "tooshort"])).toBe(false);
    expect(await verifyConsistencyProof(3, firstRoot.toUpperCase(), 7, secondRoot, proof)).toBe(false);
    // Non-safe integers and over-length proofs are rejected before any hashing.
    expect(await verifyConsistencyProof(3, firstRoot, Number.MAX_SAFE_INTEGER + 2, secondRoot, proof)).toBe(false);
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, Array(65).fill("a".repeat(64)))).toBe(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(await verifyConsistencyProof(3, firstRoot, 7, secondRoot, "notanarray" as any)).toBe(false);
  });
});
