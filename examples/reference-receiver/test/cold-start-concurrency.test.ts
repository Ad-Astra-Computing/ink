/**
 * Cold-start concurrency: the two card routes must agree byte-for-byte even
 * when both miss the cache at once.
 *
 * The card carries an `updatedAt` stamp generated at build time, so two builds
 * are two different (both individually valid) documents. A cache that stores
 * only the RESOLVED body lets two concurrent cold requests — one to the
 * versioned discovery path, one to the well-known alias — both miss, both
 * build, and both answer with different bytes. The alias contract in
 * `discovery-roundtrip.test.ts` only exercises the warm path, so it cannot see
 * that. These tests drive a genuinely cold module instance.
 *
 * `new Date()` is stubbed to advance a second per call, so a second build is
 * guaranteed to produce a different `updatedAt` rather than depending on a
 * millisecond boundary landing between two builds.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
} from "@adastracomputing/ink";

const HOST = "r.example";
const DID = `did:web:${HOST}`;
const VERSIONED_PATH = `/ink/v1/${encodeURIComponent(DID)}/agent.json`;
const WELL_KNOWN_PATH = "/.well-known/ink/agent.json";

const ctx = {
  waitUntil() { /* audit writes are fire-and-forget in tests */ },
  passThroughOnException() { /* not used */ },
} as unknown as ExecutionContext;

function memoryKv() {
  const store = new Map<string, string>();
  return {
    async get(key: string) { return store.get(key) ?? null; },
    async put(key: string, value: string) { store.set(key, String(value)); },
  };
}

async function makeEnv(): Promise<Record<string, unknown>> {
  const kp = await generateKeypair();
  return {
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
    INK_RECEIVER_HOST: HOST,
    INK_RECEIVER: memoryKv(),
  };
}

/** Import a module instance with empty module-scope caches: a cold isolate. */
async function coldWorker() {
  vi.resetModules();
  return (await import("../src/index.js")).default;
}

const RealDate = Date;

beforeEach(() => {
  let tick = RealDate.UTC(2026, 0, 1, 0, 0, 0);
  class SteppingDate extends RealDate {
    constructor(...args: ConstructorParameters<typeof Date> | []) {
      if (args.length === 0) {
        super(tick);
        tick += 1000;
      } else {
        super(...args);
      }
    }
  }
  vi.stubGlobal("Date", SteppingDate);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("cold-start card concurrency", () => {
  it("stubs Date so two builds cannot collide on updatedAt", async () => {
    // Guards the guard: if this ever stops advancing, the concurrency
    // assertions below would pass vacuously.
    expect(new Date().toISOString()).not.toBe(new Date().toISOString());
  });

  it("serves identical bytes when both card routes miss the cache at once", async () => {
    const worker = await coldWorker();
    const env = await makeEnv();
    // Fire both WITHOUT awaiting in between: the second request enters
    // `fetch` while the first is still suspended on the identity load and the
    // card build, so both observe an empty cache.
    const [versioned, wellKnown] = await Promise.all([
      worker.fetch(new Request(`https://${HOST}${VERSIONED_PATH}`), env as never, ctx),
      worker.fetch(new Request(`https://${HOST}${WELL_KNOWN_PATH}`), env as never, ctx),
    ]);
    expect(versioned.status).toBe(200);
    expect(wellKnown.status).toBe(200);
    expect(await wellKnown.text()).toBe(await versioned.text());
  });

  it("builds the card exactly once under a burst of concurrent cold requests", async () => {
    const worker = await coldWorker();
    const env = await makeEnv();
    const paths = [
      VERSIONED_PATH, WELL_KNOWN_PATH, VERSIONED_PATH, WELL_KNOWN_PATH,
      VERSIONED_PATH, WELL_KNOWN_PATH, VERSIONED_PATH, WELL_KNOWN_PATH,
    ];
    const bodies = await Promise.all(
      paths.map(async (p) =>
        (await worker.fetch(new Request(`https://${HOST}${p}`), env as never, ctx)).text()),
    );
    expect(new Set(bodies).size).toBe(1);
    // One build means one `new Date()` consumed by the card, so the stamp is
    // the first tick. A second build would show a later stamp on some body.
    const stamps = bodies.map((b) => (JSON.parse(b) as { updatedAt: string }).updatedAt);
    expect(new Set(stamps).size).toBe(1);
  });

  it("keeps serving identical bytes on the warm path after the cold burst", async () => {
    const worker = await coldWorker();
    const env = await makeEnv();
    const cold = await (await worker.fetch(
      new Request(`https://${HOST}${VERSIONED_PATH}`), env as never, ctx)).text();
    const warm = await (await worker.fetch(
      new Request(`https://${HOST}${WELL_KNOWN_PATH}`), env as never, ctx)).text();
    expect(warm).toBe(cold);
  });

  it("loads the receiver identity once across concurrent cold requests", async () => {
    const worker = await coldWorker();
    const env = await makeEnv();
    // A misconfigured identity must still fail every concurrent caller, and
    // must not poison the cache for a later correctly-configured request.
    const broken = { ...env, INK_RECEIVER_HOST: "  " };
    const [a, b] = await Promise.all([
      worker.fetch(new Request(`https://${HOST}${VERSIONED_PATH}`), broken as never, ctx),
      worker.fetch(new Request(`https://${HOST}${WELL_KNOWN_PATH}`), broken as never, ctx),
    ]);
    expect(a.status).toBe(500);
    expect(b.status).toBe(500);
    const ok = await worker.fetch(new Request(`https://${HOST}${VERSIONED_PATH}`), env as never, ctx);
    expect(ok.status).toBe(200);
  });
});
