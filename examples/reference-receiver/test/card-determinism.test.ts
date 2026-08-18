/**
 * Agent card determinism: the served body is a pure function of configuration
 * and key material.
 *
 * Why this file exists. The card is signed over its own body, and both the
 * versioned discovery path and the `/.well-known` alias serve it. Those two
 * spellings of one document must not disagree, and a consumer polling the card
 * must not see it "update" when nothing changed. The receiver used to stamp
 * `updatedAt` with `new Date()` at build time and lean on a per-isolate cache
 * to hide the consequence. That never held in production: Cloudflare gives a
 * low-traffic worker a cold isolate for nearly every request, so the cache was
 * missed almost every time and the live deployment served a fresh `updatedAt`
 * and a fresh `cardSignature` per request. It only looked correct in tests and
 * in the container-based interop lab, where one process serves every request.
 *
 * So these tests do not test the cache. They test that the cache is
 * unnecessary. Every assertion below drives a genuinely cold module instance,
 * and `new Date()` is stubbed to advance a second per call so that ANY
 * surviving clock read in the card path would show up as differing bytes
 * rather than depending on a millisecond boundary landing between two builds.
 *
 * The last test goes further and proves determinism across separate OS
 * processes: two `node` invocations, independent module registries, different
 * fake clocks, same bytes. Nothing in one process can inform the other, so
 * only a genuinely deterministic build passes it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
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

interface Identity {
  seed: string;
  publicKeyMultibase: string;
}

async function freshIdentity(): Promise<Identity> {
  const kp = await generateKeypair();
  return {
    seed: base64urlEncode(kp.privateKey),
    publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
  };
}

function makeEnv(id: Identity, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    INK_RECEIVER_SIGNING_SEED: id.seed,
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: id.publicKeyMultibase,
    INK_RECEIVER_HOST: HOST,
    INK_RECEIVER_CARD_UPDATED_AT: "2026-02-03T04:05:06Z",
    INK_RECEIVER: memoryKv(),
    ...overrides,
  };
}

/** Import a module instance with empty module-scope caches: a cold isolate. */
async function coldWorker() {
  vi.resetModules();
  return (await import("../src/index.js")).default;
}

async function fetchCard(
  worker: Awaited<ReturnType<typeof coldWorker>>,
  env: Record<string, unknown>,
  path: string,
): Promise<string> {
  const res = await worker.fetch(new Request(`https://${HOST}${path}`), env as never, ctx);
  expect(res.status).toBe(200);
  return res.text();
}

const RealDate = Date;

/**
 * Replace `Date` with one whose no-argument constructor advances a second per
 * call, starting at `startMs`. Any clock read reachable from the card build
 * therefore produces a different value on every build and in every test.
 */
function stubSteppingClock(startMs: number): void {
  let tick = startMs;
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
}

beforeEach(() => {
  stubSteppingClock(RealDate.UTC(2026, 0, 1, 0, 0, 0));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("agent card determinism", () => {
  it("stubs Date so any surviving clock read would diverge", async () => {
    // Guards the guard: if this ever stops advancing, every assertion below
    // would pass vacuously.
    expect(new Date().toISOString()).not.toBe(new Date().toISOString());
  });

  it("serves identical bytes from the versioned path and the well-known alias", async () => {
    const id = await freshIdentity();
    const worker = await coldWorker();
    const env = makeEnv(id);
    // Fire both WITHOUT awaiting in between, so neither can be served from
    // work the other completed.
    const [versioned, wellKnown] = await Promise.all([
      fetchCard(worker, env, VERSIONED_PATH),
      fetchCard(worker, env, WELL_KNOWN_PATH),
    ]);
    expect(wellKnown).toBe(versioned);
  });

  it("serves identical bytes from two cold module instances at different times", async () => {
    // This is the production case the old cache could not cover: two requests
    // 200ms apart, each landing on its own cold isolate. Independent module
    // state, independent clocks, and the bytes must still match exactly —
    // including `cardSignature`, which covers `updatedAt`.
    const id = await freshIdentity();

    const first = await fetchCard(await coldWorker(), makeEnv(id), VERSIONED_PATH);

    vi.unstubAllGlobals();
    stubSteppingClock(RealDate.UTC(2031, 6, 14, 9, 30, 0));
    const second = await fetchCard(await coldWorker(), makeEnv(id), WELL_KNOWN_PATH);

    expect(second).toBe(first);
    const card = JSON.parse(first) as { updatedAt: string; cardSignature: { signature: string } };
    expect(card.updatedAt).toBe("2026-02-03T04:05:06Z");
    expect(card.cardSignature.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
  });

  it("changes the body only when the operator changes the configured updatedAt", async () => {
    const id = await freshIdentity();
    const before = await fetchCard(await coldWorker(), makeEnv(id), VERSIONED_PATH);
    const after = await fetchCard(
      await coldWorker(),
      makeEnv(id, { INK_RECEIVER_CARD_UPDATED_AT: "2027-09-09T09:09:09Z" }),
      VERSIONED_PATH,
    );
    expect(after).not.toBe(before);
    expect((JSON.parse(after) as { updatedAt: string }).updatedAt).toBe("2027-09-09T09:09:09Z");
  });

  it("answers a burst of concurrent cold requests with one body", async () => {
    const id = await freshIdentity();
    const worker = await coldWorker();
    const env = makeEnv(id);
    const paths = [
      VERSIONED_PATH, WELL_KNOWN_PATH, VERSIONED_PATH, WELL_KNOWN_PATH,
      VERSIONED_PATH, WELL_KNOWN_PATH, VERSIONED_PATH, WELL_KNOWN_PATH,
    ];
    const bodies = await Promise.all(paths.map((p) => fetchCard(worker, env, p)));
    expect(new Set(bodies).size).toBe(1);
  });

  it("rejects a card timestamp that is not strict RFC 3339, naming the var", async () => {
    const id = await freshIdentity();
    const worker = await coldWorker();
    const res = await worker.fetch(
      new Request(`https://${HOST}${VERSIONED_PATH}`),
      makeEnv(id, { INK_RECEIVER_CARD_UPDATED_AT: "2026-08-18 12:00:00" }) as never,
      ctx,
    );
    expect(res.status).toBe(500);
    const body = await res.json() as { error: string; detail: string };
    expect(body.error).toBe("receiver_misconfigured");
    expect(body.detail).toContain("INK_RECEIVER_CARD_UPDATED_AT");
  });

  it("loads the receiver identity once across concurrent cold requests", async () => {
    const id = await freshIdentity();
    const worker = await coldWorker();
    const env = makeEnv(id);
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

/**
 * Cross-process proof.
 *
 * Everything above shares one Node process, so in principle a stray module-level
 * memo could carry a value between two "cold" instances. This test removes that
 * possibility: the worker is bundled once, then run in two separate `node`
 * processes, each with its own module registry, its own globals and its own
 * fake clock set decades apart. The only thing the two share is the
 * configuration and the signing seed. Byte equality across them is the property
 * the live deployment needs and the property caching can never provide.
 */
describe("agent card determinism across processes", () => {
  const here = fileURLToPath(new URL(".", import.meta.url));
  let dir = "";

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "ink-card-determinism-"));
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("produces identical bytes in two separate node processes with different clocks", async () => {
    const { build } = await import("esbuild");
    const bundle = join(dir, "card.mjs");

    // The runner installs its fake clock BEFORE importing the worker, so a
    // clock read at module scope would be caught too, then prints the exact
    // bytes the worker would put on the wire.
    const entrySource = [
      "const start = Number(process.env.FAKE_CLOCK_MS);",
      "const RealDate = Date;",
      "let tick = start;",
      "globalThis.Date = class extends RealDate {",
      "  constructor(...args) {",
      "    if (args.length === 0) { super(tick); tick += 1000; } else { super(...args); }",
      "  }",
      "  static now() { const t = tick; tick += 1000; return t; }",
      "};",
      "const worker = (await import('./index.js')).default;",
      "const store = new Map();",
      "const env = {",
      "  INK_RECEIVER_SIGNING_SEED: process.env.SEED,",
      "  INK_RECEIVER_PUBLIC_KEY_MULTIBASE: process.env.PUBKEY,",
      "  INK_RECEIVER_HOST: process.env.RECEIVER_HOST,",
      "  INK_RECEIVER_CARD_UPDATED_AT: process.env.CARD_UPDATED_AT,",
      "  INK_RECEIVER: {",
      "    async get(k) { return store.get(k) ?? null; },",
      "    async put(k, v) { store.set(k, String(v)); },",
      "  },",
      "};",
      "const ctx = { waitUntil() {}, passThroughOnException() {} };",
      "const url = `https://${process.env.RECEIVER_HOST}${process.env.CARD_PATH}`;",
      "const res = await worker.fetch(new Request(url), env, ctx);",
      "if (res.status !== 200) { console.error(await res.text()); process.exit(1); }",
      "process.stdout.write(await res.text());",
      "",
    ].join("\n");

    await build({
      // Resolved from the receiver's own `src`, so `./index.js` reaches the
      // real worker source and `@adastracomputing/ink` reaches the same
      // installed library the worker uses.
      stdin: { contents: entrySource, resolveDir: resolve(here, "..", "src"), loader: "js" },
      bundle: true,
      format: "esm",
      platform: "node",
      target: "node22",
      outfile: bundle,
      logLevel: "silent",
    });

    const id = await freshIdentity();
    const base = {
      ...process.env,
      SEED: id.seed,
      PUBKEY: id.publicKeyMultibase,
      RECEIVER_HOST: HOST,
      CARD_UPDATED_AT: "2026-02-03T04:05:06Z",
    };
    const run = promisify(execFile);
    // Different fake clocks AND different card paths: neither the wall clock
    // nor the URL the card was fetched from may influence the bytes.
    const [a, b] = await Promise.all([
      run(process.execPath, [bundle], {
        env: { ...base, FAKE_CLOCK_MS: String(RealDate.UTC(2026, 0, 1)), CARD_PATH: VERSIONED_PATH },
      }),
      run(process.execPath, [bundle], {
        env: { ...base, FAKE_CLOCK_MS: String(RealDate.UTC(2039, 10, 20)), CARD_PATH: WELL_KNOWN_PATH },
      }),
    ]);

    expect(a.stdout.length).toBeGreaterThan(0);
    expect(b.stdout).toBe(a.stdout);
    const card = JSON.parse(a.stdout) as { updatedAt: string };
    expect(card.updatedAt).toBe("2026-02-03T04:05:06Z");
  }, 60_000);
});
