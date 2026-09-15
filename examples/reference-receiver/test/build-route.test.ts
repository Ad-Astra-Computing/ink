/**
 * The build surface as it is actually served.
 *
 * `build-info.test.ts` pins the values; this pins that every response carries
 * them. The header rides every response, including the card and an envelope
 * verdict, so a remote implementer debugging an interop failure reads it off
 * `curl -i` with nothing to look up, and a freshness check reads it from the
 * same response that judged the envelope rather than from a second request a
 * gradual rollout could route to a different build.
 */
import { describe, it, expect, beforeAll, vi } from "vitest";
import worker from "../src/index.js";
import { BUILD_INFO_HEADER } from "../src/build-info.js";
import inkPkg from "@adastracomputing/ink/package.json" with { type: "json" };
import { generateKeypair, encodePublicKeyMultibase, base64urlEncode } from "@adastracomputing/ink";

const HOST = "r.example";
const DID = `did:web:${HOST}`;

let env: Record<string, unknown>;

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

const get = (path: string) =>
  worker.fetch(new Request(`https://${HOST}${path}`), env as never, ctx);

beforeAll(async () => {
  const kp = await generateKeypair();
  env = {
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
    INK_RECEIVER_HOST: HOST,
    INK_RECEIVER: memoryKv(),
    CF_VERSION_METADATA: { id: "dep-1", tag: "" },
  };
});

describe("build surface", () => {
  it("serves the versions as JSON", async () => {
    const res = await get("/_build");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ink: inkPkg.version, deployment: "dep-1" });
  });

  it("never lets an edge cache answer the freshness question", async () => {
    // A cached answer would report the version of whatever build happened to
    // populate the cache, which is the exact failure the route exists to
    // catch.
    const res = await get("/_build");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it.each([
    ["/_build", "the build route"],
    ["/.well-known/did.json", "the did document"],
    ["/.well-known/ink/agent.json", "the agent card"],
    [`/ink/v1/${encodeURIComponent(DID)}/agent.json`, "the versioned card"],
    ["/", "the landing page"],
    ["/nope", "a 404"],
  ])("stamps the header on %s (%s)", async (path) => {
    const res = await get(path);
    expect(res.headers.get(BUILD_INFO_HEADER)).toBe(`ink=${inkPkg.version}; deployment=dep-1`);
  });

  it("stamps the header even when the receiver cannot load its own identity", async () => {
    // The response someone debugging a broken deployment is most likely to be
    // holding, and it returns before any route matches.
    //
    // A cold module is required: identity is cached in module scope, so a
    // second import here would answer from the one already loaded.
    vi.resetModules();
    const cold = (await import("../src/index.js")).default;
    const res = await cold.fetch(
      new Request(`https://${HOST}/`),
      { INK_RECEIVER_HOST: HOST, CF_VERSION_METADATA: { id: "dep-1", tag: "" } } as never,
      ctx,
    );
    expect(res.status).toBe(500);
    expect(res.headers.get(BUILD_INFO_HEADER)).toBe(`ink=${inkPkg.version}; deployment=dep-1`);
  });

  it("keeps the build out of the card body while stamping it on the response", async () => {
    // Only the deployment id is checked for containment. Asserting the card
    // also omits the package version would fail the day a protocol version
    // equals it, testing a coincidence rather than the boundary.
    const res = await get("/.well-known/ink/agent.json");
    expect(res.headers.get(BUILD_INFO_HEADER)).toContain("dep-1");
    expect(await res.text()).not.toContain("dep-1");
  });
});
