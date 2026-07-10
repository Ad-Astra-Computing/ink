import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import {
  signAuditEvent,
  verifyAuditEventSignature,
  computeAuditMerkleLeafHash,
  verifyInclusionReceipt,
  verifyCheckpoint,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyAuditQueryResponse,
} from "../src/index.js";

// Dynamic cross-implementation interop: the Go witness ISSUES artifacts and the
// TypeScript reference verifier CHECKS them. The static conformance vectors only
// prove both sides agree on frozen inputs; this proves an inclusion receipt, a
// checkpoint, inclusion and consistency proofs, and an audit-query response
// freshly minted by independent Go code are accepted by the reference verifier
// in a live round trip. It is the strongest evidence the wire contract is not
// accidentally TypeScript-shaped: the two never share a line of code, only bytes
// on the socket.

const GO_DIR = fileURLToPath(new URL("../go", import.meta.url).href);
const ORIGIN = "witness.interop.test";
const SERVICE_DID = "did:web:witness.interop.test";
const TOKEN = "interop-operator-token";
const MESSAGE_ID = "msg-interop-1";
const REQUESTER = "did:web:alice.example";
const COUNTERPARTY = "did:web:bob.example";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// A free ephemeral port the Go server can bind. There is a small window between
// closing this listener and the Go server binding it, but it is the standard way
// to hand a subprocess an OS-chosen port and collisions are vanishingly rare.
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

const goAvailable = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;

// Skip only for a local developer who has no Go toolchain. In CI this test is a
// hard requirement: skipping there would let the job go green without ever
// exercising the Go witness, defeating the point of the interop gate. When Go is
// missing under CI the suite runs and fails in beforeAll on the build.
const skipSuite = !goAvailable && !process.env.CI;

// Build one audit event, sign it with the agent key, and return both the object
// (for the reference verifier) and the exact bytes to POST to the Go witness.
async function buildEvent(
  i: number,
  agentPriv: Uint8Array,
): Promise<{ event: Record<string, unknown>; body: string }> {
  const base: Record<string, unknown> = {
    id: `evt-${i}`,
    type: "connection_request",
    messageId: MESSAGE_ID,
    agentId: REQUESTER,
    counterpartyId: COUNTERPARTY,
    seq: i,
  };
  const agentSignature = await signAuditEvent(base, agentPriv);
  const event = { ...base, agentSignature };
  return { event, body: JSON.stringify(event) };
}

describe.skipIf(skipSuite)("Go witness issues, TypeScript reference verifies", () => {
  let proc: ChildProcess | undefined;
  let procExited: Promise<void> | undefined;
  let childStderr = "";
  let binDir: string;
  let baseUrl: string;
  let witnessPublicKey: Uint8Array;
  let agentPublicKey: Uint8Array;
  let agentPrivateKey: Uint8Array;

  beforeAll(async () => {
    binDir = mkdtempSync(join(tmpdir(), "ink-witness-"));
    const bin = join(binDir, "ink-witness-server");
    const build = spawnSync("go", ["build", "-o", bin, "./cmd/ink-witness-server"], {
      cwd: GO_DIR,
      encoding: "utf8",
    });
    if (build.status !== 0) {
      throw new Error(`go build failed: ${build.stderr || build.stdout}`);
    }

    // One witness seed drives the Go signer; the reference verifier checks with
    // the public key derived from the same seed. A @noble secret key is exactly
    // the 32-byte Ed25519 seed Go's NewKeyFromSeed expects, so the two agree on
    // the key without exchanging a public-key encoding.
    const witnessSeed = ed.utils.randomSecretKey();
    witnessPublicKey = await ed.getPublicKeyAsync(witnessSeed);
    agentPrivateKey = ed.utils.randomSecretKey();
    agentPublicKey = await ed.getPublicKeyAsync(agentPrivateKey);

    const port = await freePort();
    baseUrl = `http://127.0.0.1:${port}`;
    proc = spawn(
      bin,
      ["--addr", `127.0.0.1:${port}`, "--origin", ORIGIN, "--service-did", SERVICE_DID],
      {
        cwd: GO_DIR,
        env: { ...process.env, INK_WITNESS_SEED_HEX: hex(witnessSeed), INK_WITNESS_SUBMIT_TOKEN: TOKEN },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    // Drain the child's output so a chatty or failing server never blocks on a
    // full pipe, and keep a bounded tail of stderr for diagnostics.
    let exited = false;
    procExited = new Promise<void>((resolve) => proc!.on("exit", () => { exited = true; resolve(); }));
    proc.stdout?.on("data", () => {});
    proc.stderr?.on("data", (d: Buffer) => { childStderr = (childStderr + d.toString()).slice(-4096); });

    // Wait for the witness to answer /healthz before driving the flow, and fail
    // fast if the process dies during startup rather than waiting out the window.
    const deadline = Date.now() + 15_000;
    for (;;) {
      if (exited) throw new Error(`Go witness exited during startup:\n${childStderr}`);
      try {
        const res = await fetch(`${baseUrl}/healthz`);
        if (res.ok) break;
      } catch {
        // not up yet
      }
      if (Date.now() > deadline) throw new Error(`Go witness did not become healthy in time:\n${childStderr}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }, 60_000);

  afterAll(async () => {
    if (proc) {
      proc.kill("SIGKILL");
      await Promise.race([procExited, new Promise((r) => setTimeout(r, 5_000))]);
    }
    if (binDir) rmSync(binDir, { recursive: true, force: true });
  });

  async function submit(body: string): Promise<Record<string, unknown>> {
    const res = await fetch(`${baseUrl}/submit`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body,
    });
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, unknown>;
  }

  it("verifies a Go-issued inclusion receipt, checkpoint, proofs and audit-query response", async () => {
    // ── Submit two in-scope events; keep each Go-issued receipt. ──
    const { event: event0, body: body0 } = await buildEvent(0, agentPrivateKey);
    const { event: event1, body: body1 } = await buildEvent(1, agentPrivateKey);

    const receipt0 = await submit(body0);
    const receipt1 = await submit(body1);

    // The reference verifier accepts each receipt, binding the proof to the
    // event (leaf recomputed from the event, event.id bound to receipt.eventId).
    const r0 = await verifyInclusionReceipt({
      receipt: receipt0 as never,
      witnessPublicKey,
      event: event0,
    });
    expect(r0.valid).toBe(true);
    const r1 = await verifyInclusionReceipt({
      receipt: receipt1 as never,
      witnessPublicKey,
      event: event1,
    });
    expect(r1.valid).toBe(true);

    // ── The current checkpoint parses and verifies against the witness key. ──
    const cpRes = await fetch(`${baseUrl}/checkpoint`);
    expect(cpRes.status).toBe(200);
    const { checkpoint } = (await cpRes.json()) as { checkpoint: string };
    const cp = await verifyCheckpoint(checkpoint, witnessPublicKey, ORIGIN);
    expect(cp).not.toBeNull();
    expect(cp?.treeSize).toBe(2);
    const root2 = cp!.rootHash;

    // ── The inclusion proof of leaf 0 over the size-2 tree verifies. ──
    const leaf0 = await computeAuditMerkleLeafHash(event0);
    const incRes = await fetch(`${baseUrl}/inclusion?index=0`);
    expect(incRes.status).toBe(200);
    const inc = (await incRes.json()) as { index: number; size: number; proof: string[] };
    expect(inc.size).toBe(2);
    expect(await verifyInclusionProof(leaf0, inc.proof, inc.index, inc.size, root2)).toBe(true);

    // ── The 1 -> 2 consistency proof verifies: the size-1 tree is a prefix. ──
    // The root of a one-leaf tree is that leaf's hash, so root@1 == leaf0.
    const conRes = await fetch(`${baseUrl}/consistency?first=1&second=2`);
    expect(conRes.status).toBe(200);
    const con = (await conRes.json()) as { first: number; second: number; proof: string[] };
    expect(await verifyConsistencyProof(con.first, leaf0, con.second, root2, con.proof)).toBe(true);

    // ── The audit-query response verifies end to end, per-event signature and
    //    all. The callback resolves the submitting agent's key. ──
    const aqRes = await fetch(`${baseUrl}/audit-query`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ requester: REQUESTER, messageId: MESSAGE_ID }),
    });
    expect(aqRes.status).toBe(200);
    const response = (await aqRes.json()) as Record<string, unknown>;
    expect((response.events as unknown[]).length).toBe(2);

    const aq = await verifyAuditQueryResponse({
      response: response as never,
      witnessPublicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      expectedServiceDid: SERVICE_DID,
      verifyEventSignature: (event) => verifyAuditEventSignature(event, agentPublicKey),
    });
    expect(aq.valid).toBe(true);
  }, 30_000);
});
