import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";
import { encodePublicKeyMultibase, base64urlEncode } from "../src/index.js";

// Fixture values are the real 1 -> 2 tree the ink and witness test suites share
// (leaves = SHA-256(0x00 || "leaf-i")). root@1 == leaf0; root@2 == H(leaf0,leaf1);
// the 1 -> 2 consistency proof is [leaf1].
const LEAF0 = "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7";
const LEAF1 = "3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f";
const ROOT2 = "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc";
const ORIGIN = "witness.test";
const CLI = fileURLToPath(new URL("../bin/verify-inclusion-impl.mjs", import.meta.url).href);

async function startWitness(checkpointRoot2: string, serveConsistency = true): Promise<{ server: Server; url: string; receipt: string }> {
  // One witness key signs the DID doc, the checkpoint and the receipt.
  const secretKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(secretKey);

  const timestamp = "2026-06-10T00:00:00.000Z";
  const payload = { eventId: "evt-1", leafIndex: 0, treeSize: 1, rootHash: LEAF0, timestamp };
  const sigBase = `ink/audit-inclusion/v1\n${canonicalize(payload)}`;
  const serviceSignature = base64urlEncode(await ed.signAsync(new TextEncoder().encode(sigBase), secretKey));
  const receipt = JSON.stringify({ ...payload, inclusionProof: [], serviceSignature });

  const body = `${ORIGIN}\n2\n${checkpointRoot2}`;
  const cpSig = base64urlEncode(await ed.signAsync(new TextEncoder().encode(body), secretKey));
  const signedCheckpoint = `${body}\n\n-- ${ORIGIN} ${cpSig}\n`;
  const didDoc = JSON.stringify({ verificationMethod: [{ publicKeyMultibase: encodePublicKeyMultibase(publicKey) }] });

  const server = createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === "/.well-known/did.json") return void res.writeHead(200, { "content-type": "application/json" }).end(didDoc);
    if (path === "/ink/v1/checkpoint") return void res.writeHead(200, { "content-type": "text/plain" }).end(signedCheckpoint);
    if (path === "/ink/v1/consistency" && serveConsistency) return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ first: 1, second: 2, proof: [LEAF1] }));
    res.writeHead(404).end("nope");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return { server, url: `http://127.0.0.1:${port}`, receipt };
}

function runCli(args: string[], stdin: string): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ code: code ?? -1, out }));
    child.stdin.end(stdin);
  });
}

describe("verify-inclusion CLI consistency cross-check", () => {
  it("reports a passing consistency step against an honest, growing witness", async () => {
    const { server, url, receipt } = await startWitness(ROOT2);
    try {
      const { code, out } = await runCli(["--witness", url, "--origin", ORIGIN, "--event-hash", LEAF0, "--allow-http"], receipt);
      expect(out).toContain("[PASS] consistency");
      expect(out).toContain("RECEIPT VALID");
      expect(code).toBe(0);
    } finally {
      server.close();
    }
  });

  it("marks the step skipped (not passed) when the witness serves no consistency proof", async () => {
    // did.json and the (newer) checkpoint are served and verify, but /consistency
    // 404s. The append-only check must be reported as skipped, never passed, so a
    // forked witness cannot look clean by withholding the endpoint.
    const { server, url, receipt } = await startWitness(ROOT2, false);
    try {
      const { code, out } = await runCli(["--witness", url, "--origin", ORIGIN, "--event-hash", LEAF0, "--allow-http"], receipt);
      expect(out).toContain("[SKIP] consistency");
      expect(out).not.toContain("[PASS] consistency");
      expect(out).toContain("RECEIPT VALID");
      expect(code).toBe(0);
    } finally {
      server.close();
    }
  });

  it("fails the receipt when the witness presents a forked later root", async () => {
    // The receipt itself is valid; only the later checkpoint root is forked, so
    // the 1 -> 2 proof cannot reconstruct it and the append-only check fails.
    const { server, url, receipt } = await startWitness("f".repeat(64));
    try {
      const { code, out } = await runCli(["--witness", url, "--origin", ORIGIN, "--event-hash", LEAF0, "--allow-http"], receipt);
      expect(out).toContain("[FAIL] consistency");
      expect(out).toContain("RECEIPT INVALID");
      expect(code).toBe(1);
    } finally {
      server.close();
    }
  });
});
