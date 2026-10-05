/**
 * The `verify-inclusion` CLI's receipt and checkpoint signature checks used
 * to call the library's cofactored (zip215:false) verifier directly instead
 * of the shared `verifyStrictEd25519`. A canonical, NOT small-order "mixed
 * order" public key (an honest key plus the unique order-8 torsion point)
 * admits a forged signature that the cofactored equation accepts and the
 * cofactorless one rejects — see test/ed25519-strict-verify.test.ts for the
 * forgery's construction and src/crypto/ed25519-strict.ts for why.
 *
 * This spawns the real published CLI (not a reimplementation) against both
 * vulnerable call sites and asserts each now rejects the forgery.
 */
import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";
import { encodePublicKeyMultibase, base64urlEncode } from "../src/index.js";

const CLI = fileURLToPath(new URL("../bin/verify-inclusion-impl.mjs", import.meta.url).href);
const SUBGROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

function rawMultiply(point: InstanceType<typeof ed.Point>, scalar: bigint): InstanceType<typeof ed.Point> {
  let result = ed.Point.ZERO;
  let addend = point;
  let n = scalar;
  while (n > 0n) {
    if (n & 1n) result = result.add(addend);
    addend = addend.add(addend);
    n >>= 1n;
  }
  return result;
}

function findOrder8Point(): InstanceType<typeof ed.Point> {
  for (let attempt = 0; attempt < 200; attempt++) {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = (attempt * 7 + i * 13 + 1) & 0xff;
    let candidate: InstanceType<typeof ed.Point>;
    try {
      candidate = ed.Point.fromBytes(seed, false);
    } catch {
      continue;
    }
    const t8 = rawMultiply(candidate, SUBGROUP_ORDER);
    if (t8.is0()) continue;
    const two = t8.add(t8);
    const four = two.add(two);
    if (!four.add(four).is0()) throw new Error("expected 8*T == 0");
    if (two.is0() || four.is0()) continue;
    return t8;
  }
  throw new Error("failed to find an order-8 point");
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i] ?? 0);
  return value;
}

function numberToBytesLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * Builds a mixed-order public key A = A0 + T8 and, for the given message
 * bytes, a signature (R, S) that satisfies the cofactored equation
 * [8](R + [k]A - [S]B) == 0 with k mod 8 != 0, so the cofactorless equation
 * [S]B == R + [k]A fails. Tries small r values until one lands k mod 8 != 0;
 * this always succeeds quickly since k mod 8 is uniform over r.
 */
async function forgeMixedOrderSignature(message: Uint8Array): Promise<{ publicKey: Uint8Array; signature: Uint8Array }> {
  const t8 = findOrder8Point();
  const seed = ed.utils.randomSecretKey();
  const ext = await ed.utils.getExtendedPublicKeyAsync(seed);
  const a0 = ed.Point.fromBytes(ext.pointBytes, false);
  const mixedA = a0.add(t8);
  const publicKey = mixedA.toBytes();

  for (let r = 1n; r < 200n; r++) {
    const R = ed.Point.BASE.multiply(r, false).toBytes();
    const hashed = await ed.hashes.sha512Async(new Uint8Array([...R, ...publicKey, ...message]));
    const k = bytesToNumberLE(hashed) % SUBGROUP_ORDER;
    if (k % 8n === 0n) continue;
    const s = (r + k * ext.scalar) % SUBGROUP_ORDER;
    return { publicKey, signature: new Uint8Array([...R, ...numberToBytesLE(s, 32)]) };
  }
  throw new Error("failed to forge a mixed-order signature with k mod 8 != 0");
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

function startDidServer(publicKey: Uint8Array): Promise<{ server: Server; url: string }> {
  const didDoc = JSON.stringify({ verificationMethod: [{ publicKeyMultibase: encodePublicKeyMultibase(publicKey) }] });
  const server = createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === "/.well-known/did.json") return void res.writeHead(200, { "content-type": "application/json" }).end(didDoc);
    res.writeHead(404).end("nope");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

describe("verify-inclusion CLI rejects the mixed-order cofactor-confusion forgery", () => {
  it("rejects a forged receipt signature under a mixed-order witness key", async () => {
    const payload = {
      eventId: "evt-1",
      leafIndex: 0,
      treeSize: 1,
      rootHash: "11".repeat(32),
      timestamp: "2026-06-10T00:00:00.000Z",
    };
    const sigBase = new TextEncoder().encode(`ink/audit-inclusion/v1\n${canonicalize(payload)}`);
    const { publicKey, signature } = await forgeMixedOrderSignature(sigBase);
    const receipt = JSON.stringify({ ...payload, inclusionProof: [], serviceSignature: base64urlEncode(signature) });

    const { server, url } = await startDidServer(publicKey);
    try {
      const { code, out } = await runCli(["--witness", url, "--allow-http"], receipt);
      expect(out).toContain("[FAIL] signature");
      expect(out).toContain("RECEIPT INVALID");
      expect(code).toBe(1);
    } finally {
      server.close();
    }
  });

  it("rejects a forged checkpoint signature under a mixed-order witness key", async () => {
    const origin = "witness.test";
    const body = `${origin}\n2\n${"22".repeat(32)}`;
    const { publicKey, signature } = await forgeMixedOrderSignature(new TextEncoder().encode(body));
    const signedCheckpoint = `${body}\n\n-- ${origin} ${base64urlEncode(signature)}\n`;

    // An ordinary receipt signed by an unrelated honest key. Its own
    // signature step is irrelevant here: fetchCurrentCheckpoint runs before
    // verifyReceipt and checks the checkpoint against the single
    // DID-advertised key (the forged mixed-order one below) regardless of
    // what signed the receipt, so this is sufficient to reach and exercise
    // the checkpoint cross-check.
    const secretKey = ed.utils.randomSecretKey();
    const receiptPayload = { eventId: "evt-1", leafIndex: 0, treeSize: 1, rootHash: "11".repeat(32), timestamp: "2026-06-10T00:00:00.000Z" };
    const receiptSigBase = `ink/audit-inclusion/v1\n${canonicalize(receiptPayload)}`;
    const receiptSig = base64urlEncode(await ed.signAsync(new TextEncoder().encode(receiptSigBase), secretKey));
    const receipt = JSON.stringify({ ...receiptPayload, inclusionProof: [], serviceSignature: receiptSig });

    const didDoc = JSON.stringify({ verificationMethod: [{ publicKeyMultibase: encodePublicKeyMultibase(publicKey) }] });
    const server = createServer((req, res) => {
      const path = (req.url ?? "").split("?")[0];
      if (path === "/.well-known/did.json") return void res.writeHead(200, { "content-type": "application/json" }).end(didDoc);
      if (path === "/ink/v1/checkpoint") return void res.writeHead(200, { "content-type": "text/plain" }).end(signedCheckpoint);
      res.writeHead(404).end("nope");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const url = `http://127.0.0.1:${port}`;
      const { out } = await runCli(["--witness", url, "--origin", origin, "--allow-http"], receipt);
      // The checkpoint cross-check must never report the forged signature as
      // verified; it must read as unavailable/unverified, never PASS.
      expect(out).toContain("Current checkpoint: not available or signature unverified");
      expect(out).not.toContain("Current checkpoint (signature verified)");
    } finally {
      server.close();
    }
  });
});
