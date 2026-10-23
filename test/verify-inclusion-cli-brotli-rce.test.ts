// CVE-2026-111497: fetch() decodes Brotli lazily on body read, and a
// compromised --witness URL picks Content-Encoding on its own regardless of
// what the request asked for. fetchBounded must refuse before any read.
import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { brotliCompressSync } from "node:zlib";

const CLI = fileURLToPath(new URL("../bin/verify-inclusion-impl.mjs", import.meta.url).href);

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

describe("verify-inclusion CLI refuses a compressed witness response", () => {
  it("refuses the DID document before decoding it, rather than running the Brotli decoder on it", async () => {
    const server = createServer((req, res) => {
      const path = (req.url ?? "").split("?")[0];
      if (path === "/.well-known/did.json") {
        res
          .writeHead(200, { "content-type": "application/json", "content-encoding": "br" })
          .end(brotliCompressSync(Buffer.from("{}")));
        return;
      }
      res.writeHead(404).end("nope");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const url = `http://127.0.0.1:${port}`;
      const receipt = JSON.stringify({
        eventId: "evt-1",
        leafIndex: 0,
        treeSize: 1,
        rootHash: "11".repeat(32),
        timestamp: "2026-06-10T00:00:00.000Z",
        inclusionProof: [],
        serviceSignature: "x",
      });
      const { code, out } = await runCli(["--witness", url, "--allow-http"], receipt);
      expect(code).toBe(2);
      expect(out).toContain("refusing a response compressed as 'br'");
    } finally {
      server.close();
    }
  });
});
