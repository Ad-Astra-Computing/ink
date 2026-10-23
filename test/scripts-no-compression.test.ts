// CVE-2026-111497: the CLI scripts share this guard against a compromised or
// malicious endpoint forcing Brotli decompression on an unread response body.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { brotliCompressSync } from "node:zlib";
import { fetchUncompressed } from "../scripts/lib/no-compression.mjs";

describe("scripts/lib/no-compression", () => {
  let server: Server;
  let origin: string;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res
        .writeHead(200, { "content-type": "application/json", "content-encoding": "br" })
        .end(brotliCompressSync(Buffer.from("{}")));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => server?.close());

  it("refuses a compressed response before reading it", async () => {
    await expect(fetchUncompressed(origin)).rejects.toThrow(/refusing a response compressed/);
  });
});
