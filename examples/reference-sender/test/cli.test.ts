import { describe, it, expect } from "vitest";
import {
  verifyMessage,
  verifyInkAuth,
  validateMessage,
  decodePublicKeyMultibase,
  type NonceStore,
} from "@adastracomputing/ink";
import { parseArgs, runCli } from "../src/cli.ts";
import { generateSenderIdentity } from "../src/identity.ts";

describe("parseArgs", () => {
  it("defaults the intent to ping", () => {
    const a = parseArgs(["--to", "did:key:z6Mk"]);
    expect(a.to).toBe("did:key:z6Mk");
    expect(a.intent).toBe("ping");
  });
  it("parses flags and values", () => {
    const a = parseArgs(["--to", "did:web:r.example", "--intent", "connection_request", "--allow-private"]);
    expect(a.intent).toBe("connection_request");
    expect(a.allowPrivate).toBe(true);
  });
  it("throws on a missing value", () => {
    expect(() => parseArgs(["--to"])).toThrow();
  });
  it("throws on an unknown flag", () => {
    expect(() => parseArgs(["--bogus"])).toThrow();
  });
});

describe("runCli", () => {
  it("prints help and exits 0", async () => {
    const lines: string[] = [];
    const code = await runCli(["--help"], { log: (l) => lines.push(l), env: {} });
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("ink-send");
  });

  it("keygen prints a usable seed + public key", async () => {
    const lines: string[] = [];
    const code = await runCli(["--keygen"], { log: (l) => lines.push(l), env: {} });
    expect(code).toBe(0);
    const out = lines.join("\n");
    expect(out).toContain("did: did:key:");
    expect(out).toContain("INK_SENDER_SIGNING_SEED=");
    expect(out).toContain("INK_SENDER_PUBLIC_KEY_MULTIBASE=");
  });

  it("requires --to when sending", async () => {
    const lines: string[] = [];
    const code = await runCli([], { log: (l) => lines.push(l), env: {} });
    expect(code).toBe(2);
    expect(lines.join("\n")).toContain("--to");
  });

  it("sends a ping end-to-end against an OSS-verifying receiver", async () => {
    const recipient = await generateSenderIdentity();
    const seen = new Set<string>();
    const nonceStore: NonceStore = { has: (n) => seen.has(n), add: (n) => void seen.add(n) };

    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const env = validateMessage(body);
      const senderPub = decodePublicKeyMultibase(env.from.slice("did:key:".length));
      if (!(await verifyMessage(body, senderPub))) {
        return new Response("{}", { status: 401 });
      }
      const auth = await verifyInkAuth({
        authHeader: (init?.headers as Record<string, string>)?.Authorization,
        method: "POST",
        path: url.pathname,
        recipientAgentId: recipient.did,
        body,
        resolvePublicKey: (id) =>
          id.startsWith("did:key:") ? decodePublicKeyMultibase(id.slice("did:key:".length)) : null,
        nonceStore,
      });
      return new Response(JSON.stringify({ ok: auth.valid }), {
        status: auth.valid ? 200 : 401,
      });
    }) as typeof fetch;

    const lines: string[] = [];
    const code = await runCli(
      ["--to", recipient.did, "--endpoint", "https://ink-echo.tulpa.network/ink/v1/inbound", "--note", "hi"],
      { log: (l) => lines.push(l), env: {}, fetchImpl },
    );
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("delivered: status 200");
  });
});
