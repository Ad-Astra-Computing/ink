import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { verifyInkSignature } from "../src/index.js";

// Reverse cross-implementation interop for transport signing (gap-4 slice 1).
// The Go signer PRODUCES an INK request signature and Authorization header; the
// TypeScript reference verifier CHECKS the same bytes. The verify direction (TS
// signs, Go verifies) is already covered by the signature-base conformance
// vectors; this proves the OTHER half of the wire contract: a signature minted
// by independent Go code is accepted by the reference, and the header it emits
// parses with the reference grammar. The two share no code, only bytes.

const GO_DIR = fileURLToPath(new URL("../go", import.meta.url).href);

// The reference Authorization-header grammar from ink-protocol.md §3.3 and
// src/middleware/ink-auth.ts. A Go-built header MUST parse with it.
const AUTH_HEADER_RE = /^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$/;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const goAvailable = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;

// Skip only for a local developer with no Go toolchain. Under CI this is a hard
// requirement: skipping there would let the job go green without exercising the
// Go signer at all.
const skipSuite = !goAvailable && !process.env.CI;

interface SignedRequest {
  base: string;
  signature: string;
  authHeader: string;
  publicKeyHex: string;
  signInput: {
    method: string;
    path: string;
    recipientDid: string;
    body: Record<string, unknown>;
    timestamp: string;
  };
}

describe.skipIf(skipSuite)("Go signs a transport request, TypeScript reference verifies", () => {
  let binDir: string;
  let bin: string;

  beforeAll(() => {
    binDir = mkdtempSync(join(tmpdir(), "ink-sign-"));
    bin = join(binDir, "ink");
    const build = spawnSync("go", ["build", "-o", bin, "./cmd/ink"], {
      cwd: GO_DIR,
      encoding: "utf8",
    });
    if (build.status !== 0) {
      throw new Error(`go build failed: ${build.stderr || build.stdout}`);
    }
  }, 60_000);

  afterAll(() => {
    if (binDir) rmSync(binDir, { recursive: true, force: true });
  });

  // Run `ink sign-request` with the request JSON on stdin and return the parsed
  // signed result.
  function goSign(request: unknown): SignedRequest {
    const res = spawnSync(bin, ["sign-request"], {
      input: JSON.stringify(request),
      encoding: "utf8",
    });
    expect(res.status, res.stderr).toBe(0);
    return JSON.parse(res.stdout) as SignedRequest;
  }

  it("accepts a freshly Go-signed request and its Authorization header", async () => {
    // A fresh random seed drives the Go signer; the reference verifier derives
    // the matching public key from the same 32-byte seed (a @noble secret key is
    // exactly the Ed25519 seed Go's NewKeyFromSeed expects), so the two agree on
    // the key without exchanging an encoding.
    const seed = ed.utils.randomSecretKey();
    const publicKey = await ed.getPublicKeyAsync(seed);

    const signInput = {
      method: "POST",
      path: "/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent",
      recipientDid: "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
      // Members out of canonical order so a passing signature also proves the
      // signer canonicalizes (JCS) the body before signing.
      body: { protocol: "ink/0.1", intent: "ping", payload: { scope: "deep", note: "hello" } },
      timestamp: "2026-06-11T00:00:00.000Z",
    };

    const signed = goSign({ privateKeyHex: hex(seed), signInput, keyId: "key-2026" });

    // The Go signer derived the public key we expect from the seed.
    expect(signed.publicKeyHex).toBe(hex(publicKey));

    // The header parses with the reference grammar and carries the signature.
    const m = signed.authHeader.match(AUTH_HEADER_RE);
    expect(m, `header did not match grammar: ${signed.authHeader}`).not.toBeNull();
    expect(m![1]).toBe(signed.signature);
    expect(m![2]).toBe("key-2026");

    // The reference verifier accepts the Go-produced signature over the request.
    const ok = await verifyInkSignature(signed.signInput, signed.signature, publicKey);
    expect(ok).toBe(true);

    // Binding check: the verifier rejects the same signature against a tampered
    // body, so the acceptance above is signature-bound, not shape-only.
    const tampered = { ...signed.signInput, body: { ...signed.signInput.body, intent: "pong" } };
    expect(await verifyInkSignature(tampered, signed.signature, publicKey)).toBe(false);
  });

  it("matches the byte-exact cross-implementation pin", async () => {
    // The same fixed seed, request, and expected signature asserted in the Go
    // test (go/ink/sign_test.go TestSignatureBaseBytesPinned). Pinning both
    // sides to one wire value catches any drift in the signature base or the
    // Ed25519/base64url encoding on either implementation.
    const seedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const wantPublicKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const wantSignature =
      "4coNdBbBjKh6blEoMVuKMb7-emCrKNFPhbuuj6UGtZkK_xCN53_06hWqo4u1oFCf7lUo9XUuBHi6Z2tRZxwlBA";

    const signInput = {
      method: "POST",
      path: "/ink/v1/tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX/intent",
      recipientDid: "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
      body: { protocol: "ink/0.1", intent: "ping", payload: { note: "hello", scope: "deep" } },
      timestamp: "2026-06-11T00:00:00.000Z",
    };

    const signed = goSign({ privateKeyHex: seedHex, signInput, keyId: "key-2026" });
    expect(signed.publicKeyHex).toBe(wantPublicKeyHex);
    expect(signed.signature).toBe(wantSignature);

    const publicKey = Uint8Array.from(Buffer.from(wantPublicKeyHex, "hex"));
    expect(await verifyInkSignature(signInput, wantSignature, publicKey)).toBe(true);
  });
});
