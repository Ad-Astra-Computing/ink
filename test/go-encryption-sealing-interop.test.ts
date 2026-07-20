import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decryptInkPayload, base64urlEncode, hexToBytes, jcsCanonicalize } from "../src/index.js";

// Reverse cross-implementation interop for payload encryption (gap-4 slice 2).
// The Go sealer PRODUCES an INK ECIES envelope; the TypeScript reference
// decryptInkPayload OPENS it. The decrypt direction (TS seals, Go decrypts) is
// already covered by the payload-encryption conformance corpus and go/ink's own
// decrypt tests; this proves the OTHER half of the wire contract: a ciphertext
// sealed by independent Go code is accepted by the reference decrypter, and the
// AAD the Go sealer binds is byte-identical to the AAD the reference builds. The
// two share no crypto code, only bytes.

const GO_DIR = fileURLToPath(new URL("../go", import.meta.url).href);

// RFC 7748 §6.1 recipient (Alice): the public key drives the Go seal, the
// private key drives the reference decrypt.
const RECIPIENT_PUB_HEX = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const RECIPIENT_PRIV_HEX = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

const SENDER = "did:web:sender.example";
const RECIPIENT = "did:web:recipient.example";
const TIMESTAMP = "2026-07-11T12:00:00.000Z";
const MESSAGE_NONCE = "0123456789abcdef0123456789abcdef";

const goAvailable = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;

// Skip only for a local developer with no Go toolchain. Under CI this is a hard
// requirement: skipping there would let the job go green without exercising the
// Go sealer at all.
const skipSuite = !goAvailable && !process.env.CI;

interface SealResult {
  envelope: {
    protocol: "ink/0.1";
    type: "network.tulpa.encrypted" | "network.ink.encrypted";
    from: string;
    ephemeralKey: string;
    nonce: string;
    ciphertext: string;
    timestamp: string;
    messageNonce: string;
  };
}

describe.skipIf(skipSuite)("Go seals an ECIES payload, TypeScript reference decrypts", () => {
  let binDir: string;
  let bin: string;

  beforeAll(() => {
    binDir = mkdtempSync(join(tmpdir(), "ink-seal-"));
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

  // Run `ink seal-payload` with the request JSON on stdin and return the parsed
  // sealed result.
  function goSeal(request: unknown): SealResult {
    const res = spawnSync(bin, ["seal-payload"], {
      input: JSON.stringify(request),
      encoding: "utf8",
    });
    expect(res.status, res.stderr).toBe(0);
    return JSON.parse(res.stdout) as SealResult;
  }

  it("decrypts a freshly Go-sealed envelope back to the exact plaintext", async () => {
    const sealed = goSeal({
      recipientPublicKeyHex: RECIPIENT_PUB_HEX,
      senderDid: SENDER,
      timestamp: TIMESTAMP,
      messageNonce: MESSAGE_NONCE,
      plaintext: { from: SENDER, to: RECIPIENT, body: "hello", count: 7 },
      messageType: "network.ink.encrypted",
    });

    const decrypted = await decryptInkPayload(sealed.envelope, RECIPIENT_PRIV_HEX, RECIPIENT);
    expect(decrypted.from).toBe(SENDER);
    expect(decrypted.to).toBe(RECIPIENT);
    expect(decrypted.body).toBe("hello");
    expect(decrypted.count).toBe(7);

    // Binding check: tamper an AAD-bound outer field and the reference rejects,
    // so the acceptance above is tag-bound, not shape-only.
    const tampered = { ...sealed.envelope, timestamp: "2026-07-11T12:00:01.000Z" };
    await expect(decryptInkPayload(tampered, RECIPIENT_PRIV_HEX, RECIPIENT)).rejects.toThrow();

    // A different recipient private key does not open the Go-sealed ciphertext.
    const wrongPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    await expect(decryptInkPayload(sealed.envelope, wrongPrivHex, RECIPIENT)).rejects.toThrow();
  });

  it("builds an AAD byte-identical to the Go sealer (member set + JCS ordering pin)", () => {
    // The Go sealer draws a random ephemeral key and nonce, so its ciphertext is
    // non-deterministic and the AAD member set / ordering cannot be pinned off a
    // live envelope. Instead both implementations anchor to one fixed AAD literal
    // built from the same fixed field values. The Go side pins these exact bytes
    // in go/ink/encryption_test.go (TestEncryptInkPayloadAADPin) via its single
    // inkEncryptAAD builder; asserting the same literal here proves the reference
    // domain prefix, JCS member ordering, and base64url encodings agree with Go.
    // That the two AAD constructions also agree for ARBITRARY random field values
    // is what the round-trip decrypt above proves (a mismatch would fail the tag).
    const ephemeralKey = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";
    const nonce = "AQIDBAUGBwgJCgsM";
    // recipientKey is base64url of the recipient static X25519 public key, exactly
    // as both the Go sealer and the reference decrypter compute it.
    const recipientKey = base64urlEncode(hexToBytes(RECIPIENT_PUB_HEX));
    expect(recipientKey).toBe("hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo");

    const aadObject = {
      protocol: "ink/0.1",
      type: "network.ink.encrypted",
      from: SENDER,
      recipientKey,
      ephemeralKey,
      nonce,
      timestamp: TIMESTAMP,
      messageNonce: MESSAGE_NONCE,
    };
    const aad = `ink/0.1:envelope\n${jcsCanonicalize(aadObject)}`;

    const WANT_AAD =
      "ink/0.1:envelope\n" +
      '{"ephemeralKey":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",' +
      '"from":"did:web:sender.example",' +
      '"messageNonce":"0123456789abcdef0123456789abcdef",' +
      '"nonce":"AQIDBAUGBwgJCgsM",' +
      '"protocol":"ink/0.1",' +
      '"recipientKey":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",' +
      '"timestamp":"2026-07-11T12:00:00.000Z",' +
      '"type":"network.ink.encrypted"}';
    expect(aad).toBe(WANT_AAD);
  });
});
