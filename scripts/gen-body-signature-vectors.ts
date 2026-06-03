/**
 * Regenerate test-vectors/body-signature.json.
 *
 * The body message signature is computed over `<domain>\n` + JCS(body),
 * where the domain is selected from the signed `protocol` field
 * (src/crypto/sign.ts): ink/0.2 -> "ink/sign\n", ink/0.1 and any other
 * value -> "tulpa/sign\n". These vectors pin that, plus the cross-version
 * and tamper cases, so any implementation can confirm it matches the wire
 * contract without trusting this code.
 *
 * Run: npx tsx scripts/gen-body-signature-vectors.ts
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as ed from "@noble/ed25519";
import { signMessage, base64urlEncode, jcsCanonicalize } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, "..", "test-vectors", "body-signature.json");

// Fixed seed so the vectors are stable across runs.
const SEED = new Uint8Array(32);
for (let i = 0; i < 32; i++) SEED[i] = i + 1;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Sign a body under an EXPLICIT domain, bypassing the version-keyed
 * selection in signMessage. Used to forge the negative vectors that catch
 * a verifier which wrongly tries the wrong (or both) domains.
 */
async function signUnderDomain(
  body: Record<string, unknown>,
  privateKey: Uint8Array,
  domain: string,
): Promise<string> {
  const { signature: _drop, ...unsigned } = body;
  const canonical = jcsCanonicalize(unsigned);
  if (canonical === undefined) throw new Error("canonicalize failed");
  const bytes = new TextEncoder().encode(`${domain}${canonical}`);
  return base64urlEncode(await ed.signAsync(bytes, privateKey));
}

const baseBody = (protocol: string): Record<string, unknown> => ({
  protocol,
  id: "01HVECTORID0000000000000000",
  from: "did:key:zAlice",
  to: "did:key:zBob",
  intent: "connection_request",
  payload: { method: "discovery" },
  timestamp: "2026-06-03T00:00:00Z",
  nonce: "ZmtmaXhlZG5vbmNl",
});

async function main(): Promise<void> {
  const privateKey = SEED;
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const signerPublicKeyHex = hex(publicKey);

  const body01 = baseBody("ink/0.1");
  const sig01 = await signMessage(body01, privateKey);

  const body02 = baseBody("ink/0.2");
  const sig02 = await signMessage(body02, privateKey);

  const bodyNoProto = (() => {
    const b = baseBody("ink/0.1");
    delete (b as Record<string, unknown>).protocol;
    return b;
  })();
  const sigNoProto = await signMessage(bodyNoProto, privateKey);

  // ink/0.2 body, but signed under the LEGACY domain. The exact v0.2 body
  // is unchanged, so this is only rejected by a verifier that selects a
  // single domain from the protocol version. A verifier that tried both
  // domains would wrongly accept it. This is the key replay-resistance
  // vector.
  const sig02UnderLegacy = await signUnderDomain(body02, privateKey, "tulpa/sign\n");

  // An unknown protocol string uses the legacy domain at the body-signature
  // layer (the raw verifier is permissive; the envelope schema separately
  // rejects unknown versions). Signed under the legacy domain, it verifies.
  const bodyUnknown = baseBody("ink/0.3");
  const sigUnknownLegacy = await signUnderDomain(bodyUnknown, privateKey, "tulpa/sign\n");

  const vectors = [
    {
      description: "ink/0.1 body signed under the legacy tulpa/sign domain verifies",
      input: { body: { ...body01, signature: sig01 }, signerPublicKeyHex },
      expected: { signatureVerifies: true },
    },
    {
      description: "ink/0.2 body signed under the ink/sign domain verifies",
      input: { body: { ...body02, signature: sig02 }, signerPublicKeyHex },
      expected: { signatureVerifies: true },
    },
    {
      description: "protocol-less body signed under the legacy domain verifies",
      input: { body: { ...bodyNoProto, signature: sigNoProto }, signerPublicKeyHex },
      expected: { signatureVerifies: true },
    },
    {
      description: "ink/0.2 body relabelled ink/0.1 (domain mismatch) does not verify",
      input: { body: { ...body02, protocol: "ink/0.1", signature: sig02 }, signerPublicKeyHex },
      expected: { signatureVerifies: false },
    },
    {
      description: "ink/0.1 body relabelled ink/0.2 (domain mismatch) does not verify",
      input: { body: { ...body01, protocol: "ink/0.2", signature: sig01 }, signerPublicKeyHex },
      expected: { signatureVerifies: false },
    },
    {
      description: "ink/0.2 body with protocol removed (falls back to legacy domain) does not verify",
      input: { body: { ...body02, protocol: undefined, signature: sig02 }, signerPublicKeyHex },
      expected: { signatureVerifies: false },
    },
    {
      description: "ink/0.1 body with a flipped payload field does not verify",
      input: { body: { ...body01, payload: { method: "qr" }, signature: sig01 }, signerPublicKeyHex },
      expected: { signatureVerifies: false },
    },
    {
      description: "ink/0.2 body signed under the legacy domain does not verify (a verifier must not try both domains)",
      input: { body: { ...body02, signature: sig02UnderLegacy }, signerPublicKeyHex },
      expected: { signatureVerifies: false },
    },
    {
      description: "unknown protocol string uses the legacy body-signature domain and verifies",
      input: { body: { ...bodyUnknown, signature: sigUnknownLegacy }, signerPublicKeyHex },
      expected: { signatureVerifies: true },
    },
  ].map((v) => {
    // JSON has no `undefined`; drop those keys so the file is clean and a
    // consumer reads a body that genuinely lacks the field.
    const body = Object.fromEntries(
      Object.entries(v.input.body).filter(([, value]) => value !== undefined),
    );
    return { ...v, input: { ...v.input, body } };
  });

  const doc = {
    description:
      "INK body message signature: domain is keyed off the signed protocol field (ink/0.2 -> ink/sign, else tulpa/sign). Verify each body with the signer public key; signatureVerifies is the expected verifyMessage result.",
    vectors,
  };

  writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n", "utf-8");
  process.stdout.write(`wrote ${vectors.length} vectors to ${outPath}\n`);
}

main().catch((err) => {
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});
