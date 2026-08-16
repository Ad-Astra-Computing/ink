/**
 * Regenerate test-vectors/body-signature.json and the Go producer goldens in
 * go/ink/testdata/body-signature-producer.json.
 *
 * The body message signature is computed over `<domain>\n` + JCS(body),
 * where the domain is selected from the signed `protocol` field
 * (src/crypto/sign.ts): ink/0.2 -> "ink/sign\n", ink/0.1 and any other
 * value -> "tulpa/sign\n". These vectors pin that, plus the cross-version
 * and tamper cases, so any implementation can confirm it matches the wire
 * contract without trusting this code.
 *
 * The verify-side vectors pin what a verifier must accept and reject. The
 * producer goldens pin the other half: the exact base64url signature this
 * reference emits for a given body, so a second implementation's signer can be
 * compared byte for byte instead of only round-tripping against itself. They are
 * written as Go testdata because the manifest-governed corpus in conformance/v1
 * has no body-signature category, and adding one is a profile decision, not a
 * side effect of a producer fix.
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
const goGoldenPath = join(here, "..", "go", "ink", "testdata", "body-signature-producer.json");

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

  await writeGoProducerGoldens(privateKey, signerPublicKeyHex);
}

/**
 * Producer goldens for the Go body signer: the exact signature this reference
 * emits for each body. A second implementation reproduces them only if its
 * canonicalization, its domain selection and its `signature`-stripping all agree
 * with this one, so byte equality is the cross-implementation proof.
 *
 * The cases deliberately reach past a plain ASCII envelope: JCS member ordering
 * is by UTF-16 code unit, which is NOT the same order as UTF-8 byte comparison
 * once a non-BMP key meets a BMP key above the surrogate range; string escaping
 * is minimal (only the short escapes and \u00XX controls); and numbers are the
 * safe-integer profile including the range edges.
 */
async function writeGoProducerGoldens(
  privateKey: Uint8Array,
  signerPublicKeyHex: string,
): Promise<void> {
  const cases: { description: string; body: Record<string, unknown> }[] = [
    {
      description: "ink/0.1 intent envelope, the legacy tulpa/sign domain",
      body: baseBody("ink/0.1"),
    },
    {
      description: "ink/0.2 intent envelope, the neutral ink/sign domain",
      body: baseBody("ink/0.2"),
    },
    {
      description: "body with no protocol member falls back to the legacy domain",
      body: (() => {
        const b = baseBody("ink/0.1");
        delete b.protocol;
        return b;
      })(),
    },
    {
      description: "unknown protocol string selects the legacy domain",
      body: baseBody("ink/0.3"),
    },
    {
      description: "a stale signature member is stripped before canonicalization",
      body: { ...baseBody("ink/0.1"), signature: "A".repeat(86) },
    },
    {
      description:
        "JCS member ordering by UTF-16 code unit, where a non-BMP key sorts BEFORE a BMP key above the surrogate range",
      // The discriminating pair is "\u{1F511}" (U+1F511, encoded UTF-16 as the
      // surrogates D83D DD11) and "Ａ" (U+FF21, a single code unit above the
      // surrogate range). Sorting by UTF-16 code unit puts D83D before FF21;
      // comparing the UTF-8 encodings byte for byte puts EF BC A1 before
      // F0 9F 94 91, the opposite order. An implementation that sorted members
      // by raw bytes instead of code units therefore emits different canonical
      // bytes for this body and cannot reproduce the golden signature.
      body: {
        protocol: "ink/0.2",
        "\u{1F511}": "non-BMP key, sorts before U+FF21 by code unit and after it by UTF-8 bytes",
        "Ａ": "BMP key above the surrogate range",
        "é": "e-acute",
        z: "ascii z",
        a: "ascii a",
        Z: "ascii capital Z",
      },
    },
    {
      description: "minimal string escaping: quote, backslash, short escapes and a control char",
      body: {
        protocol: "ink/0.2",
        quote: 'a "quoted" value',
        backslash: "a\\b",
        shorts: "\b\t\n\f\r",
        control: "\u0001\u001f",
        astral: "an astral char \u{1F680} kept as-is",
        solidus: "a/b",
      },
    },
    {
      description: "safe-integer number profile at both range edges, with nesting and null",
      body: {
        protocol: "ink/0.2",
        zero: 0,
        negative: -1,
        max: Number.MAX_SAFE_INTEGER,
        min: -Number.MAX_SAFE_INTEGER,
        nested: { list: [1, 2, { deep: [true, false, null] }], empty: [] },
        emptyObject: {},
      },
    },
  ];

  const signed = [];
  for (const c of cases) {
    signed.push({ ...c, signature: await signMessage(c.body, privateKey) });
  }

  const doc = {
    description:
      "Producer goldens for the INK body message signature, emitted by the TypeScript reference signMessage (src/crypto/sign.ts). A second implementation's signer MUST reproduce `signature` byte for byte for each `body`. Generated by scripts/gen-body-signature-vectors.ts; do not hand-edit.",
    signerPrivateKeySeedHex: hex(privateKey),
    signerPublicKeyHex,
    cases: signed,
  };

  writeFileSync(goGoldenPath, JSON.stringify(doc, null, 2) + "\n", "utf-8");
  process.stdout.write(`wrote ${signed.length} producer goldens to ${goGoldenPath}\n`);
}

main().catch((err) => {
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});
