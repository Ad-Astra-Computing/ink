/**
 * The decrypted inner envelope goes through the signed-body byte rules.
 *
 * The plaintext is AES-GCM authenticated, so it came from the sender. That is
 * a fact about origin, not about wire form: the inner envelope carries its own
 * body signature, verified over the bytes the signer signed, and a lenient
 * parse admits forms no signer produced. Go runs `ParseSignedObject` here, and
 * these tests hold the reference to the same four rules.
 *
 * `encryptInkPayload` cannot mint any of these plaintexts, because it takes an
 * object and serializes it, so the hostile bytes are sealed by a test sealer
 * written to the spec's §3.4 derivation. A positive control proves that sealer
 * and the library agree on key derivation and AAD, so a rejection below is the
 * parse gate and nothing else.
 */
import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  encryptInkPayload,
  decryptInkPayload,
  base64urlEncode,
  bytesToHex,
  jcsCanonicalize,
  type InkEncryptedEnvelope,
} from "../src/crypto/ink.js";
import { ParseSignedBodyError } from "../src/crypto/parse-signed-body.js";

const SENDER = "did:web:sender.example";
const RECIPIENT = "did:web:recipient.example";
const TS = "2026-07-11T12:00:00.000Z";
const NONCE = "0123456789abcdef0123456789abcdef";
const HEAD = `{"from":"${SENDER}","to":"${RECIPIENT}",`;

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function sealRaw(
  plaintext: Uint8Array,
): Promise<{ envelope: InkEncryptedEnvelope; privHex: string }> {
  const recipientPriv = crypto.getRandomValues(new Uint8Array(32));
  const recipientPub = x25519.getPublicKey(recipientPriv);
  const ephPriv = crypto.getRandomValues(new Uint8Array(32));
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const keyBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: utf8("ink/0.1"), info: utf8("ink/0.1/encrypt") },
    hkdfKey,
    256,
  );
  const aesKey = await crypto.subtle.importKey("raw", keyBits, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const type = "network.ink.encrypted";
  const ephemeralKey = base64urlEncode(ephPub);
  const nonceStr = base64urlEncode(nonce);
  const aad = utf8(
    `ink/0.1:envelope\n${jcsCanonicalize({
      protocol: "ink/0.1",
      type,
      from: SENDER,
      recipientKey: base64urlEncode(recipientPub),
      ephemeralKey,
      nonce: nonceStr,
      timestamp: TS,
      messageNonce: NONCE,
    })}`,
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aesKey, plaintext),
  );
  return {
    envelope: {
      protocol: "ink/0.1",
      type,
      from: SENDER,
      ephemeralKey,
      nonce: nonceStr,
      ciphertext: base64urlEncode(ciphertext),
      timestamp: TS,
      messageNonce: NONCE,
    },
    privHex: bytesToHex(recipientPriv),
  };
}

describe("decryptInkPayload runs the signed-body rules on the plaintext", () => {
  it("positive control: the test sealer and the library agree", async () => {
    const inner = { from: SENDER, to: RECIPIENT, x: 1 };
    const raw = await sealRaw(utf8(JSON.stringify(inner)));
    await expect(decryptInkPayload(raw.envelope, raw.privHex, RECIPIENT)).resolves.toEqual(inner);

    const priv = crypto.getRandomValues(new Uint8Array(32));
    const { envelope } = await encryptInkPayload(
      inner, SENDER, bytesToHex(x25519.getPublicKey(priv)), TS, NONCE,
      { messageType: "network.ink.encrypted", recipientDid: RECIPIENT },
    );
    await expect(decryptInkPayload(envelope, bytesToHex(priv), RECIPIENT)).resolves.toEqual(inner);
  });

  const cases: Array<{ name: string; plaintext: Uint8Array; reason: string }> = [
    {
      name: "invalid UTF-8 in a string value",
      plaintext: concat(utf8(HEAD + `"x":"`), new Uint8Array([0xff]), utf8(`"}`)),
      reason: "utf8",
    },
    {
      name: "a lone surrogate escape",
      plaintext: utf8(HEAD + `"x":"\\ud800"}`),
      reason: "surrogate",
    },
    {
      name: "an escaped object member name",
      plaintext: utf8(HEAD + `"\\u0078":1}`),
      reason: "member-name-escape",
    },
    {
      name: "an out-of-range number literal shadowed by a duplicate member",
      plaintext: utf8(HEAD + `"n":1e309,"n":1}`),
      reason: "number-range",
    },
  ];

  for (const c of cases) {
    it(`rejects ${c.name} with ParseSignedBodyError(${c.reason})`, async () => {
      const { envelope, privHex } = await sealRaw(c.plaintext);
      const err = await decryptInkPayload(envelope, privHex, RECIPIENT).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(ParseSignedBodyError);
      expect((err as ParseSignedBodyError).reason).toBe(c.reason);
    });
  }

  it("rejects a BOM-prefixed plaintext instead of stripping the BOM", async () => {
    const { envelope, privHex } = await sealRaw(
      concat(new Uint8Array([0xef, 0xbb, 0xbf]), utf8(HEAD + `"x":1}`)),
    );
    await expect(decryptInkPayload(envelope, privHex, RECIPIENT)).rejects.toThrow(SyntaxError);
  });

  it("still throws SyntaxError for malformed JSON", async () => {
    const { envelope, privHex } = await sealRaw(utf8(HEAD + `"x":`));
    await expect(decryptInkPayload(envelope, privHex, RECIPIENT)).rejects.toThrow(SyntaxError);
  });

  it("still rejects a non-object root with the existing message", async () => {
    const { envelope, privHex } = await sealRaw(utf8(`[1]`));
    await expect(decryptInkPayload(envelope, privHex, RECIPIENT)).rejects.toThrow(
      /Inner envelope must be a JSON object/,
    );
  });
});
