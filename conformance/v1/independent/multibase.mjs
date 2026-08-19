// base58btc multibase and the Ed25519 multicodec prefix, written from the
// multibase and multicodec tables rather than from `src/` or a base58 library.
// The corpus must not be produced by the implementation it validates, and a
// wrong multibase encoding would change every agentId in it.

// The Bitcoin base58 alphabet, as multibase prefix `z` selects.
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));

// multicodec: ed25519-pub is 0xed, varint-encoded as the two bytes 0xed 0x01.
const ED25519_PUB = Uint8Array.from([0xed, 0x01]);

export function base58Decode(text) {
  let n = 0n;
  for (const ch of text) {
    const digit = INDEX.get(ch);
    if (digit === undefined)
      throw new Error(
        `base58: character ${JSON.stringify(ch)} is not in the alphabet`,
      );
    n = n * 58n + BigInt(digit);
  }
  const body = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  // A leading '1' is the zero digit and encodes one leading zero byte, which
  // the bigint conversion above cannot represent.
  let leadingZeros = 0;
  for (const ch of text) {
    if (ch !== "1") break;
    leadingZeros++;
  }
  return Uint8Array.from([...new Array(leadingZeros).fill(0), ...body]);
}

export function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }
  return "1".repeat(leadingZeros) + out;
}

// A public key multibase is `z` + base58btc(0xed 0x01 || rawKey).
export function decodePublicKeyMultibase(mb) {
  if (typeof mb !== "string" || !mb.startsWith("z")) {
    throw new Error(
      "public key multibase must start with the base58btc prefix `z`",
    );
  }
  const raw = base58Decode(mb.slice(1));
  if (
    raw.length !== 34 ||
    raw[0] !== ED25519_PUB[0] ||
    raw[1] !== ED25519_PUB[1]
  ) {
    throw new Error(
      "public key multibase is not a 32-byte ed25519-pub multicodec",
    );
  }
  return raw.slice(2);
}

export function encodePublicKeyMultibase(rawKey) {
  if (rawKey.length !== 32)
    throw new Error("ed25519 public key must be 32 bytes");
  return "z" + base58Encode(Uint8Array.from([...ED25519_PUB, ...rawKey]));
}
