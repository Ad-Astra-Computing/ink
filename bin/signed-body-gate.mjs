/**
 * The signed-body text gate, self-contained.
 *
 * `bin/` is published so its shebang resolves on any supported Node install
 * without a TypeScript toolchain, and a git checkout has no `dist/` until
 * someone builds it, so the CLI cannot import the library's copy of these
 * scanners. It carries its own.
 *
 * A second copy is exactly the drift that this release fixed elsewhere, so it
 * is not left to care: `test/bin-gate-parity.test.ts` runs the library's
 * scanners and these against one shared table and fails if they ever disagree.
 * Change one, change the other, or the test says so.
 *
 * The rules and their rationale live in `specs/ink-signed-string-safety.md`.
 */

const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The stable discriminator, matching `ParseSignedBodyReason` in the library. */
export class SignedBodyGateError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = "SignedBodyGateError";
    this.reason = reason;
  }
}

function parseHex4(s, idx) {
  if (idx + 4 > s.length) return null;
  let v = 0;
  for (let k = 0; k < 4; k++) {
    const d = s.charCodeAt(idx + k);
    v <<= 4;
    if (d >= 0x30 && d <= 0x39) v |= d - 0x30;
    else if (d >= 0x61 && d <= 0x66) v |= d - 0x61 + 10;
    else if (d >= 0x41 && d <= 0x46) v |= d - 0x41 + 10;
    else return null;
  }
  return v;
}

/** Mirrors `containsLoneSurrogateEscape` in src/crypto/surrogate.ts. */
export function containsLoneSurrogateEscape(raw) {
  let inString = false;
  const n = raw.length;
  for (let i = 0; i < n; ) {
    const c = raw.charCodeAt(i);
    if (!inString) {
      if (c === 0x22) inString = true;
      i++;
      continue;
    }
    if (c === 0x22) {
      inString = false;
      i++;
      continue;
    }
    if (c !== 0x5c) {
      i++;
      continue;
    }
    if (i + 1 >= n) return false;
    if (raw.charCodeAt(i + 1) !== 0x75) {
      i += 2;
      continue;
    }
    const hi = parseHex4(raw, i + 2);
    if (hi === null) {
      i += 2;
      continue;
    }
    if (hi >= 0xdc00 && hi <= 0xdfff) return true;
    if (hi >= 0xd800 && hi <= 0xdbff) {
      const j = i + 6;
      if (j + 1 < n && raw.charCodeAt(j) === 0x5c && raw.charCodeAt(j + 1) === 0x75) {
        const lo = parseHex4(raw, j + 2);
        if (lo !== null && lo >= 0xdc00 && lo <= 0xdfff) {
          i = j + 6;
          continue;
        }
      }
      return true;
    }
    i += 6;
  }
  return false;
}

/** Mirrors `containsOutOfRangeNumberLiteral` in src/crypto/number-literal.ts. */
function isNumberStart(c) {
  return (c >= 0x30 && c <= 0x39) || c === 0x2d;
}

function isNumberChar(c) {
  return (
    (c >= 0x30 && c <= 0x39) ||
    c === 0x2d || // -
    c === 0x2b || // +
    c === 0x2e || // .
    c === 0x65 || // e
    c === 0x45 // E
  );
}

export function containsOutOfRangeNumberLiteral(raw) {
  let inString = false;
  const n = raw.length;
  for (let i = 0; i < n; ) {
    const c = raw.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) {
        i += 2;
        continue;
      }
      if (c === 0x22) inString = false;
      i++;
      continue;
    }
    if (c === 0x22) {
      inString = true;
      i++;
      continue;
    }
    if (!isNumberStart(c)) {
      i++;
      continue;
    }
    let j = i + 1;
    while (j < n && isNumberChar(raw.charCodeAt(j))) j++;
    const value = Number(raw.slice(i, j));
    if (!Number.isNaN(value) && !Number.isFinite(value)) return true;
    i = j;
  }
  return false;
}

/** Mirrors `containsEscapedMemberName` in src/crypto/member-name.ts. */
export function containsEscapedMemberName(raw) {
  const n = raw.length;
  for (let i = 0; i < n; i++) {
    if (raw.charCodeAt(i) !== 0x22) continue;
    let sawEscape = false;
    let j = i + 1;
    for (; j < n; j++) {
      const c = raw.charCodeAt(j);
      if (c === 0x5c) {
        sawEscape = true;
        j++;
        continue;
      }
      if (c === 0x22) break;
    }
    if (j >= n) return false;
    if (sawEscape) {
      let k = j + 1;
      while (k < n) {
        const w = raw.charCodeAt(k);
        if (w === 0x20 || w === 0x09 || w === 0x0a || w === 0x0d) {
          k++;
          continue;
        }
        break;
      }
      if (k < n && raw.charCodeAt(k) === 0x3a) return true;
    }
    i = j;
  }
  return false;
}

/** Mirrors `parseSignedBodyBytes` in src/crypto/parse-signed-body.ts. */
export function parseSignedBodyBytes(bytes) {
  let text;
  try {
    text = fatalUtf8Decoder.decode(bytes);
  } catch {
    throw new SignedBodyGateError("utf8", "signed body is not valid UTF-8");
  }
  if (containsLoneSurrogateEscape(text)) {
    throw new SignedBodyGateError("surrogate", "signed body contains an unpaired UTF-16 surrogate");
  }
  if (containsOutOfRangeNumberLiteral(text)) {
    throw new SignedBodyGateError(
      "number-range",
      "signed body contains a number literal outside the IEEE-754 double range",
    );
  }
  if (containsEscapedMemberName(text)) {
    throw new SignedBodyGateError(
      "member-name-escape",
      "signed body contains an object member name written with an escape sequence",
    );
  }
  return JSON.parse(text);
}
