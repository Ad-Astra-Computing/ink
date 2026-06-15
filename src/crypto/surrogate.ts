/**
 * Lone UTF-16 surrogate detection for signed INK bodies.
 *
 * A signed body string may contain a lone surrogate (a high D800-DBFF not
 * immediately followed by a low DC00-DFFF, or a lone low), which in JSON can
 * only appear as a `\uXXXX` escape because UTF-8 cannot encode a surrogate as
 * raw bytes. Go's `encoding/json` silently replaces a lone surrogate with
 * U+FFFD at parse time, so a body that reached canonicalization would be signed
 * over different bytes than an implementation that preserves the surrogate. INK
 * therefore bans lone surrogates in signed bodies: a receiver rejects them on
 * the raw JSON text before parsing, and a signer rejects them in the object
 * before canonicalization.
 */

function parseHex4(s: string, idx: number): number | null {
  if (idx + 4 > s.length) return null;
  let v = 0;
  for (let k = 0; k < 4; k++) {
    const d = s.charCodeAt(idx + k);
    v <<= 4;
    if (d >= 0x30 && d <= 0x39) v |= d - 0x30; // 0-9
    else if (d >= 0x61 && d <= 0x66) v |= d - 0x61 + 10; // a-f
    else if (d >= 0x41 && d <= 0x46) v |= d - 0x41 + 10; // A-F
    else return null;
  }
  return v;
}

/**
 * Whether raw JSON text contains a `\uXXXX` escape for an unpaired UTF-16
 * surrogate inside any JSON string. Operates on the raw text (not the parsed
 * value) so the check is independent of how a runtime decodes surrogates. A
 * backslash escapes the next character, so a literal `\\uD800` is never read as
 * a Unicode escape.
 */
export function containsLoneSurrogateEscape(raw: string): boolean {
  let inString = false;
  const n = raw.length;
  for (let i = 0; i < n; ) {
    const c = raw.charCodeAt(i);
    if (!inString) {
      if (c === 0x22) inString = true; // "
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
      continue; // not a backslash
    }
    if (i + 1 >= n) return false; // truncated escape; invalid JSON
    if (raw.charCodeAt(i + 1) !== 0x75) {
      i += 2; // \\, \", \n, etc.
      continue;
    }
    const hi = parseHex4(raw, i + 2);
    if (hi === null) {
      i += 2; // malformed \u escape; the JSON parser will reject it
      continue;
    }
    if (hi >= 0xdc00 && hi <= 0xdfff) return true; // lone low
    if (hi >= 0xd800 && hi <= 0xdbff) {
      const j = i + 6;
      if (j + 1 < n && raw.charCodeAt(j) === 0x5c && raw.charCodeAt(j + 1) === 0x75) {
        const lo = parseHex4(raw, j + 2);
        if (lo !== null && lo >= 0xdc00 && lo <= 0xdfff) {
          i = j + 6; // valid pair
          continue;
        }
      }
      return true; // high not immediately followed by a low
    }
    i += 6;
  }
  return false;
}

function stringHasUnpairedSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++; // valid pair
        continue;
      }
      return true; // lone high
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true; // lone low
  }
  return false;
}

/**
 * Whether a parsed value contains an unpaired UTF-16 surrogate in any string
 * value or object key. Used on the signer side, where the body is an object
 * rather than raw text; a lone surrogate here would serialize as a `\uXXXX`
 * escape the receiver rejects.
 */
export function hasUnpairedSurrogate(value: unknown): boolean {
  if (typeof value === "string") return stringHasUnpairedSurrogate(value);
  if (Array.isArray(value)) return value.some(hasUnpairedSurrogate);
  if (value !== null && typeof value === "object") {
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (stringHasUnpairedSurrogate(key)) return true;
      if (hasUnpairedSurrogate(val)) return true;
    }
  }
  return false;
}
