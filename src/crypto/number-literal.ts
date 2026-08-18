/**
 * Out-of-range JSON number literal detection for signed INK bodies.
 *
 * A JSON number literal whose magnitude is outside the IEEE-754 double range
 * (`1e309`, `-1e1000`) is not portable across JSON parsers. ECMAScript
 * `JSON.parse` decodes it to `Infinity` and hands the document back; Go's
 * `encoding/json` refuses the whole document with a range error. INK's number
 * profile is a check on decoded *values*, so it catches the `Infinity` that
 * reaches canonicalization, but it never sees a literal that a later duplicate
 * member shadows: JSON member semantics are last-wins, so `{"a":1e309,"a":1}`
 * canonicalizes cleanly under one parser and is refused outright by the other.
 * Two implementations then admit different byte strings as signed bodies, which
 * is the same consensus hazard as invalid UTF-8 or a lone surrogate escape and
 * belongs at the same place: the raw-text gate, before parsing.
 */

const CHAR_QUOTE = 0x22;
const CHAR_BACKSLASH = 0x5c;
const CHAR_MINUS = 0x2d;
const CHAR_ZERO = 0x30;
const CHAR_NINE = 0x39;

/** A character that may appear inside a JSON number token. */
function isNumberChar(c: number): boolean {
  return (
    (c >= CHAR_ZERO && c <= CHAR_NINE) ||
    c === CHAR_MINUS ||
    c === 0x2b || // +
    c === 0x2e || // .
    c === 0x65 || // e
    c === 0x45 // E
  );
}

/** A character that may begin a JSON number token. */
function isNumberStart(c: number): boolean {
  return (c >= CHAR_ZERO && c <= CHAR_NINE) || c === CHAR_MINUS;
}

/**
 * Whether raw JSON text contains a number literal whose value is outside the
 * IEEE-754 double range. Operates on the raw text, not the parsed value,
 * because a duplicate member can shadow the literal and a parser that decoded
 * it to `Infinity` has already lost the distinction.
 *
 * A run of number characters outside any string is read as one token and
 * evaluated as a double. A token that is not a number at all (a malformed run
 * such as `1e`) is left alone: the JSON parser rejects it on its own, and this
 * scanner must not decide anything a parser would accept. A token that
 * underflows to zero (`1e-400`) is in range: every IEEE-754 parser decodes it
 * to `0`, so the two implementations already agree on it.
 */
export function containsOutOfRangeNumberLiteral(raw: string): boolean {
  let inString = false;
  const n = raw.length;
  for (let i = 0; i < n; ) {
    const c = raw.charCodeAt(i);
    if (inString) {
      // A backslash escapes the next character, so an escaped quote does not
      // end the string and number-like text inside one is never a token.
      if (c === CHAR_BACKSLASH) {
        i += 2;
        continue;
      }
      if (c === CHAR_QUOTE) inString = false;
      i++;
      continue;
    }
    if (c === CHAR_QUOTE) {
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
