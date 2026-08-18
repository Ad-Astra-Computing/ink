/**
 * Byte-level parse of a raw signed INK body.
 *
 * A signed body is verified over its raw bytes, so a receiver that decodes those
 * bytes leniently can canonicalize something other than what the signer signed.
 * Three text-level hazards produce that divergence:
 *
 * - Invalid UTF-8. A lenient decode substitutes U+FFFD for an invalid byte
 *   sequence, and Go's `encoding/json` does the same, so a body carrying invalid
 *   UTF-8 would be signed over different bytes across implementations.
 * - A lone UTF-16 surrogate escape, which survives a valid UTF-8 decode but which
 *   some parsers rewrite to U+FFFD at parse time.
 * - A number literal outside the IEEE-754 double range, which `JSON.parse`
 *   decodes to `Infinity` and Go's `encoding/json` refuses outright, so the two
 *   admit different byte strings whenever a duplicate member shadows the literal
 *   before the value-level number profile can see it.
 * - An object member name written with an escape sequence, which V8 can decode
 *   to an entirely different string (see `member-name.ts`), so a workerd or
 *   Node 24+ receiver canonicalizes different bytes than a Go receiver.
 *
 * `parseSignedBodyBytes` closes all four at the raw boundary a JS string cannot
 * express or a parsed value can no longer recover: it decodes with a fatal UTF-8
 * decoder (so an invalid sequence throws rather than substituting), scans the
 * decoded JSON text for a lone surrogate, an out-of-range number literal and an
 * escaped member name, then parses. A receiver that holds the body as a JS
 * string has already crossed the byte boundary and can no longer detect invalid
 * UTF-8; it must run this on the bytes.
 */

import { containsLoneSurrogateEscape } from "./surrogate.js";
import { containsOutOfRangeNumberLiteral } from "./number-literal.js";
import { containsEscapedMemberName } from "./member-name.js";

// ignoreBOM keeps a leading BOM as a U+FEFF code point instead of stripping it,
// so the decoded text is faithful to the raw bytes the signature covers.
const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Which byte-level gate rejected the body. Callers discriminate on this field
 * rather than the message prose. Native JSON parse failures are not represented
 * here; they surface as the SyntaxError JSON.parse throws.
 */
export type ParseSignedBodyReason =
  | "utf8"
  | "surrogate"
  | "number-range"
  | "member-name-escape";

/**
 * Thrown when the byte gate rejects a raw signed body. `reason` is the stable
 * discriminator between an invalid-UTF-8 rejection, a lone-surrogate-escape
 * rejection, an out-of-range number literal and an escaped member name.
 */
export class ParseSignedBodyError extends Error {
  readonly reason: ParseSignedBodyReason;

  constructor(reason: ParseSignedBodyReason, message: string) {
    super(message);
    this.name = "ParseSignedBodyError";
    this.reason = reason;
  }
}

/**
 * Decode, validate, and parse a raw signed body. Rejects invalid UTF-8, a lone
 * UTF-16 surrogate escape, a number literal outside the IEEE-754 double range,
 * and an escaped object member name before JSON parsing; returns the parsed
 * value. Throws ParseSignedBodyError for the four text-level failures and the
 * native SyntaxError from JSON.parse for a malformed body.
 */
export function parseSignedBodyBytes(bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = fatalUtf8Decoder.decode(bytes);
  } catch {
    throw new ParseSignedBodyError("utf8", "signed body is not valid UTF-8");
  }
  return parseSignedBodyText(text);
}

/**
 * The three text-level gates and the parse, for a caller that only has the body
 * as a string. Prefer `parseSignedBodyBytes` wherever the bytes are still
 * available: a string has already crossed the UTF-8 boundary, so an invalid
 * sequence has already become U+FFFD and cannot be detected here.
 */
export function parseSignedBodyText(text: string): unknown {
  if (containsLoneSurrogateEscape(text)) {
    throw new ParseSignedBodyError("surrogate", "signed body contains an unpaired UTF-16 surrogate");
  }
  if (containsOutOfRangeNumberLiteral(text)) {
    throw new ParseSignedBodyError(
      "number-range",
      "signed body contains a number literal outside the IEEE-754 double range",
    );
  }
  if (containsEscapedMemberName(text)) {
    throw new ParseSignedBodyError(
      "member-name-escape",
      "signed body contains an object member name written with an escape sequence",
    );
  }
  return JSON.parse(text);
}
