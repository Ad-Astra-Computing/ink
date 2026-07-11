/**
 * Byte-level parse of a raw signed INK body.
 *
 * A signed body is verified over its raw bytes, so a receiver that decodes those
 * bytes leniently can canonicalize something other than what the signer signed.
 * Two byte-level hazards produce that divergence:
 *
 * - Invalid UTF-8. A lenient decode substitutes U+FFFD for an invalid byte
 *   sequence, and Go's `encoding/json` does the same, so a body carrying invalid
 *   UTF-8 would be signed over different bytes across implementations.
 * - A lone UTF-16 surrogate escape, which survives a valid UTF-8 decode but which
 *   some parsers rewrite to U+FFFD at parse time.
 *
 * `parseSignedBodyBytes` closes both at the raw-bytes boundary a JS string cannot
 * express: it decodes with a fatal UTF-8 decoder (so an invalid sequence throws
 * rather than substituting), scans the decoded JSON text for a lone surrogate,
 * then parses. A receiver that holds the body as a JS string has already crossed
 * the byte boundary and can no longer detect invalid UTF-8; it must run this on
 * the bytes.
 */

import { containsLoneSurrogateEscape } from "./surrogate.js";

// ignoreBOM keeps a leading BOM as a U+FEFF code point instead of stripping it,
// so the decoded text is faithful to the raw bytes the signature covers.
const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Which byte-level gate rejected the body. Callers discriminate on this field
 * rather than the message prose. Native JSON parse failures are not represented
 * here; they surface as the SyntaxError JSON.parse throws.
 */
export type ParseSignedBodyReason = "utf8" | "surrogate";

/**
 * Thrown when the byte gate rejects a raw signed body. `reason` is the stable
 * discriminator between an invalid-UTF-8 rejection and a lone-surrogate-escape
 * rejection.
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
 * Decode, validate, and parse a raw signed body. Rejects invalid UTF-8 and a
 * lone UTF-16 surrogate escape before JSON parsing; returns the parsed value.
 * Throws ParseSignedBodyError for the two byte-level failures and the native
 * SyntaxError from JSON.parse for a malformed body.
 */
export function parseSignedBodyBytes(bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = fatalUtf8Decoder.decode(bytes);
  } catch {
    throw new ParseSignedBodyError("utf8", "signed body is not valid UTF-8");
  }
  if (containsLoneSurrogateEscape(text)) {
    throw new ParseSignedBodyError("surrogate", "signed body contains an unpaired UTF-16 surrogate");
  }
  return JSON.parse(text);
}
