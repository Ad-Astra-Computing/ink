/**
 * Escaped-member-name detection for signed INK bodies.
 *
 * V8 returns a wrong property key from `JSON.parse` when an object member name
 * is written with an escape sequence. `GetKeyChars` in V8's JSON parser builds a
 * character span from a pointer into the raw source text but sizes it with the
 * decoded length, and the hidden-class transition matcher then compares that
 * oversized-source/undersized-length span against an existing transition name.
 * On a match the transition's name is reused as the property key without ever
 * decoding the escape, so `{"x":{"\\":1},"y":{"\n":2}}` yields a `y` whose only
 * member is named `\`, not a newline. The wrong key is a real property, so
 * `JSON.stringify` and therefore JCS serialize it.
 *
 * The defect requires the member name's raw spelling to be longer than its
 * decoded value, which requires an escape. Banning escaped member names in
 * signed bodies removes the precondition entirely, whatever transitions the
 * runtime happens to hold. That matters because the runtimes affected are the
 * ones INK targets: Node 24 and newer, and Cloudflare workerd, where the
 * corruption is unconditional and a poisoned transition persists across
 * requests within an isolate. Go's `encoding/json` is unaffected, so without
 * this rule a Go receiver and a workerd receiver reach different verdicts on
 * the same signed bytes.
 *
 * A receiver rejects an escaped member name on the raw JSON text before
 * parsing; a signer rejects the corresponding object keys before
 * canonicalization. See `specs/ink-signed-string-safety.md` §5.
 */

/**
 * Whether raw JSON text contains an object member name written with any escape
 * sequence. Operates on the raw text rather than the parsed value, because by
 * the time the value exists the wrong key has already replaced the right one.
 *
 * A string is a member name exactly when the next non-whitespace character
 * after its closing quote is `:`, which is precise for well-formed JSON. Text
 * this misreads is malformed and fails the subsequent `JSON.parse`, so a
 * misread cannot admit a body. The scan never decodes an escape: it only tracks
 * whether one occurred, so it is not a second parser on the signing path.
 */
export function containsEscapedMemberName(raw: string): boolean {
  const n = raw.length;
  for (let i = 0; i < n; i++) {
    if (raw.charCodeAt(i) !== 0x22) continue; // not a string start

    // Walk to the closing quote, remembering whether an escape appeared.
    let sawEscape = false;
    let j = i + 1;
    for (; j < n; j++) {
      const c = raw.charCodeAt(j);
      if (c === 0x5c) {
        // A backslash consumes the next character, so an escaped quote is not a
        // terminator. `\uXXXX` needs no special case: the four hex digits are
        // ordinary characters that cannot terminate the string.
        sawEscape = true;
        j++;
        continue;
      }
      if (c === 0x22) break; // closing quote
    }
    if (j >= n) return false; // unterminated string; JSON.parse will reject it

    if (sawEscape) {
      // Member name iff the next non-whitespace character is a colon. JSON
      // whitespace is space, tab, LF and CR.
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

    i = j; // resume scanning after the closing quote
  }
  return false;
}

/**
 * Whether a string would have to be escaped to appear as a JSON member name.
 * RFC 8785 serializes with the minimal JSON escaping, so exactly a quote, a
 * backslash and U+0000-U+001F force an escape. U+007F is not escaped and is
 * therefore safe.
 */
function keyRequiresEscape(key: string): boolean {
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (c === 0x22 || c === 0x5c || c < 0x20) return true;
  }
  return false;
}

/**
 * Whether a parsed value contains an object key that would serialize as an
 * escaped member name. Used on the signer side, where the body is an object
 * rather than raw text: such a key produces bytes a receiver rejects, so
 * signing it would emit a body nobody can verify.
 */
export function hasUnsafeObjectKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasUnsafeObjectKey);
  if (value !== null && typeof value === "object") {
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (keyRequiresEscape(key)) return true;
      if (hasUnsafeObjectKey(val)) return true;
    }
  }
  return false;
}
