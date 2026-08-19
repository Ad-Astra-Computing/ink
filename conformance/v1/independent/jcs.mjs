// RFC 8785 (JCS) under INK's §3.2 profile, written from the RFC and the spec
// rather than from `src/`. The corpus this
// generator emits is the evidence that the implementation is correct, so it must
// not be produced by that implementation. See conformance/v1/README.md.
//
// The one dependency this cannot shed is the JavaScript runtime: RFC 8785 §3.2.2
// defines number and string serialization by reference to ECMAScript, so
// JSON.stringify on a single scalar IS the normative algorithm rather than a
// shortcut around it. Independence here means independent of INK's code.

export function jcs(value) {
  if (value === null) return "null";
  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    // Protocol §3.2 narrows RFC 8785 to a portable subset: a number in a signed
    // body MUST be a safe integer, with no fractional part, within
    // -(2^53 - 1)..2^53 - 1, and not negative zero. NaN and the infinities are
    // forbidden. A signer MUST refuse rather than canonicalize an
    // out-of-profile number, so this throws rather than emitting bytes.
    if (!Number.isSafeInteger(value)) {
      throw new Error(`§3.2: ${String(value)} is not a safe integer`);
    }
    if (Object.is(value, -0)) throw new Error("§3.2: negative zero");
    return JSON.stringify(value);
  }

  if (t === "string") {
    // Protocol §3.2: a value carrying an unpaired UTF-16 surrogate MUST be
    // rejected before signing or verifying. A `\uXXXX` escape for a lone
    // surrogate is not portable, since a Go JSON parser rewrites it to U+FFFD
    // and changes the canonical bytes. JSON.stringify would happily escape one.
    for (let i = 0; i < value.length; i++) {
      const unit = value.charCodeAt(i);
      const isHigh = unit >= 0xd800 && unit <= 0xdbff;
      const isLow = unit >= 0xdc00 && unit <= 0xdfff;
      if (!isHigh && !isLow) continue;
      const next = value.charCodeAt(i + 1);
      const paired = isHigh && next >= 0xdc00 && next <= 0xdfff;
      if (!paired) throw new Error(`§3.2: lone surrogate at index ${i}`);
      i++;
    }
    // Otherwise RFC 8785 §3.2.2.2: the RFC 8259 escape set, shortest form,
    // which is what JSON.stringify emits for a well-formed string.
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    // §3.2.3: array order is preserved. An undefined element is `null` in JSON,
    // and JCS has no separate rule for it.
    return `[${value.map((v) => jcs(v === undefined ? null : v)).join(",")}]`;
  }

  if (t === "object") {
    // §3.2.3: members sorted by the UTF-16 code units of the key, which is
    // exactly the default string ordering of Array.prototype.sort.
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }

  throw new Error(`jcs: unsupported type ${t}`);
}
