// RFC 8785 (JCS), written from the RFC rather than from `src/`. The corpus this
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
    // §3.2.2.3: ECMAScript Number::toString, which excludes NaN and Infinity
    // because they have no JSON representation at all.
    if (!Number.isFinite(value)) {
      throw new Error(`jcs: non-finite number ${String(value)}`);
    }
    return JSON.stringify(value);
  }

  // §3.2.2.2: the RFC 8259 escape set, shortest form, which is what
  // JSON.stringify emits for a well-formed string.
  if (t === "string") return JSON.stringify(value);

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
