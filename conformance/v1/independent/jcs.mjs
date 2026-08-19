// RFC 8785 (JCS) under INK's §3.2 profile, written from the RFC and the spec
// rather than from `src/`. The corpus this checks must not be produced by the
// implementation it validates. See README.md in this directory.
//
// The one dependency this cannot shed is the JavaScript runtime: RFC 8785
// §3.2.2 defines number and string serialization by reference to ECMAScript, so
// JSON.stringify on a single scalar IS the normative algorithm rather than a
// shortcut around it. Independence here means independent of INK's code.
//
// §3.2 narrows RFC 8785 three ways, and all three are enforced here. A
// canonicalizer that emits bytes for an input the spec says a signer MUST
// refuse is not a usable oracle: it would happily verify an over-profile
// signature the implementation should never have produced.

// §3.2 complexity bounds. An implementation MUST bound the walk before
// canonicalizing an attacker-supplied value.
const MAX_NODES = 10000;
const MAX_DEPTH = 32;
const MAX_STRING_UNITS = 1200000;
const MAX_OUTPUT = 1048576;

// §3.2: a value carrying an unpaired UTF-16 surrogate MUST be rejected before
// signing or verifying, because a `\uXXXX` escape for a lone surrogate is not
// portable: a Go JSON parser rewrites it to U+FFFD and changes the canonical
// bytes. This applies to member names as much as to string values, since both
// land in the signed output.
function jsonString(value, what) {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    const isHigh = unit >= 0xd800 && unit <= 0xdbff;
    const isLow = unit >= 0xdc00 && unit <= 0xdfff;
    if (!isHigh && !isLow) continue;
    const next = value.charCodeAt(i + 1);
    if (!(isHigh && next >= 0xdc00 && next <= 0xdfff)) {
      throw new Error(`§3.2: lone surrogate in ${what} at index ${i}`);
    }
    i++;
  }
  // Otherwise RFC 8785 §3.2.2.2: the RFC 8259 escape set, shortest form, which
  // is what JSON.stringify emits for a well-formed string.
  return JSON.stringify(value);
}

export function jcs(value) {
  const budget = { nodes: 0, stringUnits: 0 };
  const out = serialize(value, budget, 0);
  if (out.length > MAX_OUTPUT) {
    throw new Error(`§3.2: canonical output ${out.length} code units exceeds ${MAX_OUTPUT}`);
  }
  // Both the UTF-16 code-unit length and the UTF-8 byte length are capped, so a
  // value under the code-unit ceiling that exceeds it in bytes is still refused.
  const bytes = new TextEncoder().encode(out).length;
  if (bytes > MAX_OUTPUT) {
    throw new Error(`§3.2: canonical output ${bytes} bytes exceeds ${MAX_OUTPUT}`);
  }
  return out;
}

function serialize(value, budget, depth) {
  if (depth > MAX_DEPTH) throw new Error(`§3.2: depth exceeds ${MAX_DEPTH}`);
  if (++budget.nodes > MAX_NODES) throw new Error(`§3.2: node count exceeds ${MAX_NODES}`);

  if (value === null) return "null";
  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    // §3.2: a number in a signed body MUST be a safe integer, with no
    // fractional part, within -(2^53 - 1)..2^53 - 1, and not negative zero.
    // NaN and the infinities are forbidden. A signer MUST refuse rather than
    // canonicalize an out-of-profile number, so this throws.
    if (!Number.isSafeInteger(value)) throw new Error(`§3.2: ${String(value)} is not a safe integer`);
    if (Object.is(value, -0)) throw new Error("§3.2: negative zero");
    return JSON.stringify(value);
  }

  if (t === "string") {
    budget.stringUnits += value.length;
    if (budget.stringUnits > MAX_STRING_UNITS) {
      throw new Error(`§3.2: aggregate string length exceeds ${MAX_STRING_UNITS} code units`);
    }
    return jsonString(value, "a string value");
  }

  if (Array.isArray(value)) {
    // RFC 8785 §3.2.3: array order is preserved. An undefined element is null
    // in JSON, and JCS has no separate rule for it.
    return `[${value.map((v) => serialize(v === undefined ? null : v, budget, depth + 1)).join(",")}]`;
  }

  if (t === "object") {
    // RFC 8785 §3.2.3: members sorted by the UTF-16 code units of the key,
    // which is exactly the default string ordering of Array.prototype.sort.
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    const members = keys.map((k) => {
      budget.stringUnits += k.length;
      if (budget.stringUnits > MAX_STRING_UNITS) {
        throw new Error(`§3.2: aggregate string length exceeds ${MAX_STRING_UNITS} code units`);
      }
      return `${jsonString(k, "a member name")}:${serialize(value[k], budget, depth + 1)}`;
    });
    return `{${members.join(",")}}`;
  }

  throw new Error(`jcs: unsupported type ${t}`);
}
