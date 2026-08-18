// Structure-aware mutators and the interesting-value banks they draw from.
//
// Random bytes almost never reach past the first parser check on these
// surfaces, so the generator starts from something valid and breaks it in ways
// a spec-aware attacker would. The banks below are the edges that historically
// separate two implementations of the same grammar: Unicode that survives one
// language's string model and not the other's, numbers at the safe-integer and
// exponent boundaries, base64url at the wrong length or alphabet, and RFC 3339
// spellings that a lenient parser accepts.

/** Unicode edges for string values.
 *
 * A lone surrogate as a live string value is deliberately absent. A Go string is
 * UTF-8 bytes and cannot hold one at all, so such an input is not expressible on
 * the Go side of any API and there is nothing to compare; the conformance corpus
 * puts it out of scope for v1 for the same reason. The rule that matters, a
 * `\uXXXX` escape for an unpaired surrogate inside raw JSON text, is fully
 * expressible in ASCII and lives in JSON_TEXT_EDGES below, where it is tested. */
export const UNICODE_EDGES = [
  "", " ", "\t", "\n", "\r", "\r\n", "\u0000", "\u007f",
  "\u00e9", "e\u0301", // precomposed and decomposed: same text, different bytes
  "\ufeff", // BOM
  "\ufffd", // replacement character, what a lenient decoder substitutes
  "\u200b", "\u200e", "\u202e", // zero width and bidi overrides
  "\u3042", "\u4f60\u597d", "\ud83d\ude00", // multibyte and astral
  "\u0130", "\u0131", "\u00df", "\ufb00", // case-folding traps
  "\u2028", "\u2029", // JS line terminators that are not JSON line terminators
  // The UTF-8 length-class boundaries, where a hand-rolled encoder or decoder
  // picks the wrong number of continuation bytes.
  "\u0080", "\u07ff", "\u0800", "\ue000", "\uffff",
  "\ud800\udc00", "\udbff\udfff", // first and last astral code point
  "A".repeat(256), "A".repeat(1025),
];

/** Member names, drawn from the classes where two implementations sort
 * differently.
 *
 * RFC 8785 orders object members by UTF-16 code unit. The natural
 * implementation in Go, Rust or Python orders by code point or by UTF-8 bytes,
 * and those two orders are identical on every all-ASCII input, so an
 * ASCII-only bank can never separate them. They part company at exactly one
 * place: a BMP name above the surrogate range (U+E000 to U+FFFF) compared
 * against an astral name (U+10000 and above). UTF-16 puts the astral name
 * first, because its high surrogate is D800 to DBFF and therefore below any
 * such BMP unit; code-point and UTF-8 order put it last.
 *
 * The other classes here are the near-ties that a sort can also get wrong: two
 * names differing only by case, two differing only in normalization form, one
 * name a prefix of another, the empty name and names whose canonical
 * serialization is an escape sequence, which sorts differently from the raw
 * character an implementation should be comparing. */
export const MEMBER_NAME_EDGES = [
  "", " ", "a", "A", "aa", "ab", "b", "k", "k0", "0", "z",
  "\u007f", "\u0080", "\u07ff", "\u0800", "\u3042",
  "\ue000", "\uf8ff", "\ufb00", "\ufeff", "\ufffd", "\uff21", "\uffff",
  "\ud800\udc00", "\ud83d\ude00", "\ud83d\udd11", "\udbff\udfff",
  "\u00e9", "e\u0301", "\u0130", "\u0131", "\u00df", "\u212a",
  "\u0000", "\u001f", "\n", "\t", "\r", '"', "\\", "/", "\b", "\f",
  "\u200b", "\u2028",
];

/** Name pairs whose relative order separates one sort from another.
 *
 * Each entry is two names that a correct UTF-16 sort orders one way and a
 * plausible wrong sort orders the other way, so an object carrying both is a
 * discriminator and either name on its own proves nothing. The first group is
 * the UTF-16 versus code-point split; the rest are the near-ties.
 *
 * `orderingPairSplitsUtf16` below is the check that the first group really does
 * discriminate, so a typo in a code point cannot quietly turn a case into a
 * no-op. */
export const ORDERING_PAIRS = [
  // BMP above the surrogate range against astral: UTF-16 versus code point.
  ["\uff21", "\ud83d\udd11"],
  ["\ue000", "\ud800\udc00"],
  ["\uffff", "\udbff\udfff"],
  ["\ufeff", "\ud83d\ude00"],
  ["\ufb00", "\ud83d\udd11"],
  ["\ufffd", "\ud800\udc00"],
  ["\uf8ff", "\udbff\udfff"],
  // Same split, reached only after a common prefix, so a comparator that gets
  // the first unit right and the rest wrong is still caught.
  ["k\uffff", "k\ud83d\udd11"],
  ["\u3042\ue000", "\u3042\ud83d\ude00"],
  // Case only: a sort that folds case, or one that compares case-insensitively,
  // orders these the other way or calls them equal.
  ["A", "a"], ["K", "k"], ["k", "\u212a"], ["\u0130", "i"], ["\u00df", "SS"],
  // Normalization form only: NFC against NFD of the same text. A sort that
  // normalizes first calls them equal and may drop one member.
  ["\u00e9", "e\u0301"], ["\ufb00", "ff"], ["\u0130", "I\u0307"],
  // One name a prefix of another, including the empty name, where the tie-break
  // is length rather than a code unit.
  ["", "a"], ["a", "aa"], ["a", "a\u0000"], ["k", "k\uffff"], ["", "\ud83d\udd11"],
  // Names whose canonical serialization is an escape. A sort that compares the
  // escaped spelling rather than the raw string sees a leading backslash
  // (U+005C) where the raw string has a control character, which reverses the
  // order against any name starting in U+0041 to U+005B.
  ["\n", "A"], ["\u0000", "A"], ["\u001f", "B"], ['"', "A"], ["\\", "A"],
  ["\t", "K"], ["\b", "A"], ["\f", "A"], ["/", "A"],
];

/** True when a pair really does order differently under UTF-16 code units than
 * under code points, which is the property the first group of ORDERING_PAIRS
 * exists to exercise. Used by the self-check below, and exported so a test can
 * assert the bank has not rotted. */
export function orderingPairSplitsUtf16([a, b]) {
  const u16 = (s) => {
    const out = [];
    for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
    return out;
  };
  const cps = (s) => [...s].map((c) => c.codePointAt(0));
  const cmp = (x, y) => {
    for (let i = 0; i < x.length && i < y.length; i++) {
      if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    }
    return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
  };
  return cmp(u16(a), u16(b)) !== cmp(cps(a), cps(b));
}

/** The subset of ORDERING_PAIRS that provably splits UTF-16 from code-point
 * order. Empty means the bank has rotted, and the generator says so loudly
 * rather than generating cases that cannot discriminate. */
export const UTF16_SPLIT_PAIRS = ORDERING_PAIRS.filter(orderingPairSplitsUtf16);
if (UTF16_SPLIT_PAIRS.length === 0) {
  throw new Error("member-name bank no longer contains a UTF-16 versus code-point ordering pair");
}

/** Escapes that only exist in raw JSON text, never in a parsed value. */
export const JSON_TEXT_EDGES = [
  '\\ud800', '\\udfff', '\\uD800\\uD800', '\\ud83d\\ude00',
  '\\u0000', '\\u001f', '\\/', '\\\\', '\\"', '\\b\\f\\n\\r\\t',
  '\\uFEFF', '\\u007f',
];

/** Numeric literals as raw JSON text. The parsed value cannot express most of
 * these, which is why the generator works on text for the JCS surfaces. */
export const NUMBER_EDGES = [
  "0", "-0", "-0.0", "0.0", "1e2", "1E2", "1e+2", "1e-2", "1e0",
  "9007199254740991", "9007199254740992", "9007199254740993", "-9007199254740991",
  "-9007199254740992", "-9007199254740993",
  "1e308", "1e309", "1e-308", "1e-324", "5e-324",
  "0.1", "0.30000000000000004", "1.0", "1.5", "-1.5",
  "18446744073709551616", "340282366920938463463374607431768211456",
  "1e1000", "-1e1000", "1.7976931348623157e308", "1.7976931348623159e308",
  "0e0", "0e-0", "-0e0", "1000000000000000000000",
];

/** Timestamp spellings around the strict RFC 3339 millisecond grammar. */
export const TIMESTAMP_EDGES = [
  "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000z",
  "2026-01-01t00:00:00.000Z", "2026-01-01 00:00:00.000Z", "2026-01-01T00:00:00.000",
  "2026-01-01T00:00:00.000+00:00", "2026-01-01T00:00:00.000-00:00",
  "2026-01-01T00:00:00.000+14:00", "2026-01-01T00:00:00.000-12:00",
  "2026-01-01T00:00:00.000+24:00", "2026-01-01T00:00:00.000+00:60",
  "2026-01-01T00:00:00.0000Z", "2026-01-01T00:00:00.00Z", "2026-01-01T00:00:00.Z",
  "2026-01-01T00:00:00,000Z", "2026-01-01", "2026-01-01T24:00:00.000Z",
  "2026-01-01T23:59:60.000Z", "2026-02-29T00:00:00.000Z", "2024-02-29T00:00:00.000Z",
  "2026-00-01T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-01-32T00:00:00.000Z",
  "0000-01-01T00:00:00.000Z", "9999-12-31T23:59:59.999Z", "+2026-01-01T00:00:00.000Z",
  "-0001-01-01T00:00:00.000Z", "275760-09-13T00:00:00.000Z",
  "1970-01-01T00:00:00.000Z", "1969-12-31T23:59:59.999Z",
  " 2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z ", "2026-01-01T00:00:00.000Z\u0000",
];

/** base64url shapes around the 86-character Ed25519 signature. */
export const B64URL_EDGES = (() => {
  const ok = "A".repeat(86);
  return [
    ok, "A".repeat(85), "A".repeat(87), "A".repeat(88), "",
    "A".repeat(84) + "==", "A".repeat(86).slice(0, 85) + "=",
    "+".repeat(86), "/".repeat(86), "-".repeat(86), "_".repeat(86),
    "A".repeat(85) + "+", "A".repeat(85) + "/", "A".repeat(85) + "=",
    "A".repeat(85) + " ", "A".repeat(85) + "\n", "A".repeat(85) + "\u00e9",
    "A".repeat(43) + "\u0000" + "A".repeat(42),
  ];
})();

/** Every spelling of a principal the normalizer has to collapse or escape. */
export const PRINCIPAL_EDGES = [
  "", " ", "key:", "ink:", "tulpa:", "did:", "did:web:", "did:web:example.com",
  "did:web:EXAMPLE.com", "did:web:example.com:agent:a", "did:key:z6Mk",
  "key:z6MkExample", "ink:z6MkExample", "tulpa:z6MkExample",
  "ink:tulpa:z6MkExample", "tulpa:ink:z6MkExample", "key:key:z6MkExample",
  "INK:z6MkExample", "Ink:z6MkExample", "ink: z6MkExample", "ink:z6MkExample ",
  "ink:\u0130nk", "ink:z6Mk\ud800", "ink:" + "z".repeat(1024),
  "https://example.com/agent", "agent@example.com", "\u0000",
];

/** Hostnames across the IPv4, IPv6 and FQDN special-use blocks. */
export const HOSTNAME_EDGES = [
  "example.com", "EXAMPLE.COM", "example.com.", "localhost", "LOCALHOST",
  "127.0.0.1", "127.1", "127.0.0.001", "0177.0.0.1", "0x7f.0.0.1", "2130706433",
  "10.0.0.1", "172.16.0.1", "172.32.0.1", "192.168.1.1", "169.254.169.254",
  "100.64.0.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "255.255.255.255",
  "256.0.0.1", "1.2.3.4.5", "1.2.3", "-1.0.0.1", "1.2.3.-4",
  "::1", "[::1]", "::", "[::]", "fe80::1", "fe80::1%eth0", "[fe80::1%25eth0]",
  "fc00::1", "fd00::1", "ff00::1", "::ffff:127.0.0.1", "[::ffff:7f00:1]",
  "2002:7f00:0001::", "2001:db8::1", "64:ff9b::7f00:1",
  "[2001:db8::1]:443", "[2001:db8::1", "2001:db8::1]",
  ":::1", "1:2:3:4:5:6:7:8:9", "g::1", "", " ", ".", "..", "a..b",
  "xn--e1afmkfd.xn--p1ai", "\u0440\u0444.\u0440\u0444", "example.com\u0000.evil.com",
];

// ── generic mutators ──

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const clone = (v) => (v === undefined ? undefined : structuredClone(v));

/** Collect every path into a JSON value, root first. */
export function paths(value, prefix = [], out = []) {
  out.push(prefix);
  if (Array.isArray(value)) {
    value.forEach((v, i) => paths(v, [...prefix, i], out));
  } else if (isObj(value)) {
    for (const k of Object.keys(value)) paths(value[k], [...prefix, k], out);
  }
  return out;
}

export function getAt(value, path) {
  let cur = value;
  for (const seg of path) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[seg];
  }
  return cur;
}

export function setAt(value, path, next) {
  if (path.length === 0) return next;
  const root = clone(value);
  let cur = root;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
  cur[path[path.length - 1]] = next;
  return root;
}

export function deleteAt(value, path) {
  if (path.length === 0) return undefined;
  const root = clone(value);
  let cur = root;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
  const last = path[path.length - 1];
  if (Array.isArray(cur)) cur.splice(last, 1);
  else delete cur[last];
  return root;
}

/** Values a type flip can land on. */
export function typeFlipBank(rng) {
  return rng.pick([
    null, true, false, 0, -0, 1, -1, 1.5, 9007199254740993, "", "0", "null",
    [], [1], {}, { a: 1 }, rng.pick(UNICODE_EDGES),
  ]);
}

/** One structural mutation of a parsed JSON value. */
export function mutateJson(value, rng) {
  const all = paths(value);
  const p = rng.pick(all);
  const op = rng.pick([
    "drop", "flip", "unknown-key", "duplicate-ish", "nest", "grow", "empty", "unicode",
    "member-pair",
  ]);
  switch (op) {
    case "drop":
      return p.length === 0 ? undefined : deleteAt(value, p);
    case "flip":
      return setAt(value, p, typeFlipBank(rng));
    case "member-pair": {
      // Two members at once, drawn so their relative order is what separates one
      // sort from another. Either name on its own proves nothing, so the pair is
      // added together or not at all.
      const target = getAt(value, p);
      const added = {};
      orderingMemberNames(rng).forEach((k, i) => { added[k] = i; });
      if (!isObj(target)) return setAt(value, p, added);
      return setAt(value, p, { ...target, ...added });
    }
    case "unknown-key": {
      const target = getAt(value, p);
      if (rng.bool(0.4)) {
        const name = rng.pick(MEMBER_NAME_EDGES);
        return setAt(value, p, isObj(target) ? { ...target, [name]: typeFlipBank(rng) } : { [name]: 1 });
      }
      if (!isObj(target)) return setAt(value, p, { [rng.pick(["x", "__proto__", "constructor", "", "0", "\ud800"])]: 1 });
      return setAt(value, p, { ...target, [rng.pick(["extra", "__proto__", "toString", "", " ", "\u0000"])]: typeFlipBank(rng) });
    }
    case "duplicate-ish": {
      // A parsed value cannot hold a duplicate member, so the nearest structural
      // analogue is a second member differing only by an invisible character.
      const target = getAt(value, p);
      if (!isObj(target)) return value;
      const keys = Object.keys(target);
      if (keys.length === 0) return value;
      const k = rng.pick(keys);
      return setAt(value, p, { ...target, [k + rng.pick(["\u200b", " ", "\u0000", "\ufeff"])]: target[k] });
    }
    case "nest": {
      let deep = getAt(value, p);
      for (let i = 0; i < rng.between(1, 40); i++) deep = rng.bool() ? [deep] : { a: deep };
      return setAt(value, p, deep);
    }
    case "grow": {
      const target = getAt(value, p);
      if (Array.isArray(target)) {
        const n = rng.pick([0, 1, 32, 33, 100, 101, 1000]);
        return setAt(value, p, Array.from({ length: n }, () => (target.length ? target[0] : "x")));
      }
      if (typeof target === "string") return setAt(value, p, target.repeat(rng.pick([0, 2, 64])));
      if (typeof target === "number") return setAt(value, p, Number(rng.pick(NUMBER_EDGES)));
      return setAt(value, p, typeFlipBank(rng));
    }
    case "empty":
      return setAt(value, p, rng.pick(["", [], {}, null]));
    case "unicode": {
      const target = getAt(value, p);
      const edge = rng.pick(UNICODE_EDGES);
      if (typeof target === "string") {
        const at = rng.int(target.length + 1);
        return setAt(value, p, target.slice(0, at) + edge + target.slice(at));
      }
      return setAt(value, p, edge);
    }
    default:
      return value;
  }
}

/** One mutation of a string, at the character level. */
export function mutateString(s, rng) {
  const op = rng.pick(["insert", "delete", "replace", "dup", "case", "trim", "repeat", "truncate"]);
  const at = rng.int(Math.max(1, s.length + 1));
  switch (op) {
    case "insert":
      return s.slice(0, at) + rng.pick(UNICODE_EDGES) + s.slice(at);
    case "delete":
      return s.slice(0, at) + s.slice(at + rng.between(1, 3));
    case "replace":
      return s.slice(0, at) + rng.pick(UNICODE_EDGES) + s.slice(at + 1);
    case "dup":
      return s.slice(0, at) + s.slice(at, at + rng.between(1, 4)) + s.slice(at);
    case "case":
      return rng.bool() ? s.toUpperCase() : s.toLowerCase();
    case "trim":
      return rng.bool() ? " " + s : s + " ";
    case "repeat":
      return s.repeat(rng.pick([2, 3]));
    case "truncate":
      return s.slice(0, at);
    default:
      return s;
  }
}

/** One mutation of raw JSON text. Operates on the text so it can express what a
 * parsed value cannot: duplicate members, escape spellings, number literals. */
export function mutateJsonText(text, rng) {
  const op = rng.pick([
    "num", "escape", "dupkey", "whitespace", "trailing", "quote", "char", "bomb", "truncate",
    "member-pair",
  ]);
  switch (op) {
    case "member-pair": {
      // Splice a discriminating pair of member names into the outermost object,
      // so a corpus body that already canonicalizes cleanly starts carrying an
      // ordering decision as well.
      const i = text.indexOf("{");
      if (i < 0) return text;
      const names = orderingMemberNames(rng);
      if (names.length < 2) return text;
      const inject = names.map((k, n) => `${JSON.stringify(k)}:${n}`).join(",");
      const rest = text.slice(i + 1);
      return text.slice(0, i + 1) + inject + (/^\s*\}/.test(rest) ? "" : ",") + rest;
    }
    case "num": {
      const m = [...text.matchAll(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)];
      if (m.length === 0) return text.replace(/\}\s*$/, `,"n":${rng.pick(NUMBER_EDGES)}}`);
      const hit = rng.pick(m);
      return text.slice(0, hit.index) + rng.pick(NUMBER_EDGES) + text.slice(hit.index + hit[0].length);
    }
    case "escape": {
      const i = text.indexOf('"');
      if (i < 0) return text;
      return text.slice(0, i + 1) + rng.pick(JSON_TEXT_EDGES) + text.slice(i + 1);
    }
    case "dupkey": {
      const m = [...text.matchAll(/"([^"\\]{1,32})"\s*:/g)];
      if (m.length === 0) return text;
      const hit = rng.pick(m);
      const end = hit.index + hit[0].length;
      // Re-state the member with a different value, so a last-wins parser and a
      // first-wins parser canonicalize different bytes.
      return text.slice(0, hit.index) + `"${hit[1]}":${rng.pick(['null', '1', '"dup"'])},` + text.slice(hit.index, end) + text.slice(end);
    }
    case "whitespace": {
      const at = rng.int(Math.max(1, text.length));
      return text.slice(0, at) + rng.pick([" ", "\t", "\n", "\r", "\u00a0", "\ufeff", "\u2028"]) + text.slice(at);
    }
    case "trailing":
      return text + rng.pick(["", " ", "\u0000", "]", "}", ",", "null", "\n\n"]);
    case "quote":
      return text.replace(/"/g, rng.pick(["'", '\\"', '"']));
    case "char": {
      const at = rng.int(Math.max(1, text.length));
      return text.slice(0, at) + rng.pick(UNICODE_EDGES) + text.slice(at + 1);
    }
    case "bomb": {
      const d = rng.between(2, 64);
      return "[".repeat(d) + text + "]".repeat(d);
    }
    case "truncate":
      return text.slice(0, rng.int(Math.max(1, text.length)));
    default:
      return text;
  }
}

/** One mutation of a hex-encoded byte string, at the byte level. */
export function mutateHex(hex, rng) {
  const bytes = [];
  for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  const op = rng.pick(["flip", "insert", "delete", "seq", "truncate"]);
  const at = rng.int(Math.max(1, bytes.length + 1));
  // Byte sequences that separate a fatal UTF-8 decoder from a lenient one.
  const SEQ = [
    [0x80], [0xbf], [0xc0, 0xaf], [0xc1, 0xbf], [0xe0, 0x80, 0xaf],
    [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf], [0xf0, 0x80, 0x80, 0xaf],
    [0xf4, 0x90, 0x80, 0x80], [0xf5, 0x80, 0x80, 0x80], [0xfe], [0xff],
    [0xef, 0xbb, 0xbf], [0xe2, 0x82], [0x00], [0xc2], [0xf0, 0x9f, 0x98],
  ];
  switch (op) {
    case "flip":
      if (bytes.length) bytes[at % bytes.length] ^= 1 << rng.int(8);
      break;
    case "insert":
      bytes.splice(at, 0, ...rng.pick(SEQ));
      break;
    case "delete":
      bytes.splice(at, rng.between(1, 3));
      break;
    case "seq":
      bytes.splice(at, rng.between(0, 3), ...rng.pick(SEQ));
      break;
    case "truncate":
      bytes.length = Math.min(bytes.length, at);
      break;
    default:
      break;
  }
  return bytes.map((b) => (b & 0xff).toString(16).padStart(2, "0")).join("");
}

/** Member names for one generated object, guaranteed to contain a pair whose
 * relative order is itself the decision.
 *
 * One name out of a discriminating pair proves nothing: a canonicalizer emits
 * it in the only position there is. The pair has to appear in the same object,
 * so this returns both or neither. Noise members and an optional shared prefix
 * are added around it, which moves the deciding comparison off the first code
 * unit without changing which order is correct. */
export function orderingMemberNames(rng) {
  const pair = rng.bool(0.6) ? rng.pick(UTF16_SPLIT_PAIRS) : rng.pick(ORDERING_PAIRS);
  const names = rng.bool() ? [pair[0], pair[1]] : [pair[1], pair[0]];
  for (let i = 0, n = rng.between(0, 2); i < n; i++) names.push(rng.pick(MEMBER_NAME_EDGES));
  const prefix = rng.bool(0.25) ? rng.pick(["k", "é", "0", "", "🔑"]) : "";
  const out = [];
  const seen = new Set();
  for (const name of names) {
    const k = prefix + name;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

/** Leaf values for an ordering case.
 *
 * They are deliberately dull. An ordering divergence is only observable when
 * both sides accept the body and emit canonical bytes, so a leaf that either
 * side refuses (an out-of-range exponent, a fractional number) turns the case
 * into reject/reject and the ordering is never reached. */
const ORDERING_LEAF_VALUES = ["1", "0", "true", "false", "null", '""', '"v"', "[]", "{}", "[1,2]"];

/** A JSON object whose member names carry an ordering discriminator. */
export function orderingObjectText(rng, depth = 0) {
  const members = orderingMemberNames(rng).map((k) => {
    let value;
    if (depth < 2 && rng.bool(0.25)) value = orderingObjectText(rng, depth + 1);
    else if (rng.bool(0.1)) value = randomJsonText(rng, 3);
    else value = rng.pick(ORDERING_LEAF_VALUES);
    return `${JSON.stringify(k)}:${value}`;
  });
  const body = `{${members.join(",")}}`;
  // Sometimes bury it, so the sort under test is not always the root's.
  return depth === 0 && rng.bool(0.15) ? `{"outer":${body}}` : body;
}

/** Random JSON text, the arm that does not inherit the corpus's imagination. */
export function randomJsonText(rng, depth = 0) {
  const leaf = () =>
    rng.pick([
      "null", "true", "false", rng.pick(NUMBER_EDGES),
      JSON.stringify(rng.pick(UNICODE_EDGES)),
      `"${rng.pick(JSON_TEXT_EDGES)}"`,
    ]);
  if (depth > 3 || rng.bool(0.4)) return leaf();
  const n = rng.between(0, 4);
  if (rng.bool()) {
    return `[${Array.from({ length: n }, () => randomJsonText(rng, depth + 1)).join(",")}]`;
  }
  // A member name is drawn from the ordering bank as often as from anywhere
  // else. Sorting is the only thing an object's member names decide, and the
  // classes that separate two sorts are all in MEMBER_NAME_EDGES.
  const members = Array.from({ length: n }, () => {
    const k = rng.bool(0.35)
      ? rng.pick(MEMBER_NAME_EDGES)
      : rng.bool(0.3) ? rng.pick(UNICODE_EDGES) : `k${rng.int(4)}`;
    return `${JSON.stringify(k)}:${randomJsonText(rng, depth + 1)}`;
  });
  return `{${members.join(",")}}`;
}

/** Random bytes as hex, the byte-level equivalent of the random arm. */
export function randomHex(rng) {
  const n = rng.between(0, 64);
  let out = "";
  for (let i = 0; i < n; i++) out += rng.int(256).toString(16).padStart(2, "0");
  return out;
}

/** Random string drawn from the edge banks plus raw code points.
 *
 * The raw draw spans the whole assigned range rather than stopping at the BMP.
 * A ceiling below U+E000 would make a random string structurally incapable of
 * holding either half of the one comparison where UTF-16 order and code-point
 * order disagree, and incapable of holding a four-byte UTF-8 sequence at all. A
 * surrogate code point is shifted out of the surrogate block rather than
 * emitted: it cannot cross into a Go string, so the generator would only be
 * filtering its own output. */
export function randomString(rng) {
  const n = rng.between(0, 12);
  let out = "";
  for (let i = 0; i < n; i++) {
    if (rng.bool(0.5)) {
      out += rng.pick(UNICODE_EDGES);
      continue;
    }
    const cp = rng.between(1, 0x10ffff);
    out += String.fromCodePoint(cp >= 0xd800 && cp <= 0xdfff ? cp + 0x800 : cp);
  }
  return out;
}
