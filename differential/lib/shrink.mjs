// Shrinking. A raw divergence is usually a 4 KB envelope with forty mutations
// on it, and nobody can tell from that which byte caused the disagreement. The
// shrinker replays the same accept-or-reject comparison on progressively
// simpler inputs and keeps the simplest one that still diverges, so the artifact
// that lands on disk is a case a human can read and a vector can adopt.

import { paths, getAt, setAt, deleteAt } from "./mutators.mjs";

/** Rough size of an input, the thing the shrinker minimizes. */
export function sizeOf(value) {
  try {
    return JSON.stringify(value).length;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

function shrinkString(s) {
  const out = [];
  if (s.length === 0) return out;
  out.push("");
  if (s.length > 1) {
    out.push(s.slice(0, Math.floor(s.length / 2)));
    out.push(s.slice(Math.floor(s.length / 2)));
    out.push(s.slice(1));
    out.push(s.slice(0, -1));
  }
  // Single-character deletions, capped so one pass stays cheap on a long string.
  const step = Math.max(1, Math.floor(s.length / 64));
  for (let i = 0; i < s.length; i += step) out.push(s.slice(0, i) + s.slice(i + 1));
  // Collapse a run of the same character, which mutation often produces.
  const collapsed = s.replace(/(.)\1{2,}/g, "$1$1");
  if (collapsed !== s) out.push(collapsed);
  return out;
}

function shrinkNumber(n) {
  const out = [];
  if (n !== 0) out.push(0);
  if (n !== 1 && n > 1) out.push(1);
  if (!Number.isInteger(n)) out.push(Math.trunc(n));
  if (Math.abs(n) > 10) out.push(Math.trunc(n / 2));
  if (n < 0) out.push(-n);
  return out;
}

/** Simpler values for one JSON value, most aggressive first. */
function shrinkValue(v) {
  if (typeof v === "string") return shrinkString(v);
  if (typeof v === "number") return shrinkNumber(v);
  if (Array.isArray(v)) {
    const out = [];
    if (v.length > 0) out.push([]);
    if (v.length > 1) {
      out.push(v.slice(0, Math.floor(v.length / 2)));
      out.push(v.slice(1));
      out.push(v.slice(0, -1));
    }
    return out;
  }
  if (v !== null && typeof v === "object") {
    const keys = Object.keys(v);
    return keys.map((k) => {
      const next = { ...v };
      delete next[k];
      return next;
    });
  }
  if (v === true) return [false];
  return [];
}

/** Simpler raw JSON *text*, for the surfaces whose input is text rather than a
 * parsed value. Reserializing a parsed value is useless here: the literals that
 * cause these divergences (an out-of-range exponent, a duplicate member, an
 * escape spelling) do not survive a parse-and-stringify round trip. So this
 * works on the characters: every balanced bracket group and every scalar token
 * in the text is offered as a body on its own. */
export function jsonTextShrinkCandidates(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const open = text[i];
    if (open !== "[" && open !== "{") continue;
    const close = open === "[" ? "]" : "}";
    let depth = 0;
    let inString = false;
    for (let j = i; j < text.length; j++) {
      const ch = text[j];
      if (inString) {
        if (ch === "\\") j++;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === open) depth++;
      else if (ch === close) {
        depth--;
        if (depth === 0) {
          if (j - i + 1 < text.length) out.push(text.slice(i, j + 1));
          break;
        }
      }
    }
  }
  for (const m of text.matchAll(/-?\d[\d.eE+-]*|"(?:[^"\\]|\\.)*"|true|false|null/g)) {
    if (m[0].length < text.length) out.push(m[0]);
  }
  return out;
}

/** Every one-step simplification of an input object. */
export function shrinkCandidates(input) {
  const out = [];
  const seen = new Set();
  const push = (candidate) => {
    if (candidate === undefined) return;
    let key;
    try {
      key = JSON.stringify(candidate);
    } catch {
      return;
    }
    if (key === undefined || seen.has(key)) return;
    seen.add(key);
    out.push(candidate);
  };

  for (const p of paths(input)) {
    if (p.length === 0) continue;
    // Dropping a member is the most valuable single step, so it goes first.
    push(deleteAt(input, p));
    for (const simpler of shrinkValue(getAt(input, p))) push(setAt(input, p, simpler));
  }
  return out;
}
