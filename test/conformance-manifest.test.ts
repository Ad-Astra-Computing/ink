import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

// The manifest is the stable index a second implementation reads to enumerate
// the conformance corpus and detect drift. These tests fail closed if the
// manifest, the vector files, or their hashes ever fall out of sync, so the
// index cannot silently lie about what the corpus contains.
const v1Dir = fileURLToPath(new URL("../conformance/v1/", import.meta.url).href);
const vectorsDir = v1Dir + "vectors/";
const repoRoot = fileURLToPath(new URL("../", import.meta.url).href);

interface ManifestCategory {
  id: string;
  vector: string;
  spec: string;
  summary: string;
  caseCount: number;
  sha256: string;
}
interface Manifest {
  format: string;
  corpus: string;
  categories: ManifestCategory[];
}

// JSON.parse silently keeps the last of any duplicate object keys, so a drift
// gate that only parsed could accept a corpus that a stricter or first-key-wins
// implementation reads differently. Reject duplicate keys outright; the
// generator never emits one. Returns a dotted path to the first duplicate, or
// null. The corpus is trusted, well-formed JSON, so this is a light scanner.
function firstDuplicateKey(text: string): string | null {
  let i = 0;
  const n = text.length;
  const ws = () => { while (i < n) { const c = text[i]; if (c === " " || c === "\t" || c === "\n" || c === "\r") i++; else break; } };
  // Returns the DECODED string (escapes resolved), so keys compare by their
  // JSON member name the same way Go's json.Decoder does. Comparing raw escaped
  // text would diverge: {"a":1,"a":2} is a duplicate after decoding, and
  // the two implementations must agree on that.
  const parseString = (): string => {
    const start = i; // at opening quote
    i++;
    while (i < n) {
      const c = text[i++];
      if (c === "\\") { i++; continue; }
      if (c === '"') break;
    }
    return JSON.parse(text.slice(start, i)) as string;
  };
  const scan = (path: string): string | null => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      const seen = new Set<string>();
      if (text[i] === "}") { i++; return null; }
      for (;;) {
        ws();
        const key = parseString();
        const child = `${path}.${key}`;
        if (seen.has(key)) return child;
        seen.add(key);
        ws(); i++; // colon
        const dup = scan(child);
        if (dup) return dup;
        ws();
        if (text[i] === ",") { i++; continue; }
        i++; // closing }
        break;
      }
      return null;
    }
    if (c === "[") {
      i++; ws();
      let idx = 0;
      if (text[i] === "]") { i++; return null; }
      for (;;) {
        const dup = scan(`${path}[${idx++}]`);
        if (dup) return dup;
        ws();
        if (text[i] === ",") { i++; continue; }
        i++; // closing ]
        break;
      }
      return null;
    }
    if (c === '"') { parseString(); return null; }
    while (i < n) {
      const ch = text[i];
      if (ch === undefined || ",]}".includes(ch) || /\s/.test(ch)) break;
      i++;
    }
    return null;
  };
  return scan("$");
}

const manifestText = readFileSync(v1Dir + "manifest.json", "utf8");
const manifest = JSON.parse(manifestText) as Manifest;
const vectorFiles = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();

describe("conformance/v1 manifest", () => {
  it("declares the manifest and corpus format", () => {
    expect(manifest.format).toBe("ink.conformance.manifest.v1");
    expect(manifest.corpus).toBe("ink.conformance.v1");
  });

  it("has no duplicate object keys (ambiguous across parsers)", () => {
    expect(firstDuplicateKey(manifestText)).toBeNull();
  });

  it("its duplicate-key detector fires on a crafted duplicate and passes clean input", () => {
    expect(firstDuplicateKey('{"a":1,"b":{"c":2,"c":3}}')).toBe("$.b.c");
    expect(firstDuplicateKey('{"items":[{"id":1},{"id":1,"id":2}]}')).toBe("$.items[1].id");
    expect(firstDuplicateKey('{"a":1,"b":[1,2,{"x":true}],"c":"d"}')).toBeNull();
    expect(firstDuplicateKey('{"format":"ink.conformance.manifest.v1","categories":[]}')).toBeNull();
    // Escaped keys are compared by their decoded member name, matching Go's
    // json.Decoder, so an escape-encoded duplicate is still caught.
    expect(firstDuplicateKey('{"a":1,"\\u0061":2}')).toBe("$.a");
    expect(firstDuplicateKey('{"/":1,"\\/":2}')).toBe("$./");
  });

  it("lists categories sorted and unique by id", () => {
    const ids = manifest.categories.map((c) => c.id);
    expect(ids).toEqual([...ids].sort());
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("lists exactly the vector files present on disk", () => {
    const listed = manifest.categories.map((c) => c.vector).sort();
    expect(listed).toEqual(vectorFiles.map((f) => `vectors/${f}`));
  });

  for (const cat of manifest.categories) {
    describe(cat.id, () => {
      const path = vectorsDir + cat.id + ".json";

      it("has a vector file whose name matches its id", () => {
        expect(cat.vector).toBe(`vectors/${cat.id}.json`);
        expect(existsSync(path)).toBe(true);
      });

      it("matches the vector file format and category", () => {
        const doc = JSON.parse(readFileSync(path, "utf8")) as { format: string; category: string; cases: unknown[] };
        expect(doc.format).toBe("ink.conformance.v1");
        expect(doc.category).toBe(cat.id);
        expect(cat.caseCount).toBe(doc.cases.length);
      });

      it("pins the current sha256 of the vector bytes", () => {
        const bytes = readFileSync(path);
        expect(cat.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
      });

      it("has no duplicate object keys", () => {
        expect(firstDuplicateKey(readFileSync(path, "utf8"))).toBeNull();
      });

      it("points at an existing spec", () => {
        expect(existsSync(repoRoot + cat.spec)).toBe(true);
      });
    });
  }
});
