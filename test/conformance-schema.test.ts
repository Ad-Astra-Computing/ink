import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

// schema.json is the machine-readable JSON Schema an independent implementer
// reads to understand the shape of a vector file. Nothing validated against it
// before, so its `category` enum silently drifted behind the corpus (it listed
// only the categories present when it was last hand-edited). These tests fail
// closed if the enum ever falls behind the manifest again, and validate every
// vector file against the schema so the schema cannot lie about the corpus it
// describes. The generator derives the enum from the written vectors, so a new
// category can never ship without the schema listing it.
const v1Dir = fileURLToPath(new URL("../conformance/v1/", import.meta.url).href);
const vectorsDir = v1Dir + "vectors/";

interface JsonSchema {
  type?: string;
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  additionalProperties?: boolean;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  minItems?: number;
  pattern?: string;
}

const schema = JSON.parse(readFileSync(v1Dir + "schema.json", "utf8")) as JsonSchema;
const manifest = JSON.parse(readFileSync(v1Dir + "manifest.json", "utf8")) as {
  categories: { id: string }[];
};

// A compact validator for the JSON Schema keyword subset schema.json uses
// (type, const, enum, required, additionalProperties, properties, items,
// minItems, pattern). It re-reads the schema rather than re-encoding its rules,
// so a change to schema.json is honored here instead of duplicated. Returns the
// list of violation paths; an empty list means the value conforms.
function validate(node: JsonSchema, value: unknown, path: string): string[] {
  const errs: string[] = [];
  const typeOf = (v: unknown): string =>
    v === null ? "null" : Array.isArray(v) ? "array" : typeof v === "number" && Number.isInteger(v) ? "integer" : typeof v;

  if (node.type !== undefined) {
    const t = typeOf(value);
    const ok = node.type === "integer" ? t === "integer" : node.type === "number" ? t === "integer" || t === "number" : t === node.type;
    if (!ok) return [`${path}: type ${JSON.stringify(t)}, want ${JSON.stringify(node.type)}`];
  }
  if (node.const !== undefined && JSON.stringify(value) !== JSON.stringify(node.const)) {
    errs.push(`${path}: const mismatch, want ${JSON.stringify(node.const)}`);
  }
  if (node.enum !== undefined && !node.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    errs.push(`${path}: ${JSON.stringify(value)} not in enum`);
  }
  if (node.pattern !== undefined && typeof value === "string" && !new RegExp(node.pattern).test(value)) {
    errs.push(`${path}: ${JSON.stringify(value)} does not match /${node.pattern}/`);
  }
  if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems) {
      errs.push(`${path}: ${value.length} items, want >= ${node.minItems}`);
    }
    if (node.items) value.forEach((el, i) => errs.push(...validate(node.items!, el, `${path}[${i}]`)));
  } else if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const key of node.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(obj, key)) errs.push(`${path}: missing required ${JSON.stringify(key)}`);
    }
    for (const key of Object.keys(obj)) {
      const sub = node.properties?.[key];
      if (sub) errs.push(...validate(sub, obj[key], `${path}.${key}`));
      else if (node.additionalProperties === false) errs.push(`${path}: additional property ${JSON.stringify(key)}`);
    }
  }
  return errs;
}

const vectorFiles = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();

describe("conformance/v1 schema", () => {
  it("validates the vector file (ink.conformance.v1) shape", () => {
    expect(schema.type).toBe("object");
    expect((schema.properties?.format as JsonSchema).const).toBe("ink.conformance.v1");
  });

  it("its category enum equals the manifest category set exactly", () => {
    const enumIds = [...((schema.properties?.category as JsonSchema).enum as string[])].sort();
    const manifestIds = manifest.categories.map((c) => c.id).sort();
    // Equal as ordered lists (so the enum is sorted and complete) and as sets
    // (so it neither under- nor over-lists), the invariant that drifted.
    expect(enumIds).toEqual(manifestIds);
    expect(new Set(enumIds)).toEqual(new Set(manifestIds));
    expect(enumIds.length).toBe(manifest.categories.length);
  });

  it("its validator catches a violation and passes a conforming value", () => {
    const good = { format: "ink.conformance.v1", category: manifest.categories[0]!.id, cases: [{ caseId: "ok-1", description: "d", input: {}, expect: { result: "accept" } }] };
    expect(validate(schema, good, "$")).toEqual([]);
    expect(validate(schema, { ...good, category: "not-a-real-category" }, "$").length).toBeGreaterThan(0);
    expect(validate(schema, { ...good, cases: [{ ...good.cases[0], expect: { result: "maybe" } }] }, "$").length).toBeGreaterThan(0);
    expect(validate(schema, { ...good, cases: [{ ...good.cases[0], surprise: 1 }] }, "$").length).toBeGreaterThan(0);
  });

  for (const f of vectorFiles) {
    it(`validates ${f} against schema.json`, () => {
      const doc = JSON.parse(readFileSync(vectorsDir + f, "utf8"));
      expect(validate(schema, doc, "$")).toEqual([]);
    });
  }
});
