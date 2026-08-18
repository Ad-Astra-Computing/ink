#!/usr/bin/env node
// The differential runner.
//
//   node differential/run.mjs --cases 5000
//   node differential/run.mjs --seconds 600 --seed 12345
//   node differential/run.mjs --surfaces signed-body-canonical,signature-base
//
// It generates cases, feeds every case to both implementations, compares the
// decisions, minimizes anything that disagrees and writes the minimized case to
// differential/findings/. Exit 0 means every case agreed. Exit 1 means at least
// one did not, and the finding files say which.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveSeed, rngFromSeed } from "./lib/rng.mjs";
import { SURFACES, SURFACE_BY_ID } from "./lib/surfaces.mjs";
import { shrinkCandidates, sizeOf } from "./lib/shrink.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const vectorsDir = join(repo, "conformance", "v1", "vectors");
const binDir = join(here, ".bin");
const goBin = join(binDir, "go-decide");
let findingsDir = join(here, "findings");

// ── arguments ──

function parseArgs(argv) {
  const opts = {
    seed: null,
    cases: 2000,
    seconds: null,
    surfaces: null,
    arms: ["corpus", "mutate", "random"],
    batch: 2000,
    shrinkPasses: 8,
    shrinkCandidates: 400,
    minimizePerShape: 25,
    findingsDir: null,
    quiet: false,
    list: false,
    selfTest: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => argv[++i];
    switch (a) {
      case "--seed": opts.seed = Number(val()); break;
      case "--cases": opts.cases = Number(val()); break;
      case "--seconds": opts.seconds = Number(val()); break;
      case "--surfaces": opts.surfaces = val().split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--arms": opts.arms = val().split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--batch": opts.batch = Number(val()); break;
      case "--shrink-passes": opts.shrinkPasses = Number(val()); break;
      case "--shrink-candidates": opts.shrinkCandidates = Number(val()); break;
      case "--minimize-per-shape": opts.minimizePerShape = Number(val()); break;
      case "--findings-dir": opts.findingsDir = val(); break;
      case "--self-test": opts.selfTest = val(); break;
      case "--quiet": opts.quiet = true; break;
      case "--list": opts.list = true; break;
      case "--help": case "-h": opts.help = true; break;
      default:
        throw new Error(`unknown flag ${a}`);
    }
  }
  return opts;
}

const HELP = `differential/run.mjs - differential fuzzing between the TypeScript reference and Go

  --cases N            case budget for the run (default 2000)
  --seconds S          wall-clock budget; stops at whichever budget runs out first
  --seed N             run seed (default: random, printed so it can be replayed)
  --surfaces a,b       restrict to these surfaces (default: all)
  --arms a,b           corpus, mutate, random (default: all three)
  --batch N            cases per decider invocation (default 2000)
  --shrink-passes N    minimization passes per finding (default 8)
  --minimize-per-shape N  stop minimizing a (surface, kind) shape after N (default 25)
  --findings-dir DIR   where to write findings (default differential/findings)
  --self-test SURFACE  negative control: tell the TypeScript decider to answer
                       this surface wrongly, and pass only if that is caught
  --quiet              summary only
  --list               print the surfaces and exit
`;

// ── corpus ──

/** Load every conformance vector case, indexed by category. */
function loadCorpus() {
  const byCategory = new Map();
  for (const file of readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort()) {
    const doc = JSON.parse(readFileSync(join(vectorsDir, file), "utf8"));
    byCategory.set(doc.category, doc.cases);
  }
  return byCategory;
}

/** Seed inputs for one surface, drawn from the conformance corpus. The corpus is
 * already the set of interesting shapes for these surfaces, so it is the
 * starting population rather than a hand-written one. */
function seedsFor(surface, corpus) {
  const out = [];
  for (const src of surface.seedFrom ?? []) {
    for (const c of corpus.get(src.category) ?? []) {
      let mapped;
      try {
        mapped = src.map(c.input);
      } catch {
        continue;
      }
      if (mapped !== undefined && surface.wellFormed(mapped)) out.push(mapped);
    }
  }
  return out;
}

// ── generation ──

function* generate(opts, corpus, surfaces) {
  const seedsBySurface = new Map(surfaces.map((s) => [s.id, seedsFor(s, corpus)]));
  let index = 0;
  // Round-robin across surfaces and arms so a truncated budget still covers
  // every surface rather than exhausting the first one.
  for (let round = 0; ; round++) {
    for (const surface of surfaces) {
      const seeds = seedsBySurface.get(surface.id);
      for (const arm of opts.arms) {
        if (arm === "corpus" && round >= seeds.length) continue;
        const caseSeed = deriveSeed(opts.seed, `${surface.id}:${arm}`, round);
        const rng = rngFromSeed(caseSeed);
        let input;
        try {
          if (arm === "corpus") {
            input = seeds[round];
          } else if (arm === "mutate") {
            if (seeds.length === 0) continue;
            input = surface.mutate(structuredClone(rng.pick(seeds)), rng);
          } else {
            input = surface.random(rng);
          }
        } catch {
          continue;
        }
        if (input === undefined || !surface.wellFormed(input) || !crossable(input)) continue;
        yield {
          caseId: `${surface.id}/${arm}/${opts.seed}/${round}`,
          surface: surface.id,
          arm,
          seed: caseSeed,
          input,
        };
        index++;
      }
    }
    if (round > 0 && index === 0) return; // nothing generable at all
  }
}

// ── deciders ──

function ensureGoBinary() {
  mkdirSync(binDir, { recursive: true });
  // Always rebuild. The decider links the ink Go library through a `replace`
  // directive, so its behavior changes when any file under go/ changes, not
  // only when main.go does. An mtime check against main.go alone reported the
  // binary fresh after a library change, which compared new TypeScript against
  // an old Go and invented divergences. It would equally have hidden a real
  // one, because a stale binary keeps answering the old way. Go's own build
  // cache makes an unchanged rebuild cheap, so there is nothing to buy here.
  const res = spawnSyncish("go", ["build", "-o", goBin, "."], { cwd: join(here, "deciders", "go") });
  if (res !== 0) {
    throw new Error(
      "could not build the Go decider. Put a Go toolchain on PATH (nix develop, or nix shell nixpkgs#go) and re-run.",
    );
  }
}

function spawnSyncish(cmd, args, opts) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  return r.status === null ? 1 : r.status;
}

/** JSON with every non-ASCII character escaped.
 *
 * The bridge is NDJSON, so a case line must contain no character either reader
 * can mistake for a line break. Node's readline splits on U+2028 and U+2029,
 * which JSON.stringify emits literally, and a raw multibyte character is fine
 * for Go's scanner but not worth the asymmetry. Escaping everything above ASCII
 * makes the payload byte-identical for both readers, so a case that fails on one
 * side fails because of the library rather than because of the pipe. */
function jsonAscii(value) {
  return JSON.stringify(value).replace(/[-￿]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

/** Whether every string in an input survives the crossing into a Go string.
 *
 * An unpaired UTF-16 surrogate does not: a Go string is UTF-8 bytes, and both
 * the JSON bridge and the Go API itself rewrite it to U+FFFD. Comparing such an
 * input would measure the bridge, not the implementations, so the generator
 * drops it. The surrogate rule the protocol actually pins is about a `\uXXXX`
 * escape in raw JSON text, which is ASCII and crosses intact. */
function crossable(value) {
  if (typeof value === "string") return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value);
  if (Array.isArray(value)) return value.every(crossable);
  if (value !== null && typeof value === "object") {
    return Object.entries(value).every(([k, v]) => crossable(k) && crossable(v));
  }
  return true;
}

/** Run one decider over a batch of cases and return decisions keyed by caseId. */
function runDecider(cmd, args, cases, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: repo, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, ...env } });
    let out = "";
    let err = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`${cmd} exited ${code}\n${err.slice(0, 4000)}`));
        return;
      }
      const map = new Map();
      for (const line of out.split("\n")) {
        if (line.trim() === "") continue;
        const d = JSON.parse(line);
        map.set(d.caseId, d);
      }
      resolve(map);
    });
    const payload = cases.map((c) => jsonAscii({ caseId: c.caseId, surface: c.surface, input: c.input })).join("\n");
    child.stdin.end(payload + "\n");
  });
}

const tsxBin = join(repo, "node_modules", ".bin", "tsx");

/** Set by --self-test: the surface the TypeScript decider is told to answer
 * wrongly, so the comparison has something to catch. */
let mutantSurface = null;

async function decideBoth(cases) {
  const tsEnv = mutantSurface === null ? {} : { INK_DIFF_MUTANT: mutantSurface };
  const [ts, go] = await Promise.all([
    runDecider(tsxBin, [join(here, "deciders", "ts-decide.mts")], cases, tsEnv),
    runDecider(goBin, [], cases, {}),
  ]);
  return { ts, go };
}

// ── comparison ──

const VALUE_FIELDS = ["canonicalPrincipal", "canonicalString", "epochMs", "signature", "keyId"];
const isHarness = (r) => typeof r === "string" && r.startsWith("__harness");

/** Compare one pair of decisions. Returns null when they agree. */
function compare(ts, go) {
  if (!ts || !go) {
    return { kind: "missing", detail: `ts=${ts ? "present" : "missing"} go=${go ? "present" : "missing"}` };
  }
  if (isHarness(ts.reason) && ts.reason.startsWith("__harness_error")) {
    return { kind: "crash", detail: `typescript: ${ts.reason}` };
  }
  if (isHarness(go.reason) && go.reason.startsWith("__harness_error")) {
    return { kind: "crash", detail: `go: ${go.reason}` };
  }
  if (ts.result !== go.result) {
    return { kind: "decision", detail: `ts=${ts.result} go=${go.result}` };
  }
  for (const f of VALUE_FIELDS) {
    const a = ts[f];
    const b = go[f];
    if (a === undefined && b === undefined) continue;
    if (a !== b) return { kind: "value", detail: `${f}: ts=${JSON.stringify(a)} go=${JSON.stringify(b)}` };
  }
  // The reason code is compared only when both sides emit one and neither is a
  // harness marker: the marker means one side's public entry point could not be
  // reached with this input at all, which is an API asymmetry, not a divergence.
  if (ts.reason && go.reason && !isHarness(ts.reason) && !isHarness(go.reason) && ts.reason !== go.reason) {
    return { kind: "reason", detail: `reason: ts=${ts.reason} go=${go.reason}` };
  }
  return null;
}

// ── minimization ──

/** Shrink a divergent input to the smallest one that still diverges the same way. */
async function minimize(surface, input, kind, opts) {
  let best = input;
  for (let pass = 0; pass < opts.shrinkPasses; pass++) {
    const oneStep = surface.shrink ? surface.shrink(best) : shrinkCandidates(best);
    const candidates = oneStep
      .filter((c) => surface.wellFormed(c) && crossable(c))
      .slice(0, opts.shrinkCandidates)
      .map((c, i) => ({ caseId: `shrink/${pass}/${i}`, surface: surface.id, input: c }));
    if (candidates.length === 0) break;
    const { ts, go } = await decideBoth(candidates);
    let improved = null;
    for (const c of candidates) {
      const diff = compare(ts.get(c.caseId), go.get(c.caseId));
      if (diff && diff.kind === kind) {
        if (improved === null || sizeOf(c.input) < sizeOf(improved)) improved = c.input;
      }
    }
    if (improved === null || sizeOf(improved) >= sizeOf(best)) break;
    best = improved;
  }
  return best;
}

// ── findings ──

function writeFinding(surface, c, diff, minimized, tsD, goD, minTs, minGo, runSeed) {
  const dir = join(findingsDir, surface.id);
  mkdirSync(dir, { recursive: true });
  const slug = createHash("sha256").update(JSON.stringify({ s: surface.id, i: minimized })).digest("hex").slice(0, 16);
  const path = join(dir, `${diff.kind}-${slug}.json`);
  const finding = {
    format: "ink.differential.finding.v1",
    surface: surface.id,
    conformanceCategory: surface.id,
    kind: diff.kind,
    detail: diff.detail,
    runSeed,
    originCaseId: c.caseId,
    arm: c.arm,
    original: c.input,
    minimized,
    decisions: {
      original: { typescript: strip(tsD), go: strip(goD) },
      minimized: { typescript: strip(minTs), go: strip(minGo) },
    },
  };
  writeFileSync(path, JSON.stringify(finding, null, 2) + "\n");
  return path;
}

function strip(d) {
  if (!d) return null;
  const { caseId: _caseId, ...rest } = d;
  return rest;
}

// ── main ──

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (opts.list) {
    for (const s of SURFACES) process.stdout.write(`tier ${s.tier}  ${s.id}\n`);
    return 0;
  }
  if (opts.seed === null || !Number.isFinite(opts.seed)) {
    opts.seed = (Math.random() * 2 ** 32) >>> 0;
  }
  if (opts.selfTest !== null) {
    if (!SURFACE_BY_ID.has(opts.selfTest)) throw new Error(`unknown surface ${opts.selfTest}`);
    mutantSurface = opts.selfTest;
    opts.surfaces = [opts.selfTest];
  }
  const surfaces = opts.surfaces
    ? opts.surfaces.map((id) => {
        const s = SURFACE_BY_ID.get(id);
        if (!s) throw new Error(`unknown surface ${id}`);
        return s;
      })
    : SURFACES;

  if (opts.findingsDir !== null) findingsDir = opts.findingsDir;

  ensureGoBinary();
  const corpus = loadCorpus();

  const log = (msg) => { if (!opts.quiet) process.stderr.write(msg + "\n"); };
  log(`differential: seed ${opts.seed}, budget ${opts.cases} cases${opts.seconds ? ` / ${opts.seconds}s` : ""}`);
  log(`differential: surfaces ${surfaces.map((s) => s.id).join(", ")}`);

  const started = Date.now();
  const outOfTime = () => opts.seconds !== null && (Date.now() - started) / 1000 >= opts.seconds;

  const perSurface = new Map(surfaces.map((s) => [s.id, 0]));
  const perArm = new Map(opts.arms.map((a) => [a, 0]));
  let ran = 0;
  const findings = [];
  const seenFindings = new Set();
  const shapeCounts = new Map();

  let batch = [];
  const gen = generate(opts, corpus, surfaces);

  const flush = async () => {
    if (batch.length === 0) return;
    const { ts, go } = await decideBoth(batch);
    for (const c of batch) {
      ran++;
      perSurface.set(c.surface, perSurface.get(c.surface) + 1);
      perArm.set(c.arm, (perArm.get(c.arm) ?? 0) + 1);
      const tsD = ts.get(c.caseId);
      const goD = go.get(c.caseId);
      const diff = compare(tsD, goD);
      if (!diff) continue;
      const surface = SURFACE_BY_ID.get(c.surface);
      // Dedupe on the divergence shape so one systematic bug does not write ten
      // thousand files, and stop minimizing a shape once it is well understood:
      // minimization is the expensive step, and the twenty-sixth witness of one
      // root cause teaches nothing the first twenty-five did not.
      const key = `${c.surface}|${diff.kind}`;
      const already = (shapeCounts.get(key) ?? 0);
      shapeCounts.set(key, already + 1);
      if (already >= opts.minimizePerShape) {
        findings.push({ surface: c.surface, kind: diff.kind, detail: diff.detail, path: null, minimized: null });
        continue;
      }
      if (opts.selfTest !== null) {
        // The self-test's divergence is injected, so it is counted and never
        // written: an artifact of a deliberate fault is not a finding.
        findings.push({ surface: c.surface, kind: diff.kind, detail: diff.detail, path: null, minimized: c.input });
        seenFindings.add(key);
        continue;
      }
      const minimized = await minimize(surface, c.input, diff.kind, opts);
      const check = await decideBoth([{ caseId: "min", surface: surface.id, input: minimized }]);
      // The shrinker matches on the kind, not the exact detail, so a minimized
      // case can carry a different reason than the case it came from. Record the
      // detail of what actually landed on disk.
      const minDiff = compare(check.ts.get("min"), check.go.get("min")) ?? diff;
      const path = writeFinding(
        surface, c, minDiff, minimized, tsD, goD,
        check.ts.get("min"), check.go.get("min"), opts.seed,
      );
      findings.push({ surface: c.surface, kind: diff.kind, detail: minDiff.detail, path, minimized });
      if (!seenFindings.has(key)) {
        seenFindings.add(key);
        log(`  DIVERGENCE ${c.surface} [${diff.kind}] ${diff.detail}`);
        log(`    minimized: ${JSON.stringify(minimized).slice(0, 400)}`);
        log(`    written to ${path}`);
      }
    }
    batch = [];
  };

  for (const c of gen) {
    if (ran + batch.length >= opts.cases || outOfTime()) break;
    batch.push(c);
    if (batch.length >= opts.batch) {
      await flush();
      log(`  ${ran} cases`);
      if (outOfTime()) break;
    }
  }
  await flush();

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  process.stdout.write(`\ndifferential: ${ran} cases in ${elapsed}s, seed ${opts.seed}\n`);
  for (const s of surfaces) process.stdout.write(`  ${String(perSurface.get(s.id)).padStart(8)}  ${s.id}\n`);
  process.stdout.write(`  arms: ${[...perArm].map(([a, n]) => `${a}=${n}`).join(" ")}\n`);
  if (opts.selfTest !== null) {
    // The negative control: the TypeScript decider was told to answer this
    // surface wrongly, so the run PASSES only if the comparison caught it.
    if (findings.length > 0) {
      process.stdout.write(`differential: self-test PASS, caught ${findings.length} injected divergences on ${opts.selfTest}\n`);
      return 0;
    }
    process.stdout.write(`differential: self-test FAIL, the injected fault on ${opts.selfTest} was not caught\n`);
    return 1;
  }
  if (findings.length === 0) {
    process.stdout.write("differential: no divergence\n");
    return 0;
  }
  process.stdout.write(`differential: ${findings.length} divergent cases across ${seenFindings.size} shapes\n`);
  for (const key of seenFindings) process.stdout.write(`  ${key}\n`);
  return 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`differential: ${err.stack ?? err.message}\n`);
    process.exit(2);
  },
);
