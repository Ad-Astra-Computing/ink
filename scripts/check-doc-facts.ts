/**
 * Documented-fact drift check. Every claim below is a value that appears in
 * prose somewhere in the repository and is also derivable from the repository
 * itself. The check recomputes each one from its source of truth and fails on
 * mismatch, so a governance or spec document cannot quietly go stale between
 * releases the way it does when the numbers are transcribed by hand.
 *
 * A checked value carries a `[^ck]` footnote marker in the source document, so
 * a reader can tell which numbers are machine-checked and which are prose. The
 * marker and the claim are bound both ways: a claim whose pattern no longer
 * matches fails, and a marker with no claim behind it fails too.
 *
 * Run `npm run check:facts`. Pass `--write` to regenerate the generated blocks.
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONFIDENTIAL_INTENTS } from "../src/ink/encryption-policy.js";

const repoRoot = fileURLToPath(new URL("../", import.meta.url).href);
const write = process.argv.includes("--write");

const READINESS = "governance/releases/1.0-readiness-evidence.md";
const PROTOCOL_SPEC = "specs/ink-protocol.md";
const CHECKLIST = "specs/ink-compliance-checklist.md";
const PROFILE_SPEC = "specs/ink-conformance-profile.md";
const CARD_SIG_SPEC = "specs/ink-agent-card-signature.md";
const DIST_TAG_PIN = "governance/releases/npm-dist-tags.json";
const MARKER = "[^ck]";

function read(file: string): string {
  return readFileSync(repoRoot + file, "utf8");
}

const errors: string[] = [];
const notes: string[] = [];

function fail(file: string, line: number, id: string, claimed: string, computed: string, hint: string): void {
  errors.push(
    [
      `${file}:${line}: claim \`${id}\` is stale`,
      `      claimed:  ${claimed}`,
      `      computed: ${computed}`,
      `      source:   ${hint}`,
    ].join("\n"),
  );
}

/** Capture group `i` of a match, as a string. Absent groups read as empty. */
function group(match: RegExpMatchArray | RegExpExecArray, i: number): string {
  return match[i] ?? "";
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split("\n").length;
}

// ---------------------------------------------------------------- sources

interface ManifestCategory {
  id: string;
  profile: string;
  caseCount: number;
}
const manifestText = read("conformance/v1/manifest.json");
const manifest = JSON.parse(manifestText) as { categories: ManifestCategory[] };
const categories = manifest.categories;

const manifestSha = createHash("sha256").update(readFileSync(repoRoot + "conformance/v1/manifest.json")).digest("hex");
const totalCategories = categories.length;
const totalVectors = categories.reduce((n, c) => n + c.caseCount, 0);

const profiles = [...new Set(categories.map((c) => c.profile))].sort();
const nonBaseProfiles = profiles.filter((p) => p !== "base");
// `staged` is non-`base` but it is not capability-gated: it holds a category
// that becomes required on a scheduled date rather than one an implementation
// opts into. The capability-profile claim below must not demand it be listed as
// a capability, and the staged claim must not accept a capability in its place.
const STAGED_PROFILE = "staged";
const capabilityProfiles = nonBaseProfiles.filter((p) => p !== STAGED_PROFILE);
function inProfile(profile: string): ManifestCategory[] {
  return categories.filter((c) => c.profile === profile);
}
function profileIds(profile: string): string[] {
  return inProfile(profile).map((c) => c.id).sort();
}
function profileVectors(profile: string): number {
  return inProfile(profile).reduce((n, c) => n + c.caseCount, 0);
}
const baseIds = profileIds("base");

const pkg = JSON.parse(read("package.json")) as { name: string; version: string };
const pin = JSON.parse(read(DIST_TAG_PIN)) as {
  package: string;
  distTags: { latest: string; next: string };
};

const CATEGORY_LIST_SOURCE = "conformance/v1/manifest.json";
const PIN_SOURCE = `${DIST_TAG_PIN} (updated by the release step, verified against npm below)`;

// The published-test-count claim is the only one whose source is a test run
// rather than a file, so it is computed once, here, and reused.
function conformanceCaseCount(): number {
  const dir = mkdtempSync(join(tmpdir(), "ink-facts-"));
  const out = join(dir, "vitest.json");
  try {
    execFileSync(
      repoRoot + "node_modules/.bin/vitest",
      [
        "run",
        "test/conformance.test.ts",
        "test/conformance-manifest.test.ts",
        "--reporter=json",
        `--outputFile=${out}`,
      ],
      { cwd: repoRoot, stdio: ["ignore", "ignore", "inherit"] },
    );
    const report = JSON.parse(readFileSync(out, "utf8")) as { numTotalTests: number };
    return report.numTotalTests;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const NUMBER_WORDS: Record<number, string> = {
  10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
  15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty",
};

// ---------------------------------------------------------------- claims

interface Claim {
  id: string;
  file: string;
  /** Must capture the claimed text in group 1 and end at the `[^ck]` marker. */
  pattern: RegExp;
  expected: string;
  source: string;
  /** Normalizes the captured text before comparison. */
  normalize?: (captured: string) => string;
}

const identifiers = (s: string): string =>
  (s.match(/`[a-z0-9-]+`/g) ?? []).map((x) => x.replace(/`/g, "")).sort().join(", ");
const intentNames = (s: string): string =>
  (s.match(/`[a-z0-9_]+`/g) ?? []).map((x) => x.replace(/`/g, "")).sort().join(", ");
const plain = (s: string): string => s.replace(/`/g, "");

// The confidential-intent set is a protocol fact the code owns; the spec and
// the checklist restate it and must not drift from the exported constant.
const CONFIDENTIAL_INTENT_SOURCE = "src/ink/encryption-policy.ts (CONFIDENTIAL_INTENTS)";
const confidentialIntents = [...CONFIDENTIAL_INTENTS].sort().join(", ");

const claims: Claim[] = [
  {
    id: "encryption.confidential-intents",
    file: PROTOCOL_SPEC,
    pattern: /protocol marks confidential are ([\s\S]*?)\.\[\^ck\]/,
    expected: confidentialIntents,
    source: CONFIDENTIAL_INTENT_SOURCE,
    normalize: intentNames,
  },
  {
    id: "checklist.confidential-intents",
    file: CHECKLIST,
    pattern: /\| E5 \| (.*?) require encryption\[\^ck\] \|/,
    expected: confidentialIntents,
    source: CONFIDENTIAL_INTENT_SOURCE,
    normalize: intentNames,
  },
  {
    id: "release.version",
    file: READINESS,
    pattern: /\| Version \| `([0-9][^`]*)`\[\^ck\] \|/,
    expected: pin.distTags.next,
    source: PIN_SOURCE,
  },
  {
    id: "release.disttags",
    file: READINESS,
    pattern: /\| Current npm dist-tags \| (`latest` = `[^`]+`, `next` = `[^`]+`)\[\^ck\] \|/,
    expected: `latest = ${pin.distTags.latest}, next = ${pin.distTags.next}`,
    source: PIN_SOURCE,
    normalize: plain,
  },
  {
    id: "base.categories",
    file: READINESS,
    pattern: /\*\*(\d+)\*\*\[\^ck\] `base`-profile categories/,
    expected: String(baseIds.length),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "base.vectors",
    file: READINESS,
    pattern: /carrying\s+\*\*(\d+)\*\*\[\^ck\] vectors/,
    expected: String(profileVectors("base")),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "base.members",
    file: READINESS,
    pattern: /They are:\n\n([\s\S]*?)\.\[\^ck\]\n/,
    expected: baseIds.join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: identifiers,
  },
  {
    id: "base.categories.restated",
    file: READINESS,
    pattern: /Nothing outside those (\d+)\[\^ck\] categories/,
    expected: String(baseIds.length),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "corpus.coverage",
    file: READINESS,
    pattern: /- Coverage: \*\*(\d+ categories, \d+ vectors)\*\*\[\^ck\]/,
    expected: `${totalCategories} categories, ${totalVectors} vectors`,
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "corpus.manifest-anchor",
    file: READINESS,
    pattern: /\n  `([0-9a-f]{64})`\[\^ck\]/,
    expected: manifestSha,
    source: "sha256sum conformance/v1/manifest.json",
  },
  {
    id: "reference.test-cases",
    file: READINESS,
    pattern: /\*\*(\d+) test cases\*\*\[\^ck\]/,
    expected: "",
    source: "vitest run test/conformance.test.ts test/conformance-manifest.test.ts",
  },
  {
    id: "corpus.vectors.restated",
    file: READINESS,
    pattern: /covering the full (\d+)-vector\[\^ck\] corpus/,
    expected: String(totalVectors),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "profiles.non-base.count",
    file: READINESS,
    pattern: /The (\d+)\[\^ck\] non-`base` categories/,
    expected: String(totalCategories - baseIds.length),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "profiles.non-base.list",
    file: READINESS,
    pattern: /\| Profile\[\^ck\] \| Status at 1\.0 \|\n\|[^\n]*\|\n([\s\S]*?)\n\n/,
    expected: nonBaseProfiles.join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: identifiers,
  },
  {
    id: "spec.base.count",
    file: PROFILE_SPEC,
    pattern: /The base profile is the ([a-z]+)\[\^ck\] categories tagged/,
    expected: NUMBER_WORDS[baseIds.length] ?? String(baseIds.length),
    source: CATEGORY_LIST_SOURCE,
  },
  {
    id: "spec.base.members",
    file: PROFILE_SPEC,
    pattern: /`profile: "base"` in the manifest:\n\n([\s\S]*?)\.\[\^ck\]\n/,
    expected: baseIds.join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: identifiers,
  },
  {
    id: "spec.base.obligation-rows",
    file: PROFILE_SPEC,
    pattern: /\| Category\[\^ck\] \| Base sender MUST \| Base receiver MUST \|\n\|[^\n]*\|\n([\s\S]*?)\n\n/,
    expected: baseIds.join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: (s) => [...new Set(s.split("\n").map((row) => row.split("|")[1]?.trim() ?? ""))].filter(Boolean).sort().join(", "),
  },
  {
    id: "spec.capability-profiles",
    file: PROFILE_SPEC,
    pattern: /capability it does not fully implement\.\[\^ck\]\n\n([\s\S]*?)\n\n## /,
    expected: capabilityProfiles.map((p) => `${p}(${profileIds(p).join(" ")})`).join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: (s) =>
      [...s.matchAll(/^- \*\*([a-z-]+)\*\* \(((?:`[a-z-]+`(?:, )?)+)\)/gm)]
        .map((m) => `${group(m, 1)}(${(group(m, 2).match(/`([a-z-]+)`/g) ?? []).map((x) => x.replace(/`/g, "")).sort().join(" ")})`)
        .sort()
        .join(", "),
  },
  {
    id: "spec.staged.members",
    file: PROFILE_SPEC,
    pattern: /The\s+staged profile is ((?:`[a-z0-9-]+`(?:, )?)+)\[\^ck\]/,
    expected: profileIds(STAGED_PROFILE).join(", "),
    source: CATEGORY_LIST_SOURCE,
    normalize: identifiers,
  },
  {
    id: "readme.disttag.latest",
    file: "README.md",
    pattern: /On npm, `latest` is `([^`]+)`\[\^ck\]/,
    expected: pin.distTags.latest,
    source: PIN_SOURCE,
  },
  {
    id: "readme.disttag.next",
    file: "README.md",
    pattern: /and `next` is `([^`]+)`\[\^ck\]/,
    expected: pin.distTags.next,
    source: PIN_SOURCE,
  },
];

const testCountClaim = claims.find((c) => c.id === "reference.test-cases");
if (testCountClaim) testCountClaim.expected = String(conformanceCaseCount());

for (const claim of claims) {
  const text = read(claim.file);
  const global = new RegExp(claim.pattern.source, claim.pattern.flags.includes("g") ? claim.pattern.flags : claim.pattern.flags + "g");
  const matches = [...text.matchAll(global)];
  if (matches.length === 0) {
    errors.push(
      `${claim.file}: claim \`${claim.id}\` no longer matches the document.\n` +
        `      Expected to find a machine-checked value matching ${claim.pattern}\n` +
        `      carrying the ${MARKER} marker. Restore the sentence, or drop the claim from\n` +
        `      scripts/check-doc-facts.ts if the fact genuinely no longer belongs in the doc.`,
    );
    continue;
  }
  if (matches.length > 1) {
    errors.push(
      `${claim.file}: claim \`${claim.id}\` matches ${matches.length} places; a claim must be single-sourced.`,
    );
    continue;
  }
  const match = matches[0];
  if (!match) continue;
  const captured = group(match, 1);
  const actual = claim.normalize ? claim.normalize(captured) : captured;
  if (actual !== claim.expected) {
    fail(
      claim.file,
      lineOf(text, match.index ?? 0),
      claim.id,
      actual,
      claim.expected,
      claim.source,
    );
  }
}

// Every `[^ck]` marker in a checked document must be backed by a claim, so a
// marker cannot be sprinkled on a number nothing recomputes.
const markerFiles = [...new Set(claims.map((c) => c.file))];
for (const file of markerFiles) {
  const text = read(file);
  const markers = text.split(MARKER).length - 1;
  const expected = claims.filter((c) => c.file === file).length + 1; // +1 for the footnote definition
  if (markers !== expected) {
    errors.push(
      `${file}: found ${markers} \`${MARKER}\` markers but ${expected - 1} claims plus one footnote definition.\n` +
        `      Every marked value must have a claim in scripts/check-doc-facts.ts, and every claim must mark its value.`,
    );
  }
  if (!text.includes(`${MARKER}: Machine-checked`)) {
    errors.push(`${file}: missing the \`${MARKER}\` footnote definition that tells a reader the marked values are recomputed.`);
  }
}

// ------------------------------------------------ compliance checklist rows

/**
 * The Vectors column of a checklist requirement row names the conformance
 * categories whose vectors pin the row, by manifest id. The column used to
 * carry file names from a pre-corpus scheme that rotted silently when the
 * corpus was built, so it is now gated: every cited id must exist in the
 * manifest, and the coverage matrix in the checklist is rendered from the
 * rows rather than transcribed.
 */
interface ChecklistRow {
  id: string;
  vectors: string[];
}
const checklistRows: ChecklistRow[] = [];
{
  const categoryIds = new Set(categories.map((c) => c.id));
  read(CHECKLIST)
    .split("\n")
    .forEach((line, i) => {
      const row = /^\| ([A-Z]+\d+[a-z]?) \|/.exec(line);
      if (!row) return;
      // Split on unescaped pipes only; a `\|` inside a code span is content.
      const cells = line.split(/(?<!\\)\|/);
      if (cells.length !== 9) return;
      const cell = (cells[6] ?? "").trim();
      const cited = cell === "," || cell === "" ? [] : cell.split(",").map((s) => s.trim());
      const ids: string[] = [];
      for (const entry of cited) {
        const id = /^`([a-z0-9-]+)`$/.exec(entry);
        if (!id) {
          errors.push(
            `${CHECKLIST}:${i + 1}: row ${row[1]} cites ${JSON.stringify(entry)} in its Vectors column; ` +
              "each entry must be a backticked conformance category id, or the cell must be the empty marker `,`.",
          );
          continue;
        }
        if (!categoryIds.has(group(id, 1))) {
          errors.push(
            `${CHECKLIST}:${i + 1}: row ${row[1]} cites conformance category \`${group(id, 1)}\`, ` +
              "which is not in conformance/v1/manifest.json.",
          );
          continue;
        }
        ids.push(group(id, 1));
      }
      checklistRows.push({ id: group(row, 1), vectors: ids });
    });
}

// ------------------------------------------------------- generated blocks

interface GeneratedBlock {
  id: string;
  file: string;
  render: () => string;
}

const generated: GeneratedBlock[] = [
  {
    id: "profile-coverage-table",
    file: READINESS,
    render: () => {
      const rows = [...profiles]
        .sort((a, b) => profileVectors(b) - profileVectors(a) || a.localeCompare(b))
        .map((p) => `| \`${p}\` | ${inProfile(p).length} | ${profileVectors(p)} |`);
      return [
        "*Generated from `conformance/v1/manifest.json`. Regenerate with `npm run check:facts -- --write`.*",
        "",
        "| Profile | Categories | Vectors |",
        "|---------|-----------:|--------:|",
        ...rows,
      ].join("\n");
    },
  },
  {
    id: "checklist-vector-matrix",
    file: CHECKLIST,
    render: () => {
      const rows = [...categories]
        .sort((a, b) => a.id.localeCompare(b.id))
        .map((c) => {
          const cited = checklistRows.filter((r) => r.vectors.includes(c.id)).map((r) => r.id);
          return `| \`${c.id}\` | \`${c.profile}\` | ${c.caseCount} | ${cited.length > 0 ? cited.join(", ") : "none"} |`;
        });
      const citedCategories = categories.filter((c) => checklistRows.some((r) => r.vectors.includes(c.id))).length;
      const pinnedRows = checklistRows.filter((r) => r.vectors.length > 0).length;
      return [
        "*Generated from `conformance/v1/manifest.json` and the Vectors column of the rows above. Regenerate with `npm run check:facts -- --write`.*",
        "",
        "| Category | Profile | Cases | Rows citing it |",
        "|----------|---------|------:|----------------|",
        ...rows,
        "",
        `${pinnedRows} of ${checklistRows.length} requirement rows cite at least one category; ${citedCategories} of ${categories.length} categories are cited by at least one row; the corpus holds ${totalVectors} cases.`,
      ].join("\n");
    },
  },
];

for (const block of generated) {
  const text = read(block.file);
  const begin = `<!-- BEGIN GENERATED ${block.id} -->`;
  const end = `<!-- END GENERATED ${block.id} -->`;
  const pattern = new RegExp(`${begin.replace(/[[\]]/g, "\\$&")}\\n([\\s\\S]*?)\\n${end}`);
  const match = pattern.exec(text);
  if (!match) {
    errors.push(`${block.file}: generated block \`${block.id}\` is missing its ${begin} / ${end} fences.`);
    continue;
  }
  const rendered = block.render();
  if (group(match, 1) === rendered) continue;
  if (write) {
    writeFileSync(repoRoot + block.file, text.replace(pattern, `${begin}\n${rendered}\n${end}`));
    notes.push(`rewrote generated block \`${block.id}\` in ${block.file}`);
    continue;
  }
  errors.push(
    `${block.file}:${lineOf(text, match.index)}: generated block \`${block.id}\` is out of date.\n` +
      `      Run \`npm run check:facts -- --write\` and commit the result. Diff:\n` +
      diffLines(group(match, 1), rendered),
  );
}

function diffLines(actual: string, expected: string): string {
  const a = actual.split("\n");
  const b = expected.split("\n");
  const out: string[] = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === b[i]) continue;
    if (a[i] !== undefined) out.push(`        - ${a[i]}`);
    if (b[i] !== undefined) out.push(`        + ${b[i]}`);
  }
  return out.join("\n");
}

// -------------------------------------------------- single-sourced prose

/**
 * A normative statement belongs in exactly one place. These rules keep a second
 * copy from appearing: the owning document states the rule, every other
 * document points at it, and restating a load-bearing parameter elsewhere is an
 * error rather than a divergence waiting to happen.
 */
const SOAK_OWNER = `${READINESS}#2-soak-exit-criteria`;
const soakGovernance = read("GOVERNANCE.md");
if (!soakGovernance.includes(SOAK_OWNER)) {
  errors.push(
    `GOVERNANCE.md: must reference the soak exit criteria at \`${SOAK_OWNER}\` rather than restating them.`,
  );
}
const SOAK_PARAMETERS = [
  /\b60 evidenced days\b/,
  /\b95%/,
  /\b14 days\b/,
  /\b7 consecutive days\b/,
  /nightly shadow census/i,
  /attested synthetic exchange/i,
];
for (const parameter of SOAK_PARAMETERS) {
  const match = parameter.exec(soakGovernance);
  if (match) {
    errors.push(
      `GOVERNANCE.md:${lineOf(soakGovernance, match.index)}: restates a soak exit criterion (${JSON.stringify(match[0])}).\n` +
        `      The criteria are owned by ${READINESS} §2. Link to it instead; a second copy drifts.`,
    );
  }
}

// The "no independent security audit" statement is normative and is asserted by
// the readiness record to be present in these three files. Softening it in one
// place without the others is exactly the drift this gate exists to stop.
const AUDIT_STATEMENT = [
  { file: "SECURITY.md", pattern: /has not undergone an independent security audit/ },
  { file: "docs/threat-model.md", pattern: /has not undergone an independent security audit/ },
  { file: "docs/maturity.md", pattern: /\*\*not\*\* undergone an independent security audit/ },
];
for (const { file, pattern } of AUDIT_STATEMENT) {
  if (!pattern.test(read(file))) {
    errors.push(
      `${file}: the "no independent security audit" statement is missing or reworded.\n` +
        `      ${READINESS} §1.3 asserts it stands in this file and MUST NOT be softened.`,
    );
  }
}

// The Agent Card signature phase clock: the 90-day floor is owned by the spec,
// and the readiness record's floor date is derived from it plus the Phase B
// ship date. Two documents, one rule.
const cardSig = read(CARD_SIG_SPEC);
const windowMatch = /minimum of (\d+) days between the Phase B ship \(([0-9.]+)\)/.exec(cardSig);
if (!windowMatch) {
  errors.push(`${CARD_SIG_SPEC}: could not find the normative Phase B to Phase C window statement.`);
} else {
  const windowDays = Number(group(windowMatch, 1));
  const phaseBVersion = group(windowMatch, 2);
  const readiness = read(READINESS);
  const shipMatch = /reached Phase B in `([0-9.]+)`, shipped (\d{4}-\d{2}-\d{2})/.exec(readiness);
  const floorMatch = /\*\*Phase C MUST NOT begin before (\d{4}-\d{2}-\d{2})\*\* \((\d{4}-\d{2}-\d{2}) plus (\d+) days\)/.exec(readiness);
  if (!shipMatch || !floorMatch) {
    errors.push(`${READINESS}: could not find the Phase B ship date and the Phase C floor sentence.`);
  } else {
    const shipVersion = group(shipMatch, 1);
    const shipDate = group(shipMatch, 2);
    const claimedFloor = group(floorMatch, 1);
    const claimedShipDate = group(floorMatch, 2);
    const claimedWindow = group(floorMatch, 3);
    if (shipVersion !== phaseBVersion) {
      fail(READINESS, lineOf(readiness, shipMatch.index), "phase-c.version", shipVersion, phaseBVersion, CARD_SIG_SPEC);
    }
    if (Number(claimedWindow) !== windowDays) {
      fail(READINESS, lineOf(readiness, floorMatch.index), "phase-c.window", claimedWindow, String(windowDays), `${CARD_SIG_SPEC} §10`);
    }
    if (claimedShipDate !== shipDate) {
      fail(READINESS, lineOf(readiness, floorMatch.index), "phase-c.ship-date", claimedShipDate, shipDate, `${READINESS} phase clock`);
    }
    const floor = new Date(`${shipDate}T00:00:00Z`);
    floor.setUTCDate(floor.getUTCDate() + windowDays);
    const computed = floor.toISOString().slice(0, 10);
    if (claimedFloor !== computed) {
      fail(READINESS, lineOf(readiness, floorMatch.index), "phase-c.floor", claimedFloor, computed, `${shipDate} plus ${windowDays} days`);
    }
  }
}

// The changelog must carry a section for the version in package.json, so a
// version bump cannot ship without its release notes.
const changelogTop = /^## ([0-9]+\.[0-9]+\.[0-9]+[^,\n]*)/m.exec(read("CHANGELOG.md"));
if (!changelogTop) {
  errors.push("CHANGELOG.md: no versioned section found.");
} else if (group(changelogTop, 1) !== pkg.version) {
  fail("CHANGELOG.md", 1, "changelog.version", group(changelogTop, 1), pkg.version, "package.json version");
}

// ------------------------------------------------- second-implementation version

/**
 * The Go verifier reports a version constant, and it names the protocol and
 * library version the binary was built against. A binary that reports a version
 * it is not is an interop-debugging trap: a bug report quotes a version the
 * source never matched. The constant is derivable from package.json, so it is
 * gated rather than transcribed.
 *
 * The gate reads the constant as text. It needs no Go toolchain, so it runs in
 * the same job as its sibling checks and cannot skip on a runner without Go. A
 * missing file, a moved constant or a reformatted declaration is a failure, not
 * a pass: there is no path through this block that finds nothing and shrugs.
 */
const GO_CLI_SOURCE = "go/internal/cli/cli.go";
const GO_VERSION_PATTERN = /^const Version = "([^"]*)"$/m;
let goCli = "";
try {
  goCli = read(GO_CLI_SOURCE);
} catch (err) {
  errors.push(
    `${GO_CLI_SOURCE}: cannot read the Go CLI version constant (${err instanceof Error ? err.message : String(err)}).\n` +
      `      This gate keeps the Go binary's reported version equal to package.json. If the file moved,\n` +
      `      point GO_CLI_SOURCE in scripts/check-doc-facts.ts at its new home.`,
  );
}
if (goCli) {
  const goVersion = GO_VERSION_PATTERN.exec(goCli);
  if (!goVersion) {
    errors.push(
      `${GO_CLI_SOURCE}: no \`const Version = "..."\` declaration found.\n` +
        `      The Go binary's reported version is gated against package.json and must stay a single\n` +
        `      top-level string constant matching ${GO_VERSION_PATTERN} so it can be compared without a Go toolchain.`,
    );
  } else if (group(goVersion, 1) !== pkg.version) {
    fail(
      GO_CLI_SOURCE,
      lineOf(goCli, goVersion.index),
      "go.cli.version",
      group(goVersion, 1),
      pkg.version,
      "package.json version",
    );
  }
}

// ------------------------------------------------------------ npm dist-tags

/**
 * Offline the dist-tag claims are checked against the committed pin, which the
 * release step updates, so the gate is never network-dependent for a claim it
 * can settle from the repository. The pin itself is then verified against the
 * registry when the registry is reachable. A missed verification is announced
 * in the log rather than passing quietly, and CI sets CHECK_FACTS_REQUIRE_NPM
 * so that on CI an unreachable registry is a failure and not a shrug.
 */
if (pin.package !== pkg.name) {
  errors.push(`${DIST_TAG_PIN}: pins dist-tags for \`${pin.package}\`, but package.json is \`${pkg.name}\`.`);
}

function semverParts(v: string): number[] {
  return (v.split("-")[0] ?? v).split(".").map(Number);
}
function isNewer(a: string, b: string): boolean {
  const x = semverParts(a);
  const y = semverParts(b);
  for (let i = 0; i < 3; i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  }
  return false;
}

const requireNpm = process.env.CHECK_FACTS_REQUIRE_NPM === "1";
let live: { latest?: string; next?: string } | null = null;
let liveError = "";
try {
  const out = execFileSync("npm", ["view", pkg.name, "dist-tags", "--json"], {
    encoding: "utf8",
    timeout: 30_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  live = JSON.parse(out) as { latest?: string; next?: string };
} catch (err) {
  liveError = err instanceof Error ? (err.message.split("\n")[0] ?? err.message) : String(err);
}

if (live) {
  for (const tag of ["latest", "next"] as const) {
    const published = live[tag];
    const pinned = pin.distTags[tag];
    if (!published) {
      errors.push(`npm: dist-tag \`${tag}\` is absent from the registry but pinned as \`${pinned}\` in ${DIST_TAG_PIN}.`);
      continue;
    }
    if (published === pinned) continue;
    if (isNewer(published, pinned)) {
      errors.push(
        `${DIST_TAG_PIN}: pinned \`${tag}\` = \`${pinned}\`, but npm now serves \`${published}\`.\n` +
          `      The pin is stale, so every document that quotes a dist-tag is stale too.\n` +
          `      Update ${DIST_TAG_PIN} and rerun \`npm run check:facts\` to see which documents need the new value.`,
      );
    } else {
      notes.push(
        `npm dist-tag \`${tag}\` is \`${published}\`, behind the pinned \`${pinned}\`. ` +
          "Expected while a release is cut and not yet published; it becomes an error once the registry moves past the pin.",
      );
    }
  }
} else if (requireNpm) {
  errors.push(
    `npm dist-tag verification could not run and CHECK_FACTS_REQUIRE_NPM=1: ${liveError}\n` +
      `      The offline claims against ${DIST_TAG_PIN} still ran, but the pin itself is unverified.`,
  );
} else {
  notes.push(
    `SKIPPED: npm dist-tag verification (${liveError}). The pinned values in ${DIST_TAG_PIN} were used ` +
      "for the document claims and were NOT verified against the registry. Set CHECK_FACTS_REQUIRE_NPM=1 to make this a failure.",
  );
}

// ------------------------------------------------------------------ report

for (const note of notes) {
  // A skipped verification goes to stderr, and to the workflow log as an
  // annotation, so it cannot pass as a clean run at a glance.
  if (note.startsWith("SKIPPED")) {
    if (process.env.GITHUB_ACTIONS === "true") console.error(`::warning title=check:facts::${note}`);
    console.error(`WARNING: ${note}`);
  } else {
    console.log(`note: ${note}`);
  }
}

if (errors.length) {
  console.error("");
  console.error(`Documented-fact drift detected (${errors.length}):`);
  console.error("");
  for (const e of errors) console.error(`  - ${e}\n`);
  console.error("Each claim above is recomputed from the repository. Fix the document to match the");
  console.error("computed value, or change the source of truth. Claims live in scripts/check-doc-facts.ts.");
  process.exit(1);
}

const blockWord = generated.length === 1 ? "generated block" : "generated blocks";
console.log(`Documented facts OK (${claims.length} claims, ${generated.length} ${blockWord}).`);
