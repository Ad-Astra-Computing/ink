// Two workflow trust checks that existing tooling does not cover. Both exist
// because a real bug got past review on 2026-08-26.
//
//   node scripts/check-workflow-trust.mjs [--selftest]
//
// 1. CREDENTIALED JOBS MUST NOT RUN INSTALL HOOKS.
//    A job holding `id-token: write`, `contents: write`, or any `secrets.*`
//    reference must not run `npm ci`/`npm install` without --ignore-scripts.
//    npm runs dependency preinstall/install/postinstall hooks by default, so
//    that combination puts third-party code next to a release credential. This
//    is the Shai-Hulud vector. zizmor returns CLEAN on it, which is why this
//    check is hand-written rather than delegated.
//
//    This is necessary, not sufficient: a credentialed job that runs vitest or
//    tsc still executes third-party code. Closing that needs the gauntlet split
//    out of the publish job, which this check cannot express.
//
// 2. PINNED ACTION SHAS MUST BE REAL.
//    Every `uses: owner/repo@<sha>` must be a 40-hex commit that actually
//    exists upstream. A fabricated SHA is self-consistent, so comparing pins to
//    each other does not catch one. Resolution needs the network, so it is
//    skipped when offline or unauthenticated and reported as SKIPPED rather
//    than silently passing.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const WORKFLOW_DIR = ".github/workflows";
const selftest = process.argv.includes("--selftest");

// Deliberately line-based rather than YAML-parsed. The question is "which job
// is this line in", and job boundaries are two-space keys under `jobs:`, which
// is cheap to track exactly and keeps the check dependency-free.
function parseJobs(text) {
  const lines = text.split("\n");
  const jobs = [];
  let inJobs = false;
  let current = null;
  lines.forEach((line, i) => {
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      return;
    }
    if (!inJobs) return;
    // A new job header: exactly two spaces of indent, then `name:`.
    const header = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
    if (header) {
      current = { name: header[1], start: i + 1, lines: [] };
      jobs.push(current);
      return;
    }
    // Column 0 content ends the jobs block.
    if (/^\S/.test(line) && line.trim() !== "") {
      inJobs = false;
      current = null;
      return;
    }
    if (current) current.lines.push({ n: i + 1, text: line });
  });
  return jobs;
}

const CREDENTIAL_PATTERNS = [
  { re: /id-token:\s*write/, what: "id-token: write" },
  { re: /contents:\s*write/, what: "contents: write" },
  { re: /\$\{\{\s*secrets\./, what: "a secrets.* reference" },
];
const INSTALL_RE = /\bnpm\s+(ci|install)\b/;

function checkInstallHooks(file, text) {
  const findings = [];
  for (const job of parseJobs(text)) {
    const body = job.lines.map((l) => l.text).join("\n");
    const creds = CREDENTIAL_PATTERNS.filter((p) => p.re.test(body)).map((p) => p.what);
    if (creds.length === 0) continue;
    for (const { n, text: line } of job.lines) {
      if (!INSTALL_RE.test(line)) continue;
      // A comment mentioning the command is not the command.
      if (/^\s*#/.test(line)) continue;
      if (/--ignore-scripts/.test(line)) continue;
      findings.push(
        `${file}:${n}: job "${job.name}" holds ${creds.join(" and ")} and installs ` +
          `without --ignore-scripts, so dependency install hooks would run beside the credential\n` +
          `      ${line.trim()}`,
      );
    }
  }
  return findings;
}

function collectPins(file, text) {
  const pins = [];
  text.split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    const m = line.match(/uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+)@([0-9a-f]{40})\b/);
    if (m) pins.push({ file, line: i + 1, action: m[1], sha: m[2] });
    const unpinned = line.match(/uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+)@(?![0-9a-f]{40}\b)(\S+)/);
    if (unpinned) pins.push({ file, line: i + 1, action: unpinned[1], sha: null, ref: unpinned[2] });
  });
  return pins;
}

// Returns "ok", "missing", or "unavailable". Distinguishing the last two is the
// whole point: 404/422 means the pin names a commit that does not exist, which
// is a hard failure, while a network or rate-limit error means we learned
// nothing and must say so instead of passing.
//
// Uses fetch rather than the `gh` CLI so the check has no tooling dependency:
// `gh` is not in the devshell, so shelling out to it would make this SKIP
// forever in CI, which is worse than not having the check. GITHUB_TOKEN is used
// when present purely to lift the unauthenticated rate limit.
async function resolvePin(pin) {
  const repo = pin.action.split("/").slice(0, 2).join("/");
  const headers = { accept: "application/vnd.github+json", "user-agent": "ink-workflow-trust" };
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`https://api.github.com/repos/${repo}/commits/${pin.sha}`, { headers });
  } catch {
    return "unavailable";
  }
  if (res.status === 404 || res.status === 422) return "missing";
  if (!res.ok) return "unavailable";
  const body = await res.json().catch(() => null);
  if (!body || typeof body.sha !== "string") return "unavailable";
  return body.sha.toLowerCase() === pin.sha.toLowerCase() ? "ok" : "missing";
}

// ── self-test ─────────────────────────────────────────────────────────────
// A check that cannot fail is not a check. These are the two shapes that got
// past review; if the detector stops catching them it is broken.
if (selftest) {
  const vulnerable = `
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - run: npm ci
  safe:
    permissions:
      contents: read
    steps:
      - run: npm ci
`;
  const fixed = vulnerable.replace("run: npm ci\n  safe", "run: npm ci --ignore-scripts\n  safe");
  const a = checkInstallHooks("t.yml", vulnerable);
  const b = checkInstallHooks("t.yml", fixed);
  const problems = [];
  if (a.length !== 1) problems.push(`expected 1 finding on the vulnerable shape, got ${a.length}`);
  if (!a[0]?.includes('job "publish"')) problems.push("finding did not name the credentialed job");
  if (b.length !== 0) problems.push(`expected 0 findings once --ignore-scripts is present, got ${b.length}`);
  const uncredentialed = checkInstallHooks("t.yml", "jobs:\n  x:\n    permissions:\n      contents: read\n    steps:\n      - run: npm ci\n");
  if (uncredentialed.length !== 0) problems.push("flagged an uncredentialed job");
  const fakePin = collectPins("t.yml", "      - uses: actions/setup-node@" + "a".repeat(40) + " # v6\n");
  if (fakePin.length !== 1 || fakePin[0].sha !== "a".repeat(40)) problems.push("did not collect a pinned SHA");
  if (problems.length) {
    console.error("SELFTEST FAILED:\n  " + problems.join("\n  "));
    process.exit(1);
  }
  console.log("selftest: detector catches the credentialed-install shape and clears the fixed one");
  process.exit(0);
}

// ── run ───────────────────────────────────────────────────────────────────
const files = readdirSync(WORKFLOW_DIR)
  .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
  .sort();

let failures = 0;
const allPins = [];

for (const f of files) {
  const path = join(WORKFLOW_DIR, f);
  const text = readFileSync(path, "utf8");
  const hookFindings = checkInstallHooks(f, text);
  for (const finding of hookFindings) {
    console.error(`FAIL  ${finding}`);
    failures += 1;
  }
  allPins.push(...collectPins(f, text));
}

for (const pin of allPins.filter((p) => p.sha === null)) {
  console.error(`FAIL  ${pin.file}:${pin.line}: ${pin.action}@${pin.ref} is not pinned to a 40-hex commit`);
  failures += 1;
}

const pinned = allPins.filter((p) => p.sha !== null);
const unique = [...new Map(pinned.map((p) => [`${p.action}@${p.sha}`, p])).values()];
let resolved = 0;
let skipped = false;
for (const pin of unique) {
  const verdict = await resolvePin(pin);
  if (verdict === "ok") {
    resolved += 1;
  } else if (verdict === "missing") {
    console.error(
      `FAIL  ${pin.file}:${pin.line}: ${pin.action}@${pin.sha} is not a real commit in that action's repo`,
    );
    failures += 1;
  } else {
    // Offline, unauthenticated, or rate limited. Say so; do not pass silently.
    skipped = true;
    break;
  }
}

console.log(`checked ${files.length} workflow file(s), ${unique.length} unique action pin(s)`);
if (skipped) {
  console.log("SKIPPED action SHA resolution (no network or no gh auth); pins were not verified upstream");
} else {
  console.log(`verified ${resolved} action pin(s) resolve upstream`);
}

if (failures > 0) {
  console.error(`\n${failures} workflow trust failure(s)`);
  process.exit(1);
}
console.log("workflow trust checks passed");
