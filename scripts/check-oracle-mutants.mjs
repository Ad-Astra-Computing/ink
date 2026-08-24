// Prove the independent oracle bites. For each registered mutant this disables
// one rule in conformance/v1/independent/ (or in the oracle test itself), runs
// the oracle suite, and requires the suite to FAIL. A mutant the suite survives
// means the rule it disables is constrained by nothing, which is the hole a
// wrong implementation would pass through.
//
// This exists because the 1.0 readiness record cites mutation results as
// evidence the oracle is not vacuous. A demonstration performed once by hand
// decays the moment the suite changes; a committed harness re-earns the claim
// on every run. governance/releases/1.0-readiness-evidence.md §1 requires it to
// hold at the soak-anchoring cut.
//
// The harness mutates tracked files in place, so it defends the tree three
// ways. It refuses to start unless every file it will touch is clean in git,
// which makes `git checkout -- <file>` the complete recovery from any crash it
// cannot intercept. It snapshots every file up front and restores from the
// snapshots on exit, including SIGINT and SIGTERM. And after restoring it runs
// `git diff --exit-code` over the touched files, so "restored" means
// byte-identical to HEAD rather than merely green.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const registry = JSON.parse(
  readFileSync(join(root, "conformance/v1/independent/mutants.json"), "utf8"),
);

const only = process.argv.slice(2);
const mutants = only.length
  ? registry.mutants.filter((m) => only.includes(m.id))
  : registry.mutants;

const files = [...new Set(mutants.map((m) => m.file))];

function git(...args) {
  return execFileSync("git", args, { cwd: root, stdio: "pipe" });
}

// Refuse a dirty target: with clean targets, recovery from anything up to and
// including SIGKILL is `git checkout -- <files>`, and the final diff check
// below is meaningful.
try {
  git("diff", "--exit-code", "--", ...files);
  git("diff", "--cached", "--exit-code", "--", ...files);
} catch {
  console.error(
    "refusing to run: a file this harness mutates has uncommitted changes.\n" +
      `files: ${files.join(", ")}`,
  );
  process.exit(1);
}

const snapshots = new Map(files.map((f) => [f, readFileSync(join(root, f), "utf8")]));
let restored = false;
function restoreAll() {
  if (restored) return;
  for (const [f, contents] of snapshots) writeFileSync(join(root, f), contents);
  restored = true;
}
process.on("exit", restoreAll);
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => {
    restoreAll();
    process.exit(130);
  });
}

function suitePasses() {
  try {
    execFileSync("npx", ["vitest", "run", "test/conformance-independent.test.ts"], {
      cwd: root,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

// The suite must pass on the pristine tree first, or a pre-existing failure
// would make every mutant look caught.
process.stdout.write("baseline: ");
if (!suitePasses()) {
  console.error("FAIL. The oracle suite is red before any mutation; fix that first.");
  process.exit(1);
}
console.log("suite passes");

const survivors = [];
const stale = [];

for (const m of mutants) {
  const original = snapshots.get(m.file);
  if (!original.includes(m.find)) {
    stale.push(m.id);
    console.log(`stale    ${m.id}: find string no longer present in ${m.file}`);
    continue;
  }
  writeFileSync(join(root, m.file), original.replace(m.find, m.replace));
  const caught = !suitePasses();
  writeFileSync(join(root, m.file), original);
  console.log(`${caught ? "caught  " : "SURVIVED"} ${m.id}  (${m.rule})`);
  if (!caught) survivors.push(m.id);
}

restoreAll();

// Byte-identical to HEAD, not merely green: a botched restore that left
// semantically equivalent source would pass a test run and still be a lie.
try {
  git("diff", "--exit-code", "--", ...files);
} catch {
  console.error("a touched file differs from HEAD after restoration");
  process.exit(1);
}

if (stale.length || survivors.length) {
  if (stale.length) console.error(`\n${stale.length} stale mutant(s): ${stale.join(", ")}`);
  if (survivors.length)
    console.error(`${survivors.length} surviving mutant(s): ${survivors.join(", ")}`);
  process.exit(1);
}
console.log(`\nall ${mutants.length} mutants caught`);
