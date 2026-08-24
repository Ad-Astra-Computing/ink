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
// A find string that no longer matches is an ERROR, not a skip. It means the
// module changed and the registry rotted, and a rotted registry silently stops
// proving anything.
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
  const path = join(root, m.file);
  const original = readFileSync(path, "utf8");
  if (!original.includes(m.find)) {
    stale.push(m.id);
    console.log(`stale    ${m.id}: find string no longer present in ${m.file}`);
    continue;
  }
  writeFileSync(path, original.replace(m.find, m.replace));
  try {
    const caught = !suitePasses();
    console.log(`${caught ? "caught  " : "SURVIVED"} ${m.id}  (${m.rule})`);
    if (!caught) survivors.push(m.id);
  } finally {
    writeFileSync(path, original);
  }
}

// Restore is per-mutant, but verify the end state anyway: a harness that
// leaves a mutant behind would be worse than no harness.
if (!suitePasses()) {
  console.error("the suite is red AFTER restoration; the working tree is dirty");
  process.exit(1);
}

if (stale.length || survivors.length) {
  if (stale.length) console.error(`\n${stale.length} stale mutant(s): ${stale.join(", ")}`);
  if (survivors.length)
    console.error(`${survivors.length} surviving mutant(s): ${survivors.join(", ")}`);
  process.exit(1);
}
console.log(`\nall ${mutants.length} mutants caught`);
