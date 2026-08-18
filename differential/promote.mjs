#!/usr/bin/env node
// Promote a divergence into the conformance corpus.
//
//   node differential/promote.mjs differential/findings/<surface>/<file>.json --expect reject
//
// A differential harness is only worth running if what it finds becomes
// permanent. This turns a finding into the exact case block the conformance
// generator wants, prints where it goes and prints the commands that regenerate
// and re-verify the corpus. It deliberately does not edit
// conformance/v1/generate.mjs itself: the corpus vectors and their SHA-256s are
// pinned in manifest.json and referenced by release evidence, so the edit is a
// reviewed change, not a side effect of a fuzz run.

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const args = process.argv.slice(2);
if (args.length === 0 || args.includes("--help")) {
  process.stdout.write(`promote.mjs <finding.json> [--expect accept|reject] [--case-id ID]

Prints the conformance case block for a finding, and the steps to land it.
--expect is the agreed decision for the input, which is a judgement call: the
harness proves the two implementations disagree, not which one is right.
`);
  process.exit(0);
}

const path = args[0];
const expect = args[args.indexOf("--expect") + 1] ?? null;
const caseIdArg = args.includes("--case-id") ? args[args.indexOf("--case-id") + 1] : null;

const finding = JSON.parse(readFileSync(path, "utf8"));
if (finding.format !== "ink.differential.finding.v1") {
  throw new Error(`${path}: not an ink.differential.finding.v1 file`);
}

// The surface id is the conformance category id by construction, and the input
// shape is the category's input shape, so the case block needs no translation.
const category = finding.conformanceCategory ?? finding.surface;
const caseId = caseIdArg ?? `${category}-diff-${basename(path).replace(/\.json$/, "").split("-").pop()}`;

const block = {
  caseId,
  description: `Differential finding: ${finding.detail}. Fill in why this input decides the way it does.`,
  input: finding.minimized,
  expect: expect ? { result: expect } : { result: "TODO accept|reject" },
};

process.stdout.write(`# ${path}
# surface ${finding.surface}, kind ${finding.kind}
# typescript: ${JSON.stringify(finding.decisions.minimized.typescript)}
# go:         ${JSON.stringify(finding.decisions.minimized.go)}

Case block for the ${category} category:

${JSON.stringify(block, null, 2)}

Steps to land it:

  1. Decide which side is right. The harness proves only that they disagree.
     If the spec does not say, the spec is the thing to change first: write the
     rule into specs/, then make both implementations follow it.
  2. Fix the implementation that was wrong, with a unit test in its own suite.
  3. Add the case above to the ${category} block in conformance/v1/generate.mjs,
     with a description that says why it decides that way.
  4. Regenerate and re-verify:

       node conformance/v1/generate.mjs
       npm test
       (cd go && go test ./...)

     generate.mjs rewrites the vector file and the manifest caseCount and
     sha256 from the same bytes, so nothing is hand-maintained.
  5. Re-run the harness on the surface to confirm the finding is gone:

       node differential/run.mjs --surfaces ${finding.surface} --cases 50000 --seed ${finding.runSeed}

  6. Delete the finding file. The corpus is now the permanent record.
`);
