// Is the live INK test receiver running the library everyone else installs?
//
//   node scripts/check-receiver-freshness.mjs [dist-tag]
//
// The receiver at ink-echo.tulpa.network is built only on the published
// @adastracomputing/ink package and deployed by hand. Nothing else in this
// repository can tell a current deployment from one running a release behind,
// and a stale receiver is not a visible failure: the published-artifact e2e
// still passes against it and reports interop for a pairing nobody meant to
// ship. This asks the one question that catches it.
//
// Deliberately NOT part of the post-publish e2e. At that moment the receiver
// CANNOT be current, because the package it is built from reached npm seconds
// earlier. A check that is red for a reason no action can fix is a check
// people learn to skip. This one goes red for one reason, names one action,
// and goes green when that action is taken, so it is also worth running by
// hand straight after a deploy.
//
// What it does NOT catch: the receiver's own source changing after the last
// deploy. Only the library version is compared, so a receiver built from an
// older commit of examples/reference-receiver reads as current as long as the
// dependency matches. The deployment id is printed for correlation, not
// compared. Read a pass as "running the published library", not "matches main".
//
// Environment overrides:
//   INK_RECEIVER_BUILD_URL  build route (default the public echo receiver)
//   INK_E2E_TIMEOUT_MS      per-request timeout (default 15000)
const TAG = process.argv[2] ?? "latest";
const BUILD_URL = process.env.INK_RECEIVER_BUILD_URL ?? "https://ink-echo.tulpa.network/_build";
const TIMEOUT_MS = Number(process.env.INK_E2E_TIMEOUT_MS ?? 15000);
// Scope slash percent-encoded, the form the npm CLI itself requests.
const REGISTRY = "https://registry.npmjs.org/-/package/@adastracomputing%2fink/dist-tags";

async function getJson(url, what) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`${what}: HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// An infrastructure failure is labelled as one and never as staleness. The two
// need different responses, and a flaky morning that looks like a stale
// receiver trains exactly the habit this check is designed against.
let tags;
try {
  tags = await getJson(REGISTRY, "registry dist-tags");
} catch (err) {
  console.error(`[ERROR] could not reach the npm registry: ${err instanceof Error ? err.message : err}`);
  console.error("This says nothing about the receiver. Re-run the workflow.");
  process.exit(2);
}
const published = tags[TAG];
if (!published) {
  console.error(`[FAIL] the registry has no '${TAG}' dist-tag for @adastracomputing/ink`);
  process.exit(1);
}

let build;
try {
  build = await getJson(BUILD_URL, "receiver build route");
} catch (err) {
  // A 404 here is not an infrastructure problem. The build route ships with
  // the receiver, so a receiver that does not serve it predates the route and
  // is stale by definition.
  const message = err instanceof Error ? err.message : String(err);
  if (message.includes("404")) {
    // Not an infrastructure problem. The build route ships with the receiver,
    // so a receiver that does not serve it predates the route and is stale by
    // definition.
    console.error(`[FAIL] ${BUILD_URL} returned 404.`);
    console.error("The deployment predates the build route, so it is at least that old. Redeploy it.");
    process.exit(1);
  }
  console.error(`[ERROR] could not reach the receiver: ${message}`);
  console.error("This says nothing about which build is deployed. Re-run the workflow.");
  process.exit(2);
}
const deployed = build.ink;

console.log(`registry ${TAG}: ${published}`);
console.log(`receiver:       ${deployed} (deployment ${build.deployment})`);

if (deployed !== published) {
  console.error(
    `\n[FAIL] the live receiver is running ${deployed}, not ${published}.\n\n`
      + `Interop results against it describe a pairing nobody ships. To fix:\n`
      + `  1. set @adastracomputing/ink to ^${published} in examples/reference-receiver/package.json\n`
      + `  2. npm install && npm run typecheck && npm test in that directory\n`
      + `  3. npx wrangler deploy\n`
      + `  4. re-run this workflow to confirm it goes green\n`,
  );
  process.exit(1);
}

console.log(`\n[OK] the live receiver is running the ${TAG} release.`);
