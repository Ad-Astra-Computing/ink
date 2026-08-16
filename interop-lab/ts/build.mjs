/**
 * Bundle the TypeScript side of the interop lab into self-contained Node ESM
 * modules, so the runtime image carries no node_modules.
 *
 * Every bundle resolves `@adastracomputing/ink` to the TypeScript sources in
 * this repository, not to a published tarball: the lab exists to test the
 * reference implementation as it stands in the tree, and a published version
 * would be a different subject.
 *
 * Outputs:
 *   dist/worker.mjs        the unmodified reference receiver, as a Worker-shaped
 *                          fetch handler for the node:http adapter
 *   dist/keygen.mjs        mints the receiver identity at container start
 *   dist/peer.mjs          the lab's TypeScript peer service
 *   dist/driver.mjs        the TypeScript-produces half of the exchange
 */

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");

const common = {
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node24",
  packages: "bundle",
  alias: {
    "@adastracomputing/ink": join(repoRoot, "src", "index.ts"),
  },
  logLevel: "info",
};

const outdir = join(here, "dist");

await build({
  ...common,
  entryPoints: [join(repoRoot, "examples", "reference-receiver", "src", "index.ts")],
  outfile: join(outdir, "worker.mjs"),
});

for (const entry of ["keygen.mjs", "peer.mjs", "driver.mjs"]) {
  await build({
    ...common,
    entryPoints: [join(here, entry)],
    outfile: join(outdir, entry),
  });
}

console.log("bundled -> dist/worker.mjs, dist/keygen.mjs, dist/peer.mjs, dist/driver.mjs");
