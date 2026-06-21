/**
 * Bundle the reference receiver into a single Node ESM module.
 *
 * The receiver in `../reference-receiver` is written as a Cloudflare Worker
 * (`export default { fetch(request, env, ctx) }`) against Web-standard APIs:
 * `Request`, `Response`, `URL`, `crypto.subtle`. Node 24 provides every one
 * of those globally, so the SAME handler runs unchanged under Node once its
 * TypeScript and `@adastracomputing/ink` imports are bundled into one file.
 *
 * esbuild resolves the receiver's `.js` import specifiers and the package the
 * way wrangler and vitest do, and strips the Worker type-only imports. The
 * output is `dist/worker.mjs` with the same default `{ fetch }` export, which
 * `server.mjs` drives behind a `node:http` adapter.
 */

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const common = {
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node24",
  // Keep Node built-ins external; inline the package and example sources so the
  // runtime image needs no node_modules.
  packages: "bundle",
  // Resolve `@adastracomputing/ink` from THIS example's node_modules, not the
  // sibling receiver's (which a clean Docker build never installs). The receiver
  // entry lives under ../reference-receiver, so without this esbuild would walk
  // that tree and miss the package.
  nodePaths: [join(here, "node_modules")],
  logLevel: "info",
};

// The receiver Worker handler, driven by server.mjs under node:http.
await build({
  ...common,
  entryPoints: [join(here, "..", "reference-receiver", "src", "index.ts")],
  outfile: join(here, "dist", "worker.mjs"),
});

// The sender "agent" demo, so the compose sender service runs from the same
// self-contained image.
await build({
  ...common,
  entryPoints: [join(here, "agent-demo.mjs")],
  outfile: join(here, "dist", "agent-demo.mjs"),
});

console.log("bundled -> dist/worker.mjs, dist/agent-demo.mjs");
