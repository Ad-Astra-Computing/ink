#!/usr/bin/env node
/**
 * `ink` CLI dispatcher. Subcommands:
 *   verify-inclusion   verify an INK inclusion receipt against a witness
 *
 * Usage:
 *   npx @adastracomputing/ink verify-inclusion --file receipt.json --witness https://witness.tulpa.network
 *
 * Resolves npm's bin invocation pattern: with a single bin named `ink`
 * matching the package's unscoped slug, `npx @adastracomputing/ink ...`
 * routes all args to this dispatcher.
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const SUBCOMMANDS = {
  "verify-inclusion": "verify-inclusion-impl.mjs",
};

function printHelp() {
  console.log(`ink: INK protocol command-line interface.

Subcommands:
  verify-inclusion   Verify an INK inclusion receipt against a witness.

Run a subcommand with --help for details, e.g.:
  npx @adastracomputing/ink verify-inclusion --help
`);
}

const argv = process.argv.slice(2);
const sub = argv[0];

if (!sub || sub === "--help" || sub === "-h") {
  printHelp();
  process.exit(sub ? 0 : 2);
}

const impl = SUBCOMMANDS[sub];
if (!impl) {
  console.error(`Unknown subcommand: ${sub}`);
  printHelp();
  process.exit(2);
}

// Re-route remaining args to the subcommand implementation. The impl
// reads from process.argv directly, so rewrite it before importing.
process.argv = [process.argv[0], join(here, impl), ...argv.slice(1)];
await import(`./${impl}`);
