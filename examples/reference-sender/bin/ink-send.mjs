#!/usr/bin/env node
/**
 * Launcher for the INK reference sender.
 *
 * The orchestration lives in `src/cli.ts`; this thin wrapper forwards
 * process args and maps the returned exit code. It runs the TypeScript
 * source directly under Node's native type stripping (Node 24+, which
 * `@adastracomputing/ink` requires), so there is no build step —
 * `node bin/ink-send.mjs` just works.
 */
import { runCli } from "../src/cli.ts";

const code = await runCli(process.argv.slice(2));
process.exit(code);
