#!/usr/bin/env node
// Thin launcher. The demo is TypeScript run directly under Node 24 native type
// stripping, so there is no build step. See src/demo.ts for the walk-through.
import { runDemo } from "../src/demo.ts";

runDemo().catch((err) => {
  console.error(err);
  process.exit(1);
});
