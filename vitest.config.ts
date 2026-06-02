import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Examples vendor their own @adastracomputing/ink via npm so they
    // can demonstrate the package as an adopter would consume it. The
    // root workspace doesn't install the package against itself, so
    // running the example tests from the root would fail with
    // ERR_MODULE_NOT_FOUND. Each example has its own `npm test`.
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
      "**/.git/**",
      "examples/**",
    ],
  },
});
