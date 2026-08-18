import { defineConfig } from "vitest/config";

// Without a config here, vitest walks up and loads the library's root config,
// which imports from the library's own node_modules. An example is installed on
// its own, so that directory need not exist, and the example's tests then fail
// to start for a reason that has nothing to do with the example. Pinning the
// root keeps each example self-contained, which is the point of shipping them.
export default defineConfig({
  test: {
    root: import.meta.dirname,
  },
});
