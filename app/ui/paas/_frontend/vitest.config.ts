import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@ui": fileURLToPath(new URL("./src/ui", import.meta.url))
    }
  },
  test: {
    // The interaction suites use full jsdom trees. Bounding concurrency keeps
    // event timing deterministic on developer and CI hosts without hiding
    // regressions behind a longer per-test timeout.
    maxWorkers: 2,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: false,
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true
  }
});
