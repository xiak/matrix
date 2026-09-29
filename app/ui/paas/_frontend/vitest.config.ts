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
    // Large jsdom interaction files contend for CPU and cross the existing
    // five-second test budget when run together. Serialize files instead of
    // hiding that contention behind a longer per-test timeout.
    maxWorkers: 1,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: false,
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true
  }
});
