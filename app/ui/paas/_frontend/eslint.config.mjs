import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTypescript,
  {
    files: ["src/ui/xiak/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@/features/**"],
              message: "@ui/xiak is public and cannot depend on feature code."
            }
          ]
        }
      ]
    }
  },
  globalIgnores([
    ".next/**",
    "out/**",
    "node_modules/**",
    "internal/web/assets/**",
    "coverage/**",
    "next-env.d.ts"
  ])
]);
