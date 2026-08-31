import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const project = dirname(fileURLToPath(import.meta.url));

function addTree(digest, target) {
  for (const entry of readdirSync(target, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(target, entry.name);
    if (entry.isDirectory()) {
      addTree(digest, path);
      continue;
    }
    digest.update(relative(project, path).replaceAll("\\", "/"));
    digest.update("\0");
    digest.update(readFileSync(path));
    digest.update("\0");
  }
}

function staticBuildId() {
  const digest = createHash("sha256");
  for (const file of ["package.json", "package-lock.json", "next.config.mjs", "tsconfig.json"]) {
    digest.update(file);
    digest.update("\0");
    digest.update(readFileSync(join(project, file)));
    digest.update("\0");
  }
  addTree(digest, join(project, "src"));
  return `matrix-${digest.digest("hex").slice(0, 20)}`;
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  generateBuildId: async () => staticBuildId(),
  output: "export",
  reactStrictMode: true,
  trailingSlash: true,
  poweredByHeader: false,
  experimental: {
    cpus: 2,
  },
};

export default nextConfig;
