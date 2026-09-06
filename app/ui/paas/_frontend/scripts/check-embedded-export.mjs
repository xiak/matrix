import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { portableStaticExportPath } from "./static-export-paths.mjs";

const project = fileURLToPath(new URL("..", import.meta.url));
const deliveryUnit = resolve(project, "..");
const source = resolve(project, "out");
const target = resolve(deliveryUnit, "internal", "web", "assets");

if (
  basename(project) !== "_frontend" ||
  basename(deliveryUnit) !== "paas" ||
  basename(dirname(deliveryUnit)) !== "ui"
) {
  throw new Error("refusing to inspect an unexpected embed target");
}

async function inventory(root) {
  const result = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      if (!entry.isFile()) throw new Error("static export contains an unsupported entry");
      const portable = portableStaticExportPath(relative(root, path));
      result.push({
        path: portable,
        digest: createHash("sha256").update(await readFile(path)).digest("hex")
      });
    }
  }

  await walk(root);
  result.sort((left, right) => left.path.localeCompare(right.path));
  if (result.some((item, index) => index > 0 && result[index - 1].path === item.path)) {
    throw new Error("static export contains a duplicate portable path");
  }
  return result;
}

const exported = await inventory(source);
const embedded = await inventory(target);
if (JSON.stringify(exported) !== JSON.stringify(embedded)) {
  throw new Error("embedded control-plane assets drifted; run npm run build:embedded");
}

process.stdout.write(`embedded control-plane export matches ${exported.length} generated files\n`);
