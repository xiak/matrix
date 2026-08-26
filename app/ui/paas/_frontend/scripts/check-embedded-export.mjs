import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

async function inventory(root, directory = root) {
  const entries = await readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      result.push(...await inventory(root, path));
      continue;
    }
    const bytes = await readFile(path);
    result.push({
      path: relative(root, path).replaceAll("\\", "/"),
      digest: createHash("sha256").update(bytes).digest("hex")
    });
  }
  return result;
}

const exported = await inventory(source);
const embedded = await inventory(target);
if (JSON.stringify(exported) !== JSON.stringify(embedded)) {
  throw new Error("embedded control-plane assets drifted; run npm run build:embedded");
}

process.stdout.write(`embedded control-plane export matches ${exported.length} generated files\n`);
