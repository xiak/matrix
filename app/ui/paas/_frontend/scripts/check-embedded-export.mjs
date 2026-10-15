import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

export async function inventory(root, directory = root) {
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

export function compareInventories(exported, embedded) {
  const actual = new Map(exported.map((file) => [file.path, file.digest]));
  const expected = new Map(embedded.map((file) => [file.path, file.digest]));
  return {
    missing: [...expected.keys()].filter((path) => !actual.has(path)).sort(),
    unexpected: [...actual.keys()].filter((path) => !expected.has(path)).sort(),
    changed: [...actual.keys()].filter((path) => expected.has(path) && actual.get(path) !== expected.get(path)).sort()
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const exported = await inventory(source);
  const embedded = await inventory(target);
  const drift = compareInventories(exported, embedded);
  if (Object.values(drift).some((paths) => paths.length)) {
    const categories = Object.fromEntries(Object.entries(drift).map(([category, paths]) => {
      const extensions = {};
      for (const path of paths) {
        const extension = extname(path) || "(none)";
        extensions[extension] = (extensions[extension] ?? 0) + 1;
      }
      return [category, { count: paths.length, extensions, samples: paths.slice(0, 8) }];
    }));
    process.stderr.write(`${JSON.stringify({ exported: exported.length, embedded: embedded.length, categories }, null, 2)}\n`);
    throw new Error("embedded control-plane assets drifted; run npm run build:embedded");
  }
  process.stdout.write(`embedded control-plane export matches ${exported.length} generated files\n`);
}
