import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src", import.meta.url));

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) return files(target);
    return [target];
  }));
  return nested.flat();
}

const violations = [];
for (const file of await files(root)) {
  const path = relative(root, file).replaceAll("\\", "/");
  const source = await readFile(file, "utf8");
  if ([".ts", ".tsx"].includes(extname(file)) && /\bstyle\s*=\s*\{/.test(source)) {
    violations.push(`${path}: inline style`);
  }
  if (extname(file) === ".css" && path !== "styles/tokens.css" && /#[0-9a-f]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(/i.test(source)) {
    violations.push(`${path}: raw theme color outside tokens.css`);
  }
}

if (violations.length > 0) {
  throw new Error(`Style contract violations:\n${violations.join("\n")}`);
}

process.stdout.write("control-plane UI style check passed\n");
