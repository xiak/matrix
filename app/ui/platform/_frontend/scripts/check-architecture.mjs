import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src", import.meta.url));

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(target);
    return [target];
  }));
  return nested.flat().filter((file) => [".ts", ".tsx"].includes(extname(file)));
}

const violations = [];
for (const file of await sourceFiles(root)) {
  const path = relative(root, file).replaceAll("\\", "/");
  if (/\.test\./.test(path) || path.startsWith("test/")) continue;
  const source = await readFile(file, "utf8");
  const imports = [...source.matchAll(/(?:from\s+|import\s*\()["']([^"']+)["']/g)]
    .map((match) => match[1]);

  const local = imports.flatMap(value => {
    const target = value.startsWith("@/") ? join(root, value.slice(2)) : value.startsWith("@ui/") ? join(root, "ui", value.slice(4)) : value.startsWith(".") ? resolve(dirname(file), value) : null;
    return target ? [relative(root, target).replaceAll("\\", "/")] : [];
  });
  if (path.startsWith("ui/xiak/") && local.some(value => !value.startsWith("ui/"))) violations.push(`${path}: public UI imports application state or contracts`);
  if (local.some(value => value.startsWith("../"))) violations.push(`${path}: runtime source imports outside the frontend owner`);
  for (const [product, other] of [["paas", "devops"], ["devops", "paas"]]) {
    if (path.startsWith(`features/${product}/`) && local.some(value => value.startsWith(`features/${other}/`) || value.startsWith(`api/${other}`))) violations.push(`${path}: product imports another product's implementation or contract`);
  }
  if (path !== "api/client.ts" && /\bfetch\s*\(/.test(source) && !/\bapi\.fetch\s*</.test(source)) violations.push(`${path}: network effects must use the bounded session client`);
  if (path.startsWith("features/") && /\b(localStorage|sessionStorage)\b|document\.cookie/.test(source)) violations.push(`${path}: product/session authority cannot persist in browser storage`);
}

if (violations.length > 0) {
  throw new Error(`Architecture violations:\n${violations.join("\n")}`);
}

process.stdout.write("platform UI architecture check passed\n");
