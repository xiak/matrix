import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
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
  const source = await readFile(file, "utf8");
  const imports = [...source.matchAll(/(?:from\s+|import\s*\()["']([^"']+)["']/g)]
    .map((match) => match[1]);

  if (path.startsWith("ui/xiak/") && imports.some((value) => value?.startsWith("@/features/"))) {
    violations.push(`${path}: public UI imports feature code`);
  }
  if (path.includes("/domain/") && imports.some((value) => /\/(application|repositories|renderers|routes|ui)\//.test(value ?? ""))) {
    violations.push(`${path}: domain imports an outer layer`);
  }
  if (path.includes("/scenes/") && imports.some((value) => /\/(renderers|routes|ui)\//.test(value ?? ""))) {
    violations.push(`${path}: scene imports rendering or route code`);
  }
  if (path.includes("/repositories/") && imports.some((value) => /\/(renderers|routes|ui)\//.test(value ?? ""))) {
    violations.push(`${path}: repository imports rendering or route code`);
  }
}

if (violations.length > 0) {
  throw new Error(`Architecture violations:\n${violations.join("\n")}`);
}

process.stdout.write("control-plane UI architecture check passed\n");
