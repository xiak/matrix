import { readdir, rename, rmdir, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Next's Windows exporter passes backslashes to its slash-only segment-name
// encoder (vercel/next.js#92339). Normalize generated artifacts at the build
// boundary, not with runtime aliases or a patch to node_modules.
export async function normalizeStaticExport(directory) {
  const root = resolve(directory);
  const moves = [];
  const emptyDirectories = new Set();
  function checked(path) {
    const absolute = resolve(path);
    const within = relative(root, absolute);
    if (!within || within === ".." || within.startsWith("..\\") || within.startsWith("../") || isAbsolute(within)) {
      throw new Error("segment artifact escaped its export directory");
    }
    return absolute;
  }
  async function visit(path, segment) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const source = checked(join(path, entry.name));
      if (entry.isSymbolicLink()) throw new Error("static export must not contain symbolic links");
      const location = segment
        ? { parent: segment.parent, parts: [...segment.parts, entry.name] }
        : entry.isDirectory() && entry.name.startsWith("__next.") ? { parent: path, parts: [entry.name] } : null;
      if (entry.isDirectory()) {
        await visit(source, location);
        if (location) emptyDirectories.add(source);
      } else if (location) {
        if (!entry.name.endsWith(".txt")) throw new Error("unexpected file in a Next segment directory");
        moves.push({ source, target: checked(join(location.parent, location.parts.join("."))) });
      }
    }
  }
  await visit(root, null);
  const targets = new Set();
  for (const { target } of moves) {
    if (targets.has(target) || await stat(target).then(() => true, (error) => {
      if (error.code === "ENOENT") return false;
      throw error;
    })) throw new Error("refusing to overwrite a segment artifact");
    targets.add(target);
  }
  for (const { source, target } of moves) await rename(source, target);
  // Remove only the now-empty generated segment directories, never the export
  // root, a route directory, or a recursive collection of user-owned files.
  for (const path of [...emptyDirectories].sort((a, b) => b.length - a.length)) await rmdir(checked(path));
  return moves.length;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const project = fileURLToPath(new URL("..", import.meta.url));
  if (basename(project) !== "_frontend" || basename(dirname(project)) !== "platform") throw new Error("unexpected static-export owner");
  const count = await normalizeStaticExport(resolve(project, "out"));
  process.stdout.write(`static export segment paths normalized (${count} files)\n`);
}
