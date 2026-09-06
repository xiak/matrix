import { constants } from "node:fs";
import { copyFile, mkdir, readFile, readdir, rm, stat } from "node:fs/promises";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { portableStaticExportPath } from "./static-export-paths.mjs";

const project = fileURLToPath(new URL("..", import.meta.url));
const source = resolve(project, "out");
const deliveryUnit = resolve(project, "..");
const target = resolve(deliveryUnit, "internal", "web", "assets");

if (
  basename(project) !== "_frontend" ||
  basename(deliveryUnit) !== "paas" ||
  basename(dirname(deliveryUnit)) !== "ui"
) {
  throw new Error("refusing to replace an unexpected embed target");
}
if (!(await stat(source)).isDirectory()) {
  throw new Error("Next.js static export is missing");
}
const index = await readFile(resolve(source, "index.html"), "utf8");
if (!index.includes("Matrix Control Plane") || !index.includes("/_next/static/")) {
  throw new Error("Next.js static export does not contain the control plane entry");
}

await rm(target, { recursive: true, force: true });
await mkdir(target, { recursive: true });

async function copyTree(directory = source) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      await copyTree(path);
      continue;
    }
    if (!entry.isFile()) throw new Error("Next.js static export contains an unsupported entry");

    const portable = portableStaticExportPath(relative(source, path));
    const destination = resolve(target, portable);
    if (!destination.startsWith(target + sep)) {
      throw new Error("Next.js static export contains an unsafe path");
    }
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(path, destination, constants.COPYFILE_EXCL);
  }
}

await copyTree();
process.stdout.write("Next.js static export synchronized into the Go embed boundary\n");
