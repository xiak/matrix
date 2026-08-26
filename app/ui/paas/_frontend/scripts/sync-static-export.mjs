import { cp, mkdir, readFile, rm, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
await mkdir(dirname(target), { recursive: true });
await cp(source, target, { recursive: true, force: true });
process.stdout.write("Next.js static export synchronized into the Go embed boundary\n");
