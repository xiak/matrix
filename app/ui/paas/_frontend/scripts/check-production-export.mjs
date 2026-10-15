import { spawnSync } from "node:child_process";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compareInventories, inventory } from "./check-embedded-export.mjs";

const project = fileURLToPath(new URL("..", import.meta.url));
if (basename(project) !== "_frontend" || basename(dirname(project)) !== "paas" || !process.env.npm_execpath) {
  throw new Error("run the production export gate through the owning npm script");
}

let first;
for (const mode of [undefined, "0"]) {
  const env = { ...process.env, NODE_ENV: "production" };
  if (mode === undefined) delete env.NEXT_PUBLIC_MATRIX_UX_PREVIEW;
  else env.NEXT_PUBLIC_MATRIX_UX_PREVIEW = mode;
  const result = spawnSync(process.execPath, [process.env.npm_execpath, "run", "build"], {
    cwd: project, env, stdio: "inherit"
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`production export failed for preview=${mode ?? "unset"}`);
  const current = await inventory(resolve(project, "out"));
  if (!first) first = current;
  else {
    const drift = compareInventories(current, first);
    if (Object.values(drift).some((paths) => paths.length)) {
      process.stderr.write(`${JSON.stringify(drift, null, 2)}\n`);
      throw new Error("unset and zero preview modes produced different static bytes");
    }
  }
}
process.stdout.write(`production preview unset/0 exports match ${first.length} files byte-for-byte\n`);
