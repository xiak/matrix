import { strict as assert } from "node:assert";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { normalizeStaticExport } from "./normalize-static-export.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "matrix-static-export-test-"));
  t.after(async () => {
    const target = resolve(root);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith("matrix-static-export-test-"));
    await rm(target, { recursive: true, force: true });
  });
  async function file(path, content = "segment payload") {
    const target = join(root, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  return { root, file };
}

test("serves the same flat segment URLs on Windows and POSIX without retaining alternate paths", async (t) => {
  const { root, file } = await fixture(t);
  await file("console/access/roles/__next.console/access/$d$view/__PAGE__.txt");
  await file("console/access/roles/__next._tree.txt", "tree");
  await file("console/access/roles/index.html", "page");
  assert.equal(await normalizeStaticExport(root), 1);
  assert.equal(await readFile(join(root, "console/access/roles/__next.console.access.$d$view.__PAGE__.txt"), "utf8"), "segment payload");
  assert.deepEqual((await readdir(join(root, "console/access/roles"))).sort(), ["__next._tree.txt", "__next.console.access.$d$view.__PAGE__.txt", "index.html"].sort());
  assert.equal(await readFile(join(root, "console/access/roles/index.html"), "utf8"), "page");
  assert.equal(await normalizeStaticExport(root), 0);
});

test("leaves already-correct exports and ordinary assets unchanged", async (t) => {
  const { root, file } = await fixture(t);
  await file("console/__next.console.__PAGE__.txt");
  await file("brand/signature.svg", "<svg/>");
  assert.equal(await normalizeStaticExport(root), 0);
  assert.equal(await readFile(join(root, "brand/signature.svg"), "utf8"), "<svg/>");
});

test("fails before changing files when normalization would overwrite an artifact", async (t) => {
  const { root, file } = await fixture(t);
  await file("console/__next.console/__PAGE__.txt", "nested");
  await file("console/__next.console.__PAGE__.txt", "existing");
  await assert.rejects(normalizeStaticExport(root), /overwrite/);
  assert.equal(await readFile(join(root, "console/__next.console/__PAGE__.txt"), "utf8"), "nested");
  assert.equal(await readFile(join(root, "console/__next.console.__PAGE__.txt"), "utf8"), "existing");
});
