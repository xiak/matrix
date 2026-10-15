import { strict as assert } from "node:assert";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { compareInventories, inventory } from "./check-embedded-export.mjs";

test("compares exact asset bytes without depending on inventory ordering", () => {
  const files = [{ path: "index.html", digest: "page" }, { path: "_next/chunk.js", digest: "script" }];
  assert.deepEqual(compareInventories(files, [...files].reverse()), { missing: [], unexpected: [], changed: [] });
});

test("distinguishes missing, unexpected and changed assets instead of accepting drift", () => {
  const actual = [{ path: "index.html", digest: "new-page" }, { path: "new.js", digest: "new-script" }];
  const expected = [{ path: "index.html", digest: "old-page" }, { path: "old.js", digest: "old-script" }];
  assert.deepEqual(compareInventories(actual, expected), {
    missing: ["old.js"], unexpected: ["new.js"], changed: ["index.html"]
  });
});

test("inventories normalized relative paths and hashes bytes without exposing payloads or changing files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "matrix-export-inventory-test-"));
  t.after(async () => {
    const target = resolve(root);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith("matrix-export-inventory-test-"));
    await rm(target, { recursive: true, force: true });
  });
  await mkdir(join(root, "nested"));
  const path = join(root, "nested", "fixture.js");
  await writeFile(path, "private-fixture-material");
  const before = await inventory(root);
  assert.equal(before[0].path, "nested/fixture.js");
  assert.match(before[0].digest, /^[0-9a-f]{64}$/);
  await writeFile(path, "changed-fixture-material");
  const after = await inventory(root);
  assert.deepEqual(compareInventories(after, before).changed, ["nested/fixture.js"]);
  assert.ok(!JSON.stringify(after).includes("fixture-material"));
  assert.equal(await readFile(path, "utf8"), "changed-fixture-material");
});
