import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import ts from "typescript";

const configURL = new URL("../next.config.mjs", import.meta.url).href;
function configuration(mode, nodeEnv = "production") {
  const env = { ...process.env, NODE_ENV: nodeEnv };
  if (mode === undefined) delete env.NEXT_PUBLIC_MATRIX_UX_PREVIEW;
  else env.NEXT_PUBLIC_MATRIX_UX_PREVIEW = mode;
  const source = `const {default: config} = await import(${JSON.stringify(configURL)}); console.log(JSON.stringify({env:config.env,id:await config.generateBuildId(),nodeEnv:process.env.NODE_ENV,original:process.env.NEXT_PUBLIC_MATRIX_UX_PREVIEW??null}));`;
  return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "--eval", source], { env, encoding: "utf8" }));
}

test("canonicalizes unset, zero and non-enabled preview modes without mutating the calling environment", () => {
  const missing = configuration(undefined);
  for (const mode of ["0", "false", "invalid"]) {
    const config = configuration(mode);
    assert.equal(config.env.NEXT_PUBLIC_MATRIX_UX_PREVIEW, "0");
    assert.equal(config.id, missing.id);
    assert.equal(config.original, mode);
  }
  assert.equal(missing.env.NEXT_PUBLIC_MATRIX_UX_PREVIEW, "0");
  assert.equal(missing.original, null);
});

test("keeps explicit preview distinct and preserves the actual DEV runtime branch", () => {
  const disabled = configuration("0");
  const enabled = configuration("1");
  const development = configuration(undefined, "development");
  assert.equal(enabled.env.NEXT_PUBLIC_MATRIX_UX_PREVIEW, "1");
  assert.notEqual(enabled.id, disabled.id);
  assert.equal(development.nodeEnv, "development");
  const source = readFileSync(new URL("../src/infrastructure/runtime/uxPreviewMode.ts", import.meta.url), "utf8");
  const javascript = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
  for (const [config, expected] of [[disabled, false], [enabled, true], [development, true]]) {
    const context = { exports: {}, process: { env: { ...config.env, NODE_ENV: config.nodeEnv } } };
    runInNewContext(javascript, context);
    assert.equal(context.exports.uxPreviewEnabled, expected);
  }
});
