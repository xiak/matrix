import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standalone from "ajv/dist/standalone/index.js";
import { build } from "esbuild";

const project = fileURLToPath(new URL("..", import.meta.url));
const repository = resolve(project, "../../../..");
const roots = {
  iam: ["LoginRequest", "LoginResponse", "LogoutRequest", "LogoutResponse", "ChangePasswordRequest", "ChangePasswordResponse"],
  installation: ["InstalledProductList"],
  paas: ["Application", "Configuration", "ConfigurationRevision", "ApplicationRevision", "Deployment", "DeploymentGeneration", "Operation", "CreateApplicationRequest", "CreateConfigurationRequest", "CreateConfigurationRevisionRequest", "CreateApplicationRevisionRequest", "CreateDeploymentRequest", "RollbackDeploymentRequest"],
  devops: ["DevOpsProject", "SourceConnection", "RepositoryBinding", "Pipeline", "PipelineActivation", "PipelineRevision", "PipelineRun", "PipelineRunLogPage", "CreateDevOpsProjectRequest", "CreateSourceConnectionRequest", "CreateRepositoryBindingRequest", "CreatePipelineRequest", "UpdatePipelineDraftRequest"]
};
const checking = process.argv.includes("--check");
function ts(schema) {
  if (schema === true) return "unknown";
  if (schema === false) return "never";
  if (schema.$ref) return schema.$ref.split("/").at(-1);
  if (Object.hasOwn(schema, "const")) return JSON.stringify(schema.const);
  if (schema.enum) return schema.enum.map(value => JSON.stringify(value)).join(" | ");
  if (schema.allOf) return `(${ts({ ...schema, allOf: undefined })}) & ` + schema.allOf.map(value => `(${ts(value)})`).join(" & ");
  if (schema.oneOf || schema.anyOf) return `(${ts({ ...schema, oneOf: undefined, anyOf: undefined })}) & (${(schema.oneOf ?? schema.anyOf).map(value => `(${ts(value)})`).join(" | ")})`;
  if (schema.type === "array") return schema.prefixItems ? `[${schema.prefixItems.map(ts).join(", ")}]` : `Array<${ts(schema.items ?? {})}>`;
  if (schema.type === "object" || schema.properties) {
    const properties = Object.entries(schema.properties ?? {}).map(([key, value]) => `${JSON.stringify(key)}${schema.required?.includes(key) ? "" : "?"}: ${ts(value)};`).join(" ");
    const rest = schema.additionalProperties && typeof schema.additionalProperties === "object" ? ` & Record<string, ${ts(schema.additionalProperties)}>` : "";
    return `{ ${properties} }${rest}`;
  }
  return ({ string: "string", integer: "number", number: "number", boolean: "boolean", null: "null" })[schema.type] ?? "unknown";
}
for (const [api, entryPoints] of Object.entries(roots)) {
  const source = `api/${api}/v1/openapi.json`;
  const openapi = JSON.parse(await readFile(resolve(repository, source), "utf8"));
  const selected = new Map();
  function include(name) {
    if (selected.has(name)) return;
    const schema = openapi.components.schemas[name];
    if (!schema) throw new Error(`Unknown public schema ${api}/${name}`);
    selected.set(name, schema);
    const refs = [...JSON.stringify(schema).matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)];
    refs.forEach(match => include(match[1]));
  }
  entryPoints.forEach(include);
  const entries = [...selected].sort(([a], [b]) => a.localeCompare(b));
  const ajv = new Ajv2020({ strict: false, allErrors: false, inlineRefs: false, code: { source: true, esm: true, lines: true } });
  addFormats(ajv);
  const schemaId = "urn:matrix:" + api;
  ajv.addSchema({ $id: schemaId, components: { schemas: Object.fromEntries(entries) } });
  const exports = Object.fromEntries(entries.map(([name]) => [name, schemaId + "#/components/schemas/" + name]));
  const bundled = await build({ stdin: { contents: standalone(ajv, exports), resolveDir: project, sourcefile: api + "Validate.js" }, bundle: true, write: false, platform: "browser", format: "esm", target: "es2022", legalComments: "none" });
  const generated = "// Generated from " + source + ". Run npm run generate:contracts.\n";
  const types = generated + "import type { ContractValidators } from \"./validation\";\nimport * as compiled from \"./" + api + "Validate\";\n\n" +
    entries.map(([name, schema]) => "export type " + name + " = " + ts(schema) + ";").join("\n") +
    "\n\nexport const validators: ContractValidators = compiled;\n";
  const outputs = {
    [api + "Contract.ts"]: types,
    [api + "Validate.js"]: generated + bundled.outputFiles[0].text,
    [api + "Validate.d.ts"]: generated + entries.map(([name]) => "export function " + name + "(value: unknown): boolean;").join("\n") + "\n"
  };
  for (const [name, content] of Object.entries(outputs)) {
    const destination = resolve(project, "src/api/" + name);
    if (checking) {
      if (await readFile(destination, "utf8") !== content) throw new Error(api + " public contract drift: " + name);
    } else {
      await mkdir(resolve(project, "src/api"), { recursive: true });
      await writeFile(destination, content);
    }
  }
}
process.stdout.write(`Public API contracts ${checking ? "match" : "generated from"} the current repository\n`);
