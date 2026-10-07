import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src", import.meta.url));

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) return files(target);
    return [target];
  }));
  return nested.flat();
}

const violations = [];
const allFiles = await files(root);
const sources = new Map(await Promise.all(allFiles.map(async (file) => [file, await readFile(file, "utf8")])));
const tokenNames = new Set([...sources.values()].flatMap((source) => [...source.matchAll(/(--xiak-[\w-]+):\s*[^;]+;/g)].map((match) => match[1])));
for (const file of allFiles) {
  const path = relative(root, file).replaceAll("\\", "/");
  const source = sources.get(file);
  if ([".ts", ".tsx"].includes(extname(file)) && /\bstyle\s*=\s*\{/.test(source)) {
    violations.push(`${path}: inline style`);
  }
  if (extname(file) === ".tsx") {
    for (const binding of source.matchAll(/import\s+(\w+)\s+from\s+["']([^"']+\.module\.css)["']/g)) {
      const css = sources.get(join(dirname(file), binding[2]));
      if (!css) continue;
      const classes = new Set([...css.matchAll(/\.([_a-zA-Z][\w-]*)/g)].map((match) => match[1]));
      for (const usage of source.matchAll(new RegExp("\\b" + binding[1] + "\\.(\\w+)", "g"))) {
        if (!classes.has(usage[1])) violations.push(path + ": undefined CSS module class " + binding[1] + "." + usage[1]);
      }
    }
  }
  if (extname(file) === ".css") {
    for (const match of source.matchAll(/var\((--xiak-[\w-]+)/g)) {
      if (!tokenNames.has(match[1])) violations.push(`${path}: undefined theme token ${match[1]}`);
    }
    if (path.startsWith("ui/xiak/") && !source.trimStart().startsWith("@layer xiak {")) {
      violations.push(`${path}: public control styles must use the xiak cascade layer`);
    }
    if (path !== "styles/tokens.css" && /var\(--xiak-palette-/.test(source)) {
      violations.push(`${path}: use a semantic color, not a raw palette entry`);
    }
  }
  if (path.startsWith("features/") && extname(file) === ".tsx" && !path.includes(".test.") && /<table\b/.test(source)) {
    violations.push(`${path}: native table styling belongs to the public Table owner`);
  }
  if (extname(file) === ".css" && path !== "styles/tokens.css" && /#[0-9a-f]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(/i.test(source)) {
    violations.push(`${path}: raw theme color outside tokens.css`);
  }
}

const theme = await readFile(join(root, "styles/tokens.css"), "utf8");
const declarations = (source) => [...source.matchAll(/(--xiak-[\w-]+|color-scheme):\s*([^;]+);/g)]
  .map((match) => [match[1], match[2].trim()]);
// Resolve the actual root/surface selectors in source order, not an assumed
// light/dark split: a readable dark popup is still wrong in the light theme.
const rules = [...theme.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^{}]*)\}/g)]
  .map(([, selectors, body]) => ({ selectors: selectors.split(",").map((selector) => selector.trim()), tokens: declarations(body) }));
const requiredSelectors = [":root", ':root[data-theme="dark"]', ':root[data-theme="mixed"] [data-surface="shell"]'];
if (requiredSelectors.some((selector) => !rules.some((rule) => rule.selectors.includes(selector)))) {
  throw new Error("Light, dark and mixed surface theme contracts are required");
}
const themes = Object.fromEntries(["light", "mixed", "dark"].flatMap((scheme) => ["workspace", "shell"].map((surface) => {
  const selectors = [":root", `:root[data-theme="${scheme}"]`];
  if (surface === "shell") selectors.push(`:root[data-theme="${scheme}"] [data-surface="shell"]`, '[data-surface="shell"]');
  return [`${scheme}/${surface}`, new Map(rules.filter((rule) => rule.selectors.some((selector) => selectors.includes(selector))).flatMap((rule) => rule.tokens))];
})));

function resolveColor(name, tokens) {
  let value = `var(--xiak-color-${name})`;
  const visited = new Set();
  while (value.startsWith("var(")) {
    const token = value.slice(4, -1);
    if (visited.has(token) || !tokens.has(token)) {
      throw new Error(`Unresolved theme token: ${token}`);
    }
    visited.add(token);
    value = tokens.get(token);
  }
  if (!/^#[0-9a-f]{6}$/i.test(value)) {
    throw new Error(`Contrast color must resolve to opaque RGB: ${name}`);
  }
  return value;
}

function luminance(name, tokens) {
  const value = resolveColor(name, tokens);
  const [red, green, blue] = [1, 3, 5].map((offset) => {
    const channel = Number.parseInt(value.slice(offset, offset + 2), 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

const contrastPairs = [
  ["brand", "bg-canvas", 4.5],
  ["text-muted", "bg-control-hover", 4.5],
  ["accent-text", "bg-panel", 4.5],
  ["text-strong", "bg-panel", 4.5],
  ["text-base", "bg-panel", 4.5],
  ["text-muted", "bg-panel", 4.5],
  ["text-subtle", "bg-canvas", 4.5],
  ["text-placeholder", "bg-input", 4.5],
  ["text-code", "bg-code", 4.5],
  ["text-tooltip", "bg-tooltip", 4.5],
  ["accent-text", "accent-haze", 4.5],
  ["accent-text", "accent-haze-hover", 4.5],
  ["text-on-accent", "accent-primary", 4.5],
  ["text-on-accent", "accent-hover", 4.5],
  ["text-on-danger", "danger", 4.5],
  ["text-on-danger", "danger-hover", 4.5],
  ["border-control", "bg-input", 3],
  ["border-focus", "bg-input", 3],
  ["header-text", "header-bg", 4.5],
  ["header-muted", "header-control", 4.5],
  ["header-text", "header-panel", 4.5],
  ["header-muted", "header-panel", 4.5],
  ["header-muted", "header-selected", 4.5],
  ["header-accent", "header-selected", 4.5],
  ["header-accent", "header-bg", 4.5],
  ["header-danger", "header-danger-bg", 4.5],
  ["header-warning", "header-warning-bg", 4.5],
  ["header-control-border", "header-control", 3],
  ["header-bg", "header-danger", 4.5],
  ["header-bg", "header-accent", 4.5],
  ["text-global", "bg-global", 4.5],
  ["text-global-muted", "bg-global", 4.5],
  ["text-global", "bg-global-hover", 4.5],
  ...["neutral", "info", "success", "warning", "danger"].map((status) => [
    `status-${status}`, `status-${status}-bg`, 4.5
  ])
];

for (const [scheme, tokens] of Object.entries(themes)) {
  const darkSurface = scheme === "mixed/shell" || scheme.startsWith("dark/");
  if (tokens.get("color-scheme") !== (darkSurface ? "dark" : "light")) {
    violations.push(`${scheme}: native controls must follow the surface color scheme`);
  }
  for (const background of ["bg-canvas", "bg-panel", "bg-input", "header-bg", "header-panel", "header-control", "bg-global"]) {
    if ((luminance(background, tokens) < 0.5) !== darkSurface) {
      violations.push(`${scheme}: ${background} does not match its light/dark surface`);
    }
  }
for (const [foreground, background, minimum] of contrastPairs) {
  const a = luminance(foreground, tokens);
  const b = luminance(background, tokens);
  const contrast = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  if (contrast < minimum) {
    violations.push(`${scheme}: ${foreground} on ${background}: ${contrast.toFixed(2)}:1, requires ${minimum}:1`);
  }
}

}

if (violations.length > 0) {
  throw new Error(`Style contract violations:\n${violations.join("\n")}`);
}

process.stdout.write(`control-plane UI style check passed (${contrastPairs.length * Object.keys(themes).length} contrast pairs across light/mixed/dark workspace and shell surfaces)\n`);
