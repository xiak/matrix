import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
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
for (const file of await files(root)) {
  const path = relative(root, file).replaceAll("\\", "/");
  const source = await readFile(file, "utf8");
  if ([".ts", ".tsx"].includes(extname(file)) && /\bstyle\s*=\s*\{/.test(source)) {
    violations.push(`${path}: inline style`);
  }
  if (extname(file) === ".css" && path !== "styles/tokens.css" && /#[0-9a-f]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(/i.test(source)) {
    violations.push(`${path}: raw theme color outside tokens.css`);
  }
}

const theme = await readFile(join(root, "styles/tokens.css"), "utf8");
const tokens = new Map(
  [...theme.matchAll(/(--xiak-[\w-]+):\s*([^;]+);/g)]
    .map((match) => [match[1], match[2].trim()])
);

function luminance(name) {
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
  const [red, green, blue] = [1, 3, 5].map((offset) => {
    const channel = Number.parseInt(value.slice(offset, offset + 2), 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

const contrastPairs = [
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
  ...["neutral", "info", "success", "warning", "danger"].map((status) => [
    `status-${status}`, `status-${status}-bg`, 4.5
  ])
];

for (const [foreground, background, minimum] of contrastPairs) {
  const a = luminance(foreground);
  const b = luminance(background);
  const contrast = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  if (contrast < minimum) {
    violations.push(`${foreground} on ${background}: ${contrast.toFixed(2)}:1, requires ${minimum}:1`);
  }
}

if (violations.length > 0) {
  throw new Error(`Style contract violations:\n${violations.join("\n")}`);
}

process.stdout.write(`control-plane UI style check passed (${contrastPairs.length} contrast pairs)\n`);
