import assert from "node:assert/strict";
import { constants } from "node:fs";
import { mkdir, open, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

// Run against the same signed installation, inside its disconnected native
// network namespace, after the Go lifecycle and engine-restart gates succeed.
// Only public UI evidence is exported. Never emit browser errors, HTTP bodies,
// storage, traces or the private retention fixture: they may contain secrets.
const [retentionPath, playwrightPath, evidencePath] = process.argv.slice(2);
const origin = "http://127.0.0.1:8080";
const products = [
  { id: "elasticsearch", name: "Elasticsearch 接入示例" },
  { id: "logstash", name: "Logstash 接入示例" },
  { id: "kibana", name: "Kibana 接入示例" },
  { id: "redis", name: "Redis 接入示例" },
].map((product) => ({ ...product, instance: `handbook-browser-${product.id}` }));
const report = {
  kind: "matrix-signed-product-browser-acceptance-v1",
  status: "FAILED",
  startedAt: new Date().toISOString(),
  completedAt: null,
  stage: "private-input",
  checks: [],
  pageErrors: 0,
  serverErrors: 0,
  observedFailurePhase: null,
};
let browser;
let page;
let password;

async function step(name, action) {
  report.stage = name;
  process.stdout.write(JSON.stringify({ browserStage: name }) + "\n");
  await action();
  report.checks.push(name);
}

async function visit(product, view = "") {
  const response = await page.goto(`${origin}/console/products/${product.id}/${view ? `${view}/` : ""}`);
  assert.equal(response?.status(), 200);
}

async function choose(label, option) {
  await page.getByRole("combobox", { name: label, exact: true }).click();
  await page.getByRole("option", { name: option }).click();
}

async function waitText(locator, expected, timeout = 30_000) {
  await locator.waitFor({ state: "visible", timeout });
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const text = (await locator.innerText()).trim();
    if (text === expected) return;
    if (["失败", "回滚失败", "终止失败"].includes(text)) {
      report.observedFailurePhase = text;
      throw new Error("terminal-phase");
    }
    await delay(500);
  }
  throw new Error("observation-timeout");
}

function detail() {
  return page.locator('section[aria-labelledby="managed-service-installation-detail-title"]');
}

function fact(label) {
  return detail().locator("dt").filter({ hasText: new RegExp(`^${label}$`) }).locator("..").locator("dd");
}

async function screenshot(product, state) {
  assert.equal(new URL(page.url()).origin, origin);
  assert.equal(new URL(page.url()).pathname, `/console/products/${product.id}/instances/`);
  assert.equal(await page.locator('input[type="password"]:visible').count(), 0);
  assert.equal((await page.locator("body").innerText()).includes(password), false);
  await page.screenshot({ path: path.join(evidencePath, `${product.id}-${state}.jpg`), type: "jpeg", quality: 80, fullPage: true });
}

async function readInstance(product, phase) {
  await visit(product, "instances");
  const row = page.getByRole("table", { name: "服务实例列表", exact: true }).locator("tbody tr")
    .filter({ has: page.getByRole("button", { name: product.name, exact: true }) });
  await waitText(row.locator('td[data-label="状态"]'), phase, 210_000);
  await row.getByRole("button", { name: product.name, exact: true }).click();
  await waitText(fact("实例 ID"), product.instance);
  await waitText(fact("状态"), phase);
}

try {
  assert.equal(process.argv.length, 5);
  assert.equal(process.platform, "linux");
  assert.ok(path.isAbsolute(retentionPath) && path.isAbsolute(playwrightPath) && path.isAbsolute(evidencePath));
  const file = await open(retentionPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    assert.ok(info.isFile() && info.uid === process.getuid() && (info.mode & 0o777) === 0o600 && info.size <= 65_536);
    const contents = await file.readFile();
    try {
      const retained = JSON.parse(contents.toString("utf8"));
      assert.equal(typeof retained.AdministratorPassword, "string");
      const decoded = Buffer.from(retained.AdministratorPassword, "base64");
      try {
        assert.ok(decoded.length >= 12 && decoded.length <= 128);
        password = decoded.toString("utf8");
      } finally { decoded.fill(0); }
    } finally { contents.fill(0); }
  } finally { await file.close(); }
  await mkdir(evidencePath, { mode: 0o700 });

  await step("browser-launch", async () => {
    const { chromium } = await import(pathToFileURL(playwrightPath).href);
    browser = await chromium.launch({ channel: "chromium", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "zh-CN" });
    page = await context.newPage();
    page.setDefaultTimeout(30_000);
    page.setDefaultNavigationTimeout(30_000);
    page.on("pageerror", () => { report.pageErrors += 1; });
    page.on("response", (response) => {
      if (new URL(response.url()).origin === origin && response.status() >= 500) report.serverErrors += 1;
    });
  });
  await step("retained-administrator-ui-login", async () => {
    await page.goto(`${origin}/console/`);
    await page.locator("#login-name").fill("admin");
    await page.locator("#login-password").fill(password);
    await page.getByRole("button", { name: "登录控制台", exact: true }).click();
    await page.waitForURL(`${origin}/console/`);
    await page.locator("#login-form").waitFor({ state: "detached" });
  });

  for (const product of products) {
    await step(`${product.id}-service-activation`, async () => {
      await visit(product);
      await page.getByRole("button", { name: "开通服务", exact: true }).click();
      await page.getByRole("link", { name: "配置配额", exact: true }).waitFor();
    });
    await step(`${product.id}-quota-activation`, async () => {
      await visit(product, "quotas");
      await page.getByRole("button", { name: "激活配额", exact: true }).click();
      await choose("资源规格", /开发型/);
      await page.getByRole("spinbutton", { name: "实例数量", exact: true }).fill("1");
      await page.getByRole("button", { name: "确认激活配额", exact: true }).click();
      await page.getByText("配额已由平台确认", { exact: true }).waitFor();
    });
    await step(`${product.id}-installation-submit`, async () => {
      await visit(product, "instances");
      await page.getByRole("button", { name: "安装服务", exact: true }).click();
      await page.getByRole("textbox", { name: "实例 ID", exact: true }).fill(product.instance);
      await page.getByRole("textbox", { name: "显示名称", exact: true }).fill(product.name);
      if (product.id === "kibana") await choose("Elasticsearch 实例", /handbook-browser-elasticsearch/);
      await screenshot(product, "install");
      await page.getByRole("button", { name: "提交安装任务", exact: true }).click();
      await page.getByText("安装任务已由平台接受", { exact: true }).waitFor();
    });
    await step(`${product.id}-ready-detail`, async () => {
      await readInstance(product, "运行中");
      const endpoint = (await fact("端点").innerText()).trim();
      assert.match(endpoint, /127\.0\.0\.1:[0-9]+/);
      if (product.id === "kibana") await waitText(fact("关联 Elasticsearch"), "handbook-browser-elasticsearch");
      await screenshot(product, "running");
    });
  }

  // Kibana must finish cleanup before its exact Elasticsearch dependency.
  for (const product of [...products].reverse()) {
    await step(`${product.id}-termination`, async () => {
      await readInstance(product, "运行中");
      await detail().getByRole("button", { name: "审阅终止实例", exact: true }).click();
      await page.getByRole("textbox", { name: "输入实例 ID 以确认", exact: true }).fill(product.instance);
      await page.getByRole("button", { name: "确认终止实例", exact: true }).click();
      await detail().getByText("平台已完成实例终止并归还关联配额。有查看权限的用户仍可查看这条终止记录。", { exact: true }).waitFor({ timeout: 210_000 });
      await waitText(fact("状态"), "已终止");
      await waitText(fact("端点"), "尚未分配");
      await screenshot(product, "terminated");
    });
    await step(`${product.id}-quota-returned`, async () => {
      await visit(product, "quotas");
      for (const [label, count] of [["已激活", "1"], ["使用中", "0"], ["可用", "1"]]) {
        await waitText(page.locator("small").filter({ hasText: new RegExp(`^${label}$`) }).locator("..").locator("strong"), count);
      }
    });
  }
  await step("browser-health", async () => {
    assert.equal(report.pageErrors, 0);
    assert.equal(report.serverErrors, 0);
  });
  report.status = "PASSED";
} catch {
  // Closed diagnostics deliberately exclude exception messages and stacks.
  process.exitCode = 1;
} finally {
  password = undefined;
  if (browser) await browser.close().catch(() => { report.status = "FAILED"; process.exitCode = 1; });
  report.completedAt = new Date().toISOString();
  const encoded = JSON.stringify(report, null, 2) + "\n";
  if (evidencePath && path.isAbsolute(evidencePath)) {
    await mkdir(evidencePath, { mode: 0o700, recursive: true });
    await writeFile(path.join(evidencePath, "report.json"), encoded, { mode: 0o600 });
  }
  process.stdout.write(encoded);
}
