import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

// Run against the same signed installation, inside its disconnected native
// network namespace, after the Go lifecycle and engine-restart gates succeed.
// Only public UI evidence is exported. Never emit browser errors, HTTP bodies,
// storage, traces or the private retention fixture: they may contain secrets.
const [retentionPath, playwrightPath, evidencePath, mode] = process.argv.slice(2);
const firstUse = mode === "first-use";
const origin = process.env.MATRIX_PHASE1_EDGE || "http://127.0.0.1:8080";
const products = (firstUse ? [] : [
  { id: "elasticsearch", name: "Elasticsearch 接入示例" },
  { id: "logstash", name: "Logstash 接入示例" },
  { id: "kibana", name: "Kibana 接入示例" },
  { id: "redis", name: "Redis 接入示例" },
]).map((product) => ({ ...product, instance: `handbook-browser-${product.id}` }));
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
  failure: null,
};
let browser;
let page;
let password;
let replacementPassword;

async function step(name, action) {
  report.stage = name;
  process.stdout.write(JSON.stringify({ browserStage: name }) + "\n");
  await action();
  report.checks.push(name);
}

async function visit(product, view = "") {
  // Follow the launcher and sidebar as a user. Reload persistence has its own
  // authority-bound gate below; navigation must not manufacture another login.
  await closeWorkspace();
  const productPath = `/console/products/${product.id}/`;
  if (!new URL(page.url()).pathname.startsWith(productPath)) {
    await page.getByRole("button", { name: "打开产品与服务", exact: true }).click();
    const launcher = page.getByRole("dialog", { name: "云产品入口", exact: true });
    await launcher.getByRole("searchbox", { name: "搜索产品与服务", exact: true }).fill(product.id);
    await launcher.locator(`a[href="${productPath}"]`).click();
    await page.waitForURL(`${origin}${productPath}`);
    await launcher.waitFor({ state: "detached" });
  }
  const destination = `${productPath}${view ? `${view}/` : ""}`;
  if (new URL(page.url()).pathname !== destination) {
    await page.locator("#console-product-navigation").locator(`a[href="${destination}"]`).click();
    await page.waitForURL(`${origin}${destination}`);
  }
  assert.equal(await page.locator("#login-form").count(), 0);
  if (view === "instances" && await detail().isVisible()) {
    await detail().getByRole("button", { name: "返回服务实例", exact: true }).click();
  }
}

async function closeWorkspace() {
  const close = page.locator("#console-workspace").getByRole("button", { name: "关闭上下文面板", exact: true });
  if (await close.isVisible()) {
    await close.click();
    await close.waitFor({ state: "hidden" });
  }
}

async function readQuota(purchased, used, available) {
  for (const [label, count] of [["已激活", purchased], ["使用中", used], ["可用", available]]) {
    await waitText(page.locator("small").filter({ hasText: new RegExp(`^${label}$`) }).locator("..").locator("strong"), String(count));
  }
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
  assert.ok(process.argv.length === 5 || (process.argv.length === 6 && firstUse));
  assert.equal(process.platform, "linux");
  assert.equal(new URL(origin).hostname, "127.0.0.1");
  assert.ok(["http:", "https:"].includes(new URL(origin).protocol));
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
      if (firstUse) {
        const replacement = Buffer.from(retained.NewPassword, "base64");
        try {
          assert.ok(replacement.length >= 12 && replacement.length <= 128);
          replacementPassword = replacement.toString("utf8");
        } finally { replacement.fill(0); }
      }
    } finally { contents.fill(0); }
  } finally { await file.close(); }
  await mkdir(evidencePath, { mode: 0o700 });

  await step("browser-launch", async () => {
    const { chromium } = await import(pathToFileURL(playwrightPath).href);
    const args = ["--no-sandbox", "--disable-dev-shm-usage"];
    if (new URL(origin).protocol === "https:") {
      // Trust only this run's disposable certificate, not all HTTPS errors.
      const certificate = new X509Certificate(await readFile(process.env.SSL_CERT_FILE));
      const spki = certificate.publicKey.export({ type: "spki", format: "der" });
      args.push(`--ignore-certificate-errors-spki-list=${createHash("sha256").update(spki).digest("base64")}`);
    }
    browser = await chromium.launch({ channel: "chromium", headless: true, args });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "zh-CN" });
    page = await context.newPage();
    page.setDefaultTimeout(30_000);
    page.setDefaultNavigationTimeout(30_000);
    page.on("pageerror", () => { report.pageErrors += 1; });
    page.on("response", (response) => {
      if (new URL(response.url()).origin === origin && response.status() >= 500) report.serverErrors += 1;
    });
  });
  await step(firstUse ? "initial-administrator-ui-login" : "retained-administrator-ui-login", async () => {
    await page.goto(`${origin}/console/`);
    await page.locator("#login-name").fill("admin");
    await page.locator("#login-password").fill(password);
    await page.getByRole("button", { name: "登录控制台", exact: true }).click();
    await page.waitForURL(`${origin}/console/`);
    await page.locator("#login-form").waitFor({ state: "detached" });
  });

  if (firstUse) {
    await step("first-password-change-enters-console", async () => {
      const form = page.locator("#password-change-form");
      await form.locator('[name="currentPassword"]').fill(password);
      await form.locator('[name="newPassword"]').fill(replacementPassword);
      await form.locator('[name="confirmedPassword"]').fill(replacementPassword);
      await form.getByRole("button", { name: "保存并进入控制台", exact: true }).click();
      await form.waitFor({ state: "detached" });
      await page.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).waitFor();
      assert.equal(await page.locator("#login-form").count(), 0);
      password = replacementPassword;
      replacementPassword = undefined;
      assert.equal(await page.locator('input[type="password"]:visible').count(), 0);
      assert.equal((await page.locator("body").innerText()).includes(password), false);
      await page.screenshot({ path: path.join(evidencePath, "https-first-use-console.jpg"), type: "jpeg", quality: 80, fullPage: true });
    });
    await step("administrator-ui-logout", async () => {
      await page.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).click();
      await page.getByRole("menuitem", { name: "注销并撤销 IAM 会话", exact: true }).click();
      await page.locator("#login-form").waitFor();
      await page.reload();
      await page.locator("#login-form").waitFor();
    });
    await step("new-password-ui-relogin", async () => {
      await page.locator("#login-name").fill("admin");
      await page.locator("#login-password").fill(password);
      await page.getByRole("button", { name: "登录控制台", exact: true }).click();
      await page.locator("#login-form").waitFor({ state: "detached" });
      await page.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).waitFor();
      assert.equal(await page.locator("#password-change-form").count(), 0);
    });
  }

  await step("same-session-reload-and-new-tab", async () => {
    const current = async (target) => target.evaluate(async () => {
      const response = await fetch("/api/iam/v1/auth/browser-session", { headers: { "Matrix-Browser-Transport": "cookie" } });
      const body = await response.json();
      if (response.status !== 200 || typeof body.session?.id !== "string" || Object.hasOwn(body, "credential")) throw new Error("Invalid browser session restoration");
      return body.session.id;
    });
    await page.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).waitFor();
    const original = await current(page);
    const secure = new URL(origin).protocol === "https:";
    const cookie = (await page.context().cookies(origin)).find((value) => value.name === (secure ? "__Host-matrix-session" : "matrix-session"));
    assert.equal(cookie?.httpOnly, true);
    assert.equal(cookie?.secure, secure);
    assert.equal(cookie?.sameSite, "Lax");
    assert.equal(cookie?.path, "/");
    assert.ok(cookie.expires > Date.now() / 1000);
    await page.reload();
    await page.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).waitFor();
    assert.equal(await current(page), original);
    assert.equal(await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)].some((value) => /mx1\.[A-Za-z0-9_-]{43}/.test(value))), false);
    const sibling = await page.context().newPage();
    try {
      await sibling.goto(`${origin}/console/`);
      await sibling.getByRole("button", { name: "打开账号菜单，当前用户 admin", exact: true }).waitFor();
      assert.equal(await current(sibling), original);
    } finally { await sibling.close(); }
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
      // Successful quota reconciliation may close the form automatically.
      // Observe the server-backed quota card instead of its transient notice.
      await readQuota(1, 0, 1);
      await closeWorkspace();
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
      await readQuota(1, 0, 1);
    });
  }
  await step("browser-health", async () => {
    assert.equal(report.pageErrors, 0);
    assert.equal(report.serverErrors, 0);
  });
  report.status = "PASSED";
} catch (failure) {
  // Closed diagnostics deliberately exclude text, URLs, response bodies,
  // exception messages and stacks. Only known error names and UI facts leave.
  report.failure = {
    kind: ["TimeoutError", "AssertionError"].includes(failure?.name) ? failure.name : "Error",
  };
  if (page && !page.isClosed()) {
    report.failure.loginVisible = await page.locator("#login-form").isVisible().catch(() => null);
    report.failure.activationVisible = await page.getByRole("button", { name: "开通服务", exact: true }).isVisible().catch(() => null);
    report.failure.quotaEntryVisible = await page.getByRole("link", { name: "配置配额", exact: true }).isVisible().catch(() => null);
  }
  process.exitCode = 1;
} finally {
  password = undefined;
  replacementPassword = undefined;
  if (browser) await browser.close().catch(() => { report.status = "FAILED"; process.exitCode = 1; });
  report.completedAt = new Date().toISOString();
  const encoded = JSON.stringify(report, null, 2) + "\n";
  if (evidencePath && path.isAbsolute(evidencePath)) {
    await mkdir(evidencePath, { mode: 0o700, recursive: true });
    await writeFile(path.join(evidencePath, "report.json"), encoded, { mode: 0o600 });
  }
  process.stdout.write(encoded);
}
