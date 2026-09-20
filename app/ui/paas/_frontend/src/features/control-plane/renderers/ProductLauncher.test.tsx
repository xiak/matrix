import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type ComponentPropsWithoutRef } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { ProductLauncher } from "./ProductLauncher";

const navigation = vi.hoisted(() => ({ navigate: vi.fn() }));
vi.mock("next/link", () => ({
  default: ({ href, onClick, onNavigate, children, ...props }: ComponentPropsWithoutRef<"a"> & { onNavigate?(event: { preventDefault(): void }): void }) => <a {...props} href={href} onClick={(event) => {
    event.preventDefault();
    onClick?.(event);
    let cancelled = false;
    onNavigate?.({ preventDefault() { cancelled = true; } });
    if (!cancelled) navigation.navigate(href);
  }}>{children}</a>
}));

function ProductLauncherHarness() {
  const [open, setOpen] = useState(false);
  return <LocaleProvider><ProductLauncher onOpenChange={setOpen} open={open} /><button type="button">后续操作</button></LocaleProvider>;
}

async function openDirectory() {
  const user = userEvent.setup();
  render(<ProductLauncherHarness />);
  const trigger = screen.getByRole("button", { name: "打开产品与服务" });
  await user.click(trigger);
  return { user, trigger, search: screen.getByRole("searchbox", { name: "搜索产品与服务" }) };
}

afterEach(() => { cleanup(); localStorage.clear(); useConsoleUiStore.getState().resetSessionUi(); vi.clearAllMocks(); });

describe("ProductLauncher", () => {
  it("opens a categorized modal directory with search focus and restores its trigger on explicit close", async () => {
    const { user, trigger, search } = await openDirectory();
    expect(trigger.getAttribute("aria-haspopup")).toBe("dialog");
    expect(trigger.getAttribute("aria-controls")).toBe("global-product-launcher");
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("7 项服务");
    expect(document.activeElement).toBe(search);
    expect(screen.getByRole("heading", { name: /数据库/, level: 3 })).toBeTruthy();
    expect(screen.getByRole("link", { name: /云数据库 PostgreSQL/ }).getAttribute("href")).toBe("/console/installations/");
    await user.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("button", { name: "关闭产品与服务" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    await user.click(trigger);
    expect(document.activeElement).toBe(screen.getByRole("searchbox"));
  });

  it.each([
    [" PG ", "云数据库 PostgreSQL"],
    ["ｐｇ", "云数据库 PostgreSQL"],
    ["cI/cD", "研发效能 DevOps"],
    ["权限", "访问管理 IAM"],
    ["发布 环境", "研发效能 DevOps"]
  ])("finds service names, capabilities and aliases with %s", async (query, expected) => {
    const { user, search } = await openDirectory();
    await user.type(search, query);
    expect(screen.getByRole("status").textContent).toBe("1 项服务");
    expect(screen.getByRole("link", { name: new RegExp(expected) })).toBeTruthy();
  });

  it("filters by category and searches across categories without a hidden filter", async () => {
    const { user, search } = await openDirectory();
    const categories = within(screen.getByRole("navigation", { name: "服务分类" }));
    await user.click(categories.getByRole("button", { name: /^数据库/ }));
    expect(screen.getByRole("status").textContent).toBe("1 项服务");
    expect(screen.queryByRole("link", { name: /研发效能 DevOps/ })).toBeNull();
    await user.type(search, "ci/cd");
    expect(screen.getByRole("link", { name: /研发效能 DevOps/ })).toBeTruthy();
    expect(categories.getByRole("button", { name: /^全部服务/ }).getAttribute("aria-pressed")).toBe("true");
    await user.click(screen.getByRole("button", { name: "清空搜索" }));
    expect(screen.getByRole("link", { name: /云数据库 PostgreSQL/ })).toBeTruthy();
    expect(document.activeElement).toBe(search);
  });

  it("toggles the same header trigger and restores focus across repeated openings", async () => {
    const { user, trigger } = await openDirectory();
    for (let cycle = 0; cycle < 2; cycle += 1) {
      expect(trigger.getAttribute("aria-label")).toBe("关闭产品与服务");
      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      expect(screen.getAllByRole("dialog")).toHaveLength(1);
      await user.click(trigger);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(trigger.getAttribute("aria-controls")).toBeNull();
      expect(trigger.getAttribute("aria-label")).toBe("打开产品与服务");
      expect(document.activeElement).toBe(trigger);
      await user.keyboard(cycle === 0 ? "{Enter}" : " ");
      expect(document.activeElement).toBe(screen.getByRole("searchbox"));
    }
  });

  it("does not dismiss on Escape, blur or blank-space clicks", async () => {
    const { user, search } = await openDirectory();
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("heading", { name: /^全部服务/, level: 2 }));
    await user.click(screen.getByRole("button", { name: "后续操作" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
    search.focus();
    await user.keyboard("{Shift>}{Tab}{/Shift}");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "收藏 访问管理 IAM" }));
  });

  it("keeps no-match searches inert and provides a reset", async () => {
    const { user, search } = await openDirectory();
    await user.type(search, "<script>unknown</script>{Enter}");
    expect(screen.getByRole("status").textContent).toBe("0 项服务");
    expect(screen.getByRole("heading", { name: "未找到匹配的服务" })).toBeTruthy();
    expect(navigation.navigate).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "浏览全部服务" }));
    expect(screen.getByRole("status").textContent).toBe("7 项服务");
    expect(document.activeElement).toBe(search);
  });

  it("supports result keyboard navigation, service entry and honest recent history", async () => {
    const { user, search } = await openDirectory();
    await user.click(screen.getByRole("button", { name: /^最近访问/ }));
    expect(screen.getByText("还没有访问记录")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "浏览全部服务" }));
    await user.type(search, "发布环境");
    await user.keyboard("{ArrowDown}");
    const service = screen.getByRole("link", { name: /发布环境/ });
    expect(document.activeElement).toBe(service);
    await user.keyboard("{ArrowUp}");
    expect(document.activeElement).toBe(search);
    await user.keyboard("{Enter}");
    expect(navigation.navigate).toHaveBeenCalledExactlyOnceWith("/console/devops/");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    await user.click(screen.getByRole("button", { name: /^最近访问/ }));
    expect(screen.getByRole("status").textContent).toBe("1 项服务");
    expect(screen.getByRole("link", { name: /发布环境/ })).toBeTruthy();
  });

  it("does not navigate while an IME composition is being committed", async () => {
    const { user, search } = await openDirectory();
    await user.type(search, "PG");
    fireEvent.keyDown(search, { key: "Enter", isComposing: true });
    expect(navigation.navigate).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("keeps favorites across panel openings and safely removes the focused favorite", async () => {
    const { user } = await openDirectory();
    await user.click(screen.getByRole("button", { name: "收藏 云数据库 PostgreSQL" }));
    expect(navigation.navigate).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("dialog", { name: "云产品入口" })).getByRole("button", { name: "关闭产品与服务" }));
    await user.click(screen.getByRole("button", { name: "打开产品与服务" }));
    await user.click(screen.getByRole("button", { name: /^我的收藏/ }));
    expect(screen.getByRole("status").textContent).toBe("1 项服务");
    const remove = screen.getByRole("button", { name: "取消收藏 云数据库 PostgreSQL" });
    expect(remove.getAttribute("aria-pressed")).toBe("true");
    await user.click(remove);
    expect(screen.getByText("还没有收藏的服务")).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("searchbox"));
  });

  it("supports category keyboard movement and contains Tab inside the directory", async () => {
    const { user } = await openDirectory();
    const categories = within(screen.getByRole("navigation", { name: "服务分类" }));
    await user.click(categories.getByRole("button", { name: /^全部服务/ }));
    await user.keyboard("{End}");
    expect(document.activeElement).toBe(categories.getByRole("button", { name: /^安全与管理/ }));
    expect(screen.getByRole("status").textContent).toBe("1 项服务");
    screen.getByRole("button", { name: "收藏 访问管理 IAM" }).focus();
    await user.tab();
    expect(screen.getByRole("dialog").getAttribute("aria-modal")).toBe("true");
    expect(document.activeElement).toBe(screen.getByRole("searchbox"));
  });

  it("uses English messages while still matching Chinese service aliases", async () => {
    localStorage.setItem("matrix.locale", "en");
    const user = userEvent.setup();
    render(<ProductLauncherHarness />);
    await user.click(screen.getByRole("button", { name: "Open products & services" }));
    const search = screen.getByRole("searchbox", { name: "Search products & services" });
    await user.type(search, "数据库");
    expect(screen.getByRole("status").textContent).toBe("1 service");
    expect(screen.getByRole("link", { name: /PostgreSQL database/ })).toBeTruthy();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close products & services" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
