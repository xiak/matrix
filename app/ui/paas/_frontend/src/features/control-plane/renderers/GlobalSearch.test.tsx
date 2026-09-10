import { useState } from "react";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GlobalSearchResultScene } from "../scenes/consoleScene";
import { GlobalSearch } from "./GlobalSearch";
import { ConsoleNavigationProvider } from "../routes/ConsoleNavigation";

const navigation = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));

const results: GlobalSearchResultScene[] = [
  { id: "resources", label: "资源中心", description: "跨产品资源", category: "page", href: "/console/resources/", icon: "foundation" },
  { id: "payment", label: "支付服务", description: "服务健康与告警", category: "resource", href: "/console/observability/", icon: "observability" }
];

function SearchFixture() {
  const [open, setOpen] = useState(false);
  return <ConsoleNavigationProvider selection={{ section: "overview" }}><GlobalSearch onOpenChange={setOpen} open={open} results={results} /><button type="button">后续操作</button></ConsoleNavigationProvider>;
}

afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); localStorage.clear(); });

describe("GlobalSearch", () => {
  it("searches translated categories and announces singular/empty English results", async () => {
    localStorage.setItem("matrix.locale", "en");
    const user = userEvent.setup();
    render(<LocaleProvider><SearchFixture /></LocaleProvider>);
    const input = screen.getByRole("combobox", { name: "Search products, resources and pages" });
    await user.type(input, "RESOURCE");
    expect(screen.getAllByRole("option")).toHaveLength(1);
    expect(within(screen.getByRole("option")).getByText("Resource", { exact: true })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("1 result");
    await user.clear(input);
    await user.type(input, "no matching service");
    expect(screen.getByRole("status").textContent).toBe("0 results");
    expect(screen.getByRole("heading", { name: "No matching products or resources" })).toBeTruthy();
  });

  it("supports keyboard selection and reopens when the still-focused input is clicked", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><SearchFixture /></LocaleProvider>);
    await user.keyboard("{Control>}k{/Control}");
    const input = screen.getByRole("combobox", { name: "搜索产品、资源和页面" });
    expect(document.activeElement).toBe(input);
    const choices = within(screen.getByRole("listbox"));
    const firstOption = choices.getByRole("option", { name: /资源中心/ });
    const lastOption = choices.getByRole("option", { name: /支付服务/ });
    expect(input.getAttribute("aria-activedescendant")).toBe(firstOption.id);
    await user.keyboard("{ArrowUp}");
    expect(input.getAttribute("aria-activedescendant")).toBe(lastOption.id);
    expect(lastOption.getAttribute("aria-selected")).toBe("true");
    await user.keyboard("{Enter}");
    expect(navigation.push).toHaveBeenCalledExactlyOnceWith("/console/observability/");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.activeElement).toBe(input);
    await user.click(input);
    expect(input.getAttribute("aria-expanded")).toBe("true");
    expect(input.getAttribute("aria-activedescendant")).toBe(screen.getByRole("option", { name: /资源中心/ }).id);
    expect(navigation.push).toHaveBeenCalledExactlyOnceWith("/console/observability/");
  });

  it("keeps an empty query result after Escape and reopens on a focused input click", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><SearchFixture /></LocaleProvider>);
    const input = screen.getByRole("combobox");
    await user.type(input, "no-such-resource");
    expect(screen.getByRole("status").textContent).toBe("0 个结果");
    expect(screen.getByText("没有匹配的产品或资源")).toBeTruthy();
    expect(input.hasAttribute("aria-activedescendant")).toBe(false);
    await user.keyboard("{Enter}{Escape}");
    expect(navigation.push).not.toHaveBeenCalled();
    expect(input.getAttribute("aria-expanded")).toBe("false");
    expect(input.hasAttribute("aria-controls")).toBe(false);
    expect(document.activeElement).toBe(input);
    await user.click(input);
    expect(input.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("status").textContent).toBe("0 个结果");
    expect(navigation.push).not.toHaveBeenCalled();
  });

  it("opens the compact search and returns focus to its trigger on Escape", async () => {
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: true })));
    const user = userEvent.setup();
    render(<LocaleProvider><SearchFixture /></LocaleProvider>);
    const trigger = screen.getByRole("button", { name: "打开全局搜索" });
    await user.click(trigger);
    expect(document.activeElement).toBe(screen.getByRole("combobox"));
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(trigger);
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("reopens after pointer selection without a blur and dismisses when focus leaves search", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><SearchFixture /></LocaleProvider>);
    const input = screen.getByRole("combobox");
    await user.type(input, "支付");
    await user.click(screen.getByRole("option", { name: /支付服务/ }));
    expect(navigation.push).toHaveBeenCalledExactlyOnceWith("/console/observability/");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.activeElement).toBe(input);
    expect((input as HTMLInputElement).value).toBe("");
    await user.click(input);
    expect(screen.getAllByRole("option")).toHaveLength(2);
    expect(input.getAttribute("aria-expanded")).toBe("true");
    await user.click(input);
    expect(screen.getByRole("listbox")).toBeTruthy();
    expect(navigation.push).toHaveBeenCalledExactlyOnceWith("/console/observability/");
    await user.click(screen.getByRole("button", { name: "后续操作" }));
    expect(screen.queryByRole("listbox")).toBeNull();
  });
});
