import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { ConsoleScopeScene } from "../scenes/consoleScene";
import { RegionSwitcher } from "./ScopeSwitcher";

const scope: ConsoleScopeScene = {
  organization: { id: "org-xiak", name: "Xiak 科技" },
  regions: [{ id: "all", name: "全部区域" }, { id: "cn-local-a", name: "上海私有云 A 区" }]
};

function RegionHarness() {
  const [open, setOpen] = useState(false);
  const [regionId, setRegionId] = useState("all");
  return <LocaleProvider><RegionSwitcher onOpenChange={setOpen} onRegionChange={setRegionId} open={open} regionId={regionId} scope={scope} /><button type="button">后续操作</button></LocaleProvider>;
}

afterEach(() => { cleanup(); localStorage.clear(); });

describe("region scope switcher", () => {
  it("exposes one region-only entry and restores focus after selection", async () => {
    const user = userEvent.setup();
    render(<RegionHarness />);
    expect(screen.queryByRole("button", { name: /项目|资源范围/ })).toBeNull();
    const trigger = screen.getByRole("button", { name: "选择区域范围，当前 全部区域" });
    expect(trigger.getAttribute("aria-haspopup")).toBe("dialog");
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(trigger.hasAttribute("aria-controls")).toBe(false);
    await user.tab();
    expect(document.activeElement).toBe(trigger);
    await user.keyboard(" ");
    const panel = screen.getByRole("dialog", { name: "切换区域" });
    expect(panel.textContent).toContain("Xiak 科技");
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(trigger.getAttribute("aria-controls")).toBe(panel.id);
    expect(screen.getByRole("option", { name: /全部区域/ }).getAttribute("aria-selected")).toBe("true");
    await user.click(screen.getByRole("option", { name: /上海私有云 A 区/ }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(trigger.hasAttribute("aria-controls")).toBe(false);
    expect(trigger.getAttribute("aria-label")).toBe("选择区域范围，当前 上海私有云 A 区");
    expect(trigger.getAttribute("data-filtered")).toBe("true");
    await user.click(trigger);
    await user.click(screen.getByRole("option", { name: /全部区域/ }));
    expect(trigger.hasAttribute("data-filtered")).toBe(false);
  });

  it("moves focus without selecting until Enter and restores focus on Escape", async () => {
    const user = userEvent.setup();
    render(<RegionHarness />);
    const trigger = screen.getByRole("button", { name: /选择区域范围/ });
    await user.click(trigger);
    const all = screen.getByRole("option", { name: /全部区域/ });
    const region = screen.getByRole("option", { name: /上海私有云 A 区/ });
    expect(document.activeElement).toBe(all);
    await user.keyboard("{ArrowUp}");
    expect(document.activeElement).toBe(region);
    expect(all.getAttribute("aria-selected")).toBe("true");
    await user.keyboard("{ArrowDown}{End}{Home}");
    expect(document.activeElement).toBe(all);
    await user.keyboard("{End}{Enter}");
    expect(trigger.textContent).toContain("上海私有云 A 区");
    expect(document.activeElement).toBe(trigger);
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(screen.getByRole("option", { name: /上海私有云 A 区/ }));
    await user.keyboard("{Home}{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(trigger.textContent).toContain("上海私有云 A 区");
  });

  it("dismisses when Tab leaves without trapping keyboard focus", async () => {
    const user = userEvent.setup();
    render(<RegionHarness />);
    await user.click(screen.getByRole("button", { name: /选择区域范围/ }));
    await user.tab();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "后续操作" }));
  });

  it("localizes the entry and all-region option", async () => {
    localStorage.setItem("matrix.locale", "en");
    const user = userEvent.setup();
    render(<RegionHarness />);
    await user.click(screen.getByRole("button", { name: "Select region scope, current All regions" }));
    expect(screen.getByRole("dialog", { name: "Switch region" })).toBeTruthy();
    expect(screen.getByRole("option", { name: /All regions/ })).toBeTruthy();
    expect(screen.queryByText("全部区域")).toBeNull();
  });
});
