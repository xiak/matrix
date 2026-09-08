import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConsoleScopeScene } from "../scenes/consoleScene";
import { CompactScopeSwitcher, HeaderScopeControls } from "./ScopeSwitcher";

const scope: ConsoleScopeScene = {
  organization: { id: "org-xiak", name: "Xiak 科技" },
  projects: [{ id: "all", name: "全部项目" }, { id: "platform-dev", name: "平台研发" }],
  regions: [{ id: "all", name: "全部区域" }, { id: "cn-local-a", name: "上海私有云 A 区" }]
};

function CompactHarness() {
  const [open, setOpen] = useState(false);
  const [projectId, setProjectId] = useState("all");
  const [regionId, setRegionId] = useState("all");
  return <CompactScopeSwitcher onOpenChange={setOpen} onProjectChange={setProjectId} onRegionChange={setRegionId} open={open} projectId={projectId} regionId={regionId} scope={scope} />;
}

afterEach(cleanup);

describe("resource scope switchers", () => {
  it("keeps the desktop project and region controls explicit", async () => {
    const user = userEvent.setup();
    const onProjectChange = vi.fn();
    const onRegionChange = vi.fn();
    render(<HeaderScopeControls onProjectChange={onProjectChange} onRegionChange={onRegionChange} projectId="all" regionId="all" scope={scope} />);

    expect(screen.getByLabelText("全局资源范围").textContent).toContain("Xiak 科技");
    await user.selectOptions(screen.getByRole("combobox", { name: "选择项目范围" }), "platform-dev");
    await user.selectOptions(screen.getByRole("combobox", { name: "选择区域范围" }), "cn-local-a");
    expect(onProjectChange).toHaveBeenCalledWith("platform-dev");
    expect(onRegionChange).toHaveBeenCalledWith("cn-local-a");
  });

  it("shows compact scope context and restores its trigger after dismissal", async () => {
    const user = userEvent.setup();
    render(<CompactHarness />);
    const trigger = screen.getByRole("button", { name: "打开资源范围，项目 全部项目，区域 全部区域" });

    await user.click(trigger);
    expect(screen.getByRole("dialog", { name: "资源范围" })).toBeTruthy();
    const project = screen.getByRole("combobox", { name: "紧凑模式选择项目范围" });
    expect(document.activeElement).toBe(project);
    await user.selectOptions(project, "platform-dev");
    await user.selectOptions(screen.getByRole("combobox", { name: "紧凑模式选择区域范围" }), "cn-local-a");
    expect(screen.getByRole("button", { name: "关闭资源范围，项目 平台研发，区域 上海私有云 A 区" })).toBeTruthy();
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog", { name: "资源范围" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(screen.getByRole("button", { name: "打开资源范围，项目 平台研发，区域 上海私有云 A 区" })).toBe(trigger);
  });
});
