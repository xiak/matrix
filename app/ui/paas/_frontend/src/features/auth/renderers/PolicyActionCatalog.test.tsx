import { useState } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { policyActions } from "../domain/previewAuthorizationCatalog";
import { PolicyActionCatalog } from "./PolicyActionCatalog";

const logWriteActions = policyActions.filter((action) => action.service === "logs" && action.level === "write");

function SelectionHarness() {
  const [selected, setSelected] = useState<string[]>(["logs:read"]);
  return <LocaleProvider>
    <PolicyActionCatalog actions={logWriteActions} selected={selected} service="logs" onChange={setSelected} />
    <output aria-label="selected actions">{selected.join(",")}</output>
  </LocaleProvider>;
}

function PaginationHarness() {
  const [selected, setSelected] = useState<string[]>([]);
  return <LocaleProvider>
    <PolicyActionCatalog actions={policyActions.slice(0, 12)} selected={selected} service="regions" onChange={setSelected} />
    <output aria-label="selected action count">{selected.length}</output>
  </LocaleProvider>;
}

afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); });

describe("policy action catalog", () => {
  it("selects and clears only the filtered result set", async () => {
    const user = userEvent.setup();
    render(<SelectionHarness />);

    await user.click(screen.getByRole("checkbox", { name: "选择当前筛选结果" }));
    expect(screen.getByLabelText("selected actions").textContent).toBe("logs:read,logs:create,logs:delete");

    await user.click(screen.getByRole("checkbox", { name: "取消选择当前筛选结果" }));
    expect(screen.getByLabelText("selected actions").textContent).toBe("logs:read");
  });

  it("reveals a read-only permission definition inline", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><PolicyActionCatalog actions={[policyActions.find((action) => action.id === "logs:create")!]} selected={[]} service="logs" onChange={() => {}} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "查看 logs:create 的权限定义" }));
    const definition = screen.getByRole("region", { name: "权限定义 · logs:create" });
    expect(within(definition).getByText("隔离 MOCK，未连接 IAM AuthorizationProfile")).toBeTruthy();
    expect(within(definition).getByText(/不是当前用户的有效权限/)).toBeTruthy();
    expect(within(definition).getByText("成功产出")).toBeTruthy();
    expect(within(definition).getByText("日志主题")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("renders one action page while selecting the complete filtered result set", async () => {
    const user = userEvent.setup();
    const actions = policyActions.slice(0, 12);
    render(<PaginationHarness />);

    expect(screen.getByText("第 1 / 2 页")).toBeTruthy();
    expect(screen.getByRole("checkbox", { name: actions[9]!.id })).toBeTruthy();
    expect(screen.queryByRole("checkbox", { name: actions[10]!.id })).toBeNull();

    await user.click(screen.getByRole("checkbox", { name: "选择当前筛选结果" }));
    expect(screen.getByLabelText("selected action count").textContent).toBe("12");
    await user.click(screen.getByRole("button", { name: "下一页" }));

    expect(screen.getByText("第 2 / 2 页")).toBeTruthy();
    expect((screen.getByRole("checkbox", { name: actions[10]!.id }) as HTMLInputElement).checked).toBe(true);
    expect(screen.queryByRole("checkbox", { name: actions[0]!.id })).toBeNull();
  });
});
