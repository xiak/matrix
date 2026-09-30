import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { PolicyDiagnostics } from "./PolicyDiagnostics";

afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); });

describe("policy diagnostics", () => {
  it("separates blocking errors from security risk review and optional advice", async () => {
    const user = userEvent.setup();
    const locate = vi.fn();
    render(<LocaleProvider><PolicyDiagnostics pristine={false} onLocate={locate} diagnostics={[
      { severity: "security-warning", code: "permissionManagement", path: "$.statement[0].action" },
      { severity: "error", code: "invalid", path: "$.statement[1]" },
      { severity: "suggestion", code: "duplicateStatement", path: "$.statement[2]" }
    ]} /></LocaleProvider>);

    const analyzer = screen.getByRole("region", { name: "策略检查" });
    expect(within(analyzer).getByRole("tab", { name: /错误 1/ }).getAttribute("aria-selected")).toBe("true");
    expect(within(analyzer).getByText(/修复错误后才能进入审阅或保存/)).toBeTruthy();
    expect(within(analyzer).getByText("请检查输入格式、引用对象及数值范围。")).toBeTruthy();

    await user.click(within(analyzer).getByRole("tab", { name: /安全警告 1/ }));
    expect(within(analyzer).getByText(/需要人工复核/)).toBeTruthy();
    expect(within(analyzer).getByText(/包含权限管理操作/)).toBeTruthy();
    await user.click(within(analyzer).getByRole("button", { name: "查看 $.statement[0].action" }));
    expect(locate).toHaveBeenCalledWith("$.statement[0].action");

    expect(within(analyzer).getByRole("tab", { name: /警告 0/ })).toBeTruthy();
    expect(within(analyzer).getByRole("tab", { name: /建议 1/ })).toBeTruthy();
  });
});
