import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { initialAccessWorkspace } from "../repositories/previewAccessWorkspace";
import { ServiceAuthorizationPreview } from "./ServiceAuthorizationPreview";

afterEach(cleanup);

describe("ServiceAuthorizationPreview", () => {
  it("moves focus through the current consent step without returning to the page title", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ServiceAuthorizationPreview workspace={initialAccessWorkspace("org-xiak")} onClose={vi.fn()} /></LocaleProvider>);

    await user.click(screen.getByRole("tab", { name: "平台模板" }));
    await user.click(screen.getByRole("button", { name: "托管服务安装访问" }));
    await user.click(screen.getByRole("button", { name: "审阅服务授权" }));
    expect(screen.getByRole("heading", { level: 1, name: "审阅服务授权" })).toBe(document.activeElement);
    expect(screen.getByText("managedservice")).toBeTruthy();
    expect(screen.getByText("允许已登记的 PaaS 服务按单一用途读取一个精确的托管服务安装。")).toBeTruthy();
    expect(screen.getByText("60 分钟")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一步" }));
    await waitFor(() => expect(screen.getByRole("heading", { level: 3, name: "核对示例权限范围" })).toBe(document.activeElement));
    expect(screen.getByText("preview.policy.managed-service-installation-read")).toBeTruthy();
    expect(screen.getByText("v1", { selector: "code" })).toBeTruthy();
    expect(screen.getByText(`sha256:${"9".repeat(64)}`)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await waitFor(() => expect(screen.getByRole("heading", { level: 3, name: "确认客户同意与撤销边界" })).toBe(document.activeElement));
    expect(screen.getByRole("button", { name: "授权服务（未接入）" }).hasAttribute("disabled")).toBe(true);
  });

  it("opens the current account authorization directory before platform templates", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ServiceAuthorizationPreview workspace={initialAccessWorkspace("org-xiak")} onClose={vi.fn()} /></LocaleProvider>);

    const directory = screen.getByRole("table", { name: "当前账号服务授权" });
    expect(within(directory).getByText("1 个有效 / 1 个全部")).toBeTruthy();
    expect(within(directory).getByText("PreviewServiceRoleForManagedServiceInstallationRead")).toBeTruthy();
    const accountTrigger = within(directory).getByRole("button", { name: "查看账号服务授权：托管服务安装访问" });
    await user.click(accountTrigger);

    expect(screen.getByRole("heading", { name: "账号服务授权观察" })).toBeTruthy();
    expect(screen.getByText("账号关系与资源绑定已有固定只读契约，但这个隔离 MOCK 不调用它，也不执行写入。以下 ID、状态和时间均为设计预览，不是后端返回的数据。")).toBeTruthy();
    expect(screen.queryByText(/北向读取接口尚未发布/)).toBeNull();
    expect(screen.getByRole("heading", { name: "不可变 ServiceRoleTemplate" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "ServiceLinkedRoleAccess" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "ServiceRoleSession" })).toBeTruthy();
    expect(screen.getByText("SERVICE")).toBeTruthy();
    expect(screen.getByText("未发行")).toBeTruthy();
    expect(screen.getByText("允许已登记的 PaaS 服务按单一用途读取一个精确的托管服务安装。")).toBeTruthy();
    expect(screen.getAllByText("managed-service-installation-read", { selector: "code" }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(`sha256:${"8".repeat(64)}`).length).toBeGreaterThan(0);
    expect(screen.getAllByText(`sha256:${"9".repeat(64)}`).length).toBeGreaterThan(0);
    expect(screen.getByText("服务关联角色为 ACTIVE 只说明账号与发布模板、注册服务主体的关系可用；它不证明任何业务资源已经绑定，也不能替代逐条 WorkloadRoleBinding。")).toBeTruthy();

    const bindings = screen.getByRole("table", { name: "服务角色业务资源绑定" });
    expect(within(bindings).getByText("SERVICE_INSTALLATION")).toBeTruthy();
    expect(within(bindings).getByText("service-installation-example")).toBeTruthy();
    expect(within(bindings).getByText("preview.workload-role-binding.service-installation-example")).toBeTruthy();
    expect(within(bindings).getByText("org-xiak")).toBeTruthy();
    expect(within(bindings).getByText("preview.service-linked-role.managed-service-installation-read")).toBeTruthy();
    expect(within(bindings).getByText("preview.service-role-template.managed-service-installation-read.v1@v1")).toBeTruthy();
    expect(screen.getByText("第 1 页")).toBeTruthy();
    expect(screen.getByText("当前 MOCK 只展示一页精确绑定；LIVE 读取仅按后端返回的不透明游标继续，不推断总页数。")).toBeTruthy();
    expect((screen.getByRole("button", { name: "上一页绑定" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "下一页绑定" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: /撤销|解除/ })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "返回服务授权" }));
    expect(screen.getByRole("button", { name: "查看账号服务授权：托管服务安装访问" })).toBe(document.activeElement);
  });

  it("keeps the published template, account relation, and exact workload binding visibly separate", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ServiceAuthorizationPreview workspace={initialAccessWorkspace("org-xiak")} onClose={vi.fn()} /></LocaleProvider>);

    await user.click(screen.getByRole("tab", { name: "平台模板" }));
    await user.click(screen.getByRole("button", { name: "托管服务安装访问" }));
    const chain = screen.getByRole("heading", { name: "服务授权链" }).closest("section")!;
    expect(within(chain).getByText("示意模板 · 未发布")).toBeTruthy();
    expect(within(chain).getByText("当前账号未授权")).toBeTruthy();
    expect(within(chain).getByText("未配置")).toBeTruthy();
    const observationTrigger = screen.getByRole("button", { name: "查看授权后观察" });
    await user.click(observationTrigger);
    await user.click(screen.getByRole("button", { name: "返回授权模板" }));
    expect(screen.getByRole("button", { name: "查看授权后观察" })).toBe(document.activeElement);
  });
});
