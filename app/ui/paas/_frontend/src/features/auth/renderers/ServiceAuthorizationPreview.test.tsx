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
    const validity = screen.getByRole("region", { name: "当前授权状态" });
    expect(within(validity).getByText("配置关系有效 · MOCK")).toBeTruthy();
    expect(within(validity).getByText("运行时未观测")).toBeTruthy();
    expect(within(validity).getByText("平台模板已固定")).toBeTruthy();
    expect(within(validity).getByText("账号关系可用")).toBeTruthy();
    expect(within(validity).getByText("当前资源已绑定")).toBeTruthy();
    expect(within(validity).getByText("运行时使用未观测")).toBeTruthy();
    expect(within(validity).getByText(/当前只能得出“配置关系有效”/)).toBeTruthy();
    expect(within(validity).getByText(/不承诺实时下线/)).toBeTruthy();
    expect(within(validity).queryByRole("button")).toBeNull();
    expect(screen.getByRole("tab", { name: "授权配置" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("heading", { name: "不可变 ServiceRoleTemplate" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "ServiceLinkedRoleAccess" })).toBeTruthy();
    expect(screen.getByText("允许已登记的 PaaS 服务按单一用途读取一个精确的托管服务安装。")).toBeTruthy();
    expect(screen.getAllByText("managed-service-installation-read", { selector: "code" }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(`sha256:${"8".repeat(64)}`).length).toBeGreaterThan(0);
    expect(screen.getAllByText(`sha256:${"9".repeat(64)}`).length).toBeGreaterThan(0);
    expect(screen.getByText("服务关联角色为 ACTIVE 只说明账号与发布模板、注册服务主体的关系可用；它不证明任何业务资源已经绑定，也不能替代逐条 WorkloadRoleBinding。")).toBeTruthy();

    await user.click(screen.getByRole("tab", { name: "资源绑定 (1)" }));
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

    await user.click(screen.getByRole("tab", { name: "运行边界" }));
    expect(screen.getByRole("heading", { name: "ServiceRoleSession" })).toBeTruthy();
    expect(screen.getAllByText("SERVICE_ACCOUNT").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("目录样例 · MOCK")).toBeTruthy();
    const runtime = screen.getByRole("heading", { name: "一次服务请求的执行边界" }).closest("section")!;
    expect(within(runtime).getByText("认证受信服务主体")).toBeTruthy();
    expect(within(runtime).getByText("签发短期服务会话")).toBeTruthy();
    expect(within(runtime).getByText("产品 PEP 重新鉴权")).toBeTruthy();
    expect(within(runtime).getByText("执行并返回业务结果")).toBeTruthy();
    expect(within(runtime).getByText("未验证请求")).toBeTruthy();
    expect(within(runtime).getByText("未签发")).toBeTruthy();
    expect(within(runtime).getByText("未评估")).toBeTruthy();
    expect(within(runtime).getByText("未执行")).toBeTruthy();
    expect(within(runtime).queryByRole("button")).toBeNull();
    expect(within(runtime).getByText(/下方目录另行展示固定契约允许公开的非秘密会话元数据/)).toBeTruthy();

    let sessions = screen.getByRole("table", { name: "服务会话目录样例" });
    expect(within(sessions).getByText("preview.service-role-session.expired")).toBeTruthy();
    expect(within(sessions).getByText("preview.service-role-session.revoked")).toBeTruthy();
    expect(within(sessions).getAllByText("preview.paas.service").length).toBe(3);
    expect(within(sessions).getAllByText("SERVICE_ACCOUNT").length).toBe(3);
    const installationIds = within(sessions).getAllByText("preview.service-installation.paas");
    expect(installationIds).toHaveLength(3);
    expect(installationIds.every((node) => node.parentElement?.textContent?.includes("PAAS"))).toBe(true);
    expect(within(sessions).getAllByText("PreviewServiceRoleForManagedServiceInstallationRead").length).toBe(3);
    expect(within(sessions).queryByText("2026-10-01T02:20:00Z")).toBeNull();
    expect(within(sessions).queryByText(/credential|proof|decision/i)).toBeNull();
    expect(screen.getByText("显示 3 / 3 条")).toBeTruthy();

    const sessionSearch = screen.getByRole("searchbox", { name: "搜索会话 ID、账号、来源身份或目标角色" });
    await user.type(sessionSearch, "expired");
    sessions = screen.getByRole("table", { name: "服务会话目录样例" });
    expect(within(sessions).queryByRole("button", { name: "preview.service-role-session.current" })).toBeNull();
    expect(within(sessions).getByRole("button", { name: "preview.service-role-session.expired" })).toBeTruthy();
    expect(screen.getByText("显示 1 / 3 条")).toBeTruthy();
    await user.clear(sessionSearch);
    await user.type(sessionSearch, "missing-session");
    expect(screen.getByRole("heading", { name: "没有匹配的服务会话" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重置查询" }));
    expect(screen.getByRole("table", { name: "服务会话目录样例" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "生命周期" }));
    await user.click(screen.getByRole("option", { name: "EXPIRED · 已到期" }));
    sessions = screen.getByRole("table", { name: "服务会话目录样例" });
    expect(within(sessions).queryByRole("button", { name: "preview.service-role-session.current" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "移除筛选：生命周期: EXPIRED · 已到期" }));
    sessions = screen.getByRole("table", { name: "服务会话目录样例" });
    const currentSession = within(sessions).getByRole("button", { name: "preview.service-role-session.current" });

    await user.click(currentSession);
    expect(screen.getByRole("heading", { name: "服务会话详情" })).toBe(document.activeElement);
    expect(screen.getByText(/UNREVOKED 只表示 IAM 在观察时点报告会话未撤销且未到期/)).toBeTruthy();
    expect(screen.getByText("账号").closest("div")?.textContent).toContain("org-xiak");
    expect(screen.getByText("来源身份").closest("div")?.textContent).toContain("SERVICE_ACCOUNTpreview.paas.servicepreview.service-installation.paas · PAAS");
    expect(screen.getByText("撤销能力").closest("div")?.textContent).toContain("可请求撤销iam.role-session.revoke");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "审阅撤销" }));
    expect(screen.getByRole("heading", { name: "撤销服务会话" })).toBe(document.activeElement);
    expect(screen.getByText(/不发送请求、不生成 requestId/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "仅预览，不发送" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText("撤销成功")).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回会话详情" }));
    await user.click(screen.getByRole("button", { name: "返回会话目录" }));
    expect(within(screen.getByRole("table", { name: "服务会话目录样例" })).getByRole("button", { name: "preview.service-role-session.current" })).toBe(document.activeElement);

    await user.click(within(screen.getByRole("table", { name: "服务会话目录样例" })).getByRole("button", { name: "preview.service-role-session.expired" }));
    expect(screen.getByRole("heading", { name: "服务会话详情" })).toBeTruthy();
    expect(screen.getByText(/EXPIRED 会话不可撤销/)).toBeTruthy();
    expect(screen.getByText("撤销能力").closest("div")?.textContent).toContain("不可撤销iam.role-session.revoke");
    expect(screen.queryByRole("button", { name: "审阅撤销" })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(screen.getByRole("button", { name: "返回会话目录" }));
    await user.click(within(screen.getByRole("table", { name: "服务会话目录样例" })).getByRole("button", { name: "preview.service-role-session.revoked" }));
    expect(screen.getByText("撤销时间").closest("div")?.textContent).not.toBe("撤销时间");
    expect(screen.getByText(/REVOKED 会话不可再次撤销/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "审阅撤销" })).toBeNull();

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
    expect(within(chain).getByText("运行时使用")).toBeTruthy();
    expect(within(chain).getByText("运行时未观测")).toBeTruthy();
    const observationTrigger = screen.getByRole("button", { name: "查看授权后观察" });
    await user.click(observationTrigger);
    await user.click(screen.getByRole("button", { name: "返回授权模板" }));
    expect(screen.getByRole("button", { name: "查看授权后观察" })).toBe(document.activeElement);
  });

  it("explains product, IAM, and tenant ownership without exposing publisher controls", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><ServiceAuthorizationPreview workspace={initialAccessWorkspace("org-xiak")} onClose={vi.fn()} /></LocaleProvider>);

    await user.click(screen.getByRole("tab", { name: "平台模板" }));
    const responsibility = screen.getByRole("region", { name: "服务授权职责边界" });
    expect(within(responsibility).getByText("产品团队定义能力")).toBeTruthy();
    expect(within(responsibility).getByText("IAM 平台校验并发布")).toBeTruthy();
    expect(within(responsibility).getByText("租户管理员消费目录")).toBeTruthy();
    expect(within(responsibility).getByText(/不能注册云平台 Action/)).toBeTruthy();
    expect(within(responsibility).queryByRole("button")).toBeNull();
  });
});
