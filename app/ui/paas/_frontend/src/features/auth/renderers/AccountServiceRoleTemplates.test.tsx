import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { ServiceRoleTemplateClient, ServiceRoleTemplateLoad } from "../application/AccountAccessProvider";
import type { ServiceRoleTemplateDirectory } from "../domain/accounts";
import { AccountServiceRoleTemplates } from "./AccountServiceRoleTemplates";

const directory: ServiceRoleTemplateDirectory = { items: [{
  id: "managedservice.installation-reader",
  version: 1,
  spec: {
    product: "managedservice",
    servicePurpose: "PAAS",
    policyVersion: {
      policyId: "system.managedservice-installation-reader",
      versionId: "version-managedservice-installation-reader-v1",
      contentDigest: `sha256:${"b".repeat(64)}`
    },
    workloadResourceKinds: ["SERVICE_INSTALLATION"],
    maxSessionDurationSeconds: 900
  },
  contentDigest: `sha256:${"c".repeat(64)}`,
  status: "ACTIVE"
}] };

afterEach(cleanup);

describe("AccountServiceRoleTemplates", () => {
  it("keeps the platform-directory frame stable while loading and never presents ACTIVE as account consent", async () => {
    let resolve!: (value: ServiceRoleTemplateLoad) => void;
    const client: ServiceRoleTemplateClient = { load: vi.fn().mockImplementation(() => new Promise((done) => { resolve = done; })) };
    const user = userEvent.setup();
    render(<LocaleProvider><AccountServiceRoleTemplates client={client} onBack={vi.fn()} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "服务授权模板" })).toBeTruthy();
    expect(screen.getByText("此目录只表达平台能力", { exact: false })).toBeTruthy();
    expect(screen.getByText("正在读取服务授权模板")).toBeTruthy();
    resolve({ status: "ready", directory });

    const table = await screen.findByRole("table", { name: "服务授权模板目录" });
    expect(within(table).getByText("可用于未来同意")).toBeTruthy();
    expect(within(table).getByText("非账号授权状态")).toBeTruthy();
    expect(screen.queryByText("账号已授权")).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();

    await user.click(within(table).getByRole("button", { name: directory.items[0]!.id }));
    expect(screen.getByText("ACTIVE 只表示此平台模板可用于未来的客户同意流程", { exact: false })).toBeTruthy();
    expect(screen.getByText(directory.items[0]!.spec.policyVersion.policyId)).toBeTruthy();
    expect(screen.getByText("IAM 尚未发布当前账号的服务关联角色与工作负载绑定读取接口", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /授权|撤销/ })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("localizes authorization failure and retries the same read boundary without MOCK fallback", async () => {
    const client: ServiceRoleTemplateClient = { load: vi.fn()
      .mockResolvedValueOnce({ status: "forbidden" })
      .mockResolvedValueOnce({ status: "ready", directory: { items: [] } }) };
    const user = userEvent.setup();
    render(<LocaleProvider><AccountServiceRoleTemplates client={client} onBack={vi.fn()} /></LocaleProvider>);

    expect(await screen.findByText("无权查看服务授权模板")).toBeTruthy();
    expect(screen.getByText("不会回退到 MOCK", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试" }));
    expect(await screen.findByText("暂无已发布模板")).toBeTruthy();
    expect(client.load).toHaveBeenCalledTimes(2);
  });
});
