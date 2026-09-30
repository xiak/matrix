import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type {
  ServiceLinkedRoleAccessLoad,
  ServiceLinkedRoleClient,
  ServiceLinkedRoleDirectoryLoad,
  ServiceRoleTemplateClient
} from "../application/AccountAccessProvider";
import type {
  ServiceLinkedRoleAccess,
  ServiceLinkedRoleDirectory,
  ServiceRoleTemplateDirectory
} from "../domain/serviceAuthorization";
import { AccountServiceAuthorizations } from "./AccountServiceAuthorizations";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const templateReference = { id: "managedservice.installation-reader", version: 1, contentDigest: digest("c") };
const relation = {
  role: {
    id: "role-managedservice-reader",
    accountId: "account-xiak",
    name: "ManagedServiceInstallationReader",
    description: "Allows the managed service to inspect one consented installation.",
    tags: [],
    management: "SERVICE_LINKED" as const,
    status: "ACTIVE" as const,
    maxSessionDurationSeconds: 900,
    resourceVersion: 1,
    currentTrustVersionId: "trust-managedservice-v1",
    createdAt: "2026-09-29T09:00:00Z",
    updatedAt: "2026-09-29T09:00:00Z"
  },
  template: templateReference,
  servicePrincipal: {
    installationId: "installation-managedservice",
    principalId: "service-managedservice",
    purpose: "PAAS" as const
  },
  permissionCeiling: {
    policyId: "system.managedservice-installation-reader",
    versionId: "version-managedservice-installation-reader-v1",
    contentDigest: digest("b")
  }
};

const directory: ServiceLinkedRoleDirectory = {
  accountId: "account-xiak",
  items: [{ relation, bindingCount: 2, activeBindingCount: 1 }],
  nextAfter: null
};

const access: ServiceLinkedRoleAccess = {
  relation,
  bindings: [
    {
      id: "binding-active",
      accountId: "account-xiak",
      roleId: relation.role.id,
      template: templateReference,
      workload: { kind: "SERVICE_INSTALLATION", id: "installation-1" },
      status: "ACTIVE",
      resourceVersion: 1,
      createdAt: "2026-09-29T09:30:00Z",
      updatedAt: "2026-09-29T09:30:00Z",
      revokedAt: null
    },
    {
      id: "binding-revoked",
      accountId: "account-xiak",
      roleId: relation.role.id,
      template: templateReference,
      workload: { kind: "SERVICE_INSTALLATION", id: "installation-old" },
      status: "REVOKED",
      resourceVersion: 2,
      createdAt: "2026-09-28T09:30:00Z",
      updatedAt: "2026-09-29T08:30:00Z",
      revokedAt: "2026-09-29T08:30:00Z"
    }
  ],
  nextAfter: null
};

const templates: ServiceRoleTemplateDirectory = { items: [{
  ...templateReference,
  spec: {
    product: "managedservice",
    servicePurpose: "PAAS",
    roleName: "ManagedServiceInstallationReader",
    roleDescription: "Allows inspection of one consented installation.",
    policyVersion: relation.permissionCeiling,
    workloads: [{
      resourceKind: "SERVICE_INSTALLATION",
      bindAction: "managedservice.installation.bind-service-role",
      unbindAction: "managedservice.installation.unbind-service-role"
    }],
    maxSessionDurationSeconds: 900
  },
  status: "ACTIVE"
}] };

afterEach(cleanup);

describe("AccountServiceAuthorizations", () => {
  it("keeps stable page chrome while loading and presents current-account relations before platform templates", async () => {
    let resolve!: (value: ServiceLinkedRoleDirectoryLoad) => void;
    const relations: ServiceLinkedRoleClient = {
      accountId: "account-xiak",
      sessionRevision: 1,
      list: vi.fn().mockImplementation(() => new Promise((done) => { resolve = done; })),
      read: vi.fn()
    };
    const templateClient: ServiceRoleTemplateClient = { sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", directory: templates }) };
    render(<LocaleProvider><AccountServiceAuthorizations relations={relations} templates={templateClient} onBack={vi.fn()} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "服务授权" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "当前账号授权", selected: true })).toBeTruthy();
    expect(screen.getByText("正在读取当前账号的服务授权")).toBeTruthy();
    expect(templateClient.load).not.toHaveBeenCalled();

    resolve({ status: "ready", directory });
    const table = await screen.findByRole("table", { name: "当前账号服务授权关系" });
    expect(within(table).getByText("1 个有效 / 2 个历史绑定")).toBeTruthy();
    expect(within(table).getByText(relation.role.name)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("button", { name: /授权|解绑|撤销|承担/ })).toBeNull();
  });

  it("opens backend-confirmed binding history in content and preserves revoked records", async () => {
    const relations: ServiceLinkedRoleClient = {
      accountId: "account-xiak",
      sessionRevision: 1,
      list: vi.fn().mockResolvedValue({ status: "ready", directory }),
      read: vi.fn().mockResolvedValue({ status: "ready", access } satisfies ServiceLinkedRoleAccessLoad)
    };
    const user = userEvent.setup();
    render(<LocaleProvider><AccountServiceAuthorizations relations={relations} templates={null} onBack={vi.fn()} /></LocaleProvider>);

    await user.click(await screen.findByRole("button", { name: relation.role.name }));
    expect(await screen.findByRole("heading", { name: relation.role.name })).toBeTruthy();
    const table = screen.getByRole("table", { name: "服务授权资源绑定历史" });
    expect(within(table).getByText("有效")).toBeTruthy();
    expect(within(table).getByText("已撤销")).toBeTruthy();
    expect(within(table).getByText("installation-old")).toBeTruthy();
    expect(screen.getByText("上限不是对任意资源的自动授权", { exact: false })).toBeTruthy();
    expect(screen.getByText("有效绑定只表示该业务资源已同意关联此服务角色", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("loads the platform template directory only after the user changes section", async () => {
    const relations: ServiceLinkedRoleClient = {
      accountId: "account-xiak",
      sessionRevision: 1,
      list: vi.fn().mockResolvedValue({ status: "ready", directory }),
      read: vi.fn()
    };
    const templateClient: ServiceRoleTemplateClient = { sessionRevision: 1, load: vi.fn().mockResolvedValue({ status: "ready", directory: templates }) };
    const user = userEvent.setup();
    render(<LocaleProvider><AccountServiceAuthorizations relations={relations} templates={templateClient} onBack={vi.fn()} /></LocaleProvider>);
    await screen.findByRole("table", { name: "当前账号服务授权关系" });
    expect(templateClient.load).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "平台模板" }));
    const table = await screen.findByRole("table", { name: "服务授权模板目录" });
    expect(templateClient.load).toHaveBeenCalledTimes(1);
    expect(within(table).getByText("ManagedServiceInstallationReader")).toBeTruthy();
    expect(within(table).getByText("非账号授权状态")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("localizes relation authorization failure and retries without MOCK fallback", async () => {
    const relations: ServiceLinkedRoleClient = {
      accountId: "account-xiak",
      sessionRevision: 1,
      list: vi.fn()
        .mockResolvedValueOnce({ status: "forbidden" })
        .mockResolvedValueOnce({ status: "ready", directory: { accountId: "account-xiak", items: [], nextAfter: null } }),
      read: vi.fn()
    };
    const user = userEvent.setup();
    render(<LocaleProvider><AccountServiceAuthorizations relations={relations} templates={null} onBack={vi.fn()} /></LocaleProvider>);

    expect(await screen.findByText("无权查看当前账号服务授权")).toBeTruthy();
    expect(screen.getByText("不会回退到 MOCK", { exact: false })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试" }));
    expect(await screen.findByText("当前账号暂无服务授权")).toBeTruthy();
    expect(relations.list).toHaveBeenCalledTimes(2);
  });
});
