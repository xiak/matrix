import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import { ControlPlaneProvider, useControlPlane } from "../application/ControlPlaneProvider";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type { ManagedServiceCommandIntent, ManagedServiceCommandResult } from "../domain/managedServiceCommand";
import { managedServiceCommandType } from "../domain/managedServiceCommand";
import { ManagedServiceCommandNotice } from "./ManagedServiceCommandNotice";

const intent: ManagedServiceCommandIntent = {
  owner: { accountId: "account-a", actorKind: "USER", actorId: "user-a" }, requestId: "original-public-key",
  startedAt: "2026-10-13T10:00:00Z", targetId: "original-installation", targetLabel: "Original instance", kind: "CREATE_INSTALLATION",
  payload: { id: "original-installation", name: "Original instance", offeringId: "offering-a", quotaEntitlementId: "quota-a", regionId: "region-a" }
};
const result: ManagedServiceCommandResult = {
  idempotencyKey: intent.requestId, commandType: "INSTALLATION_CREATE", inputDigest: `sha256:${"f".repeat(64)}`, state: "SUCCEEDED",
  target: { kind: "SERVICE_INSTALLATION", id: intent.targetId }, bindingId: null, completedAt: "2026-10-13T10:01:00Z",
  operation: { id: "operation-a", kind: "PROVISION", phase: "READY", safeFailureCode: null, observedAt: "2026-10-13T10:01:00Z" }
};

function Actions({ original }: { original: ManagedServiceCommandIntent }) {
  const session = useSession(), control = useControlPlane();
  return <><button onClick={() => void session.login("user-a@account-a", "in-memory-password")}>login</button>
    <button onClick={() => control.restoreManagedServiceCommand(JSON.stringify(original))}>bring original</button>
    <ManagedServiceCommandNotice /></>;
}

function view(read: NonNullable<ControlPlaneRepository["listCommandResults"]>, original = intent) {
  const iam: IamRepository = { login: async () => ({ outcome: "AUTHENTICATED", credential: "never-persist-this-credential", mustChangePassword: false,
    session: { id: "login-a", principalId: "user-a", organizationId: "account-a", status: "ACTIVE", issuedAt: "2026-10-13T10:00:00Z", expiresAt: "2099-10-13T20:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn() };
  const repository: ControlPlaneRepository = { load: vi.fn(), getInstallation: vi.fn(), createInstallation: vi.fn(), activateQuota: vi.fn(),
    terminateInstallation: vi.fn(), bindServiceRole: vi.fn(), unbindServiceRole: vi.fn(), listCommandResults: read };
  return { repository, ...render(<LocaleProvider><SessionProvider repository={iam}><ControlPlaneProvider repository={repository} selection={{ section: "access" }}><Actions original={original} /></ControlPlaneProvider></SessionProvider></LocaleProvider>) };
}

afterEach(() => { cleanup(); localStorage.clear(); });

describe("original-operation recovery experience", () => {
  it.each(["CREATE_INSTALLATION", "TERMINATE_INSTALLATION", "BIND_SERVICE_ROLE", "UNBIND_SERVICE_ROLE"] as const)("carries non-secret %s input into a clean browser and confirms through a read-only query", async (kind) => {
    const template = { id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"c".repeat(64)}` };
    const original: ManagedServiceCommandIntent = kind === "CREATE_INSTALLATION" ? intent
      : kind === "TERMINATE_INSTALLATION" ? { ...intent, kind, payload: { installationId: intent.targetId } }
        : kind === "BIND_SERVICE_ROLE" ? { ...intent, kind, payload: { installationId: intent.targetId, template } }
        : { ...intent, kind, payload: { installationId: intent.targetId, bindingId: "binding-a", resourceVersion: 1, expectedTemplate: template } };
    const completion: ManagedServiceCommandResult = { ...result, commandType: managedServiceCommandType(kind),
      operation: kind === "CREATE_INSTALLATION" ? result.operation
        : kind === "TERMINATE_INSTALLATION" ? { ...result.operation!, kind: "TERMINATE" } : null,
      bindingId: kind === "CREATE_INSTALLATION" || kind === "TERMINATE_INSTALLATION" ? null : "binding-a" };
    const read = vi.fn(async () => [completion]);
    const first = view(read, original);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { fireEvent.click(screen.getByText("bring original")); });
    const summary = (screen.getByLabelText("只读恢复摘要") as HTMLTextAreaElement).value;
    expect(JSON.parse(summary)).toEqual(original);
    expect(summary).not.toContain("never-persist-this-credential");
    expect(summary).not.toContain("in-memory-password");
    expect(read).not.toHaveBeenCalled();
    first.unmount();
    localStorage.clear(); // The second browser has no shared site storage.
    const second = view(read);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    fireEvent.click(screen.getByText("恢复原操作"));
    fireEvent.change(screen.getByLabelText("原操作非秘密摘要"), { target: { value: summary } });
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "带入摘要并检查" })); });
    expect(screen.getByText(/服务端已确认匹配的原操作成功/)).toBeTruthy();
    expect(screen.getByText(result.inputDigest)).toBeTruthy();
    for (const page of [first, second]) {
      for (const write of [page.repository.activateQuota, page.repository.createInstallation,
        page.repository.terminateInstallation, page.repository.bindServiceRole, page.repository.unbindServiceRole]) {
        expect(write).not.toHaveBeenCalled();
      }
    }
    expect(second.repository.getInstallation).not.toHaveBeenCalled();
    expect(read).toHaveBeenCalledExactlyOnceWith("never-persist-this-credential",
      kind === "TERMINATE_INSTALLATION" ? "INSTALLATION_TERMINATE" : managedServiceCommandType(kind));
    expect(document.querySelector("[role=dialog]")).toBeNull();
  });

  it("keeps an empty authoritative result unknown and offers inspection, not resubmission", async () => {
    const read = vi.fn(async () => []);
    const page = view(read);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { fireEvent.click(screen.getByText("bring original")); });
    await act(async () => { fireEvent.click(screen.getAllByRole("button", { name: "检查原请求结果" })[0]!); });
    expect(screen.getByText(/原操作仍未知，不能因此重新提交/)).toBeTruthy();
    expect(screen.queryByText(/服务端已确认匹配的原操作成功/)).toBeNull();
    expect(page.repository.createInstallation).not.toHaveBeenCalled();
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toContain(intent.requestId);
  });

  it("rejects secret-bearing or foreign summaries without issuing a request", async () => {
    const read = vi.fn(async () => [result]);
    view(read);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    fireEvent.click(screen.getByText("恢复原操作"));
    for (const invalid of [{ ...intent, credential: "forbidden-secret" }, { ...intent, owner: { ...intent.owner, actorId: "other-user" } }]) {
      fireEvent.change(screen.getByLabelText("原操作非秘密摘要"), { target: { value: JSON.stringify(invalid) } });
      await act(async () => { fireEvent.click(screen.getByRole("button", { name: "带入摘要并检查" })); });
      expect(screen.getByText(/无法恢复这个摘要/)).toBeTruthy();
    }
    expect(read).not.toHaveBeenCalled();
    expect(localStorage.getItem("matrix.managed-service.commands.v1")).toBeNull();
  });

  it("prevents duplicate reads while inspection is pending and does not display success early", async () => {
    let finish!: (items: ManagedServiceCommandResult[]) => void;
    const read = vi.fn(() => new Promise<ManagedServiceCommandResult[]>((resolve) => { finish = resolve; }));
    view(read);
    await act(async () => { fireEvent.click(screen.getByText("login")); });
    await act(async () => { fireEvent.click(screen.getByText("bring original")); });
    await act(async () => { fireEvent.click(screen.getAllByRole("button", { name: "检查原请求结果" })[0]!); });
    expect((screen.getByRole("button", { name: "正在只读检查原请求" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText(/服务端已确认匹配的原操作成功/)).toBeNull();
    await act(async () => { finish([result]); });
    await waitFor(() => expect(screen.getByText(/服务端已确认匹配的原操作成功/)).toBeTruthy());
    expect(read).toHaveBeenCalledTimes(1);
  });
});
