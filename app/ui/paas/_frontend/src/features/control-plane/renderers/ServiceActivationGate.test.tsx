import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { ServiceActivationGate, type ServiceActivationGateProps } from "./ServiceActivationGate";

const props: ServiceActivationGateProps = {
  account: { id: "tenant-a", name: "Team A" },
  service: { key: "postgresql", name: "PostgreSQL", description: "A managed database", noticeVersion: "mock-v1", icon: <span /> },
  access: { canEnable: true, mayLoadWorkspace: true }, state: { status: "not-enabled" },
  consent: "同意开通说明", onEnable: vi.fn(), children: <p>Product workspace</p>
};
const enabled = { status: "enabled" as const, scope: { accountId: "tenant-a", serviceKey: "postgresql" }, activation: { accountId: "tenant-a", serviceKey: "postgresql", termsVersion: "mock-v1", acceptedBy: "owner-a", acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z" } };
const page = (changes: Partial<ServiceActivationGateProps> = {}) => <LocaleProvider><ServiceActivationGate {...props} {...changes} /></LocaleProvider>;
afterEach(cleanup);

describe("ServiceActivationGate", () => {
  it("requires explicit consent, exposes pending feedback and renders the workspace only after current facts allow it", async () => {
    const user = userEvent.setup();
    const onEnable = vi.fn();
    const { rerender } = render(page({ onEnable }));
    const button = screen.getByRole("button", { name: "同意并开通" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText("Product workspace")).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "同意开通说明" }));
    await user.click(button);
    expect(onEnable).toHaveBeenCalledTimes(1);

    rerender(page({ onEnable, state: { status: "enabling" } }));
    expect((screen.getByRole("button", { name: "正在开通…" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText("Product workspace")).toBeNull();
    rerender(page({ state: enabled }));
    expect(screen.getByText("Product workspace")).toBeTruthy();
  });

  it("does not equate enablement authority with resource access", () => {
    const { rerender } = render(page({ state: enabled, access: { canEnable: true, mayLoadWorkspace: false } }));
    expect(screen.queryByText("Product workspace")).toBeNull();
    expect(screen.getByText(/尚未获得资源操作权限/)).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
    rerender(page({ state: enabled, access: { canEnable: false, mayLoadWorkspace: true } }));
    expect(screen.getByText("Product workspace")).toBeTruthy();
  });

  it("shows contact-admin for a member even when that member can use an already-enabled service", () => {
    render(page({ access: { canEnable: false, mayLoadWorkspace: true } }));
    expect(screen.getByText(/当前身份没有开通资格/)).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "同意并开通" })).toBeNull();
  });

  it.each([{ accountId: "other-account", serviceKey: "postgresql" }, { accountId: "tenant-a", serviceKey: "mysql" }])("rejects another account/service's activation evidence", (scope) => {
    render(page({ state: { ...enabled, scope } }));
    expect(screen.queryByText("Product workspace")).toBeNull();
    expect(screen.getByText("暂不可用")).toBeTruthy();
  });

  it("preserves consent on a failed attempt but requires new consent for another tenant, service or notice", async () => {
    const user = userEvent.setup();
    const { rerender } = render(page());
    await user.click(screen.getByRole("checkbox", { name: "同意开通说明" }));
    rerender(page({ state: { status: "failed" } }));
    expect((screen.getByRole("button", { name: "重试开通" }) as HTMLButtonElement).disabled).toBe(false);
    rerender(page({ service: { ...props.service, noticeVersion: "mock-v2" } }));
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByRole("button", { name: "同意并开通" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("uses a direct permission-only action in LIVE instead of inventing legal consent", async () => {
    const user = userEvent.setup();
    const onEnable = vi.fn();
    render(page({ consent: undefined, enableLabel: "开通服务", onEnable }));
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.getByText("直接开通")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "开通服务" }));
    expect(onEnable).toHaveBeenCalledTimes(1);
  });

  it("keeps an unknown LIVE result distinct from failure and never retries it through the normal enable action", async () => {
    const user = userEvent.setup();
    const onEnable = vi.fn();
    const onCheckOutcome = vi.fn();
    const { rerender } = render(page({
      consent: undefined,
      onEnable,
      onCheckOutcome,
      state: { status: "outcome-unknown", checking: false, recovery: "inspect" }
    }));

    expect(screen.getByText("结果待确认")).toBeTruthy();
    expect(screen.getByText(/不会自动重复开通/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开通服务" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "检查原请求结果" }));
    expect(onCheckOutcome).toHaveBeenCalledTimes(1);
    expect(onEnable).not.toHaveBeenCalled();

    const onReplay = vi.fn();
    rerender(page({
      consent: undefined,
      onEnable,
      onReplay,
      state: { status: "outcome-unknown", checking: false, recovery: "replay" }
    }));
    expect(screen.getByText(/原幂等键/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "使用原请求重试" }));
    expect(onReplay).toHaveBeenCalledTimes(1);
    expect(onEnable).not.toHaveBeenCalled();
  });
});
