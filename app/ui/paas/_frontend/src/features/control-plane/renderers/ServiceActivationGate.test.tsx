import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { ServiceActivationGate, type ServiceActivationGateProps } from "./ServiceActivationGate";

const props: ServiceActivationGateProps = {
  account: { id: "tenant-a", name: "Team A" },
  service: { key: "postgresql", name: "PostgreSQL", description: "A managed database", termsVersion: "mock-v1", icon: <span /> },
  access: { canEnable: true, canUse: true }, state: { status: "not-enabled" },
  consent: "同意开通说明", onEnable: vi.fn(), children: <p>Product workspace</p>
};
const enabled = { status: "enabled" as const, record: { accountId: "tenant-a", serviceKey: "postgresql", termsVersion: "mock-v1", acceptedBy: "owner-a", acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z" } };
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
    const { rerender } = render(page({ state: enabled, access: { canEnable: true, canUse: false } }));
    expect(screen.queryByText("Product workspace")).toBeNull();
    expect(screen.getByText(/尚未获得资源操作权限/)).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
    rerender(page({ state: enabled, access: { canEnable: false, canUse: true } }));
    expect(screen.getByText("Product workspace")).toBeTruthy();
  });

  it("shows contact-admin for a member even when that member can use an already-enabled service", () => {
    render(page({ access: { canEnable: false, canUse: true } }));
    expect(screen.getByText(/当前身份没有开通资格/)).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "同意并开通" })).toBeNull();
  });

  it.each([{ accountId: "other-account", serviceKey: "postgresql" }, { accountId: "tenant-a", serviceKey: "mysql" }])("rejects another account/service's activation evidence", (scope) => {
    render(page({ state: { ...enabled, record: { ...enabled.record, ...scope } } }));
    expect(screen.queryByText("Product workspace")).toBeNull();
    expect(screen.getByText("暂不可用")).toBeTruthy();
  });

  it("preserves consent on a failed attempt but requires new consent for another tenant, service or notice", async () => {
    const user = userEvent.setup();
    const { rerender } = render(page());
    await user.click(screen.getByRole("checkbox", { name: "同意开通说明" }));
    rerender(page({ state: { status: "failed" } }));
    expect((screen.getByRole("button", { name: "重试开通" }) as HTMLButtonElement).disabled).toBe(false);
    rerender(page({ service: { ...props.service, termsVersion: "mock-v2" } }));
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect((screen.getByRole("button", { name: "同意并开通" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
