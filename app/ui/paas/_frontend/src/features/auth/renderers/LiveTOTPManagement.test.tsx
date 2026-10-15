import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import type { AuthenticatorState, SecurityStepUp, TOTPEnrollment, TOTPEnrollmentConfirmation, TOTPRemovalResponse } from "../domain/personalSecurity";
import type { IamRepository } from "../repositories/iamRepository";
import { replacementEnrollmentFitsProof } from "../domain/personalSecurity";
import { LiveTOTPManagement } from "./LiveTOTPManagement";
import { LivePersonalSecuritySettings } from "./LivePersonalSecuritySettings";

const setupSeed = "JBSWY3DPEHPK3PXP";
const factor: AuthenticatorState = { enrollmentState: "BOUND", factorRevision: 2, factorId: "factor-original" };
const codes = Array.from({ length: 10 }, (_, index) => `new-recovery-${index}`);
type ReplacementAPI = NonNullable<NonNullable<IamRepository["personalSecurity"]>["replacement"]>;

function fixture(renderSettings = false) {
  const createdAt = new Date(Date.now() - 1_000).toISOString(), expiresAt = new Date(Date.now() + 119_000).toISOString();
  let requestId = "", operation: SecurityStepUp["operation"] = "TOTP_REPLACE", logins = 0;
  const proof = (state: SecurityStepUp["state"]): SecurityStepUp => ({ id: "proof-original", requestId, operation,
    expectedFactorRevision: 2, state, createdAt, expiresAt, provedAt: state === "PENDING" ? null : new Date().toISOString(), consumedAt: null });
  const enrollment = (state: TOTPEnrollment["state"] = "PENDING"): TOTPEnrollment => ({ id: "enrollment-original", requestId,
    purpose: "REPLACEMENT", factorRevision: 2, state, createdAt, expiresAt, completedAt: state === "PENDING" ? null : new Date().toISOString() });
  const start = (kind: "TOTP_REPLACE" | "TOTP_REMOVE") => vi.fn(async (_credential: string, command: { requestId: string }) => {
    requestId = command.requestId; operation = kind; return proof("PENDING");
  });
  const replacement = {
    startStepUp: start("TOTP_REPLACE"), stepUpByRequest: vi.fn(async () => proof("PROVED")),
    verifyStepUp: vi.fn(async () => proof("PROVED")),
    startEnrollment: vi.fn(async () => ({ outcome: "APPLIED" as const, enrollment: enrollment(), provisioning: { seed: setupSeed, uri: `otpauth://totp/Matrix:synthetic?secret=${setupSeed}` } })),
    enrollmentByRequest: vi.fn(async () => enrollment()), cancelEnrollment: vi.fn<ReplacementAPI["cancelEnrollment"]>(async () => enrollment("CANCELLED")),
    confirmEnrollment: vi.fn<ReplacementAPI["confirmEnrollment"]>(async (): Promise<TOTPEnrollmentConfirmation> => ({ enrollment: enrollment("CONFIRMED"), nextStep: "REAUTHENTICATE", recoveryCodes: codes }))
  };
  const removal = {
    startStepUp: start("TOTP_REMOVE"), stepUpByRequest: vi.fn(async () => proof("PROVED")), verifyStepUp: vi.fn(async () => proof("PROVED")),
    remove: vi.fn(async (): Promise<TOTPRemovalResponse> => ({ outcome: "APPLIED", nextStep: "REAUTHENTICATE",
      removal: { id: "removal-original", requestId, factorId: factor.factorId!, factorRevision: 3, removedAt: new Date().toISOString() } })),
    removalByRequest: vi.fn(async () => ({ id: "removal-original", requestId, factorId: factor.factorId!, factorRevision: 3, removedAt: new Date().toISOString() }))
  };
  const repository: IamRepository = {
    login: async ({ loginName }) => ({ outcome: "AUTHENTICATED", credential: `private-credential-${++logins}`, mustChangePassword: false,
      session: { id: `session-${logins}`, principalId: loginName === "other" ? "other-user" : "user-original", organizationId: "account-original",
        status: "ACTIVE", issuedAt: createdAt, expiresAt: "2099-01-01T00:00:00Z" } }), changePassword: vi.fn(), logout: vi.fn(),
    personalSecurity: {
      notificationContact: vi.fn(), startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      authenticatorState: vi.fn(async (): Promise<AuthenticatorState> => factor), startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(),
      cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(), replacement, removal
    }
  };
  const refresh = vi.fn(async () => true);
  function Host() {
    const session = useSession();
    const [pageGeneration, setPageGeneration] = useState(0);
    return <><output data-testid="phase">{session.phase}</output><output data-testid="reason">{session.reauthenticationReason}</output>
      <output data-testid="codes">{session.enrollmentRecovery?.recoveryCodes.join("|")}</output>
      <button onClick={() => void session.login("user", "not-stored-password")}>login</button>
      <button onClick={() => void session.login("other", "not-stored-password")}>other</button>
      <button onClick={() => setPageGeneration((value) => value + 1)}>remount-factor-page</button>
      {renderSettings ? <LivePersonalSecuritySettings /> : <LiveTOTPManagement key={`${session.current?.session.id}:${session.sessionRevision}:${pageGeneration}`} factor={factor} onCommitted={refresh} />}
    </>;
  }
  render(<LocaleProvider><SessionProvider repository={repository}><Host /></SessionProvider></LocaleProvider>);
  return { repository, replacement, removal, proof, enrollment, refresh };
}

async function login() { await act(async () => { fireEvent.click(screen.getByText("login")); }); }
async function begin(label: string) { await act(async () => { fireEvent.click(screen.getByRole("button", { name: label })); }); }
async function prove() {
  fireEvent.change(screen.getByLabelText("当前密码"), { target: { value: "in-memory-password" } });
  fireEvent.change(screen.getByLabelText("原验证器动态验证码"), { target: { value: "123456" } });
  await begin("验证本人操作");
}
afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); vi.useRealTimers(); });

describe("LIVE personal factor management", () => {
  it("preserves the original proof boundary down to IAM timestamp microseconds", () => {
    const proof: SecurityStepUp = { id: "proof", requestId: "request", operation: "TOTP_REPLACE", expectedFactorRevision: 2,
      state: "PROVED", createdAt: "2026-10-14T00:00:00.000001Z", expiresAt: "2026-10-14T00:02:00.000001Z", provedAt: "2026-10-14T00:00:01Z", consumedAt: null };
    const enrollment: TOTPEnrollment = { id: "enrollment", requestId: "request", purpose: "REPLACEMENT", factorRevision: 2,
      state: "PENDING", createdAt: "2026-10-14T00:00:02Z", expiresAt: proof.expiresAt, completedAt: null };
    expect(replacementEnrollmentFitsProof(enrollment, proof)).toBe(true);
    expect(replacementEnrollmentFitsProof({ ...enrollment, expiresAt: "2026-10-14T00:02:00.000002Z" }, proof)).toBe(false);
    expect(replacementEnrollmentFitsProof({ ...enrollment, createdAt: "2026-10-14T00:00:00.000000Z" }, proof)).toBe(false);
  });
  it("replaces through the original proof and confirms once without persisting or replaying secrets", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    expect(screen.getByText(setupSeed)).toBeTruthy();
    expect(screen.getByRole("img", { name: "身份验证器设置二维码" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "654321" } });
    await begin("确认新因子并重新登录");
    expect(screen.getByTestId("phase").textContent).toBe("recovery-codes-required");
    expect(screen.getByTestId("codes").textContent).toBe(codes.join("|"));
    expect(screen.queryByText(setupSeed)).toBeNull();
    expect(screen.queryByRole("img", { name: "身份验证器设置二维码" })).toBeNull();
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.confirmEnrollment).toHaveBeenCalledTimes(1);
  });

  it("preserves an uncertain enrollment, reads only, and cannot confirm without lost provisioning", async () => {
    const f = fixture(); f.replacement.startEnrollment.mockRejectedValueOnce(new Error("response lost"));
    await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    expect(screen.queryByRole("button", { name: "开始设置新验证器" })).toBeNull();
    expect(screen.queryByRole("img", { name: "身份验证器设置二维码" })).toBeNull();
    await begin("只读检查原流程");
    expect(screen.getByText(/此原流程没有可显示的设置材料/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "确认新因子并重新登录" })).toBeNull();
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.enrollmentByRequest).toHaveBeenCalledTimes(1);
    expect(f.replacement.confirmEnrollment).not.toHaveBeenCalled();
  });

  it("keeps proof verification unknown read-only instead of resending password or OTP", async () => {
    const f = fixture(); f.replacement.verifyStepUp.mockRejectedValueOnce(new Error("proof response lost"));
    await login(); await begin("更换身份验证器"); await prove();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    await begin("只读检查原流程");
    expect(f.replacement.verifyStepUp).toHaveBeenCalledTimes(1);
    expect(f.replacement.stepUpByRequest).toHaveBeenCalledTimes(1);
    expect(f.replacement.startEnrollment).not.toHaveBeenCalled();
  });

  it("ends only the applying login on explicit removal and distinguishes it from enrollment", async () => {
    const f = fixture(); await login(); await begin("移除身份验证器"); await prove(); await begin("确认移除本人验证器");
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("reason").textContent).toBe("FACTOR_REMOVED");
    expect(screen.getByTestId("codes").textContent).toBe("");
  });

  it("queries an uncertain removal after a new same-user login without another POST or ending the new login", async () => {
    const f = fixture(); f.removal.remove.mockRejectedValueOnce(new Error("removal response lost"));
    await login(); await begin("移除身份验证器"); await prove(); await begin("确认移除本人验证器");
    await login(); await begin("只读检查原流程");
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
    expect(f.removal.removalByRequest).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.queryByRole("button", { name: "确认移除本人验证器" })).toBeNull();
  });

  it("does not expose an older actor's original intent after another user logs in", async () => {
    const f = fixture(); f.removal.remove.mockRejectedValueOnce(new Error("removal response lost"));
    await login(); await begin("移除身份验证器"); await prove(); await begin("确认移除本人验证器");
    await act(async () => { fireEvent.click(screen.getByText("other")); });
    expect(screen.queryByRole("button", { name: "只读检查原流程" })).toBeNull();
    expect(f.removal.removalByRequest).not.toHaveBeenCalled();
  });

  it("rejects policy-forbidden removal without manufacturing a completion", async () => {
    const f = fixture(); f.removal.remove.mockRejectedValueOnce(new HttpProblem(403, "iam.authenticator.removal-forbidden"));
    await login(); await begin("移除身份验证器"); await prove(); await begin("确认移除本人验证器");
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByText(/请求被拒绝/)).toBeTruthy();
    expect(f.removal.removalByRequest).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "只读检查原流程" })).toBeNull();
  });

  it("allows a definite wrong-code correction without restarting enrollment or retaining the submitted OTP", async () => {
    const f = fixture();
    f.replacement.confirmEnrollment.mockRejectedValueOnce(new HttpProblem(422, "iam.verification.rejected"));
    await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "654321" } });
    await begin("确认新因子并重新登录");
    expect(screen.getByText(setupSeed)).toBeTruthy();
    expect((screen.getByLabelText("新验证器动态验证码") as HTMLInputElement).value).toBe("");
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "765432" } });
    await begin("确认新因子并重新登录");
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.confirmEnrollment).toHaveBeenCalledTimes(2);
    expect(f.replacement.confirmEnrollment.mock.calls[1]![2].requestId).not.toBe(f.replacement.confirmEnrollment.mock.calls[0]![2].requestId);
    expect(screen.getByTestId("codes").textContent).toBe(codes.join("|"));
  });

  it("does not unlock uncertain confirmation from a merely pending enrollment projection", async () => {
    const f = fixture(); f.replacement.confirmEnrollment.mockRejectedValueOnce(new Error("confirmation response lost"));
    await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "654321" } });
    await begin("确认新因子并重新登录"); await begin("只读检查原流程");
    expect(screen.queryByText(setupSeed)).toBeNull();
    expect(screen.queryByRole("button", { name: "取消原待确认设置" })).toBeNull();
    expect(screen.queryByRole("button", { name: "确认新因子并重新登录" })).toBeNull();
    f.replacement.enrollmentByRequest.mockResolvedValueOnce(f.enrollment("CONFIRMED"));
    await begin("只读检查原流程");
    expect(screen.getByTestId("codes").textContent).toBe("");
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(f.replacement.confirmEnrollment).toHaveBeenCalledTimes(1);
  });

  it("does not unlock uncertain cancellation from a pending read or issue a second DELETE", async () => {
    const f = fixture(); f.replacement.cancelEnrollment.mockRejectedValueOnce(new Error("cancel response lost"));
    await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    await begin("取消原待确认设置"); await begin("只读检查原流程");
    expect(screen.queryByRole("button", { name: "取消原待确认设置" })).toBeNull();
    expect(screen.queryByRole("button", { name: "确认新因子并重新登录" })).toBeNull();
    f.replacement.enrollmentByRequest.mockResolvedValueOnce(f.enrollment("CANCELLED"));
    await begin("只读检查原流程");
    expect(screen.getByText(/原待确认设置已取消/)).toBeTruthy();
    expect(f.replacement.cancelEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.confirmEnrollment).not.toHaveBeenCalled();
  });

  it("does not resubmit an uncertain proof when the original proof is still pending", async () => {
    const f = fixture(); f.replacement.verifyStepUp.mockRejectedValueOnce(new Error("proof lost"));
    await login(); await begin("更换身份验证器"); await prove();
    f.replacement.stepUpByRequest.mockResolvedValueOnce(f.proof("PENDING"));
    await begin("只读检查原流程");
    expect(screen.queryByRole("button", { name: "验证本人操作" })).toBeNull();
    expect(screen.queryByRole("button", { name: "停止本页面流程" })).toBeNull();
    expect(f.replacement.verifyStepUp).toHaveBeenCalledTimes(1);
  });

  it.each([404, 403, 503])("keeps a missing or unavailable removal result UNKNOWN after HTTP %s", async (status) => {
    const f = fixture(); f.removal.remove.mockRejectedValueOnce(new Error("lost"));
    await login(); await begin("移除身份验证器"); await prove(); await begin("确认移除本人验证器");
    f.removal.removalByRequest.mockRejectedValueOnce(new HttpProblem(status, "iam.unavailable"));
    await begin("只读检查原流程");
    expect(screen.queryByRole("button", { name: "确认移除本人验证器" })).toBeNull();
    expect(screen.queryByRole("button", { name: "停止本页面流程" })).toBeNull();
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
  });

  it("rejects a replacement enrollment whose deadline extends the original proof", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove();
    f.replacement.startEnrollment.mockResolvedValueOnce({ outcome: "APPLIED", enrollment: { ...f.enrollment(),
      expiresAt: new Date(Date.now() + 120_000).toISOString() }, provisioning: { seed: "must-not-display", uri: "otpauth://never" } });
    await begin("开始设置新验证器");
    expect(screen.queryByText("must-not-display")).toBeNull();
    expect(screen.queryByRole("button", { name: "确认新因子并重新登录" })).toBeNull();
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
  });

  it("rejects a later read that changes the original enrollment's immutable deadline", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    f.replacement.confirmEnrollment.mockRejectedValueOnce(new Error("lost"));
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "654321" } });
    await begin("确认新因子并重新登录");
    f.replacement.enrollmentByRequest.mockResolvedValueOnce({ ...f.enrollment("CONFIRMED"), expiresAt: new Date(Date.now() + 118_000).toISOString() });
    await begin("只读检查原流程");
    expect(screen.queryByRole("button", { name: "结束已确认提醒" })).toBeNull();
    expect(screen.getByTestId("codes").textContent).toBe("");
  });

  it("does not end a session from a mismatched factor removal completion", async () => {
    const f = fixture(); await login(); await begin("移除身份验证器"); await prove();
    const original = await f.removal.remove(); f.removal.remove.mockClear();
    f.removal.remove.mockResolvedValueOnce({ ...original, removal: { ...original.removal, factorId: "other-factor" } });
    await begin("确认移除本人验证器");
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.queryByRole("button", { name: "结束已确认提醒" })).toBeNull();
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
  });

  it("treats EQUAL_REPLAY as historical completion without ending the current observer's session", async () => {
    const f = fixture(); await login(); await begin("移除身份验证器"); await prove();
    const original = await f.removal.remove(); f.removal.remove.mockClear();
    f.removal.remove.mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", removal: original.removal });
    await begin("确认移除本人验证器");
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("reason").textContent).toBe("");
    expect(screen.getByText(/历史完成不证明当前因子仍有效/)).toBeTruthy();
  });

  it("never lets a newer same-user login take over a previously proved ceremony", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await login();
    await begin("只读检查原流程");
    expect(screen.queryByRole("button", { name: "开始设置新验证器" })).toBeNull();
    expect(screen.getByText(/较早会话的原意图/)).toBeTruthy();
    expect(f.replacement.startEnrollment).not.toHaveBeenCalled();
  });

  it("lets a newer same-user session explicitly cancel a known pending setup, without acquiring its secrets", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器"); await login();
    expect(screen.queryByText(setupSeed)).toBeNull();
    await begin("取消原待确认设置");
    expect(f.replacement.cancelEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.cancelEnrollment.mock.calls[0]![0]).toBe("private-credential-2");
    expect(f.replacement.confirmEnrollment).not.toHaveBeenCalled();
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
  });

  it("discards late one-time provisioning after the actor has changed", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove();
    let finish!: (value: Awaited<ReturnType<typeof f.replacement.startEnrollment>>) => void;
    f.replacement.startEnrollment.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await begin("开始设置新验证器");
    await act(async () => { fireEvent.click(screen.getByText("other")); });
    await act(async () => { finish({ outcome: "APPLIED", enrollment: f.enrollment(), provisioning: { seed: "late-seed", uri: "otpauth://late" } }); });
    expect(screen.queryByText("late-seed")).toBeNull();
    expect(screen.queryByText("otpauth://late")).toBeNull();
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("closes secret entry at the original deadline without a poll, write or renewed window", async () => {
    vi.useFakeTimers();
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    await act(async () => { vi.advanceTimersByTime(120_000); });
    expect(screen.queryByText(setupSeed)).toBeNull();
    expect(screen.queryByLabelText("新验证器动态验证码")).toBeNull();
    expect(screen.getByText(/原证明期限已到/)).toBeTruthy();
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.confirmEnrollment).not.toHaveBeenCalled();
    expect(f.replacement.enrollmentByRequest).not.toHaveBeenCalled();
  });

  it("requires an authoritative current-state reread before dismissing a completed reminder", async () => {
    const f = fixture(); await login(); await begin("移除身份验证器"); await prove();
    const removal = await f.removal.remove(); f.removal.remove.mockClear();
    f.removal.remove.mockResolvedValueOnce({ outcome: "EQUAL_REPLAY", removal: removal.removal });
    await begin("确认移除本人验证器");
    f.refresh.mockResolvedValueOnce(false);
    await begin("结束已确认提醒");
    expect(screen.getByRole("button", { name: "结束已确认提醒" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "更换身份验证器" })).toBeNull();
    await begin("结束已确认提醒");
    expect(f.refresh).toHaveBeenCalledTimes(2);
    expect((screen.getByRole("button", { name: "更换身份验证器" }) as HTMLButtonElement).disabled).toBe(false);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "移除身份验证器" }));
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
  });

  it("prevents a second initialization even before React commits the first click", async () => {
    const f = fixture(); await login();
    const trigger = screen.getByRole("button", { name: "更换身份验证器" });
    await act(async () => { fireEvent.click(trigger); fireEvent.click(trigger); });
    expect(f.replacement.startStepUp).toHaveBeenCalledTimes(1);
  });

  it("does not end a later same-user login when an old removal APPLIED response arrives late", async () => {
    const f = fixture(); await login(); await begin("移除身份验证器"); await prove();
    const result = await f.removal.remove(); f.removal.remove.mockClear();
    let finish!: (value: TOTPRemovalResponse) => void;
    f.removal.remove.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await begin("确认移除本人验证器"); await login();
    await act(async () => { finish(result); });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("reason").textContent).toBe("");
    expect(f.removal.remove).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "只读检查原流程" })).toBeTruthy();
  });

  it.each(["operation", "request", "revision", "proof-id", "deadline"])("rejects proof correlation drift in %s without advancing the ceremony", async (field) => {
    const f = fixture(); await login(); await begin("更换身份验证器");
    const original = f.proof("PROVED");
    const response: SecurityStepUp = { ...original,
      ...(field === "operation" ? { operation: "TOTP_REMOVE" as const } : {}),
      ...(field === "request" ? { requestId: "other-intent" } : {}),
      ...(field === "revision" ? { expectedFactorRevision: 3 } : {}),
      ...(field === "proof-id" ? { id: "other-proof" } : {}),
      ...(field === "deadline" ? { expiresAt: new Date(Date.now() + 118_000).toISOString() } : {}) };
    f.replacement.verifyStepUp.mockResolvedValueOnce(response);
    await prove();
    expect(screen.queryByRole("button", { name: "开始设置新验证器" })).toBeNull();
    expect(screen.queryByRole("button", { name: "验证本人操作" })).toBeNull();
    expect(screen.getByRole("button", { name: "只读检查原流程" })).toBeTruthy();
    expect(f.replacement.startEnrollment).not.toHaveBeenCalled();
  });

  it("phase fence keeps a late proof reply from rewinding an enrollment already advanced by an original-request read", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器");
    let finish!: (value: SecurityStepUp) => void;
    f.replacement.verifyStepUp.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await prove(); await begin("remount-factor-page"); await begin("只读检查原流程"); await begin("开始设置新验证器");
    await act(async () => { finish(f.proof("PROVED")); });
    expect(screen.getByText(setupSeed)).toBeTruthy();
    expect(screen.getByRole("button", { name: "确认新因子并重新登录" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开始设置新验证器" })).toBeNull();
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
  });

  it("phase fence preserves a confirmed read when an older confirmation's rejection arrives late", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove(); await begin("开始设置新验证器");
    let reject!: (failure: unknown) => void;
    f.replacement.confirmEnrollment.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
    fireEvent.change(screen.getByLabelText("新验证器动态验证码"), { target: { value: "654321" } });
    await begin("确认新因子并重新登录"); await begin("remount-factor-page");
    f.replacement.enrollmentByRequest.mockResolvedValueOnce(f.enrollment("CONFIRMED"));
    await begin("只读检查原流程");
    await act(async () => { reject(new HttpProblem(422, "iam.verification.rejected")); });
    expect(screen.getByRole("button", { name: "结束已确认提醒" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "确认新因子并重新登录" })).toBeNull();
    expect(screen.queryByRole("button", { name: "取消原待确认设置" })).toBeNull();
    expect(screen.getByTestId("codes").textContent).toBe("");
    expect(f.replacement.confirmEnrollment).toHaveBeenCalledTimes(1);
  });

  it("phase fence discards a late APPLIED setup after a newer original-request read and explicit cancellation", async () => {
    const f = fixture(); await login(); await begin("更换身份验证器"); await prove();
    let finish!: (value: Awaited<ReturnType<typeof f.replacement.startEnrollment>>) => void;
    f.replacement.startEnrollment.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    await begin("开始设置新验证器"); await begin("remount-factor-page"); await begin("只读检查原流程"); await begin("取消原待确认设置");
    await act(async () => { finish({ outcome: "APPLIED", enrollment: f.enrollment(), provisioning: { seed: "late-after-cancel", uri: "otpauth://late" } }); });
    expect(screen.getByText(/原待确认设置已取消/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "取消原待确认设置" })).toBeNull();
    expect(screen.queryByText("late-after-cancel")).toBeNull();
    expect(f.replacement.startEnrollment).toHaveBeenCalledTimes(1);
    expect(f.replacement.cancelEnrollment).toHaveBeenCalledTimes(1);
  });

  it("REMOVED re-enrolls a new factor using the exact retained revision, not a fictional NEVER_BOUND or old OTP", async () => {
    const f = fixture(true);
    const security = f.repository.personalSecurity!;
    vi.mocked(security.notificationContact).mockResolvedValue({ accountId: "account-original", userId: "user-original", state: "VERIFIED",
      resourceVersion: 1, email: "user@example.com", verifiedAt: new Date(Date.now() - 1_000).toISOString(), pendingVerificationId: null });
    vi.mocked(security.authenticatorState).mockResolvedValue({ enrollmentState: "REMOVED", factorRevision: 3, factorId: null });
    vi.mocked(security.startTOTPEnrollment).mockImplementation(async (_credential, command) => ({ outcome: "APPLIED", enrollment: {
      id: "new-enrollment", requestId: command.requestId, purpose: "INITIAL", factorRevision: 3, state: "PENDING",
      createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300_000).toISOString(), completedAt: null
    }, provisioning: { seed: "fresh-rebind-only", uri: "otpauth://new-rebind" } }));
    await login();
    await screen.findByRole("button", { name: "重新设置新验证器" });
    expect(screen.queryByText("从未绑定")).toBeNull();
    fireEvent.change(screen.getByLabelText("当前密码"), { target: { value: "in-memory-password" } });
    await begin("重新设置新验证器");
    expect(security.startTOTPEnrollment).toHaveBeenCalledWith("private-credential-1", expect.objectContaining({ expectedFactorRevision: 3 }));
    expect(screen.getByText("fresh-rebind-only")).toBeTruthy();
    expect(screen.queryByLabelText("原验证器动态验证码")).toBeNull();
    expect(f.replacement.startStepUp).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
});
