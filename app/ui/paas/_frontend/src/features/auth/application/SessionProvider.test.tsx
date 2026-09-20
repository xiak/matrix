import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { IamRepository } from "../repositories/iamRepository";
import { SessionProvider, useSession, useSessionCredential } from "./SessionProvider";
import { usePersonalSecurity } from "./PersonalSecurityProvider";

const secretCredential = "must-not-enter-browser-storage-or-dom";
const challengeCredential = "must-not-become-a-session-bearer";

function challenged(nextStep: "TOTP" | "PASSWORD_CHANGE" = "TOTP", credential = challengeCredential) {
  return {
    outcome: "CHALLENGE_REQUIRED" as const,
    challenge: {
      id: `challenge-${nextStep.toLowerCase()}`,
      purpose: "LOGIN" as const,
      nextStep,
      expiresAt: "2099-08-26T20:00:00Z"
    },
    challengeCredential: credential
  };
}

function Probe() {
  const session = useSession();
  const personalSecurity = usePersonalSecurity();
  const hasCredential = useSessionCredential() !== null;
  return (
    <div>
      <span data-testid="phase">{session.phase}</span>
      <span data-testid="principal">{session.current?.loginName ?? "none"}</span>
      <span data-testid="error">{session.error ?? "none"}</span>
      <span data-testid="has-credential">{String(hasCredential)}</span>
      <span data-testid="has-challenge">{String(session.challenge !== null)}</span>
      <span data-testid="recovery-count">{session.enrollmentRecovery?.recoveryCodes.length ?? 0}</span>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <button onClick={() => void session.verifyAuthenticationChallenge("123456")} type="button">verify</button>
      <button onClick={() => void session.changeChallengePassword("Changed-Admin-Password-73!")} type="button">challenge-password</button>
      <button onClick={session.cancelAuthenticationChallenge} type="button">cancel-challenge</button>
      <button onClick={session.acknowledgeReauthentication} type="button">acknowledge</button>
      <button onClick={session.acknowledgeEnrollmentRecovery} type="button">acknowledge-recovery</button>
      <button onClick={() => { void personalSecurity?.confirmTOTPEnrollment("enrollment-one", { requestId: "confirm-one", code: "123456" }).catch(() => undefined); }} type="button">confirm-enrollment</button>
      <button
        onClick={() => void session.changePassword("Initial-Admin-Password-49!", "Changed-Admin-Password-73!")}
        type="button"
      >change</button>
      <button onClick={() => void session.changePassword("Initial-Admin-Password-49!", "Changed-Admin-Password-73!", false)} type="button">retain</button>
      <button onClick={() => void session.logout()} type="button">logout</button>
    </div>
  );
}

function repository({
  mustChangePassword = false,
  logoutFailure = false
}: {
  mustChangePassword?: boolean;
  logoutFailure?: boolean;
} = {}): IamRepository {
  return {
    async login() {
      return {
        outcome: "AUTHENTICATED",
        credential: secretCredential,
        mustChangePassword,
        session: {
          id: "session-test",
          organizationId: "organization-test",
          principalId: "principal-test",
          status: "ACTIVE",
          issuedAt: "2026-08-26T12:00:00Z",
          expiresAt: "2099-08-26T20:00:00Z"
        }
      };
    },
    authenticationChallenges: {
      async verify() {
        return {
          outcome: "AUTHENTICATED",
          credential: secretCredential,
          mustChangePassword: false,
          session: {
            id: "session-test",
            organizationId: "organization-test",
            principalId: "principal-test",
            status: "ACTIVE",
            issuedAt: "2026-08-26T12:00:00Z",
            expiresAt: "2099-08-26T20:00:00Z"
          }
        };
      },
      async changePassword() {
        return { nextStep: "REAUTHENTICATE", changedAt: "2026-08-26T12:01:00Z" };
      }
    },
    async changePassword() {},
    async logout() {
      if (logoutFailure) throw new Error("unavailable");
    }
  };
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  vi.useRealTimers();
});

describe("SessionProvider", () => {
  it("keeps the bearer only in provider memory", async () => {
    const screen = render(<SessionProvider repository={repository()}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    expect(screen.container.textContent).not.toContain(secretCredential);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("keeps a login challenge sessionless until TOTP verification succeeds", async () => {
    const source = repository();
    const authenticatedLogin = source.login;
    source.login = vi.fn().mockResolvedValue(challenged());
    source.authenticationChallenges!.verify = vi.fn().mockImplementation(async () => authenticatedLogin({ loginName: "admin", password: "unused" }));
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-required");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    expect(screen.getByTestId("has-challenge").textContent).toBe("true");
    expect(screen.container.textContent).not.toContain(challengeCredential);
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(source.authenticationChallenges!.verify).toHaveBeenCalledWith({
      challengeId: "challenge-totp", challengeCredential, code: "123456"
    });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("has-credential").textContent).toBe("true");
    expect(screen.getByTestId("has-challenge").textContent).toBe("false");
  });

  it("uses the rotated challenge only for forced password replacement, then requires a fresh login", async () => {
    const source = repository();
    source.login = vi.fn().mockResolvedValue(challenged());
    source.authenticationChallenges!.verify = vi.fn().mockResolvedValue(challenged("PASSWORD_CHANGE", "rotated-challenge"));
    source.authenticationChallenges!.changePassword = vi.fn().mockResolvedValue({
      nextStep: "REAUTHENTICATE", changedAt: "2026-08-26T12:01:00Z"
    });
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-password-required");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    await act(async () => fireEvent.click(screen.getByText("challenge-password")));
    expect(source.authenticationChallenges!.changePassword).toHaveBeenCalledWith({
      challengeId: "challenge-password_change", challengeCredential: "rotated-challenge",
      newPassword: "Changed-Admin-Password-73!"
    });
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("has-challenge").textContent).toBe("false");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    await act(async () => fireEvent.click(screen.getByText("acknowledge")));
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
  });

  it("retains only a definite invalid-code challenge and closes uncertain outcomes", async () => {
    for (const [failure, expectedPhase, retained] of [
      [new HttpProblem(401, "private upstream"), "challenge-required", true],
      [new HttpProblem(429, "private upstream"), "challenge-required", true],
      [new HttpProblem(409, "private upstream"), "anonymous", false],
      [new Error("private upstream"), "anonymous", false]
    ] as const) {
      const source = repository();
      source.login = vi.fn().mockResolvedValue(challenged());
      source.authenticationChallenges!.verify = vi.fn().mockRejectedValue(failure);
      const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
      await act(async () => fireEvent.click(screen.getByText("login")));
      await act(async () => fireEvent.click(screen.getByText("verify")));
      expect(screen.getByTestId("phase").textContent).toBe(expectedPhase);
      expect(screen.getByTestId("has-challenge").textContent).toBe(String(retained));
      expect(screen.getByTestId("has-credential").textContent).toBe("false");
      expect(screen.container.textContent).not.toContain("private upstream");
      screen.unmount();
    }
  });

  it("does not let a late challenge result survive cancellation", async () => {
    let complete!: (result: Awaited<ReturnType<IamRepository["login"]>>) => void;
    const source = repository();
    const authenticatedLogin = source.login;
    source.login = vi.fn().mockResolvedValue(challenged());
    source.authenticationChallenges!.verify = () => new Promise((resolve) => { complete = resolve; });
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    await act(async () => fireEvent.click(screen.getByText("cancel-challenge")));
    await act(async () => complete(await authenticatedLogin({ loginName: "admin", password: "unused" })));
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    expect(screen.getByTestId("has-challenge").textContent).toBe("false");
  });

  it("does not forget a session when IAM revocation fails", async () => {
    const screen = render(<SessionProvider repository={repository({ logoutFailure: true })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    await act(async () => fireEvent.click(screen.getByText("logout")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    expect(screen.getByTestId("principal").textContent).toBe("admin");
    expect(screen.getByTestId("error").textContent).toContain("会话仍保留");
  });

  it("forgets the session only after IAM confirms revocation", async () => {
    const screen = render(<SessionProvider repository={repository()}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    await act(async () => fireEvent.click(screen.getByText("logout")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("anonymous"));
    expect(screen.getByTestId("principal").textContent).toBe("none");
  });

  it("allows leaving a session already revoked by an administrator", async () => {
    const revokedRepository = repository();
    revokedRepository.logout = async () => { throw new HttpProblem(401, "iam.authentication.failed"); };
    const screen = render(<SessionProvider repository={revokedRepository}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("logout")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("anonymous"));
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });

  it("requires a first-login password change before authenticating", async () => {
    const screen = render(
      <SessionProvider repository={repository({ mustChangePassword: true })}>
        <Probe />
      </SessionProvider>
    );
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("password-change-required"));
    expect(screen.getByTestId("principal").textContent).toBe("admin");
    expect(screen.container.textContent).not.toContain(secretCredential);
    await act(async () => fireEvent.click(screen.getByText("change")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
  });

  it("keeps a definite first-login validation rejection inside the required scene", async () => {
    const source = repository({ mustChangePassword: true });
    source.changePassword = vi.fn().mockRejectedValue(new HttpProblem(422, "iam.request.invalid"));
    const screen = render(
      <SessionProvider repository={source}>
        <Probe />
      </SessionProvider>
    );
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("password-change-required"));
    await act(async () => fireEvent.click(screen.getByText("change")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("password-change-required"));
    expect(screen.getByTestId("error").textContent).toContain("新密码需为");
    expect(screen.getByTestId("has-credential").textContent).toBe("true");
  });

  it.each([
    { required: false, button: "change", revokeOtherSessions: true },
    { required: false, button: "retain", revokeOtherSessions: false },
    { required: true, button: "retain", revokeOtherSessions: true }
  ])("applies the effective password policy $required/$button", async ({ required, button, revokeOtherSessions }) => {
    const source = repository({ mustChangePassword: required });
    source.changePassword = vi.fn().mockResolvedValue(undefined);
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText(button)));
    expect(source.changePassword).toHaveBeenCalledWith(secretCredential, {
      currentPassword: "Initial-Admin-Password-49!", newPassword: "Changed-Admin-Password-73!", revokeOtherSessions
    });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("has-credential").textContent).toBe("true");
  });

  it.each([true, false])("fails closed on invalid or uncertain password results (required=%s)", async (required) => {
    for (const error of [new HttpProblem(401, "private upstream"), new HttpProblem(409, "private upstream"), new HttpProblem(503, "private upstream"), new Error("private upstream")]) {
      const source = repository({ mustChangePassword: required });
      source.changePassword = vi.fn().mockRejectedValue(error);
      const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
      await act(async () => fireEvent.click(screen.getByText("login")));
      await act(async () => fireEvent.click(screen.getByText("change")));
      expect(screen.getByTestId("phase").textContent).toBe("anonymous");
      expect(screen.getByTestId("has-credential").textContent).toBe("false");
      expect(screen.getByTestId("error").textContent).toContain("重新登录");
      expect(screen.container.textContent).not.toContain("private upstream");
      screen.unmount();
    }
  });

  it.each([true, false])("does not let a late password response undo logout (required=%s)", async (required) => {
    let complete!: () => void;
    const source = repository({ mustChangePassword: required });
    source.changePassword = () => new Promise<void>((resolve) => { complete = resolve; });
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("change")));
    expect(screen.getByTestId("phase").textContent).toBe(required ? "changing-password" : "updating-password");
    await act(async () => fireEvent.click(screen.getByText("logout")));
    await act(async () => complete());
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
  });

  it("does not let a late password response undo session expiry", async () => {
    vi.useFakeTimers();
    let complete!: () => void;
    const source = repository({ mustChangePassword: true });
    const login = source.login;
    source.login = async (command) => {
      const result = await login(command);
      if (result.outcome !== "AUTHENTICATED") throw new Error("unexpected challenged fixture");
      return { ...result, session: { ...result.session, expiresAt: new Date(Date.now() + 100).toISOString() } };
    };
    source.changePassword = () => new Promise<void>((resolve) => { complete = resolve; });
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("change")));
    await act(async () => vi.advanceTimersByTime(101));
    await act(async () => complete());
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
  });

  it("stores one-time recovery codes only in memory, revokes the old session and requires explicit acknowledgement", async () => {
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `private-recovery-${index}`);
    const source = repository();
    source.personalSecurity = {
      notificationContact: vi.fn(),
      startNotificationVerification: vi.fn(),
      notificationVerification: vi.fn(),
      confirmNotificationVerification: vi.fn(),
      authenticatorState: vi.fn(),
      startTOTPEnrollment: vi.fn(),
      totpEnrollment: vi.fn(),
      totpEnrollmentByRequest: vi.fn(),
      cancelTOTPEnrollment: vi.fn(),
      confirmTOTPEnrollment: vi.fn().mockResolvedValue({
        enrollment: {
          id: "enrollment-one", requestId: "start-one", factorRevision: 1, state: "CONFIRMED",
          createdAt: "2026-08-27T01:00:00Z", expiresAt: "2026-08-27T01:05:00Z", completedAt: "2026-08-27T01:01:00Z"
        },
        nextStep: "REAUTHENTICATE",
        recoveryCodes
      })
    };
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("confirm-enrollment")));
    expect(source.personalSecurity!.confirmTOTPEnrollment).toHaveBeenCalledWith(secretCredential, "enrollment-one", {
      requestId: "confirm-one", code: "123456"
    });
    expect(screen.getByTestId("phase").textContent).toBe("recovery-codes-required");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.getByTestId("recovery-count").textContent).toBe("10");
    expect(screen.container.textContent).not.toContain(recoveryCodes[0]);
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await act(async () => fireEvent.click(screen.getByText("acknowledge-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("recovery-count").textContent).toBe("0");
  });

  it("fails closed on an uncertain enrollment confirmation without claiming that recovery codes exist", async () => {
    const source = repository();
    source.personalSecurity = {
      notificationContact: vi.fn(),
      startNotificationVerification: vi.fn(),
      notificationVerification: vi.fn(),
      confirmNotificationVerification: vi.fn(),
      authenticatorState: vi.fn(),
      startTOTPEnrollment: vi.fn(),
      totpEnrollment: vi.fn(),
      totpEnrollmentByRequest: vi.fn(),
      cancelTOTPEnrollment: vi.fn(),
      confirmTOTPEnrollment: vi.fn().mockRejectedValue(new Error("private transport failure"))
    };
    const screen = render(<SessionProvider repository={source}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("confirm-enrollment")));
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("has-credential").textContent).toBe("false");
    expect(screen.getByTestId("recovery-count").textContent).toBe("0");
    expect(screen.getByTestId("error").textContent).toContain("无法确认身份验证器绑定结果");
    expect(screen.container.textContent).not.toContain("private transport failure");
  });
});
