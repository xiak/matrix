import { useState } from "react";
import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { LoginResult } from "../domain/session";
import type { RecoveryCodeRegenerationResponse } from "../domain/personalSecurity";
import type { IamRepository, StartAuthenticatorRecoveryCommand } from "../repositories/iamRepository";
import { SessionProvider, useSession } from "./SessionProvider";
import { usePersonalSecurity } from "./PersonalSecurityProvider";

const secretCredential = "must-not-enter-browser-storage-or-dom";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}

function Probe() {
  const session = useSession();
  const security = usePersonalSecurity();
  const [returnedCodes, setReturnedCodes] = useState<string[]>([]);
  return (
    <div>
      <span data-testid="phase">{session.phase}</span>
      <span data-testid="principal">{session.current?.loginName ?? "none"}</span>
      <span data-testid="challenge">{session.challenge?.challenge.nextStep ?? "none"}</span>
      <span data-testid="error">{session.error ?? "none"}</span>
      <span data-testid="recovery">{session.enrollmentRecovery?.recoveryCodes.join("|") ?? "none"}</span>
      <span data-testid="authenticator-recovery">{session.authenticatorRecovery?.state ?? "none"}</span>
      <span data-testid="code-regeneration">{security?.recoveryCodeRegenerationIntent?.state ?? "none"}</span>
      <span data-testid="returned-codes">{returnedCodes.join("|") || "none"}</span>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <button onClick={() => void session.login("bravo", "password")} type="button">login-b</button>
      <button
        onClick={() => void session.changePassword("Initial-Admin-Password-49!", "Changed-Admin-Password-73!")}
        type="button"
      >change</button>
      <button onClick={() => void session.logout()} type="button">logout</button>
      <button onClick={() => void session.verifyAuthenticationChallenge("123456")} type="button">verify</button>
      <button onClick={session.enterAuthenticatorRecovery} type="button">enter-recovery</button>
      <button onClick={() => void session.startAuthenticatorRecovery("RECOVERY-ONE")} type="button">start-recovery</button>
      <button onClick={() => void session.confirmAuthenticatorRecovery("654321")} type="button">confirm-recovery</button>
      <button onClick={() => void session.inspectAuthenticatorRecovery()} type="button">inspect-recovery</button>
      <button onClick={session.restartAuthenticatorRecovery} type="button">restart-recovery</button>
      <button onClick={session.leaveAuthenticatorRecovery} type="button">leave-recovery</button>
      <button onClick={() => void session.changeChallengePassword("Changed-Admin-Password-73!")} type="button">challenge-change</button>
      <button onClick={session.acknowledgeReauthentication} type="button">acknowledge</button>
      <button onClick={session.acknowledgeEnrollmentRecovery} type="button">acknowledge-recovery</button>
      {security ? <button onClick={() => void security.confirmTOTPEnrollment("enrollment-one", { requestId: "confirm-one", code: "123456" })} type="button">confirm-enrollment</button> : null}
      {security ? <button onClick={() => void security.startRecoveryCodeRegeneration({ requestId: "regenerate-one", factorId: "factor-one", expectedFactorRevision: 2 })} type="button">start-code-regeneration</button> : null}
      {security ? <button onClick={() => void security.startRecoveryCodeRegeneration({ requestId: "regenerate-two", factorId: "factor-two", expectedFactorRevision: 2 })} type="button">start-code-regeneration-b</button> : null}
      {security ? <button onClick={() => void security.verifyRecoveryCodeStepUp({ requestId: "verify-one", password: "password", code: "123456" })} type="button">verify-code-regeneration</button> : null}
      {security ? <button onClick={() => void security.regenerateRecoveryCodes().catch(() => undefined)} type="button">regenerate-codes</button> : null}
      {security ? <button onClick={() => void security.regenerateRecoveryCodes().then((result) => setReturnedCodes(result.outcome === "APPLIED" ? result.recoveryCodes : [])).catch(() => undefined)} type="button">capture-regenerated-codes</button> : null}
      {security ? <button onClick={() => void security.inspectRecoveryCodeRegeneration()} type="button">inspect-code-regeneration</button> : null}
      {security?.recoveryCodeRegenerationIntent ? <button onClick={() => security.clearRecoveryCodeRegenerationIntent(security.recoveryCodeRegenerationIntent!.requestId)} type="button">clear-code-regeneration</button> : null}
      <button onClick={session.cancelAuthenticationChallenge} type="button">cancel-challenge</button>
      <button onClick={() => session.expire(secretCredential)} type="button">expire</button>
    </div>
  );
}

function repository({
  mustChangePassword = false,
  logoutFailure = false,
  passwordFailure = false
}: {
  mustChangePassword?: boolean;
  logoutFailure?: boolean;
  passwordFailure?: boolean;
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
    async changePassword() {
      if (passwordFailure) throw new Error("unavailable");
    },
    async logout() {
      if (logoutFailure) throw new Error("unavailable");
    }
  };
}

afterEach(() => {
  vi.useRealTimers();
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
});

describe("SessionProvider", () => {
  it("does not let a late 401 from an earlier login expire a new Session that reused the bearer", async () => {
    let originalRevision = 0;
    const EpochProbe = () => {
      const session = useSession();
      return <>
        <span data-testid="epoch-phase">{session.phase}</span>
        <span data-testid="epoch-revision">{session.sessionRevision}</span>
        <button onClick={() => void session.login("admin", "password")}>login-epoch</button>
        <button onClick={() => { originalRevision = session.sessionRevision; }}>capture-epoch</button>
        <button onClick={() => { session.expire(secretCredential, originalRevision); }}>expire-old-epoch</button>
        <button onClick={() => { session.expire(secretCredential, session.sessionRevision); }}>expire-current-epoch</button>
      </>;
    };
    const view = render(<SessionProvider repository={repository()}><EpochProbe /></SessionProvider>);
    await act(async () => fireEvent.click(view.getByText("login-epoch")));
    fireEvent.click(view.getByText("capture-epoch"));
    const firstRevision = view.getByTestId("epoch-revision").textContent;
    await act(async () => fireEvent.click(view.getByText("login-epoch")));
    expect(view.getByTestId("epoch-revision").textContent).not.toBe(firstRevision);
    fireEvent.click(view.getByText("expire-old-epoch"));
    expect(view.getByTestId("epoch-phase").textContent).toBe("authenticated");
    fireEvent.click(view.getByText("expire-current-epoch"));
    expect(view.getByTestId("epoch-phase").textContent).toBe("anonymous");
  });

  it("keeps one-time recovery material visible after IAM revokes the enrollment session", async () => {
    const iam = repository();
    const codes = Array.from({ length: 10 }, (_, index) => `RECOVERY-${index}`);
    iam.personalSecurity = {
      notificationContact: vi.fn(), startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), authenticatorState: vi.fn(), startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(),
      confirmTOTPEnrollment: vi.fn().mockResolvedValue({
        enrollment: { id: "enrollment-one", requestId: "enroll-one", factorRevision: 1, state: "CONFIRMED", createdAt: "2026-09-21T01:00:00Z", expiresAt: "2026-09-21T01:05:00Z", completedAt: "2026-09-21T01:04:00Z" },
        nextStep: "REAUTHENTICATE", recoveryCodes: codes
      })
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("confirm-enrollment")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-codes-required");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.getByTestId("recovery").textContent).toContain("RECOVERY-9");
    expect(screen.container.textContent).not.toContain(secretCredential);
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await act(async () => fireEvent.click(screen.getByText("acknowledge-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("recovery").textContent).toBe("none");
  });

  it("clears private identity when the current bearer has expired", async () => {
    const screen = render(<SessionProvider repository={repository()}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("expire")));
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.container.textContent).not.toContain(secretCredential);
  });

  it("does not expire a new login because an older bearer's request returned late", async () => {
    const iam = repository();
    const initial = iam.login;
    let logins = 0;
    iam.login = async (command) => ({ ...await initial(command), credential: logins++ === 0 ? secretCredential : `${secretCredential}-new` });
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("expire")));
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("admin");
  });

  it("queries an unknown recovery-code regeneration with the fresh Session of the same USER", async () => {
    const iam = repository();
    let loginCount = 0;
    iam.login = vi.fn(async () => {
      loginCount += 1;
      return {
        outcome: "AUTHENTICATED" as const,
        credential: `${secretCredential}-${loginCount}`,
        mustChangePassword: false,
        session: {
          id: `session-${loginCount}`,
          organizationId: "organization-test",
          principalId: "principal-test",
          status: "ACTIVE" as const,
          issuedAt: "2026-08-26T12:00:00Z",
          expiresAt: "2099-08-26T20:00:00Z"
        }
      };
    });
    iam.personalSecurity = {
      notificationContact: vi.fn(), startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), authenticatorState: vi.fn(), startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: {
        startStepUp: vi.fn().mockResolvedValue({ id: "step-up-one", requestId: "regenerate-one", operation: "RECOVERY_CODES_REGENERATE", expectedFactorRevision: 2, state: "PENDING", createdAt: "2026-09-21T01:00:00Z", expiresAt: "2026-09-21T01:02:00Z", provedAt: null, consumedAt: null }),
        stepUpByRequest: vi.fn(),
        verifyStepUp: vi.fn().mockResolvedValue({ id: "step-up-one", requestId: "regenerate-one", operation: "RECOVERY_CODES_REGENERATE", expectedFactorRevision: 2, state: "PROVED", createdAt: "2026-09-21T01:00:00Z", expiresAt: "2026-09-21T01:02:00Z", provedAt: "2026-09-21T01:00:30Z", consumedAt: null }),
        regenerate: vi.fn().mockRejectedValue(new Error("connection lost after command")),
        regenerationByRequest: vi.fn().mockResolvedValue({ id: "regeneration-one", requestId: "regenerate-one", factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-21T01:00:40Z" })
      }
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);

    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("start-code-regeneration")));
    await act(async () => fireEvent.click(screen.getByText("verify-code-regeneration")));
    await act(async () => fireEvent.click(screen.getByText("regenerate-codes")));
    expect(screen.getByTestId("code-regeneration").textContent).toBe("REGENERATION_UNKNOWN");

    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("code-regeneration").textContent).toBe("REGENERATION_UNKNOWN"));
    await act(async () => fireEvent.click(screen.getByText("inspect-code-regeneration")));

    expect(iam.personalSecurity.recoveryCodes!.regenerationByRequest).toHaveBeenCalledWith(`${secretCredential}-2`, "regenerate-one");
    expect(screen.getByTestId("code-regeneration").textContent).toBe("COMPLETED");
    expect(screen.container.textContent).not.toContain(secretCredential);
  });
  it.each(["same USER", "different USER"])("never returns a late one-time batch to a new %s Session or overwrites its intent", async (nextIdentity) => {
    const late = deferred<RecoveryCodeRegenerationResponse>();
    const iam = repository();
    let loginCount = 0;
    iam.login = vi.fn(async ({ loginName }) => {
      loginCount += 1;
      return {
        outcome: "AUTHENTICATED" as const,
        credential: nextIdentity === "same USER" ? secretCredential : `${secretCredential}-${loginCount}`,
        mustChangePassword: false,
        session: { id: `session-${loginCount}`, organizationId: "organization-test", principalId: nextIdentity === "same USER" ? "principal-test" : `principal-${loginName}`, status: "ACTIVE" as const, issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
      };
    });
    iam.personalSecurity = {
      notificationContact: vi.fn(), startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(), authenticatorState: vi.fn(), startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: {
        startStepUp: vi.fn(async (_credential, command) => ({ id: `step-up-${command.requestId}`, requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-21T01:02:00Z", provedAt: null, consumedAt: null })),
        stepUpByRequest: vi.fn(),
        verifyStepUp: vi.fn(async (_credential, _stepUpId, command) => ({ id: `step-up-${command.requestId === "verify-one" ? "regenerate-one" : "regenerate-two"}`, requestId: command.requestId === "verify-one" ? "regenerate-one" : "regenerate-two", operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PROVED" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-21T01:02:00Z", provedAt: "2026-09-21T01:00:30Z", consumedAt: null })),
        regenerate: vi.fn(() => late.promise),
        regenerationByRequest: vi.fn(async () => ({ id: "regeneration-one", requestId: "regenerate-one", factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-21T01:00:40Z" }))
      }
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("start-code-regeneration")));
    await act(async () => fireEvent.click(screen.getByText("verify-code-regeneration")));
    await act(async () => fireEvent.click(screen.getByText("capture-regenerated-codes")));
    expect(screen.getByTestId("code-regeneration").textContent).toBe("REGENERATION_UNKNOWN");

    await act(async () => fireEvent.click(screen.getByText(nextIdentity === "same USER" ? "login" : "login-b")));
    if (nextIdentity === "same USER") {
      await act(async () => fireEvent.click(screen.getByText("inspect-code-regeneration")));
      await act(async () => fireEvent.click(screen.getByText("clear-code-regeneration")));
    }
    await act(async () => fireEvent.click(screen.getByText("start-code-regeneration-b")));
    expect(screen.getByTestId("code-regeneration").textContent).toBe("PENDING");

    await act(async () => {
      late.resolve({ outcome: "APPLIED", regeneration: { id: "regeneration-one", requestId: "regenerate-one", factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-21T01:00:40Z" }, recoveryCodes: Array.from({ length: 10 }, (_, index) => `A-ONLY-CODE-${index}`) });
      await Promise.resolve();
    });
    expect(screen.getByTestId("returned-codes").textContent).toBe("none");
    expect(screen.getByTestId("code-regeneration").textContent).toBe("PENDING");
    expect(screen.container.textContent).not.toContain("A-ONLY-CODE-");
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("keeps the bearer only in provider memory", async () => {
    const screen = render(<SessionProvider repository={repository()}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    expect(screen.container.textContent).not.toContain(secretCredential);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("does not forget a session when IAM revocation fails", async () => {
    const screen = render(<SessionProvider repository={repository({ logoutFailure: true })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    await act(async () => fireEvent.click(screen.getByText("logout")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("authenticated"));
    expect(screen.getByTestId("principal").textContent).toBe("admin");
    expect(screen.getByTestId("error").textContent).toBe("logoutUnavailable");
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

  it("keeps a failed first-login password change inside the required scene", async () => {
    const screen = render(
      <SessionProvider repository={repository({ mustChangePassword: true, passwordFailure: true })}>
        <Probe />
      </SessionProvider>
    );
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("password-change-required"));
    await act(async () => fireEvent.click(screen.getByText("change")));
    await waitFor(() => expect(screen.getByTestId("phase").textContent).toBe("password-change-required"));
    expect(screen.getByTestId("error").textContent).toBe("passwordUnavailable");
  });

  it("keeps a TOTP challenge sessionless and memory-only until verification succeeds", async () => {
    const challengeCredential = "challenge-secret-must-not-render";
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({
      outcome: "CHALLENGE_REQUIRED",
      challenge: { id: "challenge-one", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential
    });
    iam.authenticationChallenges = {
      verify: vi.fn().mockResolvedValue({ outcome: "AUTHENTICATED", credential: secretCredential, mustChangePassword: false,
        session: { id: "session-test", organizationId: "organization-test", principalId: "principal-test", status: "ACTIVE", issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" } }),
      changePassword: vi.fn()
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-required");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.getByTestId("challenge").textContent).toBe("TOTP");
    expect(screen.container.textContent).not.toContain(challengeCredential);
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(iam.authenticationChallenges.verify).toHaveBeenCalledWith({ challengeId: "challenge-one", challengeCredential, code: "123456" });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("admin");
  });

  it("uses a separate password challenge and requires a fresh login after the change", async () => {
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge: { id: "challenge-totp", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" }, challengeCredential: "totp-secret" });
    iam.authenticationChallenges = {
      verify: vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge: { id: "challenge-password", purpose: "LOGIN", nextStep: "PASSWORD_CHANGE", expiresAt: "2099-09-20T01:07:03Z" }, challengeCredential: "password-secret" }),
      changePassword: vi.fn().mockResolvedValue({ nextStep: "REAUTHENTICATE", changedAt: "2026-09-20T01:03:00Z" })
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-password-required");
    expect(screen.getByTestId("challenge").textContent).toBe("PASSWORD_CHANGE");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    await act(async () => fireEvent.click(screen.getByText("challenge-change")));
    expect(iam.authenticationChallenges.changePassword).toHaveBeenCalledWith({ challengeId: "challenge-password", challengeCredential: "password-secret", newPassword: "Changed-Admin-Password-73!" });
    expect(screen.getByTestId("phase").textContent).toBe("reauthentication-required");
    expect(screen.getByTestId("challenge").textContent).toBe("none");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    await act(async () => fireEvent.click(screen.getByText("acknowledge")));
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
  });

  it("keeps authenticator recovery sessionless through irreversible start, rebind, and one-time codes", async () => {
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({
      outcome: "CHALLENGE_REQUIRED",
      challenge: { id: "login-challenge", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "login-challenge-secret"
    });
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `NEW-RECOVERY-${index}`);
    const startRecovery = vi.fn(async (command: StartAuthenticatorRecoveryCommand) => ({
      recovery: { id: "recovery-one", requestId: command.requestId, state: "STARTED" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z" },
      challenge: { id: "recovery-challenge", purpose: "RECOVERY" as const, nextStep: "ENROLLMENT" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "recovery-challenge-secret",
      provisioning: { seed: "NEW-SEED-MUST-STAY-IN-MEMORY", uri: "otpauth://totp/Matrix:test?secret=NEW-SEED-MUST-STAY-IN-MEMORY" }
    }));
    iam.authenticationChallenges = {
      verify: vi.fn(), changePassword: vi.fn(), inspectRecovery: vi.fn(),
      startRecovery,
      confirmRecovery: vi.fn(async (command) => ({
        recovery: { id: "recovery-one", requestId: command.recoveryRequestId, state: "COMPLETED" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z", completedAt: "2026-09-21T01:02:00Z" },
        nextStep: "REAUTHENTICATE" as const,
        recoveryCodes
      }))
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("enter-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-code-required");
    await act(async () => fireEvent.click(screen.getByText("start-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-enrollment-required");
    expect(screen.getByTestId("challenge").textContent).toBe("ENROLLMENT");
    expect(screen.getByTestId("authenticator-recovery").textContent).toBe("STARTED");
    expect(screen.container.textContent).not.toContain("NEW-SEED-MUST-STAY-IN-MEMORY");
    expect(localStorage.length + sessionStorage.length).toBe(0);
    await act(async () => fireEvent.click(screen.getByText("confirm-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-codes-required");
    expect(screen.getByTestId("challenge").textContent).toBe("none");
    expect(screen.getByTestId("authenticator-recovery").textContent).toBe("none");
    expect(screen.getByTestId("recovery").textContent).toContain("NEW-RECOVERY-9");
  });

  it("never auto-retries an unknown recovery start and inspects the original request after a fresh login", async () => {
    const iam = repository();
    let logins = 0;
    iam.login = vi.fn(async () => ({
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: {
        id: logins++ === 0 ? "login-original" : "login-fresh",
        purpose: "LOGIN" as const,
        nextStep: logins === 1 ? "TOTP" as const : "RECOVER" as const,
        expiresAt: "2099-09-20T01:07:03Z"
      },
      challengeCredential: logins === 1 ? "original-secret" : "fresh-secret"
    }));
    const startRecovery = vi.fn().mockRejectedValue(new Error("connection ended after request write"));
    const inspectRecovery = vi.fn(async (command) => ({
      id: "recovery-unknown", requestId: command.requestId, state: "STARTED" as const,
      createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z"
    }));
    iam.authenticationChallenges = { verify: vi.fn(), changePassword: vi.fn(), startRecovery, confirmRecovery: vi.fn(), inspectRecovery };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("enter-recovery")));
    await act(async () => fireEvent.click(screen.getByText("start-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-start-unknown");
    expect(screen.getByTestId("error").textContent).toBe("recoveryOutcomeUnknown");
    expect(startRecovery).toHaveBeenCalledOnce();
    const originalRequestId = startRecovery.mock.calls[0]![0].requestId as string;
    await act(async () => fireEvent.click(screen.getByText("leave-recovery")));
    await act(async () => fireEvent.click(screen.getByText("login")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-result-required");
    await act(async () => fireEvent.click(screen.getByText("inspect-recovery")));
    expect(inspectRecovery).toHaveBeenCalledWith({ challengeId: "login-fresh", challengeCredential: "fresh-secret", requestId: originalRequestId });
    expect(startRecovery).toHaveBeenCalledOnce();
    expect(screen.getByTestId("phase").textContent).toBe("recovery-start-unknown");
    expect(screen.getByTestId("authenticator-recovery").textContent).toBe("MATERIAL_LOST");
    await act(async () => fireEvent.click(screen.getByText("restart-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-code-required");
  });

  it("does not inspect or replay one-time codes after an unknown recovery confirmation", async () => {
    const iam = repository();
    let logins = 0;
    iam.login = vi.fn(async () => ({
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: { id: `login-${++logins}`, purpose: "LOGIN" as const, nextStep: "TOTP" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: `login-secret-${logins}`
    }));
    const inspectRecovery = vi.fn();
    iam.authenticationChallenges = {
      verify: vi.fn().mockResolvedValue({ outcome: "AUTHENTICATED", credential: secretCredential, mustChangePassword: false,
        session: { id: "session-test", organizationId: "organization-test", principalId: "principal-test", status: "ACTIVE", issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" } }),
      changePassword: vi.fn(), inspectRecovery,
      startRecovery: vi.fn(async (command) => ({
        recovery: { id: "recovery-one", requestId: command.requestId, state: "STARTED" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z" },
        challenge: { id: "recovery-challenge", purpose: "RECOVERY" as const, nextStep: "ENROLLMENT" as const, expiresAt: "2099-09-20T01:07:03Z" },
        challengeCredential: "recovery-secret", provisioning: { seed: "new-seed", uri: "otpauth://new" }
      })),
      confirmRecovery: vi.fn().mockRejectedValue(new Error("connection ended after commit"))
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("enter-recovery")));
    await act(async () => fireEvent.click(screen.getByText("start-recovery")));
    await act(async () => fireEvent.click(screen.getByText("confirm-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-confirm-unknown");
    await act(async () => fireEvent.click(screen.getByText("leave-recovery")));
    await act(async () => fireEvent.click(screen.getByText("login")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-required");
    expect(inspectRecovery).not.toHaveBeenCalled();
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("authenticator-recovery").textContent).toBe("none");
  });

  it.each(["STARTED", "EXPIRED"] as const)("inspects the original recovery after a pre-commit confirmation loss resolves to %s", async (recoveryState) => {
    const iam = repository();
    let logins = 0;
    iam.login = vi.fn(async () => ({
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: {
        id: logins++ === 0 ? "login-original" : "login-after-loss",
        purpose: "LOGIN" as const,
        nextStep: logins === 1 ? "TOTP" as const : "RECOVER" as const,
        expiresAt: "2099-09-20T01:07:03Z"
      },
      challengeCredential: logins === 1 ? "original-secret" : "fresh-secret"
    }));
    const startRecovery = vi.fn(async (command: StartAuthenticatorRecoveryCommand) => ({
      recovery: { id: "recovery-pre-commit", requestId: command.requestId, state: "STARTED" as const, createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z" },
      challenge: { id: "recovery-challenge", purpose: "RECOVERY" as const, nextStep: "ENROLLMENT" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "recovery-secret", provisioning: { seed: "never-persist", uri: "otpauth://never-persist" }
    }));
    const inspectRecovery = vi.fn(async (command) => ({
      id: "recovery-pre-commit", requestId: command.requestId, state: recoveryState,
      createdAt: "2026-09-21T01:00:00Z", expiresAt: "2099-09-20T01:07:03Z",
      ...(recoveryState === "EXPIRED" ? { completedAt: "2099-09-20T01:07:03Z" } : {})
    }));
    iam.authenticationChallenges = {
      verify: vi.fn(), changePassword: vi.fn(), startRecovery, inspectRecovery,
      confirmRecovery: vi.fn().mockRejectedValue(new Error("connection ended before commit"))
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("enter-recovery")));
    await act(async () => fireEvent.click(screen.getByText("start-recovery")));
    await act(async () => fireEvent.click(screen.getByText("confirm-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-confirm-unknown");
    const originalRequestId = startRecovery.mock.calls[0]![0].requestId as string;

    await act(async () => fireEvent.click(screen.getByText("leave-recovery")));
    await act(async () => fireEvent.click(screen.getByText("login")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-result-required");
    await act(async () => fireEvent.click(screen.getByText("inspect-recovery")));
    expect(inspectRecovery).toHaveBeenCalledWith({ challengeId: "login-after-loss", challengeCredential: "fresh-secret", requestId: originalRequestId });
    expect(screen.getByTestId("phase").textContent).toBe(recoveryState === "STARTED" ? "recovery-start-unknown" : "recovery-code-required");
    expect(screen.getByTestId("recovery").textContent).toBe("none");
    expect(startRecovery).toHaveBeenCalledOnce();
    expect(iam.authenticationChallenges.confirmRecovery).toHaveBeenCalledOnce();

    if (recoveryState === "STARTED") {
      await act(async () => fireEvent.click(screen.getByText("restart-recovery")));
      expect(screen.getByTestId("phase").textContent).toBe("recovery-code-required");
      expect(startRecovery).toHaveBeenCalledOnce();
    }
  });

  it("does not let one login name's unresolved recovery alter another identity's challenge", async () => {
    const iam = repository();
    iam.login = vi.fn(async ({ loginName }) => ({
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: { id: `challenge-${loginName}`, purpose: "LOGIN" as const, nextStep: "TOTP" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: `secret-${loginName}`
    }));
    const inspectRecovery = vi.fn();
    iam.authenticationChallenges = {
      verify: vi.fn().mockResolvedValue({ outcome: "AUTHENTICATED", credential: `${secretCredential}-bravo`, mustChangePassword: false,
        session: { id: "session-bravo", organizationId: "organization-test", principalId: "principal-bravo", status: "ACTIVE", issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" } }),
      changePassword: vi.fn(), inspectRecovery,
      startRecovery: vi.fn().mockRejectedValue(new Error("connection ended after request write")),
      confirmRecovery: vi.fn()
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("enter-recovery")));
    await act(async () => fireEvent.click(screen.getByText("start-recovery")));
    expect(screen.getByTestId("phase").textContent).toBe("recovery-start-unknown");
    await act(async () => fireEvent.click(screen.getByText("leave-recovery")));

    await act(async () => fireEvent.click(screen.getByText("login-b")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-required");
    expect(inspectRecovery).not.toHaveBeenCalled();
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("bravo");
    expect(screen.getByTestId("authenticator-recovery").textContent).toBe("none");
  });

  it("does not turn a rejected challenge into a session", async () => {
    const iam = repository();
    iam.login = vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge: { id: "challenge-one", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" }, challengeCredential: "challenge-secret" });
    iam.authenticationChallenges = { verify: vi.fn().mockRejectedValue(new HttpProblem(401, "private")), changePassword: vi.fn() };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("challenge-required");
    expect(screen.getByTestId("principal").textContent).toBe("none");
    expect(screen.getByTestId("error").textContent).toBe("invalidVerificationCode");
  });

  it.each(["success", "failure"] as const)("discards a late verify %s after cancellation and a newer login", async (result) => {
    const lateVerify = deferred<LoginResult>();
    const iam = repository();
    iam.login = vi.fn(async ({ loginName }) => loginName === "admin" ? {
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: { id: "challenge-a", purpose: "LOGIN" as const, nextStep: "TOTP" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "challenge-a-secret"
    } : {
      outcome: "AUTHENTICATED" as const,
      credential: `${secretCredential}-bravo`,
      mustChangePassword: false,
      session: { id: "session-bravo", organizationId: "organization-test", principalId: "principal-bravo", status: "ACTIVE" as const,
        issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
    });
    iam.authenticationChallenges = { verify: vi.fn(() => lateVerify.promise), changePassword: vi.fn() };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    expect(screen.getByTestId("phase").textContent).toBe("verifying-challenge");
    await act(async () => fireEvent.click(screen.getByText("cancel-challenge")));
    await act(async () => fireEvent.click(screen.getByText("login-b")));
    expect(screen.getByTestId("principal").textContent).toBe("bravo");

    await act(async () => {
      if (result === "success") lateVerify.resolve({
        outcome: "AUTHENTICATED", credential: secretCredential, mustChangePassword: false,
        session: { id: "session-a", organizationId: "organization-test", principalId: "principal-a", status: "ACTIVE",
          issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
      });
      else lateVerify.reject(new HttpProblem(401, "late-private-error"));
      await Promise.resolve();
    });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("bravo");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });

  it("discards a late verify result after the challenge expires and a newer login succeeds", async () => {
    vi.useFakeTimers({ now: new Date("2026-09-21T00:00:00Z") });
    const lateVerify = deferred<LoginResult>();
    const iam = repository();
    iam.login = vi.fn(async ({ loginName }) => loginName === "admin" ? {
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: { id: "challenge-expiring", purpose: "LOGIN" as const, nextStep: "TOTP" as const, expiresAt: "2026-09-21T00:00:01Z" },
      challengeCredential: "challenge-expiring-secret"
    } : {
      outcome: "AUTHENTICATED" as const,
      credential: `${secretCredential}-bravo`, mustChangePassword: false,
      session: { id: "session-bravo", organizationId: "organization-test", principalId: "principal-bravo", status: "ACTIVE" as const,
        issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
    });
    iam.authenticationChallenges = { verify: vi.fn(() => lateVerify.promise), changePassword: vi.fn() };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    await act(async () => vi.advanceTimersByTime(1_001));
    expect(screen.getByTestId("phase").textContent).toBe("anonymous");
    expect(screen.getByTestId("error").textContent).toBe("challengeExpired");
    await act(async () => fireEvent.click(screen.getByText("login-b")));
    await act(async () => {
      lateVerify.resolve({
        outcome: "AUTHENTICATED", credential: secretCredential, mustChangePassword: false,
        session: { id: "session-a", organizationId: "organization-test", principalId: "principal-a", status: "ACTIVE",
          issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
      });
      await Promise.resolve();
    });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("bravo");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });

  it.each(["success", "failure"] as const)("discards a late challenge-password %s after cancellation and a newer login", async (result) => {
    const latePassword = deferred<{ nextStep: "REAUTHENTICATE"; changedAt: string }>();
    const iam = repository();
    iam.login = vi.fn(async ({ loginName }) => loginName === "admin" ? {
      outcome: "CHALLENGE_REQUIRED" as const,
      challenge: { id: "challenge-a", purpose: "LOGIN" as const, nextStep: "TOTP" as const, expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "challenge-a-secret"
    } : {
      outcome: "AUTHENTICATED" as const,
      credential: `${secretCredential}-bravo`, mustChangePassword: false,
      session: { id: "session-bravo", organizationId: "organization-test", principalId: "principal-bravo", status: "ACTIVE" as const,
        issuedAt: "2026-08-26T12:00:00Z", expiresAt: "2099-08-26T20:00:00Z" }
    });
    iam.authenticationChallenges = {
      verify: vi.fn().mockResolvedValue({ outcome: "CHALLENGE_REQUIRED", challenge: {
        id: "challenge-password", purpose: "LOGIN", nextStep: "PASSWORD_CHANGE", expiresAt: "2099-09-20T01:07:03Z"
      }, challengeCredential: "challenge-password-secret" }),
      changePassword: vi.fn(() => latePassword.promise)
    };
    const screen = render(<SessionProvider repository={iam}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("verify")));
    await act(async () => fireEvent.click(screen.getByText("challenge-change")));
    expect(screen.getByTestId("phase").textContent).toBe("changing-challenge-password");
    await act(async () => fireEvent.click(screen.getByText("cancel-challenge")));
    await act(async () => fireEvent.click(screen.getByText("login-b")));

    await act(async () => {
      if (result === "success") latePassword.resolve({ nextStep: "REAUTHENTICATE", changedAt: "2026-09-21T00:00:00Z" });
      else latePassword.reject(new HttpProblem(409, "late-private-error"));
      await Promise.resolve();
    });
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(screen.getByTestId("principal").textContent).toBe("bravo");
    expect(screen.getByTestId("challenge").textContent).toBe("none");
    expect(screen.getByTestId("error").textContent).toBe("none");
  });
});
