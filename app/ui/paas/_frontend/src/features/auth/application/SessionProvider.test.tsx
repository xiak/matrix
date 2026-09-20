import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { IamRepository } from "../repositories/iamRepository";
import { SessionProvider, useSession } from "./SessionProvider";

const secretCredential = "must-not-enter-browser-storage-or-dom";

function Probe() {
  const session = useSession();
  return (
    <div>
      <span data-testid="phase">{session.phase}</span>
      <span data-testid="principal">{session.current?.loginName ?? "none"}</span>
      <span data-testid="challenge">{session.challenge?.challenge.nextStep ?? "none"}</span>
      <span data-testid="error">{session.error ?? "none"}</span>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <button
        onClick={() => void session.changePassword("Initial-Admin-Password-49!", "Changed-Admin-Password-73!")}
        type="button"
      >change</button>
      <button onClick={() => void session.logout()} type="button">logout</button>
      <button onClick={() => void session.verifyAuthenticationChallenge("123456")} type="button">verify</button>
      <button onClick={() => void session.changeChallengePassword("Changed-Admin-Password-73!")} type="button">challenge-change</button>
      <button onClick={session.acknowledgeReauthentication} type="button">acknowledge</button>
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
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
});

describe("SessionProvider", () => {
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
});
