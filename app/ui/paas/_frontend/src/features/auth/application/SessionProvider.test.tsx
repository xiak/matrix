import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { IamRepository } from "../repositories/iamRepository";
import { SessionProvider, useSession, useSessionCredential } from "./SessionProvider";

const secretCredential = "must-not-enter-browser-storage-or-dom";

function Probe() {
  const session = useSession();
  const hasCredential = useSessionCredential() !== null;
  return (
    <div>
      <span data-testid="phase">{session.phase}</span>
      <span data-testid="principal">{session.current?.loginName ?? "none"}</span>
      <span data-testid="error">{session.error ?? "none"}</span>
      <span data-testid="has-credential">{String(hasCredential)}</span>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
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
});
