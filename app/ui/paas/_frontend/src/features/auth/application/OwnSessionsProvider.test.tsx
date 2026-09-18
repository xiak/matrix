import { act, cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { OwnSessionPage } from "../domain/session";
import type { IamRepository } from "../repositories/iamRepository";
import { useOwnSessions } from "./OwnSessionsProvider";
import { SessionProvider, useSession } from "./SessionProvider";

const credentials = ["private-bearer-one", "private-bearer-two"];

function sessionPage(currentSessionId = "session-caller-1"): OwnSessionPage {
  return {
    accountId: "account-acme",
    userId: "user-alex",
    currentSessionId,
    observedAt: "2026-09-18T12:00:00Z",
    items: [
      { id: currentSessionId, organizationId: "account-acme", principalId: "user-alex", status: "ACTIVE" as const, issuedAt: "2026-09-17T10:00:00Z", expiresAt: "2099-09-17T10:00:00Z" },
      { id: "session-target", organizationId: "account-acme", principalId: "user-alex", status: "ACTIVE" as const, issuedAt: "2026-09-16T10:00:00Z", expiresAt: "2099-09-16T10:00:00Z" }
    ].sort((left, right) => left.id.localeCompare(right.id)),
    nextCursor: null
  };
}

function repository({
  list = async () => sessionPage(),
  revoke = async (_credential: string, targetSessionId: string) => ({
    outcome: "APPLIED" as const,
    revocation: { id: targetSessionId, resourceVersion: 2, revokedAt: "2026-09-18T12:00:00Z" }
  })
}: {
  list?: NonNullable<IamRepository["sessions"]>["list"];
  revoke?: NonNullable<IamRepository["sessions"]>["revoke"];
} = {}): IamRepository {
  let logins = 0;
  return {
    async login() {
      const index = Math.min(logins++, 1);
      return {
        credential: credentials[index]!,
        mustChangePassword: false,
        session: {
          id: `session-caller-${index + 1}`,
          organizationId: "account-acme",
          principalId: "user-alex",
          status: "ACTIVE",
          issuedAt: "2026-09-17T10:00:00Z",
          expiresAt: "2099-09-17T10:00:00Z"
        }
      };
    },
    async changePassword() {},
    async logout() {},
    sessions: { list, revoke }
  };
}

function Probe() {
  const session = useSession();
  const own = useOwnSessions();
  return <div>
    <output aria-label="phase">{session.phase}</output>
    <output aria-label="error">{own.error ?? "none"}</output>
    <output aria-label="success">{own.success ?? "none"}</output>
    <output aria-label="uncertain">{own.uncertainTargetId ?? "none"}</output>
    <output aria-label="count">{own.page?.items.length ?? 0}</output>
    <button onClick={() => { void session.login("alex@acme", "synthetic-password"); }}>login</button>
    <button onClick={() => { void own.load(); }}>load</button>
    <button onClick={() => { void own.revoke("session-target"); }}>revoke</button>
  </div>;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("OwnSessionsProvider", () => {
  it("retains and reuses the exact command after an unknown outcome", async () => {
    const requests: string[] = [];
    const revoke = vi.fn(async (_credential: string, targetSessionId: string, requestId: string) => {
      requests.push(requestId);
      if (requests.length === 1) throw new Error("connection lost");
      return { outcome: "EQUAL_REPLAY" as const, revocation: { id: targetSessionId, resourceVersion: 2, revokedAt: "2026-09-18T12:00:00Z" } };
    });
    const screen = render(<SessionProvider repository={repository({ revoke })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("load")));
    await waitFor(() => expect(screen.getByLabelText("count").textContent).toBe("2"));
    await act(async () => fireEvent.click(screen.getByText("revoke")));
    await waitFor(() => expect(screen.getByLabelText("uncertain").textContent).toBe("session-target"));
    await act(async () => fireEvent.click(screen.getByText("revoke")));
    await waitFor(() => expect(screen.getByLabelText("success").textContent).toBe("replayed"));
    expect(requests).toHaveLength(2);
    expect(requests[1]).toBe(requests[0]);
    expect(screen.getByLabelText("count").textContent).toBe("1");
    expect(screen.container.textContent).not.toContain(credentials[0]);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("never carries an uncertain revocation into a new login", async () => {
    const requests: Array<{ credential: string; requestId: string }> = [];
    const revoke = vi.fn(async (credential: string, _target: string, requestId: string) => {
      requests.push({ credential, requestId });
      throw new Error("connection lost");
    });
    const screen = render(<SessionProvider repository={repository({ revoke })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("revoke")));
    await waitFor(() => expect(screen.getByLabelText("uncertain").textContent).toBe("session-target"));
    await act(async () => fireEvent.click(screen.getByText("login")));
    await waitFor(() => expect(screen.getByLabelText("uncertain").textContent).toBe("none"));
    await act(async () => fireEvent.click(screen.getByText("revoke")));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[0]!.credential).toBe(credentials[0]);
    expect(requests[1]!.credential).toBe(credentials[1]);
    expect(requests[1]!.requestId).not.toBe(requests[0]!.requestId);
  });

  it("expires only the credential rejected by the session endpoint", async () => {
    const screen = render(<SessionProvider repository={repository({ list: async () => { throw new HttpProblem(401, "iam.authentication.failed"); } })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("load")));
    await waitFor(() => expect(screen.getByLabelText("phase").textContent).toBe("anonymous"));
  });

  it("fails closed when the response identity differs from the actual login", async () => {
    const screen = render(<SessionProvider repository={repository({ list: async () => ({ ...sessionPage(), accountId: "other-account" }) })}><Probe /></SessionProvider>);
    await act(async () => fireEvent.click(screen.getByText("login")));
    await act(async () => fireEvent.click(screen.getByText("load")));
    await waitFor(() => expect(screen.getByLabelText("error").textContent).toBe("unavailable"));
    expect(screen.getByLabelText("phase").textContent).toBe("authenticated");
    expect(screen.getByLabelText("count").textContent).toBe("0");
  });
});
