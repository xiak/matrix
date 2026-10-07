import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthenticatedSession } from "../domain/session";
import type { AssumableRole, CurrentRoleIdentity, LiveRoleSession } from "../domain/roles";
import type { IamRepository } from "../repositories/iamRepository";
import { RoleSessionProvider, useEffectiveCredential, useRoleSession } from "./RoleSessionProvider";

const current: AuthenticatedSession = {
  loginName: "qiao",
  session: {
    id: "login-session-a",
    organizationId: "account-a",
    principalId: "user-a",
    status: "ACTIVE",
    issuedAt: "2099-09-29T08:00:00Z",
    expiresAt: "2099-09-29T20:00:00Z"
  }
};

const role: AssumableRole = {
  roleId: "role-reviewer",
  accountId: "account-a",
  name: "ReviewerRole",
  status: "ACTIVE",
  maxSessionDurationSeconds: 3600,
  resourceVersion: 4,
  capability: {
    action: "iam.role.assume",
    resource: { kind: "ROLE", id: "role-reviewer" },
    available: true,
    restrictionReason: null
  }
};

const issued: LiveRoleSession = {
  id: "role-session-a",
  accountId: "account-a",
  roleId: "role-reviewer",
  sourceUserId: "user-a",
  status: "ACTIVE",
  issuedAt: "2099-09-29T09:00:00Z",
  expiresAt: "2099-09-29T09:15:00Z",
  revokedAt: null
};

const identity: CurrentRoleIdentity = {
  session: issued as CurrentRoleIdentity["session"],
  account: { id: "account-a", displayName: "Xiak" },
  role: { id: "role-reviewer", name: "ReviewerRole" },
  sourceUser: { id: "user-a", loginName: "qiao", displayName: "Qiao" }
};

function repository(overrides: Partial<NonNullable<IamRepository["roleSelfService"]>> = {}): IamRepository {
  return {
    roleSelfService: {
      listAssumable: vi.fn(async () => ({ accountId: "account-a", sourceUserId: "user-a", items: [role], nextAfter: null })),
      assume: vi.fn(async () => ({ outcome: "APPLIED" as const, session: issued, credential: "role-secret" })),
      readByRequest: vi.fn(async () => issued),
      revokeByRequest: vi.fn(async () => ({ ...issued, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z" })),
      currentIdentity: vi.fn(async () => identity),
      logout: vi.fn(async () => ({ ...issued, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z" })),
      revalidateSource: vi.fn(async () => undefined),
      ...overrides
    }
  } as IamRepository;
}

function Probe() {
  const roleSession = useRoleSession();
  const credential = useEffectiveCredential();
  return <div>
    <output aria-label="stage">{roleSession.stage}</output>
    <output aria-label="credential">{credential ?? "none"}</output>
    <output aria-label="request">{roleSession.intent?.requestId ?? "none"}</output>
    <button onClick={() => void roleSession.discover()}>discover</button>
    <button disabled={!roleSession.directory?.items[0]} onClick={() => void roleSession.assume(roleSession.directory!.items[0]!, 900)}>assume</button>
    <button onClick={() => void roleSession.locateOriginal()}>locate</button>
    <button onClick={() => void roleSession.revokeOriginal()}>revoke</button>
    <button onClick={() => void roleSession.exitRole()}>exit</button>
    <button onClick={() => void roleSession.retryExit()}>retry-exit</button>
    <button onClick={() => roleSession.clearAttempt()}>clear</button>
  </div>;
}

function view(iam: IamRepository, expireSource = vi.fn(() => true)) {
  return {
    expireSource,
    ...render(<RoleSessionProvider current={current} expireSource={expireSource} repository={iam} sourceCredential="user-secret"><Probe /></RoleSessionProvider>)
  };
}

afterEach(cleanup);

describe("RoleSessionProvider", () => {
  it("activates only after CurrentRoleIdentity and revalidates the source after confirmed logout", async () => {
    const user = userEvent.setup();
    const iam = repository();
    view(iam);
    expect(screen.getByLabelText("credential").textContent).toBe("user-secret");
    await user.click(screen.getByRole("button", { name: "discover" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("ready"));
    await user.click(screen.getByRole("button", { name: "assume" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("role-active"));
    expect(screen.getByLabelText("credential").textContent).toBe("role-secret");
    await user.click(screen.getByRole("button", { name: "exit" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("idle"));
    expect(screen.getByLabelText("credential").textContent).toBe("user-secret");
    expect(iam.roleSelfService!.revalidateSource).toHaveBeenCalledWith("user-secret", "account-a", "user-a");
  });

  it("freezes an uncertain issuance intent and revokes the located non-secret session", async () => {
    const user = userEvent.setup();
    const assume = vi.fn().mockRejectedValueOnce(new Error("network down"));
    const revoke = vi.fn(async () => ({ ...issued, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z" }));
    const iam = repository({ assume, revokeByRequest: revoke });
    view(iam);
    await user.click(screen.getByRole("button", { name: "discover" }));
    await user.click(screen.getByRole("button", { name: "assume" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("assume-unknown"));
    const frozenRequest = screen.getByLabelText("request").textContent;
    await user.click(screen.getByRole("button", { name: "locate" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("located"));
    await user.click(screen.getByRole("button", { name: "revoke" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("revoked"));
    expect(revoke).toHaveBeenCalledWith("user-secret", frozenRequest, expect.stringMatching(/^ui-role-revoke-/));
  });

  it("stops business use and retries an uncertain role logout with the same request id", async () => {
    const user = userEvent.setup();
    const logout = vi.fn().mockRejectedValueOnce(new Error("lost response")).mockResolvedValueOnce({
      ...issued, status: "REVOKED" as const, revokedAt: "2099-09-29T09:05:00Z"
    });
    const iam = repository({ logout });
    view(iam);
    await user.click(screen.getByRole("button", { name: "discover" }));
    await user.click(screen.getByRole("button", { name: "assume" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("role-active"));
    await user.click(screen.getByRole("button", { name: "exit" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("exit-unknown"));
    expect(screen.getByLabelText("credential").textContent).toBe("none");
    await user.click(screen.getByRole("button", { name: "retry-exit" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("idle"));
    expect(logout).toHaveBeenCalledTimes(2);
    expect(logout.mock.calls[0]![1]).toBe(logout.mock.calls[1]![1]);
  });

  it("does not let a generic clear action discard an unverified role credential", async () => {
    const user = userEvent.setup();
    const iam = repository({ currentIdentity: vi.fn(async () => { throw new Error("network down"); }) });
    view(iam);
    await user.click(screen.getByRole("button", { name: "discover" }));
    await user.click(screen.getByRole("button", { name: "assume" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("activation-unknown"));
    expect(screen.getByLabelText("credential").textContent).toBe("user-secret");
    await user.click(screen.getByRole("button", { name: "clear" }));
    expect(screen.getByLabelText("stage").textContent).toBe("activation-unknown");
  });

  it("clears the old role context and best-effort logs it out when the source login changes", async () => {
    const user = userEvent.setup();
    const iam = repository();
    const rendered = render(<RoleSessionProvider current={current} expireSource={vi.fn(() => true)} repository={iam} sourceCredential="user-secret"><Probe /></RoleSessionProvider>);
    await user.click(screen.getByRole("button", { name: "discover" }));
    await user.click(screen.getByRole("button", { name: "assume" }));
    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("role-active"));

    rendered.rerender(<RoleSessionProvider current={current} expireSource={vi.fn(() => true)} repository={iam} sourceCredential="replacement-user-secret"><Probe /></RoleSessionProvider>);

    await waitFor(() => expect(screen.getByLabelText("stage").textContent).toBe("idle"));
    expect(screen.getByLabelText("credential").textContent).toBe("replacement-user-secret");
    expect(iam.roleSelfService!.logout).toHaveBeenCalledWith("role-secret", expect.stringMatching(/^ui-role-logout-/));
  });
});
