import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { useLiveServiceActivation } from "./liveServiceActivation";

const definition = {
  id: "postgresql",
  displayName: "PostgreSQL",
  description: "Managed PostgreSQL",
  revision: 1,
  contentDigest: `sha256:${"1".repeat(64)}`,
  activationPrerequisite: "PERMISSION_ONLY" as const,
  state: "AVAILABLE" as const
};

const activation = {
  service: { id: definition.id, revision: definition.revision, contentDigest: definition.contentDigest },
  resourceVersion: 1,
  activatedAt: "2026-10-12T11:00:00.123456Z"
};

function directory(available: boolean) {
  return {
    services: [definition],
    activationCapability: {
      action: "managedservice.service-activation.activate" as const,
      resource: { kind: "SERVICE_ACTIVATION" as const, id: "collection" as const },
      available,
      ...(available ? {} : { restrictionReason: "AUTHORITY_REQUIRED" as const })
    }
  };
}

function repository(changes: Partial<ControlPlaneRepository> = {}): ControlPlaneRepository {
  return {
    load: vi.fn(),
    getInstallation: vi.fn(),
    activateQuota: vi.fn(),
    createInstallation: vi.fn(),
    listServiceDefinitions: vi.fn().mockResolvedValue(directory(true)),
    getServiceActivation: vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND")),
    activateService: vi.fn().mockResolvedValue(activation),
    ...changes
  };
}

afterEach(cleanup);

describe("useLiveServiceActivation", () => {
  it("uses only the exact server capability and leaves a readable missing activation closed", async () => {
    const repo = repository({ listServiceDefinitions: vi.fn().mockResolvedValue(directory(false)) });
    const { result } = renderHook(() => useLiveServiceActivation({
      accountId: "account-a", active: true, credential: "session-a", repository: repo, serviceKey: "postgresql"
    }));

    await waitFor(() => expect(result.current.state.status).toBe("not-enabled"));
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: false });
    await act(async () => { await result.current.enable(); });
    expect(repo.activateService).not.toHaveBeenCalled();
  });

  it("admits an independent product-resource probe when activation read is forbidden", async () => {
    const repo = repository({
      listServiceDefinitions: vi.fn().mockResolvedValue(directory(false)),
      getServiceActivation: vi.fn().mockRejectedValue(new HttpProblem(403, "PERMISSION_DENIED"))
    });
    const { result } = renderHook(() => useLiveServiceActivation({
      accountId: "account-a", active: true, credential: "session-a", repository: repo, serviceKey: "postgresql"
    }));

    await waitFor(() => expect(result.current.state.status).toBe("unobservable"));
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: true });
  });

  it("discards activation evidence and controls immediately when the effective credential changes", async () => {
    const repo = repository({
      listServiceDefinitions: vi.fn().mockResolvedValueOnce(directory(true)).mockReturnValueOnce(new Promise(() => {})),
      getServiceActivation: vi.fn().mockResolvedValue(activation)
    });
    const { result, rerender } = renderHook(({ credential }) => useLiveServiceActivation({
      accountId: "account-a", active: true, credential, repository: repo, serviceKey: "postgresql"
    }), { initialProps: { credential: "session-a" } });

    await waitFor(() => expect(result.current.state.status).toBe("enabled"));
    rerender({ credential: "role-session-a" });

    expect(result.current.state.status).toBe("checking");
    expect(result.current.definition).toBeNull();
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: false });
    await act(async () => { await result.current.enable(); });
    expect(repo.activateService).not.toHaveBeenCalled();
  });

  it("reconciles an unknown write and reuses the original idempotency key after a confirmed miss", async () => {
    const activateService = vi.fn()
      .mockRejectedValueOnce(new Error("connection closed"))
      .mockResolvedValueOnce(activation);
    const getServiceActivation = vi.fn().mockRejectedValue(new HttpProblem(404, "NOT_FOUND"));
    const repo = repository({ activateService, getServiceActivation });
    const { result } = renderHook(() => useLiveServiceActivation({
      accountId: "account-a", active: true, credential: "session-a", repository: repo, serviceKey: "postgresql"
    }));

    await waitFor(() => expect(result.current.state.status).toBe("not-enabled"));
    await act(async () => { await result.current.enable(); });
    expect(result.current.state.status).toBe("failed");
    const originalKey = activateService.mock.calls[0]![2];
    await act(async () => { await result.current.enable(); });
    expect(activateService.mock.calls[1]![2]).toBe(originalKey);
    expect(result.current.state.status).toBe("enabled");
    expect(result.current.access.mayLoadWorkspace).toBe(true);
  });

  it("fails closed when the fixed LIVE repository methods are absent", async () => {
    const repo = repository({ listServiceDefinitions: undefined, getServiceActivation: undefined, activateService: undefined });
    const { result } = renderHook(() => useLiveServiceActivation({
      accountId: "account-a", active: true, credential: "session-a", repository: repo, serviceKey: "postgresql"
    }));
    await waitFor(() => expect(result.current.state.status).toBe("unavailable"));
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: false });
  });
});
