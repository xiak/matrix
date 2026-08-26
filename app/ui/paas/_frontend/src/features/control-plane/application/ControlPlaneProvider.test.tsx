import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionProvider, useSession } from "@/features/auth/application/SessionProvider";
import type { IamRepository } from "@/features/auth/repositories/iamRepository";
import type { ControlPlaneSnapshot, ServiceInstallation } from "../domain/resources";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { ControlPlaneProvider, useControlPlane } from "./ControlPlaneProvider";

const pendingInstallation: ServiceInstallation = {
  id: "postgres-primary",
  name: "Postgres primary",
  offeringId: "postgresql-18",
  engineVersion: "18",
  quotaEntitlementId: "quota-primary",
  regionId: "local-primary",
  phase: "PENDING",
  endpoint: null,
  credentialReference: null,
  createdAt: "2026-08-26T12:00:00Z",
  operation: {
    id: "operation-primary",
    phase: "PENDING",
    safeFailureCode: null,
    observedAt: "2026-08-26T12:00:00Z"
  }
};

const readyInstallation: ServiceInstallation = {
  ...pendingInstallation,
  phase: "READY",
  endpoint: "127.0.0.1:35432",
  credentialReference: "credential-postgres-primary",
  operation: {
    ...pendingInstallation.operation,
    phase: "READY",
    observedAt: "2026-08-26T12:00:04Z"
  }
};

function snapshot(installation: ServiceInstallation, consumedCount: number): ControlPlaneSnapshot {
  return {
    offerings: [{
      id: "postgresql-18",
      kind: "POSTGRESQL",
      displayName: "PostgreSQL 18",
      description: "Managed PostgreSQL",
      engineFamily: "postgresql",
      engineVersion: "18",
      state: "AVAILABLE",
      quotaShapes: [{
        id: "pg-small",
        displayName: "开发型",
        cpuMillicores: 500,
        memoryMiB: 1024,
        storageGiB: 10
      }]
    }],
    regions: [{
      id: "local-primary",
      displayName: "本机主区域",
      profile: "LOCAL_MACHINE",
      state: "READY",
      inspectedAt: "2026-08-26T12:00:00Z",
      capacity: { cpuMillicores: 4000, memoryMiB: 8192, storageGiB: 100 }
    }],
    entitlements: [{
      id: "quota-primary",
      offeringId: "postgresql-18",
      quotaShapeId: "pg-small",
      purchasedCount: 1,
      reservedCount: consumedCount === 0 ? 1 : 0,
      consumedCount,
      resourceVersion: consumedCount === 0 ? 2 : 3,
      activatedAt: "2026-08-26T12:00:00Z"
    }],
    installations: [installation]
  };
}

function Probe() {
  const session = useSession();
  const controlPlane = useControlPlane();
  const installation = controlPlane.scene?.content.kind === "installations"
    ? controlPlane.scene.content.installations[0]
    : null;
  return (
    <div>
      <button onClick={() => void session.login("admin", "password")} type="button">login</button>
      <span data-testid="phase">{installation?.phase ?? "none"}</span>
    </div>
  );
}

function iamRepository(): IamRepository {
  return {
    async login() {
      return {
        credential: "memory-only-session",
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
    async changePassword() {},
    async logout() {}
  };
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("ControlPlaneProvider", () => {
  it("polls only pending installation resources before refreshing terminal quota state", async () => {
    vi.useFakeTimers();
    const repository: ControlPlaneRepository = {
      load: vi.fn()
        .mockResolvedValueOnce(snapshot(pendingInstallation, 0))
        .mockResolvedValueOnce(snapshot(readyInstallation, 1)),
      getInstallation: vi.fn().mockResolvedValue(readyInstallation),
      activateQuota: vi.fn(),
      createInstallation: vi.fn()
    };
    const screen = render(
      <SessionProvider repository={iamRepository()}>
        <ControlPlaneProvider repository={repository} selection={{ section: "installations" }}>
          <Probe />
        </ControlPlaneProvider>
      </SessionProvider>
    );
    await act(async () => {
      fireEvent.click(screen.getByText("login"));
      await Promise.resolve();
    });
    expect(repository.load).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("phase").textContent).toBe("PENDING");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });

    expect(repository.getInstallation).toHaveBeenCalledWith(
      "memory-only-session",
      "postgres-primary"
    );
    expect(repository.load).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("phase").textContent).toBe("READY");
  });
});
