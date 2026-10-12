import { afterEach, describe, expect, it } from "vitest";
import type { ManagedServiceCommandIntent, ManagedServiceCommandOwner } from "../domain/managedServiceCommand";
import {
  clearManagedServiceCommand,
  managedServiceCommandStorageKey,
  readManagedServiceCommand,
  writeManagedServiceCommand
} from "./managedServiceCommandStorage";

const owner: ManagedServiceCommandOwner = {
  accountId: "organization-test",
  actorKind: "USER",
  actorId: "principal-test"
};

const command: ManagedServiceCommandIntent = {
  owner,
  requestId: "ui-install-fixed-request",
  startedAt: "2026-10-12T00:00:00Z",
  targetId: "postgres-primary",
  targetLabel: "Postgres primary",
  kind: "CREATE_INSTALLATION",
  payload: {
    id: "postgres-primary",
    name: "Postgres primary",
    offeringId: "postgresql-18",
    quotaEntitlementId: "quota-primary",
    regionId: "local-primary"
  }
};

afterEach(() => localStorage.clear());

describe("managedServiceCommandStorage", () => {
  it("restores only the exact owner and preserves the frozen request and payload", () => {
    writeManagedServiceCommand(localStorage, command);

    expect(readManagedServiceCommand(localStorage, owner)).toEqual(command);
    expect(readManagedServiceCommand(localStorage, { ...owner, actorId: "principal-other" })).toBeNull();
  });

  it("keeps independent account actors and clears only the exact request", () => {
    const other: ManagedServiceCommandIntent = {
      ...command,
      owner: { accountId: "organization-other", actorKind: "ROLE", actorId: "role-reader:principal-other" },
      requestId: "ui-install-other-request"
    };
    writeManagedServiceCommand(localStorage, command);
    writeManagedServiceCommand(localStorage, other);

    clearManagedServiceCommand(localStorage, owner, command.requestId);

    expect(readManagedServiceCommand(localStorage, owner)).toBeNull();
    expect(readManagedServiceCommand(localStorage, other.owner)).toEqual(other);
  });

  it("fails closed and removes malformed or secret-bearing records", () => {
    localStorage.setItem(managedServiceCommandStorageKey, JSON.stringify({
      version: 1,
      commands: [{ ...command, credential: "must-not-persist" }]
    }));

    expect(readManagedServiceCommand(localStorage, owner)).toBeNull();
    expect(localStorage.getItem(managedServiceCommandStorageKey)).toBeNull();
  });
});
