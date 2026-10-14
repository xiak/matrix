import { afterEach, describe, expect, it } from "vitest";
import type { ManagedServiceCommandIntent, ManagedServiceCommandOwner } from "../domain/managedServiceCommand";
import {
  clearManagedServiceCommand,
  managedServiceCommandStorageKey,
  readManagedServiceCommand,
  parseManagedServiceCommandIntent,
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

const templateReference = { id: "managedservice.installation-reader", version: 2, contentDigest: `sha256:${"f".repeat(64)}` };
const serviceRoleCommands: ManagedServiceCommandIntent[] = [
  { ...command, kind: "BIND_SERVICE_ROLE", payload: { installationId: command.targetId, template: templateReference } },
  { ...command, kind: "UNBIND_SERVICE_ROLE", payload: { installationId: command.targetId, bindingId: "binding-primary", resourceVersion: 1, expectedTemplate: templateReference } }
];

afterEach(() => localStorage.clear());

describe("managedServiceCommandStorage", () => {
  it("keeps the Role and its original source User as separate exact identities", () => {
    const roleOwner = { accountId: owner.accountId, actorKind: "ROLE" as const, actorId: "role:a", sourceUserId: "b" };
    const roleCommand: ManagedServiceCommandIntent = { ...command, owner: roleOwner };
    writeManagedServiceCommand(localStorage, roleCommand);
    expect(readManagedServiceCommand(localStorage, roleCommand.owner)).toEqual(roleCommand);
    expect(readManagedServiceCommand(localStorage, { ...roleOwner, actorId: "role", sourceUserId: "a:b" })).toBeNull();
    expect(readManagedServiceCommand(localStorage, { ...roleOwner, sourceUserId: "other-user" })).toBeNull();
  });

  it.each([
    { password: "never-persist" }, { payload: { ...command.payload, secret: "never-persist" } },
    { targetId: "different-installation" }, { kind: "ARBITRARY_COMMAND" },
    { owner: { ...owner, actorKind: "ROLE" } }
  ])("rejects unsupported or secret-bearing portable summaries: %j", (change) => {
    expect(parseManagedServiceCommandIntent({ ...command, ...change })).toBeNull();
  });

  it.each(serviceRoleCommands)("does not accept $kind consent from a Role session", (intent) => {
    expect(parseManagedServiceCommandIntent({ ...intent,
      owner: { ...owner, actorKind: "ROLE", sourceUserId: "source-user" } })).toBeNull();
  });

  it.each(serviceRoleCommands)("preserves the exact received reference for $kind across supported heads", (intent) => {
    const field = intent.kind === "BIND_SERVICE_ROLE" ? "template" : "expectedTemplate";
    for (const version of [1, 2, 3]) {
      const original = { ...intent, payload: { ...intent.payload, [field]: { ...templateReference, version } } } as ManagedServiceCommandIntent;
      writeManagedServiceCommand(localStorage, original);
      expect(readManagedServiceCommand(localStorage, owner)).toEqual(original);
      expect(parseManagedServiceCommandIntent(JSON.parse(JSON.stringify(original)))).toEqual(original);
      expect(readManagedServiceCommand(localStorage, { ...owner, actorId: "other-user" })).toBeNull();
    }
  });

  it.each(serviceRoleCommands)("rejects invalid versions, other templates or secret-bearing references for $kind", (intent) => {
    const field = intent.kind === "BIND_SERVICE_ROLE" ? "template" : "expectedTemplate";
    for (const reference of [
      ...[0, -1, 2.5, Number.MAX_SAFE_INTEGER + 1, "2"].map((version) => ({ ...templateReference, version })),
      { ...templateReference, id: "managedservice.other-reader" },
      { ...templateReference, contentDigest: "sha256:invalid" },
      { ...templateReference, credential: "must-not-persist" }
    ]) {
      expect(parseManagedServiceCommandIntent({ ...intent, payload: { ...intent.payload, [field]: reference } })).toBeNull();
    }
  });
  it("restores only the exact owner and preserves the frozen request and payload", () => {
    writeManagedServiceCommand(localStorage, command);

    expect(readManagedServiceCommand(localStorage, owner)).toEqual(command);
    expect(readManagedServiceCommand(localStorage, { ...owner, actorId: "principal-other" })).toBeNull();
  });

  it("keeps independent account actors and clears only the exact request", () => {
    const other: ManagedServiceCommandIntent = {
      ...command,
      owner: { accountId: "organization-other", actorKind: "ROLE", actorId: "role-reader", sourceUserId: "principal-other" },
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
