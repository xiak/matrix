import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  QuotaShape,
  Region,
  ServiceInstallation,
  ServiceOffering
} from "../domain/resources";
import type {
  ControlPlaneRepository,
  ControlPlaneResourceKind,
  ControlPlaneResourceSnapshot
} from "./controlPlaneRepository";
import { httpAccountRepository } from "@/features/auth/repositories/httpIamRepository";
import {
  isManagedServiceInstallationReader,
  managedServiceInstallationReader,
  sameTemplateReference,
  type BindManagedServiceRoleCommand,
  type ManagedServiceAuthorizationObservation,
  type ManagedServiceRoleBindingReceipt,
  type ManagedServiceRoleUnbindingReceipt,
  type UnbindManagedServiceRoleCommand
} from "../domain/serviceAuthorization";
import type {
  ServiceLinkedRoleAccess,
  ServiceLinkedRoleListing,
  ServiceRoleTemplate,
  ServiceRoleTemplateReference,
  WorkloadRoleBinding
} from "@/features/auth/domain/serviceAuthorization";

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value as UnknownRecord;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value;
}

function integer(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`INVALID_${name.toUpperCase()}_RESPONSE`);
  }
  return value;
}

function exactKeys(wire: UnknownRecord, required: string[]): void {
  const allowed = new Set(required);
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
}

const publicIdentifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const installationIdentifierPattern = /^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

function publicIdentifier(value: unknown): string {
  if (typeof value !== "string" || !publicIdentifierPattern.test(value)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  return value;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string" || !timestampPattern.test(value) || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  return value;
}

function timestampOrder(value: string): string {
  return value.slice(0, 19) + "." + value.slice(19, -1).slice(1).padEnd(6, "0");
}

function parseTemplateReference(value: unknown): ServiceRoleTemplateReference {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  const wire = value as UnknownRecord;
  exactKeys(wire, ["id", "version", "contentDigest"]);
  if (typeof wire.version !== "number" || !Number.isSafeInteger(wire.version) || wire.version < 1 ||
      typeof wire.contentDigest !== "string" || !digestPattern.test(wire.contentDigest)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  return {
    id: publicIdentifier(wire.id),
    version: wire.version,
    contentDigest: wire.contentDigest
  };
}

function validBindCommand(command: BindManagedServiceRoleCommand): boolean {
  try {
    const template = parseTemplateReference(command.template);
    return command.requestId.length > 0 && publicIdentifierPattern.test(command.requestId) &&
      template.id === managedServiceInstallationReader.id && template.version === managedServiceInstallationReader.version;
  } catch {
    return false;
  }
}

function validUnbindCommand(command: UnbindManagedServiceRoleCommand): boolean {
  try {
    return publicIdentifierPattern.test(command.bindingId) && command.resourceVersion === 1 &&
      validBindCommand({ template: command.expectedTemplate, requestId: command.requestId });
  } catch {
    return false;
  }
}

function validInstallationId(installationId: string): boolean {
  return installationIdentifierPattern.test(installationId);
}

function parseBindingReceipt(
  value: unknown,
  installationId: string,
  expectedTemplate: ServiceRoleTemplateReference
): ManagedServiceRoleBindingReceipt {
  const wire = record(value, "service role binding receipt");
  exactKeys(wire, ["kind", "serviceInstallationId", "bindingId", "roleId", "template", "status", "resourceVersion", "createdAt"]);
  const template = parseTemplateReference(wire.template);
  const receipt: ManagedServiceRoleBindingReceipt = {
    kind: "ServiceRoleBindingReceipt",
    serviceInstallationId: publicIdentifier(wire.serviceInstallationId),
    bindingId: publicIdentifier(wire.bindingId),
    roleId: publicIdentifier(wire.roleId),
    template,
    status: "ACTIVE",
    resourceVersion: 1,
    createdAt: timestamp(wire.createdAt)
  };
  if (wire.kind !== receipt.kind || wire.status !== receipt.status || wire.resourceVersion !== receipt.resourceVersion ||
      receipt.serviceInstallationId !== installationId || !sameTemplateReference(template, expectedTemplate)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  return receipt;
}

function parseUnbindingReceipt(
  value: unknown,
  installationId: string,
  bindingId: string,
  expectedTemplate: ServiceRoleTemplateReference
): ManagedServiceRoleUnbindingReceipt {
  const wire = record(value, "service role unbinding receipt");
  exactKeys(wire, ["kind", "serviceInstallationId", "bindingId", "roleId", "template", "status", "resourceVersion", "createdAt", "revokedAt"]);
  const template = parseTemplateReference(wire.template);
  const receipt: ManagedServiceRoleUnbindingReceipt = {
    kind: "ServiceRoleUnbindingReceipt",
    serviceInstallationId: publicIdentifier(wire.serviceInstallationId),
    bindingId: publicIdentifier(wire.bindingId),
    roleId: publicIdentifier(wire.roleId),
    template,
    status: "REVOKED",
    resourceVersion: 2,
    createdAt: timestamp(wire.createdAt),
    revokedAt: timestamp(wire.revokedAt)
  };
  if (wire.kind !== receipt.kind || wire.status !== receipt.status || wire.resourceVersion !== receipt.resourceVersion ||
      receipt.serviceInstallationId !== installationId || receipt.bindingId !== bindingId ||
      !sameTemplateReference(template, expectedTemplate) || timestampOrder(receipt.revokedAt) < timestampOrder(receipt.createdAt)) {
    throw new Error("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  }
  return receipt;
}

function nullableText(value: unknown, name: string): string | null {
  if (value === null) return null;
  return text(value, name);
}

function listItems(value: unknown, expectedKind: string): unknown[] {
  const wire = record(value, expectedKind);
  if (wire.kind !== expectedKind || !Array.isArray(wire.items)) {
    throw new Error(`INVALID_${expectedKind.toUpperCase()}_RESPONSE`);
  }
  return wire.items;
}

function parseShape(value: unknown): QuotaShape {
  const wire = record(value, "quota shape");
  return {
    id: text(wire.id, "quota shape id"),
    displayName: text(wire.displayName, "quota shape display name"),
    cpuMillicores: integer(wire.cpuMillicores, "quota cpu"),
    memoryMiB: integer(wire.memoryMiB, "quota memory"),
    storageGiB: integer(wire.storageGiB, "quota storage")
  };
}

function parseOffering(value: unknown): ServiceOffering {
  const wire = record(value, "offering");
  if (
    wire.kind !== "POSTGRESQL" ||
    (wire.state !== "AVAILABLE" && wire.state !== "UNAVAILABLE") ||
    !Array.isArray(wire.quotaShapes)
  ) {
    throw new Error("INVALID_OFFERING_RESPONSE");
  }
  return {
    id: text(wire.id, "offering id"),
    kind: "POSTGRESQL",
    displayName: text(wire.displayName, "offering display name"),
    description: text(wire.description, "offering description"),
    engineFamily: text(wire.engineFamily, "engine family"),
    engineVersion: text(wire.engineVersion, "engine version"),
    state: wire.state,
    quotaShapes: wire.quotaShapes.map(parseShape)
  };
}

function parseRegion(value: unknown): Region {
  const wire = record(value, "region");
  const capacity = record(wire.capacity, "region capacity");
  if (
    wire.profile !== "LOCAL_MACHINE" ||
    !["READY", "STALE", "UNAVAILABLE"].includes(String(wire.state))
  ) {
    throw new Error("INVALID_REGION_RESPONSE");
  }
  return {
    id: text(wire.id, "region id"),
    displayName: text(wire.displayName, "region display name"),
    profile: "LOCAL_MACHINE",
    state: wire.state as Region["state"],
    inspectedAt: wire.inspectedAt === null ? null : text(wire.inspectedAt, "region inspected time"),
    capacity: {
      cpuMillicores: integer(capacity.cpuMillicores, "region cpu"),
      memoryMiB: integer(capacity.memoryMiB, "region memory"),
      storageGiB: integer(capacity.storageGiB, "region storage")
    }
  };
}

function parseEntitlement(value: unknown): QuotaEntitlement {
  const wire = record(value, "quota entitlement");
  return {
    id: text(wire.id, "entitlement id"),
    offeringId: text(wire.offeringId, "entitlement offering"),
    quotaShapeId: text(wire.quotaShapeId, "entitlement shape"),
    purchasedCount: integer(wire.purchasedCount, "entitlement count"),
    reservedCount: integer(wire.reservedCount, "entitlement reserved"),
    consumedCount: integer(wire.consumedCount, "entitlement consumed"),
    resourceVersion: integer(wire.resourceVersion, "entitlement version"),
    activatedAt: text(wire.activatedAt, "entitlement activation")
  };
}

function parseInstallation(value: unknown): ServiceInstallation {
  const wire = record(value, "service installation");
  const operation = record(wire.operation, "installation operation");
  const phase = String(wire.phase);
  if (!["PENDING", "PROVISIONING", "READY", "FAILED"].includes(phase)) {
    throw new Error("INVALID_INSTALLATION_RESPONSE");
  }
  return {
    id: text(wire.id, "installation id"),
    name: text(wire.name, "installation name"),
    offeringId: text(wire.offeringId, "installation offering"),
    engineVersion: text(wire.engineVersion, "installation engine version"),
    quotaEntitlementId: text(wire.quotaEntitlementId, "installation entitlement"),
    regionId: text(wire.regionId, "installation region"),
    phase: phase as ServiceInstallation["phase"],
    endpoint: nullableText(wire.endpoint, "installation endpoint"),
    credentialReference: nullableText(wire.credentialReference, "installation credential reference"),
    createdAt: text(wire.createdAt, "installation creation"),
    operation: {
      id: text(operation.id, "operation id"),
      phase: phase as ServiceInstallation["phase"],
      safeFailureCode: nullableText(operation.safeFailureCode, "operation failure"),
      observedAt: text(operation.observedAt, "operation observation")
    }
  };
}

function authorization(credential: string): HeadersInit {
  return { Authorization: `Bearer ${credential}` };
}

const maximumServiceAuthorizationPages = 20;

async function matchingServiceRoleListings(credential: string, accountId: string, template: ServiceRoleTemplate) {
  const read = httpAccountRepository.listServiceLinkedRoles;
  if (!read) throw new Error("SERVICE_AUTHORIZATION_READ_UNAVAILABLE");
  const result: ServiceLinkedRoleListing[] = [];
  const cursors = new Set<string>();
  let after: string | undefined;
  for (let page = 0; page < maximumServiceAuthorizationPages; page += 1) {
    const directory = await read(credential, accountId, after);
    result.push(...directory.items.filter((item) =>
      item.relation.servicePrincipal.purpose === managedServiceInstallationReader.purpose &&
      sameTemplateReference(item.relation.template, template)
    ));
    if (!directory.nextAfter) return result;
    if (cursors.has(directory.nextAfter)) throw new Error("INVALID_SERVICE_AUTHORIZATION_CURSOR");
    cursors.add(directory.nextAfter);
    after = directory.nextAfter;
  }
  throw new Error("SERVICE_AUTHORIZATION_DIRECTORY_TOO_LARGE");
}

async function completeServiceRoleAccess(
  credential: string,
  accountId: string,
  listing: ServiceLinkedRoleListing
): Promise<ServiceLinkedRoleAccess> {
  const read = httpAccountRepository.getServiceLinkedRole;
  if (!read) throw new Error("SERVICE_AUTHORIZATION_READ_UNAVAILABLE");
  const bindings: WorkloadRoleBinding[] = [];
  const cursors = new Set<string>();
  let after: string | undefined;
  let relation = listing.relation;
  for (let page = 0; page < maximumServiceAuthorizationPages; page += 1) {
    const access = await read(credential, accountId, listing.relation.role.id, after);
    if (access.relation.role.id !== relation.role.id || !sameTemplateReference(access.relation.template, relation.template)) {
      throw new Error("INVALID_SERVICE_AUTHORIZATION_RELATION");
    }
    relation = access.relation;
    bindings.push(...access.bindings);
    if (!access.nextAfter) return { relation, bindings, nextAfter: null };
    if (cursors.has(access.nextAfter)) throw new Error("INVALID_SERVICE_AUTHORIZATION_CURSOR");
    cursors.add(access.nextAfter);
    after = access.nextAfter;
  }
  throw new Error("SERVICE_AUTHORIZATION_HISTORY_TOO_LARGE");
}

async function inspectServiceAuthorization(
  credential: string,
  accountId: string,
  installationId: string
): Promise<ManagedServiceAuthorizationObservation> {
  const readTemplates = httpAccountRepository.listServiceRoleTemplates;
  if (!readTemplates) throw new Error("SERVICE_AUTHORIZATION_TEMPLATE_READ_UNAVAILABLE");
  const templates = (await readTemplates(credential)).items.filter(isManagedServiceInstallationReader);
  if (templates.length !== 1) throw new Error("SERVICE_AUTHORIZATION_TEMPLATE_UNAVAILABLE");
  const template = templates[0]!;
  const listings = await matchingServiceRoleListings(credential, accountId, template);
  if (listings.length > 1) throw new Error("INVALID_SERVICE_AUTHORIZATION_RELATIONS");
  const listing = listings[0];
  if (!listing) return { template, relation: null, binding: null };
  if (listing.activeBindingCount === 0) return { template, relation: listing.relation, binding: null };
  const access = await completeServiceRoleAccess(credential, accountId, listing);
  const matches = access.bindings
    .filter((binding) => binding.status === "ACTIVE" &&
      binding.workload.kind === managedServiceInstallationReader.workloadKind &&
      binding.workload.id === installationId &&
      sameTemplateReference(binding.template, template))
    .map((binding) => ({ relation: access.relation, binding }));
  if (matches.length > 1) throw new Error("INVALID_SERVICE_AUTHORIZATION_BINDINGS");
  return { template, relation: access.relation, binding: matches[0]?.binding ?? null };
}

export const httpControlPlaneRepository: ControlPlaneRepository = {
  async load(
    credential: string,
    resources: readonly ControlPlaneResourceKind[]
  ): Promise<ControlPlaneResourceSnapshot> {
    const headers = authorization(credential);
    const readers: Record<ControlPlaneResourceKind, () => Promise<ControlPlaneSnapshot[ControlPlaneResourceKind]>> = {
      offerings: async () => listItems(
        await requestJSON<unknown>("/api/managed-services/v1/offerings", { headers }),
        "ServiceOfferingList"
      ).map(parseOffering),
      regions: async () => listItems(
        await requestJSON<unknown>("/api/managed-services/v1/regions", { headers }),
        "RegionList"
      ).map(parseRegion),
      entitlements: async () => listItems(
        await requestJSON<unknown>("/api/managed-services/v1/quota-entitlements", { headers }),
        "QuotaEntitlementList"
      ).map(parseEntitlement),
      installations: async () => listItems(
        await requestJSON<unknown>("/api/managed-services/v1/service-installations", { headers }),
        "ServiceInstallationList"
      ).map(parseInstallation)
    };
    const entries = await Promise.all(resources.map(async (resource) => (
      [resource, await readers[resource]()] as const
    )));
    return Object.fromEntries(entries) as ControlPlaneResourceSnapshot;
  },

  async getInstallation(credential, installationId) {
    const value = await requestJSON<unknown>(
      `/api/managed-services/v1/service-installations/${encodeURIComponent(installationId)}`,
      { headers: authorization(credential) }
    );
    const installation = parseInstallation(value);
    if (installation.id !== installationId) {
      throw new Error("INVALID_INSTALLATION_ID_RESPONSE");
    }
    return installation;
  },

  async activateQuota(credential, command: ActivateQuotaCommand) {
    const value = await requestJSON<unknown>("/api/managed-services/v1/quota-entitlements", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestToken("ui-quota-")
      },
      body: JSON.stringify(command)
    });
    return parseEntitlement(value);
  },

  async createInstallation(credential, command: CreateInstallationCommand) {
    const value = await requestJSON<unknown>("/api/managed-services/v1/service-installations", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestToken("ui-install-")
      },
      body: JSON.stringify(command)
    });
    return parseInstallation(value);
  },

  async bindServiceRole(credential, installationId, command) {
    if (!validInstallationId(installationId) || !validBindCommand(command)) {
      throw new Error("INVALID_SERVICE_AUTHORIZATION_REQUEST");
    }
    const value = await requestJSON<unknown>(
      `/api/managed-services/v1/service-installations/${encodeURIComponent(installationId)}/service-role-bindings`,
      {
        method: "POST",
        headers: {
          ...authorization(credential),
          "Content-Type": "application/json",
          "Idempotency-Key": command.requestId
        },
        body: JSON.stringify({ template: command.template })
      }
    );
    return parseBindingReceipt(value, installationId, command.template);
  },

  async unbindServiceRole(credential, installationId, command) {
    if (!validInstallationId(installationId) || !validUnbindCommand(command)) {
      throw new Error("INVALID_SERVICE_AUTHORIZATION_REQUEST");
    }
    const value = await requestJSON<unknown>(
      `/api/managed-services/v1/service-installations/${encodeURIComponent(installationId)}/service-role-bindings/${encodeURIComponent(command.bindingId)}`,
      {
        method: "DELETE",
        headers: {
          ...authorization(credential),
          "Content-Type": "application/json",
          "Idempotency-Key": command.requestId
        },
        body: JSON.stringify({ resourceVersion: command.resourceVersion })
      }
    );
    return parseUnbindingReceipt(value, installationId, command.bindingId, command.expectedTemplate);
  },

  inspectServiceAuthorization
};
