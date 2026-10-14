import { requestJSON, requestJSONResponse } from "@/infrastructure/http/jsonRequest";
import {
  validApplicationCursor,
  validApplicationId,
  validApplicationLabels,
  validApplicationName,
  type ApplicationDirectoryPage,
  type ApplicationResource,
  type ApplicationReadSnapshot
} from "../domain/application";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  InstallationOperationKind,
  InstallationPhase,
  QuotaEntitlement,
  QuotaShape,
  Region,
  ServiceDefinitionReference,
  ServiceInstallation,
  ServiceOffering
} from "../domain/resources";
import type {
  ServiceActivation,
  ServiceActivationCapability,
  ServiceDefinition,
  ServiceDefinitionDirectory
} from "../domain/serviceActivation";
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
import { managedServiceCommandTypes, type ManagedServiceCommandResult, type ManagedServiceCommandType } from "../domain/managedServiceCommand";

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
const serviceIdentifierPattern = /^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const strongApplicationETagPattern = /^"[1-9][0-9]*"$/;

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

function invalidApplicationResponse(): never {
  throw new Error("INVALID_APPLICATION_RESPONSE");
}

function applicationRecord(value: unknown): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalidApplicationResponse();
  return value as UnknownRecord;
}

function applicationExactKeys(wire: UnknownRecord, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) {
    invalidApplicationResponse();
  }
}

function applicationTimestamp(value: unknown): string {
  if (typeof value !== "string" || !timestampPattern.test(value) || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    invalidApplicationResponse();
  }
  return value;
}

function parseApplication(value: unknown): ApplicationResource {
  const wire = applicationRecord(value);
  applicationExactKeys(wire, ["apiVersion", "kind", "metadata"]);
  const metadata = applicationRecord(wire.metadata);
  applicationExactKeys(metadata, ["id", "name", "scope", "resourceVersion", "createdAt", "updatedAt"], ["labels"]);
  const scope = applicationRecord(metadata.scope);
  applicationExactKeys(scope, ["kind", "tenantId"]);

  if (wire.apiVersion !== "paas.matrix.xiak.com/v1" || wire.kind !== "Application" ||
      typeof metadata.id !== "string" || !validApplicationId(metadata.id) ||
      typeof metadata.name !== "string" || !validApplicationName(metadata.name) ||
      scope.kind !== "TENANT" || typeof scope.tenantId !== "string" || !validApplicationId(scope.tenantId) ||
      typeof metadata.resourceVersion !== "number" || !Number.isSafeInteger(metadata.resourceVersion) || metadata.resourceVersion < 1) {
    invalidApplicationResponse();
  }

  const createdAt = applicationTimestamp(metadata.createdAt);
  const updatedAt = applicationTimestamp(metadata.updatedAt);
  if (timestampOrder(updatedAt) < timestampOrder(createdAt)) invalidApplicationResponse();

  let labels: Record<string, string> | undefined;
  if ("labels" in metadata) {
    const labelWire = applicationRecord(metadata.labels);
    if (Object.values(labelWire).some((item) => typeof item !== "string")) invalidApplicationResponse();
    labels = { ...labelWire } as Record<string, string>;
    if (!validApplicationLabels(labels)) invalidApplicationResponse();
  }

  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "Application",
    metadata: {
      id: metadata.id,
      name: metadata.name,
      scope: { kind: "TENANT", tenantId: scope.tenantId },
      ...(labels ? { labels } : {}),
      resourceVersion: metadata.resourceVersion,
      createdAt,
      updatedAt
    }
  };
}

function parseApplicationRead(value: unknown, requestedId: string, etag: string | null): ApplicationReadSnapshot {
  const application = parseApplication(value);
  if (application.metadata.id !== requestedId || typeof etag !== "string" ||
      !strongApplicationETagPattern.test(etag) || etag !== `"${application.metadata.resourceVersion}"`) {
    invalidApplicationResponse();
  }
  return { etag, application };
}

function parseApplicationDirectory(value: unknown, requestedAfter?: string): ApplicationDirectoryPage {
  const wire = applicationRecord(value);
  applicationExactKeys(wire, ["apiVersion", "kind", "items"], ["nextAfter"]);
  if (wire.apiVersion !== "paas.matrix.xiak.com/v1" || wire.kind !== "ApplicationList" ||
      !Array.isArray(wire.items) || wire.items.length > 50) {
    invalidApplicationResponse();
  }
  const items = wire.items.map(parseApplication);
  const tenantId = items[0]?.metadata.scope.tenantId;
  for (let index = 0; index < items.length; index += 1) {
    const current = items[index]!;
    if (current.metadata.scope.tenantId !== tenantId ||
        (index > 0 && current.metadata.id <= items[index - 1]!.metadata.id)) {
      invalidApplicationResponse();
    }
  }
  let nextAfter: string | null = null;
  if ("nextAfter" in wire) {
    if (typeof wire.nextAfter !== "string" || !validApplicationCursor(wire.nextAfter) || wire.nextAfter === requestedAfter) {
      invalidApplicationResponse();
    }
    nextAfter = wire.nextAfter;
  }
  return { items, nextAfter };
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
      template.id === managedServiceInstallationReader.id;
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

function managedServiceInvalid(): never {
  throw new Error("INVALID_MANAGED_SERVICE_RESPONSE");
}

function managedServiceExactKeys(wire: UnknownRecord, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) managedServiceInvalid();
}

function managedServiceRecord(value: unknown): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) managedServiceInvalid();
  return value as UnknownRecord;
}

function managedServiceText(value: unknown, minimum: number, maximum: number): string {
  if (typeof value !== "string") managedServiceInvalid();
  const byteLength = new TextEncoder().encode(value).length;
  if (byteLength < minimum || byteLength > maximum || value.trim() !== value || /[\0\r\n]/.test(value)) {
    managedServiceInvalid();
  }
  return value;
}

function positiveSafeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) managedServiceInvalid();
  return value;
}

function positiveUint32(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 4_294_967_295) managedServiceInvalid();
  return value;
}

function managedServiceIdentifier(value: unknown): string {
  if (typeof value !== "string" || !publicIdentifierPattern.test(value)) managedServiceInvalid();
  return value;
}

function serviceIdentifier(value: unknown): string {
  if (typeof value !== "string" || !serviceIdentifierPattern.test(value)) managedServiceInvalid();
  return value;
}

function parseServiceDefinitionReference(value: unknown): ServiceDefinitionReference {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["id", "revision", "contentDigest"]);
  if (typeof wire.contentDigest !== "string" || !digestPattern.test(wire.contentDigest)) managedServiceInvalid();
  return {
    id: serviceIdentifier(wire.id),
    revision: positiveSafeInteger(wire.revision),
    contentDigest: wire.contentDigest
  };
}

function parseServiceDefinition(value: unknown): ServiceDefinition {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["id", "displayName", "description", "revision", "contentDigest", "activationPrerequisite", "state"]);
  if (wire.activationPrerequisite !== "PERMISSION_ONLY" || (wire.state !== "AVAILABLE" && wire.state !== "UNAVAILABLE") ||
      typeof wire.contentDigest !== "string" || !digestPattern.test(wire.contentDigest)) managedServiceInvalid();
  return {
    id: serviceIdentifier(wire.id),
    displayName: managedServiceText(wire.displayName, 1, 128),
    description: managedServiceText(wire.description, 1, 512),
    revision: positiveSafeInteger(wire.revision),
    contentDigest: wire.contentDigest,
    activationPrerequisite: "PERMISSION_ONLY",
    state: wire.state
  };
}

function parseServiceActivationCapability(value: unknown): ServiceActivationCapability {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["action", "resource", "available"], ["restrictionReason"]);
  const resource = managedServiceRecord(wire.resource);
  managedServiceExactKeys(resource, ["kind", "id"]);
  if (wire.action !== "managedservice.service-activation.activate" || resource.kind !== "SERVICE_ACTIVATION" ||
      resource.id !== "collection" || typeof wire.available !== "boolean" ||
      (wire.available && "restrictionReason" in wire) || (!wire.available && wire.restrictionReason !== "AUTHORITY_REQUIRED")) {
    managedServiceInvalid();
  }
  return {
    action: "managedservice.service-activation.activate",
    resource: { kind: "SERVICE_ACTIVATION", id: "collection" },
    available: wire.available,
    ...(wire.available ? {} : { restrictionReason: "AUTHORITY_REQUIRED" as const })
  };
}

function parseServiceDefinitionDirectory(value: unknown): ServiceDefinitionDirectory {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["kind", "items", "activationCapability"]);
  if (wire.kind !== "ServiceDefinitionList" || !Array.isArray(wire.items) || wire.items.length > 50) managedServiceInvalid();
  const services = wire.items.map(parseServiceDefinition);
  if (services.some((item, index) => index > 0 && item.id <= services[index - 1]!.id)) managedServiceInvalid();
  return { services, activationCapability: parseServiceActivationCapability(wire.activationCapability) };
}

function parseServiceActivation(value: unknown, expectedServiceId: string): ServiceActivation {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["service", "resourceVersion", "activatedAt"]);
  const service = parseServiceDefinitionReference(wire.service);
  if (service.id !== expectedServiceId) managedServiceInvalid();
  const activatedAt = managedServiceText(wire.activatedAt, 1, 40);
  if (!timestampPattern.test(activatedAt) || Number.isNaN(Date.parse(activatedAt)) ||
      new Date(activatedAt).toISOString().slice(0, 19) !== activatedAt.slice(0, 19)) managedServiceInvalid();
  return { service, resourceVersion: positiveSafeInteger(wire.resourceVersion), activatedAt };
}

function parseShape(value: unknown): QuotaShape {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["id", "displayName", "cpuMillicores", "memoryMiB", "storageGiB"]);
  return {
    id: managedServiceIdentifier(wire.id),
    displayName: managedServiceText(wire.displayName, 1, 128),
    cpuMillicores: positiveUint32(wire.cpuMillicores),
    memoryMiB: positiveUint32(wire.memoryMiB),
    storageGiB: positiveUint32(wire.storageGiB)
  };
}

function parseOffering(value: unknown): ServiceOffering {
  const wire = managedServiceRecord(value);
  managedServiceExactKeys(wire, ["id", "service", "displayName", "description", "engineFamily", "engineVersion", "state", "quotaShapes"]);
  if (
    (wire.state !== "AVAILABLE" && wire.state !== "UNAVAILABLE") ||
    !Array.isArray(wire.quotaShapes) || wire.quotaShapes.length < 1 || wire.quotaShapes.length > 16
  ) {
    managedServiceInvalid();
  }
  const quotaShapes = wire.quotaShapes.map(parseShape);
  if (new Set(quotaShapes.map((shape) => shape.id)).size !== quotaShapes.length) managedServiceInvalid();
  return {
    id: managedServiceIdentifier(wire.id),
    service: parseServiceDefinitionReference(wire.service),
    displayName: managedServiceText(wire.displayName, 1, 128),
    description: managedServiceText(wire.description, 1, 512),
    engineFamily: serviceIdentifier(wire.engineFamily),
    engineVersion: managedServiceIdentifier(wire.engineVersion),
    state: wire.state,
    quotaShapes
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

const installationOperationPhaseByResourcePhase: Record<
  InstallationOperationKind,
  Partial<Record<InstallationPhase, InstallationPhase>>
> = {
  PROVISION: {
    PENDING: "PENDING",
    PROVISIONING: "PROVISIONING",
    READY: "READY",
    FAILED: "FAILED",
    ROLLBACK_FAILED: "FAILED"
  },
  TERMINATE: {
    TERMINATION_PENDING: "PENDING",
    TERMINATING: "PROVISIONING",
    TERMINATION_FAILED: "FAILED",
    TERMINATED: "READY"
  }
};

function installationOperationMatchesResourcePhase(
  kind: InstallationOperationKind,
  operationPhase: string,
  resourcePhase: InstallationPhase
): boolean {
  return installationOperationPhaseByResourcePhase[kind][resourcePhase] === operationPhase;
}

function parseInstallation(value: unknown): ServiceInstallation {
  const wire = record(value, "service installation");
  const operation = record(wire.operation, "installation operation");
  const phase = String(wire.phase);
  const operationKind = String(operation.kind);
  const operationPhase = String(operation.phase);
  const installationPhases: InstallationPhase[] = [
    "PENDING", "PROVISIONING", "READY", "FAILED", "ROLLBACK_FAILED",
    "TERMINATION_PENDING", "TERMINATING", "TERMINATION_FAILED", "TERMINATED"
  ];
  const operationKinds: InstallationOperationKind[] = ["PROVISION", "TERMINATE"];
  if (!installationPhases.includes(phase as InstallationPhase) ||
    !operationKinds.includes(operationKind as InstallationOperationKind) ||
    !installationOperationMatchesResourcePhase(
      operationKind as InstallationOperationKind,
      operationPhase,
      phase as InstallationPhase
    )) {
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
    resourceVersion: integer(wire.resourceVersion, "installation version"),
    createdAt: text(wire.createdAt, "installation creation"),
    operation: {
      id: text(operation.id, "operation id"),
      kind: operationKind as ServiceInstallation["operation"]["kind"],
      phase: operationPhase as ServiceInstallation["phase"],
      safeFailureCode: nullableText(operation.safeFailureCode, "operation failure"),
      observedAt: text(operation.observedAt, "operation observation")
    }
  };
}

function authorization(credential: string): HeadersInit {
  return { Authorization: `Bearer ${credential}` };
}

function commandResultKeys(value: UnknownRecord, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in value)) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
  }
}

function commandResultTime(value: unknown): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
  }
  return value;
}

function parseCommandResult(value: unknown, commandType: ManagedServiceCommandType): ManagedServiceCommandResult {
  const wire = record(value, "managed service command result");
  commandResultKeys(wire, ["kind", "idempotencyKey", "commandType", "inputDigest", "state", "target"], ["operation", "bindingId", "completedAt"]);
  const target = record(wire.target, "command target");
  commandResultKeys(target, ["kind", "id"]);
  if (wire.kind !== "ManagedServiceCommandResult" || wire.commandType !== commandType ||
      typeof wire.inputDigest !== "string" || !digestPattern.test(wire.inputDigest) ||
      !["IN_PROGRESS", "SUCCEEDED", "FAILED"].includes(String(wire.state)) ||
      (wire.state === "IN_PROGRESS") !== !("completedAt" in wire)) throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
  const completedAt = "completedAt" in wire ? commandResultTime(wire.completedAt) : null;
  let operation: ManagedServiceCommandResult["operation"] = null;
  let bindingId: string | null = null;
  if (commandType === "QUOTA_ACTIVATE") {
    if (target.kind !== "QUOTA_ENTITLEMENT" || wire.state !== "SUCCEEDED" || "operation" in wire || "bindingId" in wire) {
      throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
    }
  } else if (commandType === "INSTALLATION_CREATE" || commandType === "INSTALLATION_TERMINATE") {
    const details = record(wire.operation, "command operation");
    commandResultKeys(details, ["id", "kind", "phase", "safeFailureCode", "observedAt"]);
    const expectedKind = commandType === "INSTALLATION_CREATE" ? "PROVISION" : "TERMINATE";
    const states: Record<string, string> = { PENDING: "IN_PROGRESS", PROVISIONING: "IN_PROGRESS", READY: "SUCCEEDED", FAILED: "FAILED" };
    if (target.kind !== "SERVICE_INSTALLATION" || "bindingId" in wire || details.kind !== expectedKind ||
        states[String(details.phase)] !== wire.state ||
        (details.phase === "FAILED") !== (details.safeFailureCode !== null) ||
        (details.safeFailureCode !== null && (typeof details.safeFailureCode !== "string" || !/^[A-Z][A-Z0-9_]{1,63}$/.test(details.safeFailureCode)))) {
      throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
    }
    operation = { id: publicIdentifier(details.id), kind: expectedKind, phase: details.phase as InstallationPhase,
      safeFailureCode: details.safeFailureCode as string | null, observedAt: commandResultTime(details.observedAt) };
  } else {
    if (target.kind !== "SERVICE_INSTALLATION" || wire.state !== "SUCCEEDED" || "operation" in wire) {
      throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
    }
    bindingId = publicIdentifier(wire.bindingId);
  }
  return { idempotencyKey: publicIdentifier(wire.idempotencyKey), commandType, inputDigest: wire.inputDigest,
    state: wire.state as ManagedServiceCommandResult["state"], target: { kind: target.kind as ManagedServiceCommandResult["target"]["kind"], id: publicIdentifier(target.id) },
    operation, bindingId, completedAt };
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
  async listCommandResults(credential, commandType) {
    if (!managedServiceCommandTypes.includes(commandType)) throw new Error("INVALID_MANAGED_SERVICE_COMMAND_TYPE");
    const response = await requestJSONResponse<unknown>(`/api/managed-services/v1/command-results/${commandType}`, { headers: authorization(credential) });
    if (response.status !== 200 || response.headers.get("Cache-Control") !== "no-store" ||
        response.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
    const wire = record(response.body, "managed service command result list");
    commandResultKeys(wire, ["kind", "items"]);
    if (wire.kind !== "ManagedServiceCommandResultList" || !Array.isArray(wire.items) || wire.items.length > 100) {
      throw new Error("INVALID_MANAGED_SERVICE_COMMAND_RESULT");
    }
    const items = wire.items.map((item) => parseCommandResult(item, commandType));
    if (new Set(items.map((item) => item.idempotencyKey)).size !== items.length) throw new Error("DUPLICATE_MANAGED_SERVICE_COMMAND_RESULT");
    return items;
  },
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

  async listServiceDefinitions(credential) {
    const value = await requestJSON<unknown>("/api/managed-services/v1/services", {
      headers: authorization(credential)
    });
    return parseServiceDefinitionDirectory(value);
  },

  async getServiceActivation(credential, serviceId) {
    if (!serviceIdentifierPattern.test(serviceId)) throw new Error("INVALID_SERVICE_ACTIVATION_REQUEST");
    const value = await requestJSON<unknown>(
      `/api/managed-services/v1/service-activations/${encodeURIComponent(serviceId)}`,
      { headers: authorization(credential) }
    );
    return parseServiceActivation(value, serviceId);
  },

  async activateService(credential, service, requestId) {
    const parsedService = parseServiceDefinitionReference(service);
    if (!publicIdentifierPattern.test(requestId)) throw new Error("INVALID_SERVICE_ACTIVATION_REQUEST");
    const response = await requestJSONResponse<unknown>("/api/managed-services/v1/service-activations", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestId
      },
      body: JSON.stringify({ service: parsedService })
    });
    const expectedLocation = `/managed-services/v1/service-activations/${parsedService.id}`;
    if ((response.status !== 200 && response.status !== 201) || response.headers.get("Location") !== expectedLocation) {
      managedServiceInvalid();
    }
    const activation = parseServiceActivation(response.body, parsedService.id);
    if (activation.service.revision !== parsedService.revision || activation.service.contentDigest !== parsedService.contentDigest) {
      managedServiceInvalid();
    }
    return activation;
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

  async readApplication(credential, applicationId) {
    if (!validApplicationId(applicationId)) throw new Error("INVALID_APPLICATION_REQUEST");
    const response = await requestJSONResponse<unknown>(
      `/api/paas/v1/applications/${encodeURIComponent(applicationId)}`,
      { headers: authorization(credential) }
    );
    return parseApplicationRead(response.body, applicationId, response.headers.get("ETag"));
  },

  async listApplications(credential, after) {
    if (after !== undefined && !validApplicationCursor(after)) throw new Error("INVALID_APPLICATION_CURSOR");
    const path = after === undefined
      ? "/api/paas/v1/applications"
      : `/api/paas/v1/applications?after=${encodeURIComponent(after)}`;
    const value = await requestJSON<unknown>(path, { headers: authorization(credential) });
    return parseApplicationDirectory(value, after);
  },

  async activateQuota(credential, command: ActivateQuotaCommand, requestId) {
    if (!publicIdentifierPattern.test(requestId)) throw new Error("INVALID_QUOTA_ACTIVATION_REQUEST");
    const value = await requestJSON<unknown>("/api/managed-services/v1/quota-entitlements", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestId
      },
      body: JSON.stringify(command)
    });
    return parseEntitlement(value);
  },

  async createInstallation(credential, command: CreateInstallationCommand, requestId) {
    if (!publicIdentifierPattern.test(requestId)) throw new Error("INVALID_INSTALLATION_CREATION_REQUEST");
    const value = await requestJSON<unknown>("/api/managed-services/v1/service-installations", {
      method: "POST",
      headers: {
        ...authorization(credential),
        "Content-Type": "application/json",
        "Idempotency-Key": requestId
      },
      body: JSON.stringify(command)
    });
    return parseInstallation(value);
  },

  async terminateInstallation(credential, installationId, requestId) {
    if (!validInstallationId(installationId) || !publicIdentifierPattern.test(requestId)) {
      throw new Error("INVALID_INSTALLATION_TERMINATION_REQUEST");
    }
    const value = await requestJSON<unknown>(
      `/api/managed-services/v1/service-installations/${encodeURIComponent(installationId)}/termination`,
      {
        method: "POST",
        headers: {
          ...authorization(credential),
          "Idempotency-Key": requestId
        }
      }
    );
    const installation = parseInstallation(value);
    if (installation.id !== installationId || installation.operation.kind !== "TERMINATE") {
      throw new Error("INVALID_INSTALLATION_TERMINATION_RESPONSE");
    }
    return installation;
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
