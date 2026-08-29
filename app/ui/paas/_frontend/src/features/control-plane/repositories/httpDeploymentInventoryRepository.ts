import { requestJSON } from "@/infrastructure/http/jsonRequest";
import type {
  DeploymentDesiredState,
  DeploymentInstanceHealth,
  DeploymentInstanceState,
  DeploymentInventory,
  DeploymentInventoryItem,
  DeploymentPhase,
  DeploymentRuntimeInstance,
  DeploymentRuntimeSnapshot,
  DeploymentRuntimeState
} from "../domain/deployments";
import type { DeploymentInventoryRepository } from "./deploymentInventoryRepository";

type UnknownRecord = Record<string, unknown>;

const apiVersion = "paas.matrix.xiak.com/v1";
const maximumDeployments = 100;
const maximumInstances = 64;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const namePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const instanceIDPattern = /^instance-[0-9a-f]{32}$/;
const timestampPattern = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/;
const controlCharacterPattern = /[\u0000-\u001f\u007f]/;
const utf8 = new TextEncoder();
const phases = new Set<DeploymentPhase>([
  "PENDING", "PLACING", "APPLYING", "READY", "DEGRADED", "FAILED", "STOPPING", "STOPPED"
]);
const desiredStates = new Set<DeploymentDesiredState>(["RUNNING", "STOPPED"]);
const runtimeStates = new Set<DeploymentRuntimeState>(["AVAILABLE", "STALE", "UNAVAILABLE"]);
const instanceStates = new Set<DeploymentInstanceState>([
  "CREATED", "RUNNING", "RESTARTING", "REMOVING", "PAUSED", "EXITED", "DEAD"
]);
const healthStates = new Set<DeploymentInstanceHealth>(["NONE", "STARTING", "HEALTHY", "UNHEALTHY"]);

function invalid(name: string): Error {
  return new Error(`INVALID_${name.toUpperCase().replaceAll(/[^A-Z0-9]+/g, "_")}_RESPONSE`);
}

function record(value: unknown, name: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(name);
  return value as UnknownRecord;
}

function closed(value: unknown, name: string, keys: readonly string[]): UnknownRecord {
  const wire = record(value, name);
  const allowed = new Set(keys);
  if (Object.keys(wire).some((key) => !allowed.has(key))) throw invalid(name);
  return wire;
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw invalid(name);
  return value;
}

function id(value: unknown, name: string): string {
  const result = text(value, name);
  if (!idPattern.test(result)) throw invalid(name);
  return result;
}

function name(value: unknown, field: string): string {
  const result = text(value, field);
  if (!namePattern.test(result)) throw invalid(field);
  return result;
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field);
  if (!timestampPattern.test(result) || !Number.isFinite(Date.parse(result))) throw invalid(field);
  return result;
}

function integer(value: unknown, field: string, positive = false): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw invalid(field);
  }
  return value;
}

function optionalID(wire: UnknownRecord, key: string, field: string): string | null {
  if (!Object.hasOwn(wire, key) || wire[key] === undefined) return null;
  return id(wire[key], field);
}

function scope(value: unknown, expectedTenantId: string, field: string): void {
  const wire = closed(value, field, ["kind", "tenantId"]);
  if (wire.kind !== "TENANT" || id(wire.tenantId, `${field} tenant`) !== expectedTenantId) {
    throw invalid(field);
  }
}

function labels(value: unknown): void {
  if (value === undefined) return;
  const wire = record(value, "deployment labels");
  if (Object.keys(wire).length > 64) throw invalid("deployment labels");
  for (const [key, item] of Object.entries(wire)) {
    if (!namePattern.test(key) || typeof item !== "string" || utf8.encode(item).length > 128 ||
        item.trim() !== item || controlCharacterPattern.test(item)) {
      throw invalid("deployment labels");
    }
  }
}

function binding(value: unknown): void {
  const wire = closed(value, "deployment binding", ["name", "configurationRevisionId", "secretVersion"]);
  name(wire.name, "deployment binding name");
  const hasConfiguration = Object.hasOwn(wire, "configurationRevisionId") && wire.configurationRevisionId !== undefined;
  const hasSecret = Object.hasOwn(wire, "secretVersion") && wire.secretVersion !== undefined;
  if (hasConfiguration === hasSecret) throw invalid("deployment binding");
  if (hasConfiguration) id(wire.configurationRevisionId, "deployment configuration revision");
  if (hasSecret) {
    const secret = closed(wire.secretVersion, "deployment secret version", ["secretId", "version"]);
    id(secret.secretId, "deployment secret");
    id(secret.version, "deployment secret version");
  }
}

function deployment(value: unknown, expectedTenantId: string): DeploymentInventoryItem {
  const wire = closed(value, "deployment", ["apiVersion", "kind", "metadata", "generation", "spec", "status"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "Deployment") throw invalid("deployment");

  const metadata = closed(wire.metadata, "deployment metadata", [
    "id", "name", "scope", "labels", "resourceVersion", "createdAt", "updatedAt"
  ]);
  scope(metadata.scope, expectedTenantId, "deployment scope");
  labels(metadata.labels);
  const createdAt = timestamp(metadata.createdAt, "deployment created at");
  const updatedAt = timestamp(metadata.updatedAt, "deployment updated at");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) throw invalid("deployment metadata");

  const spec = closed(wire.spec, "deployment spec", [
    "applicationRevisionId", "placementPolicyId", "desiredState", "components"
  ]);
  if (!desiredStates.has(spec.desiredState as DeploymentDesiredState) || !Array.isArray(spec.components) || spec.components.length === 0) {
    throw invalid("deployment spec");
  }
  const componentNames = new Set<string>();
  const components = spec.components.map((item) => {
    const component = closed(item, "deployment component", ["name", "replicas", "bindings"]);
    const componentName = name(component.name, "deployment component name");
    const bindings = component.bindings === undefined ? [] : component.bindings;
    if (componentNames.has(componentName) || !Array.isArray(bindings)) throw invalid("deployment component");
    componentNames.add(componentName);
    const bindingNames = new Set<string>();
    bindings.forEach((itemValue) => {
      binding(itemValue);
      const itemWire = itemValue as UnknownRecord;
      const bindingName = String(itemWire.name);
      if (bindingNames.has(bindingName)) throw invalid("deployment binding");
      bindingNames.add(bindingName);
    });
    return { name: componentName, replicas: integer(component.replicas, "deployment replicas", true) };
  });

  const status = closed(wire.status, "deployment status", [
    "phase", "observedGeneration", "placementDecisionId", "currentOperationId",
    "observedApplicationRevisionId", "readyComponents", "observedAt"
  ]);
  if (!phases.has(status.phase as DeploymentPhase)) throw invalid("deployment phase");
  const generation = integer(wire.generation, "deployment generation", true);
  const observedGeneration = integer(status.observedGeneration, "deployment observed generation");
  const observedApplicationRevisionId = optionalID(
    status, "observedApplicationRevisionId", "deployment observed application revision"
  );
  const readyComponents = integer(status.readyComponents, "deployment ready components");
  if (observedGeneration > generation || readyComponents > components.length ||
      (observedGeneration === 0 && (observedApplicationRevisionId !== null || readyComponents !== 0)) ||
      (observedGeneration > 0 && observedApplicationRevisionId === null)) {
    throw invalid("deployment status");
  }
  if (status.phase === "READY" &&
      (observedGeneration !== generation || observedApplicationRevisionId !== spec.applicationRevisionId || readyComponents !== components.length)) {
    throw invalid("deployment status");
  }
  if (status.phase === "STOPPED" && (observedGeneration !== generation || readyComponents !== 0)) {
    throw invalid("deployment status");
  }

  return {
    id: id(metadata.id, "deployment id"),
    name: name(metadata.name, "deployment name"),
    tenantId: expectedTenantId,
    resourceVersion: integer(metadata.resourceVersion, "deployment resource version", true),
    generation,
    applicationRevisionId: id(spec.applicationRevisionId, "deployment application revision"),
    placementPolicyId: id(spec.placementPolicyId, "deployment placement policy"),
    desiredState: spec.desiredState as DeploymentDesiredState,
    components,
    phase: status.phase as DeploymentPhase,
    observedGeneration,
    placementDecisionId: optionalID(status, "placementDecisionId", "deployment placement decision"),
    currentOperationId: optionalID(status, "currentOperationId", "deployment current operation"),
    observedApplicationRevisionId,
    readyComponents,
    observedAt: timestamp(status.observedAt, "deployment observed at"),
    createdAt,
    updatedAt
  };
}

function runtimeInstance(value: unknown): DeploymentRuntimeInstance {
  const wire = closed(value, "deployment runtime instance", ["id", "componentName", "state", "health", "exitCode"]);
  const instanceId = text(wire.id, "deployment runtime instance id");
  if (!instanceIDPattern.test(instanceId) || !instanceStates.has(wire.state as DeploymentInstanceState) ||
      !healthStates.has(wire.health as DeploymentInstanceHealth)) {
    throw invalid("deployment runtime instance");
  }
  const hasExitCode = Object.hasOwn(wire, "exitCode") && wire.exitCode !== undefined;
  const terminal = wire.state === "EXITED" || wire.state === "DEAD";
  if (hasExitCode !== terminal) throw invalid("deployment runtime exit code");
  return {
    id: instanceId,
    componentName: name(wire.componentName, "deployment runtime component"),
    state: wire.state as DeploymentInstanceState,
    health: wire.health as DeploymentInstanceHealth,
    exitCode: hasExitCode ? integer(wire.exitCode, "deployment runtime exit code") : null
  };
}

function runtime(value: unknown, expectedTenantId: string, expectedDeploymentId: string): DeploymentRuntimeSnapshot {
  const wire = closed(value, "deployment runtime", ["apiVersion", "kind", "scope", "state", "value"]);
  if (wire.apiVersion !== apiVersion || wire.kind !== "DeploymentRuntimeSnapshot" ||
      !runtimeStates.has(wire.state as DeploymentRuntimeState)) {
    throw invalid("deployment runtime");
  }
  scope(wire.scope, expectedTenantId, "deployment runtime scope");
  const hasValue = Object.hasOwn(wire, "value") && wire.value !== undefined;
  if ((wire.state === "UNAVAILABLE") === hasValue) throw invalid("deployment runtime");
  if (!hasValue) return { tenantId: expectedTenantId, state: "UNAVAILABLE", value: null };

  const runtimeValue = closed(wire.value, "deployment runtime value", ["observation", "validUntil"]);
  const observation = closed(runtimeValue.observation, "deployment runtime observation", [
    "deploymentId", "generation", "applicationRevisionId", "executionTargetId", "instances", "observedAt"
  ]);
  if (id(observation.deploymentId, "deployment runtime deployment") !== expectedDeploymentId ||
      !Array.isArray(observation.instances) || observation.instances.length > maximumInstances) {
    throw invalid("deployment runtime observation");
  }
  const instances = observation.instances.map(runtimeInstance);
  if (new Set(instances.map((item) => item.id)).size !== instances.length) throw invalid("deployment runtime instances");
  const observedAt = timestamp(observation.observedAt, "deployment runtime observed at");
  const validUntil = timestamp(runtimeValue.validUntil, "deployment runtime valid until");
  if (Date.parse(validUntil) <= Date.parse(observedAt)) throw invalid("deployment runtime validity");
  return {
    tenantId: expectedTenantId,
    state: wire.state as DeploymentRuntimeState,
    value: {
      deploymentId: expectedDeploymentId,
      generation: integer(observation.generation, "deployment runtime generation", true),
      applicationRevisionId: id(observation.applicationRevisionId, "deployment runtime application revision"),
      executionTargetId: id(observation.executionTargetId, "deployment runtime execution target"),
      instances,
      observedAt,
      validUntil
    }
  };
}

function authorization(credential: string): HeadersInit {
  return { Authorization: `Bearer ${credential}` };
}

export const httpDeploymentInventoryRepository: DeploymentInventoryRepository = {
  async load(credential, tenantId, signal) {
    id(tenantId, "deployment tenant");
    const value = await requestJSON<unknown>("/api/paas/v1/deployments", {
      headers: authorization(credential),
      signal
    });
    const wire = closed(value, "deployment inventory", ["apiVersion", "kind", "scope", "items", "nextAfter"]);
    if (wire.apiVersion !== apiVersion || wire.kind !== "DeploymentList" ||
        !Array.isArray(wire.items) || wire.items.length > maximumDeployments) {
      throw invalid("deployment inventory");
    }
    scope(wire.scope, tenantId, "deployment inventory scope");
    const items = wire.items.map((item) => deployment(item, tenantId));
    for (let index = 1; index < items.length; index += 1) {
      if (items[index - 1]!.id >= items[index]!.id) throw invalid("deployment inventory");
    }
    const nextAfter = optionalID(wire, "nextAfter", "deployment next cursor");
    if (nextAfter !== null && (items.length === 0 || items.at(-1)!.id !== nextAfter)) {
      throw invalid("deployment inventory");
    }
    return {
      tenantId,
      items,
      nextAfter
    } satisfies DeploymentInventory;
  },

  async loadRuntime(credential, tenantId, deploymentId, signal) {
    id(tenantId, "deployment tenant");
    id(deploymentId, "deployment id");
    const value = await requestJSON<unknown>(
      `/api/paas/v1/deployments/${encodeURIComponent(deploymentId)}/runtime`,
      { headers: authorization(credential), signal }
    );
    return runtime(value, tenantId, deploymentId);
  }
};
