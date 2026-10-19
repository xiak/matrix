"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import {
  useExpireEffectiveCredential,
  useRoleSession,
  useEffectiveCredential
} from "@/features/auth/application/RoleSessionProvider";
import { useSession } from "@/features/auth/application/SessionProvider";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { ExperienceSnapshot } from "../domain/experience";
import type { ManagedServiceProductId } from "../domain/managedServiceProduct";
import type { ServiceDefinitionDirectory } from "../domain/serviceActivation";
import {
  validApplicationCursor,
  validApplicationId,
  type ApplicationDirectoryLoad,
  type ApplicationReadLoad
} from "../domain/application";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  InstallationTerminationIntent,
  InstallationTerminationMutationError,
  InstallationReadLoad
} from "../domain/resources";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type {
  ManagedServiceAuthorizationIntent,
  ManagedServiceAuthorizationLoad,
  ManagedServiceAuthorizationObservation
} from "../domain/serviceAuthorization";
import {
  managedServiceCommandType,
  matchesManagedServiceCommandResult,
  sameManagedServiceCommandOwner,
  type ManagedServiceCommandResult,
  type ManagedServiceCommandError,
  type ManagedServiceCommandIntent,
  type ManagedServiceCommandOwner,
  type ManagedServiceCommandState
} from "../domain/managedServiceCommand";
import type {
  ControlPlaneRepository,
  ControlPlaneResourceKind,
  ControlPlaneResourceSnapshot
} from "../repositories/controlPlaneRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { buildAccessConsoleScene, buildAuditConsoleScene, buildConsoleScene } from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";
import {
  clearManagedServiceCommand,
  managedServiceCommandStorageKey,
  parseManagedServiceCommandIntent,
  readManagedServiceCommand,
  writeManagedServiceCommand
} from "./managedServiceCommandStorage";

type ControlPlaneError = "expired" | "forbidden" | "unavailable";

type MutationKind = "quota" | "installation" | null;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  projectScene(selection: ControlPlaneRouteSelection): ConsoleScene | null;
  prepare(selection: ControlPlaneRouteSelection): Promise<void>;
  loading: boolean;
  error: ControlPlaneError | null;
  mutation: MutationKind;
  readServiceDefinitions(): Promise<ServiceDefinitionDirectory>;
  managedServiceCommand: ManagedServiceCommandState | null;
  commandRecoveryAvailable: boolean;
  restoreManagedServiceCommand(summary: string): boolean;
  inspectManagedServiceCommand(): Promise<boolean>;
  clearManagedServiceCommandNotice(): void;
  reload(): Promise<void>;
  activateQuota(command: ActivateQuotaCommand): Promise<boolean>;
  createInstallation(command: CreateInstallationCommand): Promise<boolean>;
  readInstallation(installationId: string): Promise<InstallationReadLoad>;
  installationTerminationIntent: InstallationTerminationIntent | null;
  beginInstallationTermination(installation: InstallationTerminationIntent["installation"]): void;
  submitInstallationTermination(): Promise<InstallationTerminationIntent["installation"] | null>;
  closeInstallationTerminationIntent(): void;
  reopenInstallationTerminationIntent(): void;
  readApplication(applicationId: string): Promise<ApplicationReadLoad>;
  listApplications(after?: string): Promise<ApplicationDirectoryLoad>;
  inspectServiceAuthorization(accountId: string, installationId: string): Promise<ManagedServiceAuthorizationLoad>;
  serviceAuthorizationIntent: ManagedServiceAuthorizationIntent | null;
  beginServiceAuthorization(accountId: string, installationId: string, observation: ManagedServiceAuthorizationObservation, kind: "bind" | "unbind"): void;
  submitServiceAuthorization(): Promise<boolean>;
  closeServiceAuthorizationIntent(): void;
  reopenServiceAuthorizationIntent(): void;
};

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null);

const emptySnapshot: ControlPlaneSnapshot = {
  offerings: [],
  regions: [],
  entitlements: [],
  installations: []
};

type ControlPlaneCache = {
  owner: string;
  snapshot: ControlPlaneSnapshot;
  loaded: ReadonlySet<ControlPlaneResourceKind>;
};

type ProductDataAccess = { product: ManagedServiceProductId; ready: boolean } | null;

type ControlPlaneRequestOwner = Readonly<{
  credential: string | null;
  repository: ControlPlaneRepository;
  sessionRevision: number;
  ownerKey: string | null;
}>;

// Presentation admission avoids unrelated resource reads during first use. It
// is not a permit: the repository and owning service still authorize requests.
function productDataReady(selection: ControlPlaneRouteSelection, access: ProductDataAccess): boolean {
  return !selection.product || (access?.product === selection.product && access.ready);
}

function requiredResourcesFor(
  selection: ControlPlaneRouteSelection,
  hasExperience: boolean,
  productAccess: ProductDataAccess
): readonly ControlPlaneResourceKind[] {
  if (!productDataReady(selection, productAccess)) return [];
  if (selection.section === "access" || selection.section === "audit") return [];
  if (selection.section === "catalog") return selection.product
    ? ["offerings", "entitlements", "installations"]
    : ["offerings"];
  if (selection.section === "quotas") return ["offerings", "entitlements"];
  if (selection.section === "installations") return ["installations"];
  if (selection.section === "regions") return ["regions"];
  if (selection.section === "overview") {
    return hasExperience ? ["regions"] : ["offerings", "regions", "entitlements", "installations"];
  }
  return [];
}

function enrichmentResourcesFor(
  selection: ControlPlaneRouteSelection,
  productAccess: ProductDataAccess
): readonly ControlPlaneResourceKind[] {
  if (!productDataReady(selection, productAccess)) return [];
  return selection.section === "installations"
    ? ["offerings", "regions", "entitlements"]
    : [];
}

function mergeResources(
  current: ControlPlaneSnapshot,
  loaded: ControlPlaneResourceSnapshot,
  resources: readonly ControlPlaneResourceKind[]
): ControlPlaneSnapshot {
  const next = { ...current };
  for (const resource of resources) {
    const values = loaded[resource];
    if (!values) throw new Error(`INVALID_${resource.toUpperCase()}_RESPONSE`);
    Object.assign(next, { [resource]: values });
  }
  return next;
}

function loadMessage(error: unknown): ControlPlaneError {
  if (error instanceof HttpProblem && error.status === 401) {
    return "expired";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "forbidden";
  }
  return "unavailable";
}

function installationTerminationMutationError(error: unknown): InstallationTerminationMutationError {
  if (!(error instanceof HttpProblem)) return "unknown";
  if (error.status === 401) return "expired";
  if (error.status === 403) return "forbidden";
  if (error.status === 404) return "notFound";
  if (error.status === 409) return "conflict";
  if ([400, 413, 415, 422].includes(error.status)) return "invalid";
  return "unknown";
}

function managedServiceCommandError(error: unknown): ManagedServiceCommandError {
  return installationTerminationMutationError(error);
}

export function ControlPlaneProvider({
  children,
  experience,
  productAccess = null,
  repository = httpControlPlaneRepository,
  selection
}: {
  children: ReactNode;
  experience?: ExperienceSnapshot;
  productAccess?: ProductDataAccess;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const credential = useEffectiveCredential();
  const expireEffectiveCredential = useExpireEffectiveCredential();
  const { current, sessionRevision } = useSession();
  const roleSession = useRoleSession();
  const isAccess = selection.section === "access";
  const [cache, setCache] = useState<ControlPlaneCache | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ControlPlaneError | null>(null);
  const [mutation, setMutation] = useState<MutationKind>(null);
  const [installationTerminationIntent, setInstallationTerminationIntent] = useState<InstallationTerminationIntent | null>(null);
  const [serviceAuthorizationIntent, setServiceAuthorizationIntent] = useState<ManagedServiceAuthorizationIntent | null>(null);
  const [managedServiceCommand, setManagedServiceCommand] = useState<ManagedServiceCommandState | null>(null);
  const cacheRef = useRef<ControlPlaneCache | null>(null);
  const serviceAuthorizationIntentRef = useRef<ManagedServiceAuthorizationIntent | null>(null);
  const installationTerminationIntentRef = useRef<InstallationTerminationIntent | null>(null);
  const managedServiceCommandRef = useRef<ManagedServiceCommandState | null>(null);
  const managedServiceCommandSlowTimer = useRef<number | null>(null);
  const inFlight = useRef(new Map<ControlPlaneResourceKind, { owner: string; promise: Promise<void> }>());
  const prepareRevision = useRef(0);
  const managedServiceCommandOwner = useMemo<ManagedServiceCommandOwner | null>(() => {
    if (roleSession.mode === "ROLE" && roleSession.identity) {
      return {
        accountId: roleSession.identity.account.id,
        actorKind: "ROLE",
        actorId: roleSession.identity.role.id,
        sourceUserId: roleSession.identity.sourceUser.id
      };
    }
    if (roleSession.mode === "USER" && current) {
      return {
        accountId: current.session.organizationId,
        actorKind: "USER",
        actorId: current.session.principalId
      };
    }
    return null;
  }, [current, roleSession.identity, roleSession.mode]);
  const managedServiceCommandOwnerKey = managedServiceCommandOwner
    ? JSON.stringify(managedServiceCommandOwner)
    : null;
  const commandReadOwner = useRef<ControlPlaneRequestOwner>({ credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey });
  useLayoutEffect(() => {
    commandReadOwner.current = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
  }, [credential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const ownsRequest = useCallback((owner: ControlPlaneRequestOwner): boolean => {
    const latest = commandReadOwner.current;
    return owner.credential !== null && latest.credential === owner.credential && latest.repository === owner.repository &&
      latest.sessionRevision === owner.sessionRevision && latest.ownerKey === owner.ownerKey;
  }, []);

  const expireUnauthorizedCredential = useCallback((failure: unknown, owner: ControlPlaneRequestOwner): boolean => {
    if (!(failure instanceof HttpProblem) || failure.status !== 401 || !owner.credential || !ownsRequest(owner)) return false;
    return expireEffectiveCredential(owner.credential);
  }, [expireEffectiveCredential, ownsRequest]);

  const commitManagedServiceCommand = useCallback((state: ManagedServiceCommandState | null) => {
    managedServiceCommandRef.current = state;
    setManagedServiceCommand(state);
  }, []);

  const clearManagedServiceCommandSlowTimer = useCallback(() => {
    if (managedServiceCommandSlowTimer.current === null) return;
    window.clearTimeout(managedServiceCommandSlowTimer.current);
    managedServiceCommandSlowTimer.current = null;
  }, []);

  const commandStorage = useCallback((): Storage | null => {
    if (experience || typeof window === "undefined") return null;
    try {
      return window.localStorage;
    } catch {
      return null;
    }
  }, [experience]);

  const beginManagedServiceCommand = useCallback((intent: ManagedServiceCommandIntent): boolean => {
    const active = managedServiceCommandRef.current;
    if (active?.checking || active?.phase === "submitting" || active?.phase === "unknown") return false;
    const storage = commandStorage();
    if (!experience) {
      if (!storage) {
        commitManagedServiceCommand({ intent, phase: "failed", error: "storageUnavailable", slow: false, restored: false });
        return false;
      }
      try {
        writeManagedServiceCommand(storage, intent);
      } catch {
        commitManagedServiceCommand({ intent, phase: "failed", error: "storageUnavailable", slow: false, restored: false });
        return false;
      }
    }
    clearManagedServiceCommandSlowTimer();
    commitManagedServiceCommand({ intent, phase: "submitting", error: null, slow: false, restored: false });
    managedServiceCommandSlowTimer.current = window.setTimeout(() => {
      const currentCommand = managedServiceCommandRef.current;
      if (currentCommand?.intent.requestId === intent.requestId && currentCommand.phase === "submitting") {
        commitManagedServiceCommand({ ...currentCommand, slow: true });
      }
    }, 800);
    return true;
  }, [clearManagedServiceCommandSlowTimer, commandStorage, commitManagedServiceCommand, experience]);

  const clearPersistedManagedServiceCommand = useCallback((intent: ManagedServiceCommandIntent) => {
    const storage = commandStorage();
    if (!storage) return;
    try {
      clearManagedServiceCommand(storage, intent.owner, intent.requestId);
    } catch {
      // Equal replay is safe even if the browser cannot remove the local record.
    }
  }, [commandStorage]);

  const completeManagedServiceCommand = useCallback((intent: ManagedServiceCommandIntent) => {
    clearManagedServiceCommandSlowTimer();
    clearPersistedManagedServiceCommand(intent);
    const currentCommand = managedServiceCommandRef.current;
    if (currentCommand?.intent.requestId === intent.requestId) {
      commitManagedServiceCommand({ ...currentCommand, phase: "completed", error: null, slow: false, restored: false });
    }
  }, [clearManagedServiceCommandSlowTimer, clearPersistedManagedServiceCommand, commitManagedServiceCommand]);

  const failManagedServiceCommand = useCallback((intent: ManagedServiceCommandIntent, failure: unknown, owner: ControlPlaneRequestOwner) => {
    clearManagedServiceCommandSlowTimer();
    const error = managedServiceCommandError(failure);
    expireUnauthorizedCredential(failure, owner);
    if (error !== "unknown") clearPersistedManagedServiceCommand(intent);
    const currentCommand = managedServiceCommandRef.current;
    if (currentCommand?.intent.requestId === intent.requestId) {
      commitManagedServiceCommand({
        ...currentCommand,
        phase: error === "unknown" ? "unknown" : "failed",
        error,
        slow: false
      });
    }
    return error;
  }, [clearManagedServiceCommandSlowTimer, clearPersistedManagedServiceCommand, commitManagedServiceCommand, expireUnauthorizedCredential]);

  useEffect(() => {
    let active = true;
    clearManagedServiceCommandSlowTimer();
    if (!managedServiceCommandOwner || experience) {
      queueMicrotask(() => { if (active) commitManagedServiceCommand(null); });
      return () => { active = false; };
    }
    const restore = () => {
      if (!active) return;
      const storage = commandStorage();
      if (!storage) {
        commitManagedServiceCommand(null);
        return;
      }
      try {
        const intent = readManagedServiceCommand(storage, managedServiceCommandOwner);
        commitManagedServiceCommand(intent ? {
          intent,
          phase: "unknown",
          error: "unknown",
          slow: false,
          restored: true
        } : null);
      } catch {
        commitManagedServiceCommand(null);
      }
    };
    queueMicrotask(restore);
    const onStorage = (event: StorageEvent) => {
      if (event.key === managedServiceCommandStorageKey || event.key === null) restore();
    };
    window.addEventListener("storage", onStorage);
    return () => {
      active = false;
      window.removeEventListener("storage", onStorage);
    };
  }, [clearManagedServiceCommandSlowTimer, commandStorage, commitManagedServiceCommand, experience, managedServiceCommandOwner, managedServiceCommandOwnerKey]);

  useEffect(() => () => clearManagedServiceCommandSlowTimer(), [clearManagedServiceCommandSlowTimer]);

  const commitResources = useCallback((
    owner: string,
    resources: readonly ControlPlaneResourceKind[],
    loaded: ControlPlaneResourceSnapshot
  ) => {
    const current = cacheRef.current;
    if (!current || current.owner !== owner) return;
    const next: ControlPlaneCache = {
      owner,
      snapshot: mergeResources(current.snapshot, loaded, resources),
      loaded: new Set([...current.loaded, ...resources])
    };
    cacheRef.current = next;
    setCache(next);
  }, []);

  const readResources = useCallback(async (
    resources: readonly ControlPlaneResourceKind[],
    force: boolean,
    mayCommit?: () => boolean
  ) => {
    if (!credential || resources.length === 0) return;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    let current = cacheRef.current;
    if (!current || current.owner !== credential) {
      current = { owner: credential, snapshot: emptySnapshot, loaded: new Set() };
      cacheRef.current = current;
      setCache(current);
      inFlight.current.clear();
    }

    const waits = new Set<Promise<void>>();
    const missing: ControlPlaneResourceKind[] = [];
    for (const resource of resources) {
      if (!force && current.loaded.has(resource)) continue;
      const pending = !force ? inFlight.current.get(resource) : undefined;
      if (pending?.owner === credential) waits.add(pending.promise);
      else missing.push(resource);
    }

    if (missing.length > 0) {
      const request = repository.load(credential, missing)
        .catch((failure) => {
          expireUnauthorizedCredential(failure, owner);
          throw failure;
        })
        .then((loaded) => {
          if (mayCommit && !mayCommit()) return;
          const owned = missing.filter(resource => inFlight.current.get(resource)?.promise === request);
          if (owned.length > 0) commitResources(credential, owned, loaded);
        })
        .finally(() => {
          for (const resource of missing) {
            if (inFlight.current.get(resource)?.promise === request) inFlight.current.delete(resource);
          }
        });
      for (const resource of missing) inFlight.current.set(resource, { owner: credential, promise: request });
      waits.add(request);
    }
    await Promise.all(waits);
  }, [commitResources, credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const readEnrichments = useCallback((
    resources: readonly ControlPlaneResourceKind[],
    force: boolean
  ) => {
    for (const resource of resources) {
      void readResources([resource], force).catch(() => {
        // Enrichment is deliberately fail-soft. The authoritative installation
        // directory remains usable with stable resource IDs when display names,
        // quota context, or region metadata are unavailable to this identity.
      });
    }
  }, [readResources]);

  const readServiceDefinitions = useCallback(async () => {
    if (!credential || !repository.listServiceDefinitions) throw new Error("SERVICE_DIRECTORY_UNAVAILABLE");
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    try {
      return await repository.listServiceDefinitions(credential);
    } catch (failure) {
      expireUnauthorizedCredential(failure, owner);
      throw failure;
    }
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const prepare = useCallback(async (target: ControlPlaneRouteSelection) => {
    // Route chrome and preview-owned content render synchronously. Only the
    // target's server-owned data regions participate in this asynchronous read.
    await Promise.resolve();
    const revision = ++prepareRevision.current;
    const resources = requiredResourcesFor(target, Boolean(experience), productAccess);
    const enrichments = enrichmentResourcesFor(target, productAccess);
    if (!credential || (resources.length === 0 && enrichments.length === 0)) {
      if (revision === prepareRevision.current) {
        setError(null);
        setLoading(false);
      }
      return;
    }
    const current = cacheRef.current;
    if (current?.owner === credential && resources.every((resource) => current.loaded.has(resource))) {
      if (revision === prepareRevision.current) {
        setError(null);
        setLoading(false);
      }
      readEnrichments(enrichments, false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await readResources(resources, false);
      if (revision === prepareRevision.current) {
        setError(null);
        readEnrichments(enrichments, false);
      }
    } catch (loadError) {
      if (revision === prepareRevision.current) setError(loadMessage(loadError));
    } finally {
      if (revision === prepareRevision.current) setLoading(false);
    }
  }, [credential, experience, productAccess, readEnrichments, readResources]);

  const reload = useCallback(async () => {
    const revision = ++prepareRevision.current;
    const resources = requiredResourcesFor(selection, Boolean(experience), productAccess);
    const enrichments = enrichmentResourcesFor(selection, productAccess);
    if (!credential || (resources.length === 0 && enrichments.length === 0)) {
      setError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await readResources(resources, true);
      if (revision === prepareRevision.current) {
        setError(null);
        readEnrichments(enrichments, true);
      }
    } catch (loadError) {
      if (revision === prepareRevision.current) setError(loadMessage(loadError));
    } finally {
      if (revision === prepareRevision.current) setLoading(false);
    }
  }, [credential, experience, productAccess, readEnrichments, readResources, selection]);

  useEffect(() => {
    if (credential && cacheRef.current?.owner === credential) return;
    prepareRevision.current += 1;
    cacheRef.current = null;
    inFlight.current.clear();
    setCache(null);
    setError(null);
    setLoading(false);
    serviceAuthorizationIntentRef.current = null;
    setServiceAuthorizationIntent(null);
    installationTerminationIntentRef.current = null;
    setInstallationTerminationIntent(null);
  }, [credential]);

  useEffect(() => {
    let active = true;
    const target = { section: selection.section, view: selection.view, product: selection.product };
    queueMicrotask(() => { if (active) void prepare(target); });
    return () => { active = false; };
  }, [prepare, selection.product, selection.section, selection.view]);

  const ownedCache = cache?.owner === credential ? cache : null;
  const productResourcesReady = productDataReady(selection, productAccess);

  useEffect(() => {
    if (!credential || selection.section !== "installations" || !productResourcesReady) return;
    if (!ownedCache?.loaded.has("installations")) return;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    const pending = ownedCache.snapshot.installations.filter((item) => [
      "PENDING", "PROVISIONING", "TERMINATION_PENDING", "TERMINATING"
    ].includes(item.phase));
    if (pending.length === 0) return;
    let active = true;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const reads = await Promise.all(pending.map(async (item) => {
            try {
              return { installation: await repository.getInstallation(credential, item.id), missing: false };
            } catch (pollError) {
              const terminating = item.phase === "TERMINATION_PENDING" || item.phase === "TERMINATING";
              if (terminating && pollError instanceof HttpProblem && pollError.status === 404) {
                return { installation: null, missing: true };
              }
              throw pollError;
            }
          }));
          if (!active) return;
          if (reads.some((read) => read.missing)) {
            await readResources(["installations"], true);
            if (active) readEnrichments(["entitlements"], true);
            return;
          }
          const updates = reads.flatMap((read) => read.installation ? [read.installation] : []);
          setError(null);
          const byId = new Map(updates.map((item) => [item.id, item]));
          const current = cacheRef.current;
          if (current?.owner === credential) {
            const next = {
              ...current,
              snapshot: {
                ...current.snapshot,
                installations: current.snapshot.installations.map((item) => byId.get(item.id) ?? item)
              }
            };
            cacheRef.current = next;
            setCache(next);
          }
          if (!updates.some((item) => [
            "READY", "FAILED", "ROLLBACK_FAILED", "TERMINATION_FAILED", "TERMINATED"
          ].includes(item.phase))) {
            return;
          }
          await readResources(["installations"], true);
          if (active) readEnrichments(["entitlements"], true);
        } catch (pollError: unknown) {
          if (active) {
            expireUnauthorizedCredential(pollError, owner);
            setError(loadMessage(pollError));
          }
        }
      })();
    }, 4_000);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, ownedCache, productResourcesReady, readEnrichments, readResources, repository, selection.product, selection.section, sessionRevision]);

  const activateQuota = useCallback(async (command: ActivateQuotaCommand) => {
    if (!credential || !managedServiceCommandOwner) return false;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    const intent: ManagedServiceCommandIntent = {
      owner: managedServiceCommandOwner,
      requestId: requestToken("ui-quota-"),
      startedAt: new Date().toISOString(),
      targetId: command.offeringId,
      targetLabel: `${command.offeringId} · ${command.quotaShapeId}`,
      kind: "ACTIVATE_QUOTA",
      payload: { ...command }
    };
    if (!beginManagedServiceCommand(intent)) return false;
    setMutation("quota");
    setError(null);
    try {
      const entitlement = await repository.activateQuota(credential, intent.payload, intent.requestId);
      const current = cacheRef.current;
      if (current?.owner === credential) {
        const next = {
          ...current,
          snapshot: {
            ...current.snapshot,
            entitlements: [...current.snapshot.entitlements.filter((item) => item.id !== entitlement.id), entitlement]
          }
        };
        cacheRef.current = next;
        setCache(next);
      }
      completeManagedServiceCommand(intent);
      return true;
    } catch (mutationError) {
      failManagedServiceCommand(intent, mutationError, owner);
      return false;
    } finally {
      setMutation(null);
    }
  }, [beginManagedServiceCommand, completeManagedServiceCommand, credential, failManagedServiceCommand, managedServiceCommandOwner, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const createInstallation = useCallback(async (command: CreateInstallationCommand) => {
    if (!credential || !managedServiceCommandOwner) return false;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    const intent: ManagedServiceCommandIntent = {
      owner: managedServiceCommandOwner,
      requestId: requestToken("ui-install-"),
      startedAt: new Date().toISOString(),
      targetId: command.id,
      targetLabel: command.name,
      kind: "CREATE_INSTALLATION",
      payload: { ...command }
    };
    if (!beginManagedServiceCommand(intent)) return false;
    setMutation("installation");
    setError(null);
    try {
      const installation = await repository.createInstallation(credential, intent.payload, intent.requestId);
      const current = cacheRef.current;
      if (current?.owner === credential) {
        const next = {
          ...current,
          snapshot: {
            ...current.snapshot,
            installations: [...current.snapshot.installations.filter((item) => item.id !== installation.id), installation]
          }
        };
        cacheRef.current = next;
        setCache(next);
      }
      completeManagedServiceCommand(intent);
      return true;
    } catch (mutationError) {
      failManagedServiceCommand(intent, mutationError, owner);
      return false;
    } finally {
      setMutation(null);
    }
  }, [beginManagedServiceCommand, completeManagedServiceCommand, credential, failManagedServiceCommand, managedServiceCommandOwner, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const commitInstallationTerminationIntent = useCallback((intent: InstallationTerminationIntent | null) => {
    installationTerminationIntentRef.current = intent;
    setInstallationTerminationIntent(intent);
  }, []);

  const beginInstallationTermination = useCallback((installation: InstallationTerminationIntent["installation"]) => {
    const activeCommand = managedServiceCommandRef.current;
    if (activeCommand && (activeCommand.phase === "submitting" || activeCommand.phase === "unknown")) return;
    const current = installationTerminationIntentRef.current;
    if (current) {
      if (current.installation.id === installation.id) {
        commitInstallationTerminationIntent({ ...current, open: true });
      }
      return;
    }
    if (!["READY", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(installation.phase)) return;
    commitInstallationTerminationIntent({
      installation,
      requestId: requestToken("ui-installation-termination-"),
      phase: "review",
      error: null,
      open: true
    });
  }, [commitInstallationTerminationIntent]);

  const submitInstallationTermination = useCallback(async () => {
    const intent = installationTerminationIntentRef.current;
    if (!credential || !managedServiceCommandOwner || !intent || intent.phase === "submitting" || !repository.terminateInstallation) return null;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    const commandIntent: ManagedServiceCommandIntent = {
      owner: managedServiceCommandOwner,
      requestId: intent.requestId,
      startedAt: new Date().toISOString(),
      targetId: intent.installation.id,
      targetLabel: intent.installation.name,
      kind: "TERMINATE_INSTALLATION",
      payload: { installationId: intent.installation.id }
    };
    const existingCommand = managedServiceCommandRef.current;
    const frozenIntent = existingCommand?.intent.requestId === intent.requestId
      ? existingCommand.intent
      : commandIntent;
    if (frozenIntent.kind !== "TERMINATE_INSTALLATION" || !beginManagedServiceCommand(frozenIntent)) return null;
    commitInstallationTerminationIntent({ ...intent, phase: "submitting", error: null, open: true });
    try {
      const installation = await repository.terminateInstallation(
        credential,
        frozenIntent.payload.installationId,
        frozenIntent.requestId
      );
      const current = cacheRef.current;
      if (current?.owner === credential) {
        const next = {
          ...current,
          snapshot: {
            ...current.snapshot,
            installations: current.snapshot.installations.map((item) =>
              item.id === installation.id ? installation : item
            )
          }
        };
        cacheRef.current = next;
        setCache(next);
      }
      if (installationTerminationIntentRef.current?.requestId === intent.requestId) {
        commitInstallationTerminationIntent(null);
      }
      completeManagedServiceCommand(frozenIntent);
      return installation;
    } catch (terminationError) {
      const commandError = failManagedServiceCommand(frozenIntent, terminationError, owner);
      if (installationTerminationIntentRef.current?.requestId === intent.requestId) {
        commitInstallationTerminationIntent({
          ...intent,
          phase: "failed",
          error: commandError === "storageUnavailable" || commandError === "unavailable" || commandError === "mismatch" || commandError === "operationFailed" ? "unknown" : commandError,
          open: true
        });
      }
      if (commandError !== "unknown") commitManagedServiceCommand(null);
      return null;
    }
  }, [beginManagedServiceCommand, commitInstallationTerminationIntent, commitManagedServiceCommand, completeManagedServiceCommand, credential, failManagedServiceCommand, managedServiceCommandOwner, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const closeInstallationTerminationIntent = useCallback(() => {
    const intent = installationTerminationIntentRef.current;
    if (!intent) return;
    if (intent.phase === "failed" && intent.error === "unknown") {
      commitInstallationTerminationIntent({ ...intent, open: false });
      return;
    }
    commitInstallationTerminationIntent(null);
  }, [commitInstallationTerminationIntent]);

  const reopenInstallationTerminationIntent = useCallback(() => {
    const intent = installationTerminationIntentRef.current;
    if (intent) commitInstallationTerminationIntent({ ...intent, open: true });
  }, [commitInstallationTerminationIntent]);

  const readInstallation = useCallback(async (installationId: string): Promise<InstallationReadLoad> => {
    if (!credential) return { status: "expired" };
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    try {
      return {
        status: "ready",
        installation: await repository.getInstallation(credential, installationId)
      };
    } catch (readError) {
      if (readError instanceof HttpProblem) {
        if (readError.status === 401) {
          expireUnauthorizedCredential(readError, owner);
          return { status: "expired" };
        }
        if (readError.status === 403) return { status: "forbidden" };
        if (readError.status === 404) return { status: "notFound" };
      }
      return { status: "unavailable" };
    }
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const inspectServiceAuthorization = useCallback(async (
    accountId: string,
    installationId: string
  ): Promise<ManagedServiceAuthorizationLoad> => {
    if (!credential || !repository.inspectServiceAuthorization) return { status: "unavailable" };
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    try {
      return { status: "ready", observation: await repository.inspectServiceAuthorization(credential, accountId, installationId) };
    } catch (inspectionError) {
      if (inspectionError instanceof HttpProblem && inspectionError.status === 401) {
        expireUnauthorizedCredential(inspectionError, owner);
        return { status: "expired" };
      }
      if (inspectionError instanceof HttpProblem && inspectionError.status === 403) return { status: "forbidden" };
      return { status: "unavailable" };
    }
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const readApplication = useCallback(async (applicationId: string): Promise<ApplicationReadLoad> => {
    if (!validApplicationId(applicationId)) return { status: "invalid" };
    if (!credential || !repository.readApplication) return { status: "unavailable" };
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    try {
      return { status: "ready", snapshot: await repository.readApplication(credential, applicationId) };
    } catch (readError) {
      if (!(readError instanceof HttpProblem)) return { status: "unavailable" };
      if (readError.status === 400) return { status: "invalid" };
      if (readError.status === 401) {
        expireUnauthorizedCredential(readError, owner);
        return { status: "expired" };
      }
      if (readError.status === 403) return { status: "forbidden" };
      if (readError.status === 404) return { status: "notFound" };
      return { status: "unavailable" };
    }
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const listApplications = useCallback(async (after?: string): Promise<ApplicationDirectoryLoad> => {
    if (after !== undefined && !validApplicationCursor(after)) return { status: "invalidCursor" };
    if (!credential || !repository.listApplications) return { status: "unavailable" };
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    try {
      return { status: "ready", page: await repository.listApplications(credential, after) };
    } catch (directoryError) {
      if (!(directoryError instanceof HttpProblem)) return { status: "unavailable" };
      if (directoryError.status === 400) return { status: "invalidCursor" };
      if (directoryError.status === 401) {
        expireUnauthorizedCredential(directoryError, owner);
        return { status: "expired" };
      }
      if (directoryError.status === 403) return { status: "forbidden" };
      return { status: "unavailable" };
    }
  }, [credential, expireUnauthorizedCredential, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const commitServiceAuthorizationIntent = useCallback((intent: ManagedServiceAuthorizationIntent | null) => {
    serviceAuthorizationIntentRef.current = intent;
    setServiceAuthorizationIntent(intent);
  }, []);

  const beginServiceAuthorization = useCallback((
    accountId: string,
    installationId: string,
    observation: ManagedServiceAuthorizationObservation,
    kind: "bind" | "unbind"
  ) => {
    const activeCommand = managedServiceCommandRef.current;
    if (activeCommand && (activeCommand.phase === "submitting" || activeCommand.phase === "unknown")) return;
    const current = serviceAuthorizationIntentRef.current;
    if (current) {
      if (current.installationId === installationId) commitServiceAuthorizationIntent({ ...current, open: true });
      return;
    }
    if (kind === "unbind" && !observation.binding) return;
    commitServiceAuthorizationIntent({
      accountId,
      installationId,
      kind,
      template: observation.template,
      relation: observation.relation,
      binding: observation.binding,
      requestId: requestToken(`ui-service-role-${kind}-`),
      phase: "review",
      error: null,
      open: true
    });
  }, [commitServiceAuthorizationIntent]);

  const submitServiceAuthorization = useCallback(async () => {
    const intent = serviceAuthorizationIntentRef.current;
    if (!credential || !managedServiceCommandOwner || !intent || intent.phase === "submitting") return false;
    const owner: ControlPlaneRequestOwner = { credential, repository, sessionRevision, ownerKey: managedServiceCommandOwnerKey };
    const template = {
      id: intent.template.id,
      version: intent.template.version,
      contentDigest: intent.template.contentDigest
    };
    const commandIntent: ManagedServiceCommandIntent | null = intent.kind === "bind"
      ? {
          owner: managedServiceCommandOwner,
          requestId: intent.requestId,
          startedAt: new Date().toISOString(),
          targetId: intent.installationId,
          targetLabel: intent.installationId,
          kind: "BIND_SERVICE_ROLE",
          payload: { installationId: intent.installationId, template }
        }
      : intent.binding ? {
          owner: managedServiceCommandOwner,
          requestId: intent.requestId,
          startedAt: new Date().toISOString(),
          targetId: intent.installationId,
          targetLabel: intent.installationId,
          kind: "UNBIND_SERVICE_ROLE",
          payload: {
            installationId: intent.installationId,
            bindingId: intent.binding.id,
            resourceVersion: intent.binding.resourceVersion,
            expectedTemplate: template
          }
        } : null;
    if (!commandIntent) return false;
    const existingCommand = managedServiceCommandRef.current;
    const frozenIntent = existingCommand?.intent.requestId === intent.requestId
      ? existingCommand.intent
      : commandIntent;
    if (!["BIND_SERVICE_ROLE", "UNBIND_SERVICE_ROLE"].includes(frozenIntent.kind) || !beginManagedServiceCommand(frozenIntent)) return false;
    commitServiceAuthorizationIntent({ ...intent, phase: "submitting", error: null, open: true });
    try {
      if (frozenIntent.kind === "BIND_SERVICE_ROLE") {
        if (!repository.bindServiceRole) throw new Error("SERVICE_ROLE_BIND_UNAVAILABLE");
        await repository.bindServiceRole(credential, frozenIntent.payload.installationId, {
          template: frozenIntent.payload.template,
          requestId: frozenIntent.requestId
        });
      } else if (frozenIntent.kind === "UNBIND_SERVICE_ROLE") {
        if (!repository.unbindServiceRole) throw new Error("SERVICE_ROLE_UNBIND_UNAVAILABLE");
        await repository.unbindServiceRole(credential, frozenIntent.payload.installationId, {
          bindingId: frozenIntent.payload.bindingId,
          resourceVersion: frozenIntent.payload.resourceVersion,
          expectedTemplate: frozenIntent.payload.expectedTemplate,
          requestId: frozenIntent.requestId
        });
      }
      if (serviceAuthorizationIntentRef.current?.requestId === intent.requestId) commitServiceAuthorizationIntent(null);
      completeManagedServiceCommand(frozenIntent);
      return true;
    } catch (mutationError) {
      const commandError = failManagedServiceCommand(frozenIntent, mutationError, owner);
      if (serviceAuthorizationIntentRef.current?.requestId === intent.requestId) {
        commitServiceAuthorizationIntent({
          ...intent,
          phase: "failed",
          error: commandError === "storageUnavailable" || commandError === "unavailable" || commandError === "mismatch" || commandError === "operationFailed" ? "unknown" : commandError,
          open: true
        });
      }
      if (commandError !== "unknown") commitManagedServiceCommand(null);
      return false;
    }
  }, [beginManagedServiceCommand, commitManagedServiceCommand, commitServiceAuthorizationIntent, completeManagedServiceCommand, credential, failManagedServiceCommand, managedServiceCommandOwner, managedServiceCommandOwnerKey, repository, sessionRevision]);

  const closeServiceAuthorizationIntent = useCallback(() => {
    const intent = serviceAuthorizationIntentRef.current;
    if (!intent) return;
    if (intent.phase === "failed" && intent.error === "unknown") {
      commitServiceAuthorizationIntent({ ...intent, open: false });
      return;
    }
    commitServiceAuthorizationIntent(null);
  }, [commitServiceAuthorizationIntent]);

  const reopenServiceAuthorizationIntent = useCallback(() => {
    const intent = serviceAuthorizationIntentRef.current;
    if (intent) commitServiceAuthorizationIntent({ ...intent, open: true });
  }, [commitServiceAuthorizationIntent]);

  const commandRecoveryAvailable = Boolean(!experience && credential && managedServiceCommandOwner && repository.listCommandResults);

  const restoreManagedServiceCommand = useCallback((summary: string): boolean => {
    if (!commandRecoveryAvailable || !managedServiceCommandOwner || summary.length > 16_384) return false;
    let intent: ManagedServiceCommandIntent | null;
    try { intent = parseManagedServiceCommandIntent(JSON.parse(summary)); } catch { return false; }
    if (!intent || !sameManagedServiceCommandOwner(intent.owner, managedServiceCommandOwner)) return false;
    const active = managedServiceCommandRef.current;
    if (active?.checking || active?.phase === "submitting" ||
        (active?.phase === "unknown" && JSON.stringify(active.intent) !== JSON.stringify(intent))) return false;
    try {
      const storage = commandStorage();
      if (!storage) return false;
      writeManagedServiceCommand(storage, intent);
    } catch { return false; }
    clearManagedServiceCommandSlowTimer();
    commitManagedServiceCommand({ intent, phase: "unknown", error: "unknown", slow: false, restored: true });
    return true;
  }, [clearManagedServiceCommandSlowTimer, commandRecoveryAvailable, commandStorage, commitManagedServiceCommand, managedServiceCommandOwner]);

  const inspectManagedServiceCommand = useCallback(async (): Promise<boolean> => {
    const state = managedServiceCommandRef.current;
    if (!credential || !managedServiceCommandOwner || !repository.listCommandResults || !state || state.checking ||
        !["unknown", "inProgress"].includes(state.phase) || !sameManagedServiceCommandOwner(state.intent.owner, managedServiceCommandOwner)) return false;
    const intent = state.intent, owner = commandReadOwner.current;
    const isCurrent = () => {
      const latest = commandReadOwner.current, active = managedServiceCommandRef.current;
      return latest.credential === owner.credential && latest.repository === owner.repository &&
        latest.sessionRevision === owner.sessionRevision && latest.ownerKey === owner.ownerKey &&
        active?.intent === intent;
    };
    const unknown = (error: ManagedServiceCommandError) => {
      if (isCurrent()) commitManagedServiceCommand({ ...state, phase: "unknown", result: undefined, checking: false, error });
    };
    commitManagedServiceCommand({ ...state, checking: true, error: null });
    try {
      const results = await repository.listCommandResults(credential, managedServiceCommandType(intent.kind));
      if (!isCurrent()) return false;
      const matches = results.filter((item) => item.idempotencyKey === intent.requestId);
      if (matches.length === 0) { unknown("notFound"); return false; }
      const result: ManagedServiceCommandResult = matches[0]!;
      if (matches.length !== 1 || !matchesManagedServiceCommandResult(intent, result)) { unknown("mismatch"); return false; }
      const quotaCache = cacheRef.current;
      const refreshQuota = intent.kind === "ACTIVATE_QUOTA" && result.state === "SUCCEEDED" && quotaCache?.owner === credential &&
        (quotaCache.loaded.has("entitlements") || inFlight.current.get("entitlements")?.owner === credential);
      if (result.state !== "IN_PROGRESS") clearPersistedManagedServiceCommand(intent);
      const settled: ManagedServiceCommandState = { ...state, phase: result.state === "IN_PROGRESS" ? "inProgress" : result.state === "SUCCEEDED" ? "completed" : "failed",
        result, error: result.state === "FAILED" ? "operationFailed" : null, checking: refreshQuota, slow: false };
      commitManagedServiceCommand(settled);
      if (installationTerminationIntentRef.current?.requestId === intent.requestId) commitInstallationTerminationIntent(null);
      if (serviceAuthorizationIntentRef.current?.requestId === intent.requestId) commitServiceAuthorizationIntent(null);
      // A command result proves only this operation. Resource details still
      // require their independently authorized reads; never synthesize a cache.
      if (refreshQuota) {
        const loaded = new Set(quotaCache.loaded);
        loaded.delete("entitlements");
        const invalidated = { ...quotaCache, loaded };
        cacheRef.current = invalidated;
        setCache(invalidated);
        const revision = ++prepareRevision.current;
        setLoading(true);
        setError(null);
        try {
          await readResources(["entitlements"], true, isCurrent);
        } catch (readError) {
          if (isCurrent() && revision === prepareRevision.current) setError(loadMessage(readError));
        } finally {
          if (isCurrent()) {
            commitManagedServiceCommand({ ...settled, checking: false });
            if (revision === prepareRevision.current) setLoading(false);
          }
        }
      }
      return isCurrent();
    } catch (failure) {
      if (!isCurrent()) return false;
      const reason = failure instanceof HttpProblem && failure.status === 401 ? "expired"
        : failure instanceof HttpProblem && failure.status === 403 ? "forbidden"
          : failure instanceof HttpProblem && failure.status === 404 ? "notFound" : "unavailable";
      unknown(reason);
      if (reason === "expired") expireUnauthorizedCredential(failure, owner);
      return false;
    }
  }, [clearPersistedManagedServiceCommand, commitInstallationTerminationIntent, commitManagedServiceCommand, commitServiceAuthorizationIntent, credential, expireUnauthorizedCredential, managedServiceCommandOwner, readResources, repository]);

  const clearManagedServiceCommandNotice = useCallback(() => {
    const state = managedServiceCommandRef.current;
    if (state && !state.checking && (state.phase === "failed" || state.phase === "completed" || state.phase === "inProgress")) {
      clearPersistedManagedServiceCommand(state.intent);
      commitManagedServiceCommand(null);
    }
  }, [clearPersistedManagedServiceCommand, commitManagedServiceCommand]);

  const projectScene = useCallback((target: ControlPlaneRouteSelection): ConsoleScene | null => {
    if (target.section === "access") return buildAccessConsoleScene(experience, target.view);
    if (target.section === "audit") return buildAuditConsoleScene(experience);
    if (!productDataReady(target, productAccess)) {
      // The independent first-use gate can project immediately, without cached
      // resource counts or a resource-loading placeholder above it.
      return buildConsoleScene(target.section, emptySnapshot, experience, target.view, target.product);
    }
    const resources = requiredResourcesFor(target, Boolean(experience), productAccess);
    const targetCache = ownedCache;
    if (!resources.every((resource) => targetCache?.loaded.has(resource))) return null;
    return buildConsoleScene(
      target.section,
      targetCache?.snapshot ?? emptySnapshot,
      experience,
      target.view,
      target.product
    );
  }, [experience, ownedCache, productAccess]);
  const scene = useMemo(
    () => projectScene({ section: selection.section, view: selection.view, product: selection.product }),
    [projectScene, selection.product, selection.section, selection.view]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    projectScene,
    prepare,
    loading: productDataReady(selection, productAccess) && loading,
    error: isAccess || requiredResourcesFor(selection, Boolean(experience), productAccess).length === 0 ? null : error,
    mutation,
    readServiceDefinitions,
    managedServiceCommand,
    commandRecoveryAvailable,
    restoreManagedServiceCommand,
    inspectManagedServiceCommand,
    clearManagedServiceCommandNotice,
    reload,
    activateQuota,
    createInstallation,
    readInstallation,
    installationTerminationIntent,
    beginInstallationTermination,
    submitInstallationTermination,
    closeInstallationTerminationIntent,
    reopenInstallationTerminationIntent,
    readApplication,
    listApplications,
    inspectServiceAuthorization,
    serviceAuthorizationIntent,
    beginServiceAuthorization,
    submitServiceAuthorization,
    closeServiceAuthorizationIntent,
    reopenServiceAuthorizationIntent
  }), [activateQuota, beginInstallationTermination, beginServiceAuthorization, clearManagedServiceCommandNotice, closeInstallationTerminationIntent, closeServiceAuthorizationIntent, commandRecoveryAvailable, createInstallation, error, experience, inspectManagedServiceCommand, inspectServiceAuthorization, installationTerminationIntent, isAccess, listApplications, loading, managedServiceCommand, mutation, prepare, productAccess, projectScene, readApplication, readInstallation, readServiceDefinitions, reload, reopenInstallationTerminationIntent, reopenServiceAuthorizationIntent, restoreManagedServiceCommand, scene, selection, serviceAuthorizationIntent, submitInstallationTermination, submitServiceAuthorization]);

  return (
    <ControlPlaneContext.Provider value={value}>
      {children}
    </ControlPlaneContext.Provider>
  );
}

export function useControlPlane(): ControlPlaneContextValue {
  const value = useContext(ControlPlaneContext);
  if (!value) {
    throw new Error("useControlPlane must be used inside ControlPlaneProvider");
  }
  return value;
}
