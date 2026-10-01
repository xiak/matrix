"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import { useEffectiveCredential } from "@/features/auth/application/RoleSessionProvider";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { ExperienceSnapshot } from "../domain/experience";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand
} from "../domain/resources";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type {
  ManagedServiceAuthorizationIntent,
  ManagedServiceAuthorizationLoad,
  ManagedServiceAuthorizationMutationError,
  ManagedServiceAuthorizationObservation
} from "../domain/serviceAuthorization";
import type {
  ControlPlaneRepository,
  ControlPlaneResourceKind,
  ControlPlaneResourceSnapshot
} from "../repositories/controlPlaneRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { buildAccessConsoleScene, buildConsoleScene } from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";

type ControlPlaneError = "expired" | "forbidden" | "unavailable";

type MutationKind = "quota" | "installation" | null;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  projectScene(selection: ControlPlaneRouteSelection): ConsoleScene | null;
  prepare(selection: ControlPlaneRouteSelection): Promise<void>;
  loading: boolean;
  error: ControlPlaneError | null;
  mutation: MutationKind;
  reload(): Promise<void>;
  activateQuota(command: ActivateQuotaCommand): Promise<boolean>;
  createInstallation(command: CreateInstallationCommand): Promise<boolean>;
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

function resourcesFor(
  selection: ControlPlaneRouteSelection,
  hasExperience: boolean
): readonly ControlPlaneResourceKind[] {
  if (selection.section === "access") return [];
  if (selection.section === "catalog") return ["offerings"];
  if (selection.section === "quotas") return ["offerings", "entitlements"];
  if (selection.section === "installations") return ["offerings", "regions", "entitlements", "installations"];
  if (selection.section === "regions") return ["regions"];
  if (selection.section === "overview") {
    return hasExperience ? ["regions"] : ["offerings", "regions", "entitlements", "installations"];
  }
  return [];
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

function serviceAuthorizationMutationError(error: unknown): ManagedServiceAuthorizationMutationError {
  if (!(error instanceof HttpProblem)) return "unknown";
  if (error.status === 401) return "expired";
  if (error.status === 403) return "forbidden";
  if (error.status === 404) return "notFound";
  if (error.status === 409) return "conflict";
  if ([400, 413, 415, 422].includes(error.status)) return "invalid";
  return "unknown";
}

export function ControlPlaneProvider({
  children,
  experience,
  repository = httpControlPlaneRepository,
  selection
}: {
  children: ReactNode;
  experience?: ExperienceSnapshot;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const credential = useEffectiveCredential();
  const isAccess = selection.section === "access";
  const [cache, setCache] = useState<ControlPlaneCache | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ControlPlaneError | null>(null);
  const [mutation, setMutation] = useState<MutationKind>(null);
  const [serviceAuthorizationIntent, setServiceAuthorizationIntent] = useState<ManagedServiceAuthorizationIntent | null>(null);
  const cacheRef = useRef<ControlPlaneCache | null>(null);
  const serviceAuthorizationIntentRef = useRef<ManagedServiceAuthorizationIntent | null>(null);
  const inFlight = useRef(new Map<ControlPlaneResourceKind, { owner: string; promise: Promise<void> }>());
  const prepareRevision = useRef(0);

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
    force: boolean
  ) => {
    if (!credential || resources.length === 0) return;
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
        .then((loaded) => commitResources(credential, missing, loaded))
        .finally(() => {
          for (const resource of missing) {
            if (inFlight.current.get(resource)?.promise === request) inFlight.current.delete(resource);
          }
        });
      for (const resource of missing) inFlight.current.set(resource, { owner: credential, promise: request });
      waits.add(request);
    }
    await Promise.all(waits);
  }, [commitResources, credential, repository]);

  const prepare = useCallback(async (target: ControlPlaneRouteSelection) => {
    // Route chrome and preview-owned content render synchronously. Only the
    // target's server-owned data regions participate in this asynchronous read.
    await Promise.resolve();
    const revision = ++prepareRevision.current;
    const resources = resourcesFor(target, Boolean(experience));
    if (!credential || resources.length === 0) {
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
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await readResources(resources, false);
      if (revision === prepareRevision.current) setError(null);
    } catch (loadError) {
      if (revision === prepareRevision.current) setError(loadMessage(loadError));
    } finally {
      if (revision === prepareRevision.current) setLoading(false);
    }
  }, [credential, experience, readResources]);

  const reload = useCallback(async () => {
    const revision = ++prepareRevision.current;
    const resources = resourcesFor(selection, Boolean(experience));
    if (!credential || resources.length === 0) {
      setError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await readResources(resources, true);
      if (revision === prepareRevision.current) setError(null);
    } catch (loadError) {
      if (revision === prepareRevision.current) setError(loadMessage(loadError));
    } finally {
      if (revision === prepareRevision.current) setLoading(false);
    }
  }, [credential, experience, readResources, selection]);

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
  }, [credential]);

  useEffect(() => {
    let active = true;
    const target = { section: selection.section, view: selection.view };
    queueMicrotask(() => { if (active) void prepare(target); });
    return () => { active = false; };
  }, [prepare, selection.section, selection.view]);

  const ownedCache = cache?.owner === credential ? cache : null;

  useEffect(() => {
    if (!credential || selection.section !== "installations") return;
    if (!ownedCache?.loaded.has("installations")) return;
    const pending = ownedCache.snapshot.installations.filter(
      (item) => item.phase === "PENDING" || item.phase === "PROVISIONING"
    );
    if (pending.length === 0) return;
    let active = true;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const updates = await Promise.all(
            pending.map((item) => repository.getInstallation(credential, item.id))
          );
          if (!active) return;
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
          if (!updates.some((item) => item.phase === "READY" || item.phase === "FAILED")) {
            return;
          }
          const refreshedResources = ["entitlements", "installations"] as const;
          const refreshed = await repository.load(credential, refreshedResources);
          if (active) commitResources(credential, refreshedResources, refreshed);
        } catch (pollError: unknown) {
          if (active) setError(loadMessage(pollError));
        }
      })();
    }, 4_000);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [commitResources, credential, ownedCache, repository, selection.section]);

  const activateQuota = useCallback(async (command: ActivateQuotaCommand) => {
    if (!credential) return false;
    setMutation("quota");
    setError(null);
    try {
      const entitlement = await repository.activateQuota(credential, command);
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
      return true;
    } catch (mutationError) {
      setError(loadMessage(mutationError));
      return false;
    } finally {
      setMutation(null);
    }
  }, [credential, repository]);

  const createInstallation = useCallback(async (command: CreateInstallationCommand) => {
    if (!credential) return false;
    setMutation("installation");
    setError(null);
    try {
      const installation = await repository.createInstallation(credential, command);
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
      return true;
    } catch (mutationError) {
      setError(loadMessage(mutationError));
      return false;
    } finally {
      setMutation(null);
    }
  }, [credential, repository]);

  const inspectServiceAuthorization = useCallback(async (
    accountId: string,
    installationId: string
  ): Promise<ManagedServiceAuthorizationLoad> => {
    if (!credential || !repository.inspectServiceAuthorization) return { status: "unavailable" };
    try {
      return { status: "ready", observation: await repository.inspectServiceAuthorization(credential, accountId, installationId) };
    } catch (inspectionError) {
      if (inspectionError instanceof HttpProblem && inspectionError.status === 401) return { status: "expired" };
      if (inspectionError instanceof HttpProblem && inspectionError.status === 403) return { status: "forbidden" };
      return { status: "unavailable" };
    }
  }, [credential, repository]);

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
    if (!credential || !intent || intent.phase === "submitting") return false;
    commitServiceAuthorizationIntent({ ...intent, phase: "submitting", error: null, open: true });
    try {
      if (intent.kind === "bind") {
        if (!repository.bindServiceRole) throw new Error("SERVICE_ROLE_BIND_UNAVAILABLE");
        await repository.bindServiceRole(credential, intent.installationId, {
          template: {
            id: intent.template.id,
            version: intent.template.version,
            contentDigest: intent.template.contentDigest
          },
          requestId: intent.requestId
        });
      } else {
        if (!repository.unbindServiceRole || !intent.binding) throw new Error("SERVICE_ROLE_UNBIND_UNAVAILABLE");
        await repository.unbindServiceRole(credential, intent.installationId, {
          bindingId: intent.binding.id,
          resourceVersion: intent.binding.resourceVersion,
          expectedTemplate: {
            id: intent.template.id,
            version: intent.template.version,
            contentDigest: intent.template.contentDigest
          },
          requestId: intent.requestId
        });
      }
      if (serviceAuthorizationIntentRef.current?.requestId === intent.requestId) commitServiceAuthorizationIntent(null);
      return true;
    } catch (mutationError) {
      if (serviceAuthorizationIntentRef.current?.requestId === intent.requestId) {
        commitServiceAuthorizationIntent({
          ...intent,
          phase: "failed",
          error: serviceAuthorizationMutationError(mutationError),
          open: true
        });
      }
      return false;
    }
  }, [commitServiceAuthorizationIntent, credential, repository]);

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

  const projectScene = useCallback((target: ControlPlaneRouteSelection): ConsoleScene | null => {
    if (target.section === "access") return buildAccessConsoleScene(experience, target.view);
    const resources = resourcesFor(target, Boolean(experience));
    const targetCache = ownedCache;
    if (!resources.every((resource) => targetCache?.loaded.has(resource))) return null;
    return buildConsoleScene(
      target.section,
      targetCache?.snapshot ?? emptySnapshot,
      experience,
      target.view
    );
  }, [experience, ownedCache]);
  const scene = useMemo(
    () => projectScene({ section: selection.section, view: selection.view }),
    [projectScene, selection.section, selection.view]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    projectScene,
    prepare,
    loading,
    error: isAccess || resourcesFor(selection, Boolean(experience)).length === 0 ? null : error,
    mutation,
    reload,
    activateQuota,
    createInstallation,
    inspectServiceAuthorization,
    serviceAuthorizationIntent,
    beginServiceAuthorization,
    submitServiceAuthorization,
    closeServiceAuthorizationIntent,
    reopenServiceAuthorizationIntent
  }), [activateQuota, beginServiceAuthorization, closeServiceAuthorizationIntent, createInstallation, error, experience, inspectServiceAuthorization, isAccess, loading, mutation, prepare, projectScene, reload, reopenServiceAuthorizationIntent, scene, selection, serviceAuthorizationIntent, submitServiceAuthorization]);

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
