"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useExpireEffectiveCredential } from "@/features/auth/application/RoleSessionProvider";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { ManagedServiceProductId } from "../domain/managedServiceProduct";
import type {
  ServiceActivationAccess,
  ServiceActivation,
  ServiceActivationState,
  ServiceDefinition,
  ServiceDefinitionDirectory
} from "../domain/serviceActivation";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";

type LiveActivationSnapshot = {
  access: ServiceActivationAccess;
  definition: ServiceDefinition | null;
  state: ServiceActivationState;
};

type ScopedActivationSnapshot = {
  repository: ControlPlaneRepository;
  scopeKey: string;
  value: LiveActivationSnapshot;
};

type ActivationIntent = {
  access: ServiceActivationAccess;
  definition: ServiceDefinition;
  definitionKey: string;
  repository: ControlPlaneRepository;
  requestId: string;
  scopeKey: string;
};

const unavailable: LiveActivationSnapshot = {
  access: { canEnable: false, mayLoadWorkspace: false },
  definition: null,
  state: { status: "unavailable" }
};

function definitionKey(definition: ServiceDefinition): string {
  return JSON.stringify([definition.id, definition.revision, definition.contentDigest]);
}

function activationMatchesDefinition(activation: ServiceActivation, definition: ServiceDefinition): boolean {
  return activation.service.id === definition.id &&
    activation.service.revision === definition.revision &&
    activation.service.contentDigest === definition.contentDigest;
}

type ServiceDirectoryRead = () => Promise<ServiceDefinitionDirectory>;
type ServiceDirectoryObservation = {
  request: { source: ServiceDirectoryRead; attempt: number };
  status: "ready" | "forbidden" | "expired" | "unavailable";
  directory: ServiceDefinitionDirectory | null;
};

// Each opening, retry, or change of credential-scoped source owns a fresh read.
export function useLiveServiceDefinitionDirectory(active: boolean, source?: ServiceDirectoryRead) {
  const [observation, setObservation] = useState<ServiceDirectoryObservation | null>(null);
  const [attempt, setAttempt] = useState(0);
  const request = useMemo(() => active && source ? { source, attempt } : null, [active, source, attempt]);
  useEffect(() => {
    if (!request) return;
    let current = true;
    queueMicrotask(async () => {
      if (!current) return;
      try {
        const directory = await request.source();
        if (current) setObservation({ request, status: "ready", directory });
      } catch (failure) {
        if (current) setObservation({ request, directory: null, status: failure instanceof HttpProblem && failure.status === 403
          ? "forbidden" : failure instanceof HttpProblem && failure.status === 401 ? "expired" : "unavailable" });
      }
    });
    return () => { current = false; };
  }, [request]);

  const owned = request && observation?.request === request ? observation : null;
  return {
    directory: owned?.directory ?? null,
    status: owned?.status ?? (request ? "checking" : "unavailable"),
    retry: () => setAttempt((value) => value + 1)
  } as const;
}

export type LiveServiceDirectory = ReturnType<typeof useLiveServiceDefinitionDirectory>;

// LIVE activation is deliberately independent from the product data provider.
// A forbidden activation read admits an ordinary product-resource probe instead
// of pretending that the service is disabled. The product API remains the
// authority for every resource response.
export function useLiveServiceActivation({
  accountId,
  active,
  credential,
  repository,
  serviceKey
}: {
  accountId?: string;
  active: boolean;
  credential?: string;
  repository: ControlPlaneRepository;
  serviceKey?: ManagedServiceProductId;
}) {
  const expireEffectiveCredential = useExpireEffectiveCredential();
  const [observation, setObservation] = useState<ScopedActivationSnapshot | null>(null);
  const revision = useRef(0);
  const intent = useRef<ActivationIntent | null>(null);
  const scopeKey = JSON.stringify([accountId, serviceKey, credential]);
  const canRead = Boolean(active && accountId && credential && serviceKey && repository.listServiceDefinitions && repository.getServiceActivation);
  const snapshot = useMemo<LiveActivationSnapshot>(() => canRead && observation?.scopeKey === scopeKey && observation.repository === repository
    ? observation.value
    : { ...unavailable, state: { status: canRead ? "checking" : "unavailable" } }, [canRead, observation, repository, scopeKey]);
  const setSnapshot = useCallback((value: LiveActivationSnapshot) => {
    setObservation({ repository, scopeKey, value });
  }, [repository, scopeKey]);
  const expireUnauthorized = useCallback((failure: unknown) => {
    if (!credential || !(failure instanceof HttpProblem) || failure.status !== 401) return false;
    return expireEffectiveCredential(credential);
  }, [credential, expireEffectiveCredential]);

  const reconcileIntent = useCallback(async (currentIntent: ActivationIntent) => {
    if (!active || !accountId || !credential || !serviceKey || !repository.getServiceActivation ||
        currentIntent.repository !== repository || currentIntent.scopeKey !== scopeKey || intent.current !== currentIntent) return;
    const currentRevision = ++revision.current;
    const unknownSnapshot = (recovery: "inspect" | "replay", checking = false): LiveActivationSnapshot => ({
      access: currentIntent.access,
      definition: currentIntent.definition,
      state: { status: "outcome-unknown", checking, recovery }
    });
    setSnapshot(unknownSnapshot("inspect", true));
    try {
      const activation = await repository.getServiceActivation(credential, serviceKey);
      if (currentRevision !== revision.current || intent.current !== currentIntent) return;
      if (!activationMatchesDefinition(activation, currentIntent.definition)) {
        setSnapshot(unknownSnapshot("inspect"));
        return;
      }
      intent.current = null;
      setSnapshot({
        access: { ...currentIntent.access, mayLoadWorkspace: true },
        definition: currentIntent.definition,
        state: { status: "enabled", scope: { accountId, serviceKey }, activation }
      });
    } catch (failure) {
      if (currentRevision !== revision.current || intent.current !== currentIntent) return;
      if (failure instanceof HttpProblem && failure.status === 401) {
        expireUnauthorized(failure);
        setSnapshot(unavailable);
      } else if (failure instanceof HttpProblem && failure.status === 404) {
        setSnapshot(unknownSnapshot("replay"));
      } else {
        // A forbidden or temporarily unavailable observation cannot prove that
        // the original POST failed. Keep the frozen intent and permit GET only.
        setSnapshot(unknownSnapshot("inspect"));
      }
    }
  }, [accountId, active, credential, expireUnauthorized, repository, scopeKey, serviceKey, setSnapshot]);

  const load = useCallback(async () => {
    if (!active || !accountId || !credential || !serviceKey ||
        !repository.listServiceDefinitions || !repository.getServiceActivation) {
      intent.current = null;
      setSnapshot(unavailable);
      return;
    }

    const currentIntent = intent.current;
    if (currentIntent && currentIntent.repository === repository && currentIntent.scopeKey === scopeKey) {
      await reconcileIntent(currentIntent);
      return;
    }
    if (currentIntent) intent.current = null;

    const currentRevision = ++revision.current;
    setSnapshot({ ...unavailable, state: { status: "checking" } });
    try {
      const directory = await repository.listServiceDefinitions(credential);
      if (currentRevision !== revision.current) return;
      const definition = directory.services.find((candidate) => candidate.id === serviceKey) ?? null;
      if (!definition) {
        intent.current = null;
        setSnapshot(unavailable);
        return;
      }
      const access: ServiceActivationAccess = {
        canEnable: directory.activationCapability.available,
        mayLoadWorkspace: false
      };
      if (definition.state !== "AVAILABLE") {
        setSnapshot({ access, definition, state: { status: "unavailable" } });
        return;
      }
      try {
        const activation = await repository.getServiceActivation(credential, serviceKey);
        if (currentRevision !== revision.current) return;
        if (!activationMatchesDefinition(activation, definition)) {
          setSnapshot({ access, definition, state: { status: "unavailable" } });
          return;
        }
        setSnapshot({
          access: { ...access, mayLoadWorkspace: true },
          definition,
          state: { status: "enabled", scope: { accountId, serviceKey }, activation }
        });
      } catch (failure) {
        if (currentRevision !== revision.current) return;
        if (failure instanceof HttpProblem && failure.status === 401) {
          expireUnauthorized(failure);
          setSnapshot(unavailable);
          return;
        }
        if (failure instanceof HttpProblem && failure.status === 404) {
          setSnapshot({ access, definition, state: { status: "not-enabled" } });
          return;
        }
        if (failure instanceof HttpProblem && failure.status === 403) {
          setSnapshot({
            access: { ...access, mayLoadWorkspace: true },
            definition,
            state: { status: "unobservable", scope: { accountId, serviceKey } }
          });
          return;
        }
        setSnapshot({ access, definition, state: { status: "unavailable" } });
      }
    } catch (failure) {
      if (currentRevision === revision.current) {
        expireUnauthorized(failure);
        setSnapshot(unavailable);
      }
    }
  }, [accountId, active, credential, expireUnauthorized, reconcileIntent, repository, scopeKey, serviceKey, setSnapshot]);

  useEffect(() => {
    let mounted = true;
    queueMicrotask(() => { if (mounted) void load(); });
    return () => { mounted = false; revision.current += 1; };
  }, [load]);

  const enable = useCallback(async () => {
    const definition = snapshot.definition;
    if (!active || !accountId || !credential || !serviceKey || !definition ||
        definition.state !== "AVAILABLE" || !snapshot.access.canEnable || !repository.activateService ||
        (snapshot.state.status !== "not-enabled" && snapshot.state.status !== "failed")) return;
    const currentRevision = ++revision.current;
    const nextDefinitionKey = definitionKey(definition);
    if (!intent.current || intent.current.scopeKey !== scopeKey || intent.current.definitionKey !== nextDefinitionKey) {
      intent.current = {
        access: snapshot.access,
        definition,
        definitionKey: nextDefinitionKey,
        repository,
        requestId: requestToken("ui-service-activation-"),
        scopeKey
      };
    }
    const currentIntent = intent.current;
    setSnapshot({ ...snapshot, state: { status: "enabling" } });
    try {
      const activation = await repository.activateService(credential, {
        id: currentIntent.definition.id,
        revision: currentIntent.definition.revision,
        contentDigest: currentIntent.definition.contentDigest
      }, currentIntent.requestId);
      if (currentRevision !== revision.current) return;
      if (!activationMatchesDefinition(activation, currentIntent.definition)) {
        await reconcileIntent(currentIntent);
        return;
      }
      intent.current = null;
      setSnapshot({
        access: { ...snapshot.access, mayLoadWorkspace: true },
        definition,
        state: { status: "enabled", scope: { accountId, serviceKey }, activation }
      });
    } catch (failure) {
      if (currentRevision !== revision.current) return;
      if (failure instanceof HttpProblem && failure.status === 401) {
        expireUnauthorized(failure);
        setSnapshot(unavailable);
        return;
      }
      if (failure instanceof HttpProblem && failure.status >= 400 && failure.status < 500) {
        intent.current = null;
        await load();
        return;
      }
      if (!repository.getServiceActivation) {
        setSnapshot({ ...snapshot, state: { status: "outcome-unknown", checking: false, recovery: "inspect" } });
        return;
      }
      await reconcileIntent(currentIntent);
    }
  }, [accountId, active, credential, expireUnauthorized, load, reconcileIntent, repository, scopeKey, serviceKey, setSnapshot, snapshot]);

  const checkOutcome = useCallback(async () => {
    const currentIntent = intent.current;
    if (snapshot.state.status !== "outcome-unknown" || snapshot.state.checking || !currentIntent) return;
    await reconcileIntent(currentIntent);
  }, [reconcileIntent, snapshot.state]);

  const replay = useCallback(async () => {
    const currentIntent = intent.current;
    if (!active || !accountId || !credential || !serviceKey || !repository.activateService || !currentIntent ||
        snapshot.state.status !== "outcome-unknown" || snapshot.state.checking || snapshot.state.recovery !== "replay" ||
        currentIntent.repository !== repository || currentIntent.scopeKey !== scopeKey) return;
    const currentRevision = ++revision.current;
    setSnapshot({
      access: currentIntent.access,
      definition: currentIntent.definition,
      state: { status: "enabling" }
    });
    try {
      const activation = await repository.activateService(credential, {
        id: currentIntent.definition.id,
        revision: currentIntent.definition.revision,
        contentDigest: currentIntent.definition.contentDigest
      }, currentIntent.requestId);
      if (currentRevision !== revision.current || intent.current !== currentIntent) return;
      if (!activationMatchesDefinition(activation, currentIntent.definition)) {
        await reconcileIntent(currentIntent);
        return;
      }
      intent.current = null;
      setSnapshot({
        access: { ...currentIntent.access, mayLoadWorkspace: true },
        definition: currentIntent.definition,
        state: { status: "enabled", scope: { accountId, serviceKey }, activation }
      });
    } catch (failure) {
      if (currentRevision !== revision.current || intent.current !== currentIntent) return;
      if (failure instanceof HttpProblem && failure.status === 401) {
        expireUnauthorized(failure);
        setSnapshot(unavailable);
        return;
      }
      await reconcileIntent(currentIntent);
    }
  }, [accountId, active, credential, expireUnauthorized, reconcileIntent, repository, scopeKey, serviceKey, setSnapshot, snapshot.state]);

  return { ...snapshot, checkOutcome, enable, replay, preview: false as const };
}
