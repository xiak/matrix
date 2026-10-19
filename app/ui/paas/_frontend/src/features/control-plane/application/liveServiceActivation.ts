"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useExpireEffectiveCredential } from "@/features/auth/application/RoleSessionProvider";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { ManagedServiceProductId } from "../domain/managedServiceProduct";
import type {
  ServiceActivationAccess,
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
  definitionKey: string;
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

type ServiceDirectoryRead = () => Promise<ServiceDefinitionDirectory>;
type ServiceDirectoryObservation = {
  source: ServiceDirectoryRead;
  status: "checking" | "ready" | "forbidden" | "expired" | "unavailable";
  directory: ServiceDefinitionDirectory | null;
};

// The launcher's backend read stays local to the opened data region. Its source
// callback is credential-scoped by the provider, so changed identities cannot
// keep another identity's service entries visible while the new read resolves.
export function useLiveServiceDefinitionDirectory(active: boolean, source?: ServiceDirectoryRead) {
  const [observation, setObservation] = useState<ServiceDirectoryObservation | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!active || !source) return;
    let current = true;
    queueMicrotask(async () => {
      if (!current) return;
      setObservation({ source, status: "checking", directory: null });
      try {
        const directory = await source();
        if (current) setObservation({ source, status: "ready", directory });
      } catch (failure) {
        if (current) setObservation({ source, directory: null, status: failure instanceof HttpProblem && failure.status === 403
          ? "forbidden" : failure instanceof HttpProblem && failure.status === 401 ? "expired" : "unavailable" });
      }
    });
    return () => { current = false; };
  }, [active, source, attempt]);

  const owned = active && source && observation?.source === source ? observation : null;
  return {
    directory: owned?.directory ?? null,
    status: owned?.status ?? (active && source ? "checking" : "unavailable"),
    retry: () => setAttempt((value) => value + 1)
  };
}

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

  const load = useCallback(async () => {
    const currentRevision = ++revision.current;
    if (!active || !accountId || !credential || !serviceKey ||
        !repository.listServiceDefinitions || !repository.getServiceActivation) {
      intent.current = null;
      setSnapshot(unavailable);
      return;
    }

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
      const nextDefinitionKey = definitionKey(definition);
      if (intent.current && (intent.current.scopeKey !== scopeKey || intent.current.definitionKey !== nextDefinitionKey)) {
        intent.current = null;
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
  }, [accountId, active, credential, expireUnauthorized, repository, scopeKey, serviceKey, setSnapshot]);

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
        definitionKey: nextDefinitionKey,
        requestId: requestToken("ui-service-activation-"),
        scopeKey
      };
    }
    const currentIntent = intent.current;
    setSnapshot({ ...snapshot, state: { status: "enabling" } });
    try {
      const activation = await repository.activateService(credential, {
        id: definition.id,
        revision: definition.revision,
        contentDigest: definition.contentDigest
      }, currentIntent.requestId);
      if (currentRevision !== revision.current) return;
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
        await load();
        return;
      }
      if (!repository.getServiceActivation) {
        setSnapshot({ ...snapshot, state: { status: "unavailable" } });
        return;
      }
      try {
        const activation = await repository.getServiceActivation(credential, serviceKey);
        if (currentRevision !== revision.current) return;
        intent.current = null;
        setSnapshot({
          access: { ...snapshot.access, mayLoadWorkspace: true },
          definition,
          state: { status: "enabled", scope: { accountId, serviceKey }, activation }
        });
      } catch (readFailure) {
        if (currentRevision !== revision.current) return;
        if (readFailure instanceof HttpProblem && readFailure.status === 401) {
          expireUnauthorized(readFailure);
          setSnapshot(unavailable);
        } else if (readFailure instanceof HttpProblem && readFailure.status === 404) {
          setSnapshot({ ...snapshot, state: { status: "failed" } });
        } else if (readFailure instanceof HttpProblem && readFailure.status === 403) {
          setSnapshot({
            access: { ...snapshot.access, mayLoadWorkspace: true },
            definition,
            state: { status: "unobservable", scope: { accountId, serviceKey } }
          });
        } else {
          setSnapshot({ ...snapshot, state: { status: "unavailable" } });
        }
      }
    }
  }, [accountId, active, credential, expireUnauthorized, load, repository, scopeKey, serviceKey, setSnapshot, snapshot]);

  return { ...snapshot, enable, preview: false as const };
}
