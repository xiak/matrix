"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";
import { useSessionCredential } from "@/features/auth/application/SessionProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import type { ExperienceSnapshot } from "../domain/experience";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand
} from "../domain/resources";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { buildAccessConsoleScene, buildConsoleScene } from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";

type ControlPlaneError = "expired" | "forbidden" | "unavailable";

type MutationKind = "quota" | "installation" | null;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  loading: boolean;
  error: ControlPlaneError | null;
  mutation: MutationKind;
  reload(): Promise<void>;
  activateQuota(command: ActivateQuotaCommand): Promise<boolean>;
  createInstallation(command: CreateInstallationCommand): Promise<boolean>;
};

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null);

function loadMessage(error: unknown): ControlPlaneError {
  if (error instanceof HttpProblem && error.status === 401) {
    return "expired";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "forbidden";
  }
  return "unavailable";
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
  const credential = useSessionCredential();
  const isAccess = selection.section === "access";
  const [snapshot, setSnapshot] = useState<ControlPlaneSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ControlPlaneError | null>(null);
  const [mutation, setMutation] = useState<MutationKind>(null);

  const reload = useCallback(async () => {
    if (!credential) {
      setSnapshot(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setSnapshot(await repository.load(credential));
    } catch (loadError) {
      setSnapshot(null);
      setError(loadMessage(loadError));
    } finally {
      setLoading(false);
    }
  }, [credential, repository]);

  useEffect(() => {
    if (!credential || isAccess) return;
    let active = true;
    repository.load(credential).then(
      (loaded) => {
        if (!active) return;
        setSnapshot(loaded);
        setError(null);
      },
      (loadError: unknown) => {
        if (!active) return;
        setSnapshot(null);
        setError(loadMessage(loadError));
      }
    ).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [credential, isAccess, repository]);

  useEffect(() => {
    if (!credential || isAccess) return;
    const pending = snapshot?.installations.filter(
      (item) => item.phase === "PENDING" || item.phase === "PROVISIONING"
    ) ?? [];
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
          setSnapshot((current) => current ? {
            ...current,
            installations: current.installations.map((item) => byId.get(item.id) ?? item)
          } : current);
          if (!updates.some((item) => item.phase === "READY" || item.phase === "FAILED")) {
            return;
          }
          const refreshed = await repository.load(credential);
          if (active) setSnapshot(refreshed);
        } catch (pollError: unknown) {
          if (active) setError(loadMessage(pollError));
        }
      })();
    }, 4_000);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [credential, isAccess, repository, snapshot]);

  const activateQuota = useCallback(async (command: ActivateQuotaCommand) => {
    if (!credential) return false;
    setMutation("quota");
    setError(null);
    try {
      const entitlement = await repository.activateQuota(credential, command);
      setSnapshot((current) => current ? {
        ...current,
        entitlements: [...current.entitlements.filter((item) => item.id !== entitlement.id), entitlement]
      } : current);
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
      setSnapshot((current) => current ? {
        ...current,
        installations: [...current.installations.filter((item) => item.id !== installation.id), installation]
      } : current);
      return true;
    } catch (mutationError) {
      setError(loadMessage(mutationError));
      return false;
    } finally {
      setMutation(null);
    }
  }, [credential, repository]);

  const scene = useMemo(
    () => isAccess ? buildAccessConsoleScene(experience, selection.view) : snapshot ? buildConsoleScene(selection.section, snapshot, experience, selection.view) : null,
    [experience, isAccess, selection.section, selection.view, snapshot]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    loading,
    error: isAccess ? null : error,
    mutation,
    reload,
    activateQuota,
    createInstallation
  }), [activateQuota, createInstallation, error, isAccess, loading, mutation, reload, scene]);

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
