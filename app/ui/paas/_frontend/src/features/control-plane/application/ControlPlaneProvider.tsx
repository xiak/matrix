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
import { buildAccessConsoleScene, buildConsoleScene, buildExperienceConsoleScene } from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";

type ControlPlaneError = "expired" | "forbidden" | "unavailable";

type MutationKind = "quota" | "installation" | null;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  projectScene(selection: ControlPlaneRouteSelection): ConsoleScene | null;
  prepare(): Promise<void>;
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
  const [snapshotOwner, setSnapshotOwner] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ControlPlaneError | null>(null);
  const [mutation, setMutation] = useState<MutationKind>(null);
  const snapshotRef = useRef<ControlPlaneSnapshot | null>(null);
  const snapshotOwnerRef = useRef<string | null>(null);
  const inFlight = useRef<Promise<ControlPlaneSnapshot> | null>(null);
  const inFlightOwner = useRef<string | null>(null);
  const loadRevision = useRef(0);

  useEffect(() => { snapshotRef.current = snapshot; }, [snapshot]);

  const loadSnapshot = useCallback(async (force: boolean) => {
    // Keep both route effects and pointer handlers responsive; state changes
    // belong to the asynchronous provider read, never the caller's render.
    await Promise.resolve();
    if (!credential) {
      loadRevision.current += 1;
      snapshotRef.current = null;
      snapshotOwnerRef.current = null;
      inFlight.current = null;
      inFlightOwner.current = null;
      setSnapshot(null);
      setSnapshotOwner(null);
      setLoading(false);
      return;
    }
    if (!force && snapshotOwnerRef.current === credential && snapshotRef.current) return;
    if (!force && inFlightOwner.current === credential && inFlight.current) {
      await inFlight.current.catch(() => undefined);
      return;
    }
    const revision = ++loadRevision.current;
    setLoading(true);
    setError(null);
    const request = repository.load(credential);
    inFlight.current = request;
    inFlightOwner.current = credential;
    try {
      const loaded = await request;
      if (revision !== loadRevision.current) return;
      snapshotRef.current = loaded;
      snapshotOwnerRef.current = credential;
      setSnapshot(loaded);
      setSnapshotOwner(credential);
      setError(null);
    } catch (loadError) {
      if (revision !== loadRevision.current) return;
      snapshotRef.current = null;
      snapshotOwnerRef.current = null;
      setSnapshot(null);
      setSnapshotOwner(null);
      setError(loadMessage(loadError));
    } finally {
      if (revision === loadRevision.current) {
        inFlight.current = null;
        inFlightOwner.current = null;
        setLoading(false);
      }
    }
  }, [credential, repository]);

  const prepare = useCallback(() => loadSnapshot(false), [loadSnapshot]);

  const reload = useCallback(async () => {
    await loadSnapshot(true);
  }, [loadSnapshot]);

  useEffect(() => {
    if (!credential || isAccess) return;
    let active = true;
    queueMicrotask(() => { if (active) void prepare(); });
    return () => { active = false; };
  }, [credential, isAccess, prepare]);

  const ownedSnapshot = snapshotOwner === credential ? snapshot : null;

  useEffect(() => {
    if (!credential || isAccess) return;
    const pending = ownedSnapshot?.installations.filter(
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
          if (active) {
            snapshotRef.current = refreshed;
            snapshotOwnerRef.current = credential;
            setSnapshot(refreshed);
            setSnapshotOwner(credential);
          }
        } catch (pollError: unknown) {
          if (active) setError(loadMessage(pollError));
        }
      })();
    }, 4_000);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [credential, isAccess, ownedSnapshot, repository]);

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

  // The repository snapshot is product-wide. A route transition may project a
  // destination from that already-authoritative cache without issuing another
  // read. Preview-only products can also project from their own fixed snapshot;
  // managed-service products remain unavailable until prepare() completes.
  const projectScene = useCallback((target: ControlPlaneRouteSelection): ConsoleScene | null => (
    target.section === "access"
      ? buildAccessConsoleScene(experience, target.view)
      : ownedSnapshot
        ? buildConsoleScene(target.section, ownedSnapshot, experience, target.view)
        : experience
          ? buildExperienceConsoleScene(target, experience)
          : null
  ), [experience, ownedSnapshot]);
  const scene = useMemo(
    () => projectScene({ section: selection.section, view: selection.view }),
    [projectScene, selection.section, selection.view]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    projectScene,
    prepare,
    loading,
    error: isAccess ? null : error,
    mutation,
    reload,
    activateQuota,
    createInstallation
  }), [activateQuota, createInstallation, error, isAccess, loading, mutation, prepare, projectScene, reload, scene]);

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
