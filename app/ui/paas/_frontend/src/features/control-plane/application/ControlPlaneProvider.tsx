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
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand
} from "../domain/resources";
import type { HostInventory } from "../domain/hosts";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type { HostInventoryRepository } from "../repositories/hostInventoryRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { httpHostInventoryRepository } from "../repositories/httpHostInventoryRepository";
import { buildAccessConsoleScene, buildConsoleScene, buildHostConsoleScene } from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";

type MutationKind = "quota" | "installation" | null;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  loading: boolean;
  error: string | null;
  mutation: MutationKind;
  reload(): Promise<void>;
  activateQuota(command: ActivateQuotaCommand): Promise<boolean>;
  createInstallation(command: CreateInstallationCommand): Promise<boolean>;
};

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null);

function failureMessage(error: unknown, operation: "read" | "write" = "read"): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "IAM 会话已失效，请注销后重新登录。";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return operation === "write" ? "当前角色无权执行此操作。" : "当前角色无权查看托管服务控制面。";
  }
  if (operation === "write") return "操作未完成，请检查输入或稍后重试。";
  return "托管服务控制面暂时不可用，未展示任何模拟资源。";
}

function hostFailureMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "IAM 会话已失效，请注销后重新登录。";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "当前角色没有平台主机查看权限。";
  }
  return "主机观测暂时不可用；已有采样（如有）保持原时间，不会被续期。";
}

function ManagedControlPlaneProvider({
  children,
  repository = httpControlPlaneRepository,
  selection
}: {
  children: ReactNode;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const credential = useSessionCredential();
  const isAccess = selection.section === "access";
  const [snapshot, setSnapshot] = useState<ControlPlaneSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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
      setError(failureMessage(loadError));
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
        setError(failureMessage(loadError));
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
          if (active) {
            setSnapshot(null);
            setError(failureMessage(pollError));
          }
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
      if (mutationError instanceof HttpProblem && mutationError.status === 401) setSnapshot(null);
      setError(failureMessage(mutationError, "write"));
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
      if (mutationError instanceof HttpProblem && mutationError.status === 401) setSnapshot(null);
      setError(failureMessage(mutationError, "write"));
      return false;
    } finally {
      setMutation(null);
    }
  }, [credential, repository]);

  const scene = useMemo(
    () => isAccess ? buildAccessConsoleScene() : snapshot ? buildConsoleScene(selection.section, snapshot) : null,
    [isAccess, selection.section, snapshot]
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

type HostRequest = {
  controller: AbortController;
  promise: Promise<boolean>;
};

function HostInventoryProvider({
  children,
  repository
}: {
  children: ReactNode;
  repository: HostInventoryRepository;
}) {
  const credential = useSessionCredential();
  const [inventory, setInventory] = useState<HostInventory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const active = useRef(false);
  const epoch = useRef(0);
  const request = useRef<HostRequest | null>(null);
  const timer = useRef<number | null>(null);
  const cycle = useRef<(() => void) | null>(null);

  const load = useCallback((): Promise<boolean> => {
    if (!credential) {
      setInventory(null);
      setLoading(false);
      return Promise.resolve(false);
    }
    if (request.current) return request.current.promise;

    const requestEpoch = epoch.current;
    const controller = new AbortController();
    const slot: HostRequest = { controller, promise: Promise.resolve(false) };
    request.current = slot;
    setLoading(true);
    slot.promise = Promise.resolve().then(async () => {
      try {
        const loaded = await repository.load(credential, controller.signal);
        if (controller.signal.aborted || requestEpoch !== epoch.current) return false;
        setInventory(loaded);
        setError(null);
        return true;
      } catch (loadError) {
        if (controller.signal.aborted || requestEpoch !== epoch.current) return false;
        const authorizationFailure = loadError instanceof HttpProblem &&
          (loadError.status === 401 || loadError.status === 403);
        if (authorizationFailure) setInventory(null);
        setError(hostFailureMessage(loadError));
        return !authorizationFailure;
      } finally {
        if (request.current === slot) request.current = null;
        if (!controller.signal.aborted && requestEpoch === epoch.current) setLoading(false);
      }
    });
    return slot.promise;
  }, [credential, repository]);

  const scheduleNext = useCallback(() => {
    if (!active.current || !cycle.current) return;
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => cycle.current?.(), 5_000);
  }, []);

  useEffect(() => {
    active.current = true;
    epoch.current++;
    const effectEpoch = epoch.current;
    cycle.current = () => {
      void load().then((continuePolling) => {
        if (active.current && effectEpoch === epoch.current && continuePolling) scheduleNext();
      });
    };
    cycle.current();
    return () => {
      active.current = false;
      epoch.current = effectEpoch + 1;
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = null;
      cycle.current = null;
      request.current?.controller.abort();
      request.current = null;
    };
  }, [load, scheduleNext]);

  const reload = useCallback(async () => {
    const continuePolling = await load();
    if (continuePolling) scheduleNext();
  }, [load, scheduleNext]);

  const scene = useMemo(
    () => inventory ? buildHostConsoleScene(inventory) : null,
    [inventory]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    loading,
    error,
    mutation: null,
    reload,
    activateQuota: async () => false,
    createInstallation: async () => false
  }), [error, loading, reload, scene]);

  return (
    <ControlPlaneContext.Provider value={value}>
      {children}
    </ControlPlaneContext.Provider>
  );
}

export function ControlPlaneProvider({
  children,
  repository = httpControlPlaneRepository,
  hostRepository = httpHostInventoryRepository,
  selection
}: {
  children: ReactNode;
  repository?: ControlPlaneRepository;
  hostRepository?: HostInventoryRepository;
  selection: ControlPlaneRouteSelection;
}) {
  if (selection.section === "hosts") {
    return <HostInventoryProvider repository={hostRepository}>{children}</HostInventoryProvider>;
  }
  return (
    <ManagedControlPlaneProvider repository={repository} selection={selection}>
      {children}
    </ManagedControlPlaneProvider>
  );
}

export function useControlPlane(): ControlPlaneContextValue {
  const value = useContext(ControlPlaneContext);
  if (!value) {
    throw new Error("useControlPlane must be used inside ControlPlaneProvider");
  }
  return value;
}
