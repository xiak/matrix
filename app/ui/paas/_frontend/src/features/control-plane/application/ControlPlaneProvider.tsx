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
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand
} from "../domain/resources";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { buildConsoleScene } from "../scenes/buildConsoleScene";
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

function loadMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "IAM 会话已失效，请注销后重新登录。";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "当前角色无权查看托管服务控制面。";
  }
  return "托管服务控制面暂时不可用，未展示任何模拟资源。";
}

export function ControlPlaneProvider({
  children,
  repository = httpControlPlaneRepository,
  selection
}: {
  children: ReactNode;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const credential = useSessionCredential();
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
      setError(loadMessage(loadError));
    } finally {
      setLoading(false);
    }
  }, [credential, repository]);

  useEffect(() => {
    if (!credential) return;
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
  }, [credential, repository]);

  useEffect(() => {
    if (!credential || !snapshot?.installations.some(
      (item) => item.phase === "PENDING" || item.phase === "PROVISIONING"
    )) return;
    const timer = window.setTimeout(() => void reload(), 4_000);
    return () => window.clearTimeout(timer);
  }, [credential, reload, snapshot]);

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
    () => snapshot ? buildConsoleScene(selection.section, snapshot) : null,
    [selection.section, snapshot]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    loading,
    error,
    mutation,
    reload,
    activateQuota,
    createInstallation
  }), [activateQuota, createInstallation, error, loading, mutation, reload, scene]);

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
