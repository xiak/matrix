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
import { useSession, useSessionCredential } from "@/features/auth/application/SessionProvider";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand
} from "../domain/resources";
import type { HostInventory, HostLifecycleCommand } from "../domain/hosts";
import type { DeploymentInventory, DeploymentRuntimeSnapshot } from "../domain/deployments";
import type { TerminalServerError, TerminalSession, TerminalSize } from "../domain/terminalSessions";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type { HostInventoryRepository } from "../repositories/hostInventoryRepository";
import type { DeploymentInventoryRepository } from "../repositories/deploymentInventoryRepository";
import type { TerminalConnection, TerminalSessionRepository } from "../repositories/terminalSessionRepository";
import { httpControlPlaneRepository } from "../repositories/httpControlPlaneRepository";
import { httpHostInventoryRepository } from "../repositories/httpHostInventoryRepository";
import { httpDeploymentInventoryRepository } from "../repositories/httpDeploymentInventoryRepository";
import { httpTerminalSessionRepository } from "../repositories/httpTerminalSessionRepository";
import {
  buildAccessConsoleScene,
  buildConsoleScene,
  buildDeploymentConsoleScene,
  buildHostConsoleScene
} from "../scenes/buildConsoleScene";
import type { ConsoleScene } from "../scenes/consoleScene";

type MutationKind = "quota" | "installation" | "host" | null;

export type TerminalConsolePhase = "IDLE" | "CREATING" | "CONNECTING" | "ACTIVE" | "ENDED" | "ERROR";

export type TerminalConsoleState = {
  phase: TerminalConsolePhase;
  deploymentId: string | null;
  instanceId: string | null;
  session: TerminalSession | null;
  message: string | null;
};

export type OpenTerminal = (
  deploymentId: string,
  instanceId: string,
  size: TerminalSize
) => Promise<boolean>;

export type ConnectTerminal = () => TerminalConnection | null;

export type CloseTerminal = () => Promise<void>;
export type TransitionHost = (command: HostLifecycleCommand) => Promise<boolean>;

type ControlPlaneContextValue = {
  scene: ConsoleScene | null;
  loading: boolean;
  error: string | null;
  mutation: MutationKind;
  reload(): Promise<void>;
  activateQuota(command: ActivateQuotaCommand): Promise<boolean>;
  createInstallation(command: CreateInstallationCommand): Promise<boolean>;
  transitionHost: TransitionHost;
  selectDeployment(deploymentId: string): void;
  terminal: TerminalConsoleState;
  openTerminal: OpenTerminal;
  connectTerminal: ConnectTerminal;
  closeTerminal: CloseTerminal;
};

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null);

export const idleTerminalConsoleState: TerminalConsoleState = {
  phase: "IDLE",
  deploymentId: null,
  instanceId: null,
  session: null,
  message: null
};

const unsupportedOpenTerminal: OpenTerminal = async () => false;
const unsupportedConnectTerminal: ConnectTerminal = () => null;
const unsupportedCloseTerminal: CloseTerminal = async () => {};
const unsupportedTransitionHost: TransitionHost = async () => false;

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

function hostMutationFailureMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "IAM 会话已失效，请注销后重新登录。";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "当前角色无权变更平台主机生命周期。";
  }
  if (error instanceof HttpProblem && error.status === 412 ||
      error instanceof Error && error.message === "STALE_HOST_LIFECYCLE_COMMAND") {
    return "主机资源版本已变化，已保留服务端状态；请刷新后重试。";
  }
  if (error instanceof HttpProblem && error.status === 409) {
    return "主机状态已变化，或仍有工作负载、容量、命令或终端占用；平台未执行部分移除。";
  }
  if (error instanceof HttpProblem && error.status === 404) {
    return "主机登记已不存在，请刷新资源清单。";
  }
  return "主机生命周期操作未完成，平台未重启主机、Docker 或工作负载。";
}

function deploymentFailureMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) {
    return "IAM 会话已失效，请注销后重新登录。";
  }
  if (error instanceof HttpProblem && error.status === 403) {
    return "当前角色没有租户部署查看权限。";
  }
  return "部署运行态暂时不可用；已有来源采样（如有）保持原时间，不会被续期。";
}

function terminalFailureMessage(error: unknown): string {
  if (error instanceof HttpProblem && error.status === 401) return "IAM 会话已失效，终端没有启动。";
  if (error instanceof HttpProblem && error.status === 403) return "当前角色无权打开或关闭该部署终端。";
  if (error instanceof HttpProblem && error.status === 404) return "目标容器已不属于当前部署运行代次。";
  if (error instanceof HttpProblem && (error.status === 409 || error.status === 410)) {
    return "终端请求已过期或与当前部署运行态冲突，请刷新后重试。";
  }
  return "终端请求未能安全完成；不会自动连接到其他容器。";
}

function terminalServerMessage(code: TerminalServerError): string {
  if (code === "UNSUPPORTED") return "该执行节点不支持受控终端。";
  if (code === "UNAVAILABLE") return "执行节点或目标容器当前不可用。";
  return "终端连接异常结束；不会自动重连。";
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
    createInstallation,
    transitionHost: unsupportedTransitionHost,
    selectDeployment: () => {},
    terminal: idleTerminalConsoleState,
    openTerminal: unsupportedOpenTerminal,
    connectTerminal: unsupportedConnectTerminal,
    closeTerminal: unsupportedCloseTerminal
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
  const [readError, setReadError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [hostMutation, setHostMutation] = useState<string | null>(null);
  const active = useRef(false);
  const mutationActive = useRef(false);
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
        setReadError(null);
        return true;
      } catch (loadError) {
        if (controller.signal.aborted || requestEpoch !== epoch.current) return false;
        const authorizationFailure = loadError instanceof HttpProblem &&
          (loadError.status === 401 || loadError.status === 403);
        if (authorizationFailure) setInventory(null);
        setReadError(hostFailureMessage(loadError));
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
    setMutationError(null);
    const continuePolling = await load();
    if (continuePolling) scheduleNext();
  }, [load, scheduleNext]);

  const transitionHost = useCallback<TransitionHost>(async (command) => {
    if (!credential || mutationActive.current ||
        !inventory?.items.some((item) => item.id === command.targetId && item.resourceVersion === command.resourceVersion)) {
      return false;
    }
    mutationActive.current = true;
    setHostMutation(command.targetId);
    setMutationError(null);
    try {
      const changed = await repository.transition(credential, command);
      setInventory((current) => {
        if (!current) return current;
        const items = changed.desiredState === "REMOVED"
          ? current.items.filter((item) => item.id !== changed.id)
          : current.items.map((item) => item.id === changed.id ? changed : item);
        return { items };
      });
      scheduleNext();
      return true;
    } catch (mutationFailure) {
      const authorizationFailure = mutationFailure instanceof HttpProblem &&
        (mutationFailure.status === 401 || mutationFailure.status === 403);
      if (authorizationFailure) setInventory(null);
      setMutationError(hostMutationFailureMessage(mutationFailure));
      void load().then((continuePolling) => {
        if (continuePolling) scheduleNext();
      });
      return false;
    } finally {
      mutationActive.current = false;
      setHostMutation(null);
    }
  }, [credential, inventory, load, repository, scheduleNext]);

  const scene = useMemo(
    () => inventory ? buildHostConsoleScene(inventory) : null,
    [inventory]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    loading,
    error: mutationError ?? readError,
    mutation: hostMutation === null ? null : "host",
    reload,
    activateQuota: async () => false,
    createInstallation: async () => false,
    transitionHost,
    selectDeployment: () => {},
    terminal: idleTerminalConsoleState,
    openTerminal: unsupportedOpenTerminal,
    connectTerminal: unsupportedConnectTerminal,
    closeTerminal: unsupportedCloseTerminal
  }), [hostMutation, loading, mutationError, readError, reload, scene, transitionHost]);

  return (
    <ControlPlaneContext.Provider value={value}>
      {children}
    </ControlPlaneContext.Provider>
  );
}

type DeploymentRequest = {
  controller: AbortController;
  promise: Promise<boolean>;
};

function DeploymentInventoryProvider({
  children,
  repository,
  terminalRepository
}: {
  children: ReactNode;
  repository: DeploymentInventoryRepository;
  terminalRepository: TerminalSessionRepository;
}) {
  const credential = useSessionCredential();
  const session = useSession();
  const tenantId = session.current?.session.organizationId ?? null;
  const [inventory, setInventory] = useState<DeploymentInventory | null>(null);
  const [selectedDeploymentId, setSelectedDeploymentId] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<DeploymentRuntimeSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [terminal, setTerminal] = useState<TerminalConsoleState>(idleTerminalConsoleState);
  const inventoryEpoch = useRef(0);
  const runtimeEpoch = useRef(0);
  const selectedDeploymentIdRef = useRef<string | null>(null);
  const inventoryRequest = useRef<DeploymentRequest | null>(null);
  const runtimeRequest = useRef<DeploymentRequest | null>(null);
  const runtimeTimer = useRef<number | null>(null);
  const runtimeCycle = useRef<(() => void) | null>(null);
  const terminalState = useRef<TerminalConsoleState>(idleTerminalConsoleState);
  const terminalEpoch = useRef(0);
  const terminalConnection = useRef<TerminalConnection | null>(null);
  const terminalConnectionSubscription = useRef<(() => void) | null>(null);

  const commitTerminal = useCallback((next: TerminalConsoleState) => {
    terminalState.current = next;
    setTerminal(next);
  }, []);

  const updateTerminal = useCallback((change: (current: TerminalConsoleState) => TerminalConsoleState) => {
    setTerminal((current) => {
      const next = change(current);
      terminalState.current = next;
      return next;
    });
  }, []);

  const disconnectTerminal = useCallback(() => {
    terminalConnectionSubscription.current?.();
    terminalConnectionSubscription.current = null;
    const connection = terminalConnection.current;
    terminalConnection.current = null;
    if (!connection) return;
    try { connection.closeInput(); } catch {}
    connection.close();
  }, []);

  const closeTerminal = useCallback(async () => {
    const operationEpoch = ++terminalEpoch.current;
    const previous = terminalState.current;
    disconnectTerminal();
    commitTerminal(idleTerminalConsoleState);
    if (!credential || !tenantId || !previous.session) return;
    try {
      await terminalRepository.close(credential, tenantId, previous.session.id);
    } catch (closeError) {
      if (operationEpoch !== terminalEpoch.current) return;
      commitTerminal({
        ...idleTerminalConsoleState,
        phase: "ERROR",
        message: terminalFailureMessage(closeError)
      });
    }
  }, [commitTerminal, credential, disconnectTerminal, tenantId, terminalRepository]);

  const openTerminal = useCallback<OpenTerminal>(async (deploymentId, instanceId, size) => {
    const deployment = inventory?.items.find((item) => item.id === deploymentId);
    const runtimeValue = runtime?.state === "AVAILABLE" ? runtime.value : null;
    const instance = runtimeValue?.instances.find((item) => item.id === instanceId);
    if (!credential || !tenantId || selectedDeploymentId !== deploymentId || !deployment ||
        !runtimeValue || runtimeValue.deploymentId !== deploymentId ||
        runtimeValue.generation !== deployment.generation ||
        runtimeValue.applicationRevisionId !== deployment.applicationRevisionId ||
        instance?.state !== "RUNNING") {
      commitTerminal({
        phase: "ERROR", deploymentId, instanceId, session: null,
        message: "只能进入当前已证明运行代次中的运行中容器。"
      });
      return false;
    }

    const operationEpoch = ++terminalEpoch.current;
    const previous = terminalState.current;
    disconnectTerminal();
    commitTerminal({ phase: "CREATING", deploymentId, instanceId, session: null, message: null });
    if (previous.session) {
      void terminalRepository.close(credential, tenantId, previous.session.id).catch(() => {});
    }
    try {
      const sessionValue = await terminalRepository.create(
        credential,
        tenantId,
        deploymentId,
        instanceId,
        size,
        requestToken("terminal-session-")
      );
      if (operationEpoch !== terminalEpoch.current) {
        void terminalRepository.close(credential, tenantId, sessionValue.id).catch(() => {});
        return false;
      }
      if (sessionValue.tenantId !== tenantId || sessionValue.deploymentId !== deploymentId ||
          sessionValue.instanceId !== instanceId || sessionValue.generation !== runtimeValue.generation ||
          sessionValue.applicationRevisionId !== runtimeValue.applicationRevisionId ||
          sessionValue.state !== "PENDING") {
        void terminalRepository.close(credential, tenantId, sessionValue.id).catch(() => {});
        throw new Error("terminal response does not match the selected runtime proof");
      }
      commitTerminal({
        phase: "CONNECTING", deploymentId, instanceId,
        session: sessionValue, message: "正在建立一次性受控连接…"
      });
      return true;
    } catch (openError) {
      if (operationEpoch !== terminalEpoch.current) return false;
      commitTerminal({
        phase: "ERROR", deploymentId, instanceId, session: null,
        message: terminalFailureMessage(openError)
      });
      return false;
    }
  }, [commitTerminal, credential, disconnectTerminal, inventory, runtime, selectedDeploymentId, tenantId, terminalRepository]);

  const connectTerminal = useCallback<ConnectTerminal>(() => {
    const current = terminalState.current;
    if (!current.session || (current.phase !== "CONNECTING" && current.phase !== "ACTIVE")) return null;
    if (terminalConnection.current) return terminalConnection.current;
    const expiresAt = current.session.expiresAt;
    let connection: TerminalConnection;
    try {
      connection = terminalRepository.connect(current.session.id);
    } catch (connectError) {
      updateTerminal((value) => value.session?.id === current.session?.id ? {
        ...value, phase: "ERROR", message: terminalFailureMessage(connectError)
      } : value);
      return null;
    }
    terminalConnection.current = connection;
    terminalConnectionSubscription.current = connection.subscribe({
      ready: () => updateTerminal((value) => value.session?.id === current.session?.id ? {
        ...value, phase: "ACTIVE", message: `连接有效至 ${new Date(expiresAt).toLocaleTimeString("zh-CN")}`
      } : value),
      exit: (exitCode) => updateTerminal((value) => value.session?.id === current.session?.id ? {
        ...value, phase: "ENDED", message: `容器终端已退出（退出码 ${exitCode}），不会自动重连。`
      } : value),
      error: (code) => updateTerminal((value) => value.session?.id === current.session?.id ? {
        ...value, phase: "ENDED", message: terminalServerMessage(code)
      } : value),
      closed: () => updateTerminal((value) => value.session?.id === current.session?.id &&
        value.phase !== "ENDED" && value.phase !== "ERROR" ? {
          ...value, phase: "ENDED", message: "终端连接已断开；不会自动重连。"
        } : value)
    });
    return connection;
  }, [terminalRepository, updateTerminal]);

  useEffect(() => () => {
    ++terminalEpoch.current;
    const previous = terminalState.current;
    disconnectTerminal();
    if (credential && tenantId && previous.session) {
      void terminalRepository.close(credential, tenantId, previous.session.id).catch(() => {});
    }
  }, [credential, disconnectTerminal, tenantId, terminalRepository]);

  const loadInventory = useCallback((): Promise<boolean> => {
    if (!credential || !tenantId) {
      setInventory(null);
      selectedDeploymentIdRef.current = null;
      setSelectedDeploymentId(null);
      setRuntime(null);
      setInventoryError(null);
      setRuntimeError(null);
      setLoading(false);
      return Promise.resolve(false);
    }
    if (inventoryRequest.current) return inventoryRequest.current.promise;

    const requestEpoch = inventoryEpoch.current;
    const controller = new AbortController();
    const slot: DeploymentRequest = { controller, promise: Promise.resolve(false) };
    inventoryRequest.current = slot;
    setLoading(true);
    slot.promise = Promise.resolve().then(async () => {
      try {
        const loaded = await repository.load(credential, tenantId, controller.signal);
        if (controller.signal.aborted || requestEpoch !== inventoryEpoch.current) return false;
        setInventory(loaded);
        const current = selectedDeploymentIdRef.current;
        const next = current && loaded.items.some((item) => item.id === current)
          ? current
          : loaded.items[0]?.id ?? null;
        if (next !== current) {
          setRuntime(null);
        }
        selectedDeploymentIdRef.current = next;
        setSelectedDeploymentId(next);
        setInventoryError(null);
        return true;
      } catch (loadError) {
        if (controller.signal.aborted || requestEpoch !== inventoryEpoch.current) return false;
        const authorizationFailure = loadError instanceof HttpProblem &&
          (loadError.status === 401 || loadError.status === 403);
        if (authorizationFailure) {
          void closeTerminal();
          setInventory(null);
          selectedDeploymentIdRef.current = null;
          setSelectedDeploymentId(null);
          setRuntime(null);
          setRuntimeError(null);
        }
        setInventoryError(deploymentFailureMessage(loadError));
        return !authorizationFailure;
      } finally {
        if (inventoryRequest.current === slot) inventoryRequest.current = null;
        if (!controller.signal.aborted && requestEpoch === inventoryEpoch.current) setLoading(false);
      }
    });
    return slot.promise;
  }, [closeTerminal, credential, repository, tenantId]);

  useEffect(() => {
    inventoryEpoch.current++;
    const effectEpoch = inventoryEpoch.current;
    void Promise.resolve().then(loadInventory);
    return () => {
      inventoryEpoch.current = effectEpoch + 1;
      inventoryRequest.current?.controller.abort();
      inventoryRequest.current = null;
    };
  }, [loadInventory]);

  useEffect(() => {
    runtimeEpoch.current++;
    const effectEpoch = runtimeEpoch.current;
    if (runtimeTimer.current !== null) window.clearTimeout(runtimeTimer.current);
    runtimeTimer.current = null;
    runtimeRequest.current?.controller.abort();
    runtimeRequest.current = null;
    if (!credential || !tenantId || !selectedDeploymentId) {
      runtimeCycle.current = null;
      return;
    }

    let active = true;
    const schedule = () => {
      if (!active || effectEpoch !== runtimeEpoch.current || !runtimeCycle.current) return;
      runtimeTimer.current = window.setTimeout(() => runtimeCycle.current?.(), 5_000);
    };
    runtimeCycle.current = () => {
      if (!active || effectEpoch !== runtimeEpoch.current || runtimeRequest.current) return;
      const controller = new AbortController();
      const slot: DeploymentRequest = { controller, promise: Promise.resolve(false) };
      runtimeRequest.current = slot;
      slot.promise = Promise.resolve().then(async () => {
        try {
          const loaded = await repository.loadRuntime(
            credential, tenantId, selectedDeploymentId, controller.signal
          );
          if (controller.signal.aborted || effectEpoch !== runtimeEpoch.current) return false;
          setRuntime(loaded);
          setRuntimeError(null);
          return true;
        } catch (loadError) {
          if (controller.signal.aborted || effectEpoch !== runtimeEpoch.current) return false;
          const authorizationFailure = loadError instanceof HttpProblem &&
            (loadError.status === 401 || loadError.status === 403);
          if (authorizationFailure) {
            void closeTerminal();
            setInventory(null);
            selectedDeploymentIdRef.current = null;
            setSelectedDeploymentId(null);
            setRuntime(null);
            setInventoryError(null);
          }
          setRuntimeError(deploymentFailureMessage(loadError));
          return !authorizationFailure;
        } finally {
          if (runtimeRequest.current === slot) runtimeRequest.current = null;
          if (!controller.signal.aborted && effectEpoch === runtimeEpoch.current) setLoading(false);
        }
      }).then((continuePolling) => {
        if (continuePolling) schedule();
        return continuePolling;
      });
    };
    runtimeCycle.current();

    return () => {
      active = false;
      runtimeEpoch.current = effectEpoch + 1;
      if (runtimeTimer.current !== null) window.clearTimeout(runtimeTimer.current);
      runtimeTimer.current = null;
      runtimeCycle.current = null;
      runtimeRequest.current?.controller.abort();
      runtimeRequest.current = null;
    };
  }, [closeTerminal, credential, repository, selectedDeploymentId, tenantId]);

  const reload = useCallback(async () => {
    const continueReading = await loadInventory();
    if (continueReading) runtimeCycle.current?.();
  }, [loadInventory]);

  const selectDeployment = useCallback((deploymentId: string) => {
    if (!inventory?.items.some((item) => item.id === deploymentId) || deploymentId === selectedDeploymentId) return;
    void closeTerminal();
    if (runtimeTimer.current !== null) window.clearTimeout(runtimeTimer.current);
    runtimeTimer.current = null;
    runtimeRequest.current?.controller.abort();
    runtimeRequest.current = null;
    setRuntime(null);
    setRuntimeError(null);
    selectedDeploymentIdRef.current = deploymentId;
    setSelectedDeploymentId(deploymentId);
  }, [closeTerminal, inventory, selectedDeploymentId]);

  const scene = useMemo(
    () => inventory ? buildDeploymentConsoleScene(inventory, selectedDeploymentId, runtime) : null,
    [inventory, runtime, selectedDeploymentId]
  );
  const value = useMemo<ControlPlaneContextValue>(() => ({
    scene,
    loading,
    error: inventoryError ?? runtimeError,
    mutation: null,
    reload,
    activateQuota: async () => false,
    createInstallation: async () => false,
    transitionHost: unsupportedTransitionHost,
    selectDeployment,
    terminal,
    openTerminal,
    connectTerminal,
    closeTerminal
  }), [closeTerminal, connectTerminal, inventoryError, loading, openTerminal, reload, runtimeError, scene, selectDeployment, terminal]);

  return <ControlPlaneContext.Provider value={value}>{children}</ControlPlaneContext.Provider>;
}

export function ControlPlaneProvider({
  children,
  repository = httpControlPlaneRepository,
  hostRepository = httpHostInventoryRepository,
  deploymentRepository = httpDeploymentInventoryRepository,
  terminalRepository = httpTerminalSessionRepository,
  selection
}: {
  children: ReactNode;
  repository?: ControlPlaneRepository;
  hostRepository?: HostInventoryRepository;
  deploymentRepository?: DeploymentInventoryRepository;
  terminalRepository?: TerminalSessionRepository;
  selection: ControlPlaneRouteSelection;
}) {
  if (selection.section === "hosts") {
    return <HostInventoryProvider repository={hostRepository}>{children}</HostInventoryProvider>;
  }
  if (selection.section === "deployments") {
    return (
      <DeploymentInventoryProvider repository={deploymentRepository} terminalRepository={terminalRepository}>
        {children}
      </DeploymentInventoryProvider>
    );
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
