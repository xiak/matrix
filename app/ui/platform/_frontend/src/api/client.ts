import { matchesContract, type ContractValidators } from "./validation";
import { validators as iamValidators, type LoginResponse, type Session } from "./iamContract";

export type ErrorCode = "INPUT" | "SESSION" | "DENIED" | "NOT_FOUND" | "CONFLICT" | "VERSION" | "LIMIT" | "UNAVAILABLE" | "CONTRACT" | "NETWORK" | "CANCELLED" | "SCOPE";
export class ApiError extends Error {
  constructor(readonly code: ErrorCode, readonly status = 0) { super(code); }
}
export type AccountSession = Session & { loginName: string };
export type RequestOptions = { method?: "GET" | "POST" | "PUT"; body?: unknown; version?: number; idempotencyKey?: string; signal?: AbortSignal; sessionId?: string };
export function requestIdentity(prefix: string) { return prefix + crypto.randomUUID(); }
export function resourcePath(id: string) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) throw new ApiError("INPUT");
  return encodeURIComponent(id);
}
function statusCode(status: number): ErrorCode {
  return ({ 400: "INPUT", 401: "SESSION", 403: "DENIED", 404: "NOT_FOUND", 409: "CONFLICT", 412: "VERSION", 413: "LIMIT", 415: "INPUT", 428: "VERSION", 429: "LIMIT", 503: "UNAVAILABLE" } as Record<number, ErrorCode>)[status] ?? "UNAVAILABLE";
}
async function boundedJSON(response: Response) {
  const type = response.headers.get("Content-Type")?.split(";")[0];
  if (type !== "application/json" || !response.body) throw new ApiError("CONTRACT");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  let bytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > 2 * 1024 * 1024) { await reader.cancel(); throw new ApiError("LIMIT"); }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError("CONTRACT");
  } finally { reader.releaseLock(); }
}

/** One tab's private IAM session. No credential, role or product state is persisted. */
export function createApiSession(fetcher: typeof fetch = (...args) => fetch(...args)) {
  let credential = "";
  let account: AccountSession | null = null;
  let epoch = 0;
  let notice: "sessionEnded" | "logoutUncertain" | "passwordChanged" | null = null;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  const pending = new Set<AbortController>();
  const listeners = new Set<() => void>();
  function clear(message: typeof notice = null) {
    notice = message;
    credential = "";
    account = null;
    epoch++;
    clearTimeout(expiry);
    pending.forEach(controller => controller.abort());
    pending.clear();
    listeners.forEach(listener => listener());
  }
  async function transport(path: string, options: RequestOptions = {}, authenticated = true, capturedCredential = credential) {
    if (!/^\/api\/(iam|platform|paas|devops)\/v1\/[A-Za-z0-9._/%:?=&-]+$/.test(path) && path !== "/ui/v1/configuration-digest") throw new ApiError("INPUT");
    if (authenticated && !capturedCredential) throw new ApiError("SESSION");
    if (options.version !== undefined && (!Number.isSafeInteger(options.version) || options.version < 1)) throw new ApiError("VERSION");
    const currentEpoch = epoch;
    const controller = new AbortController();
    pending.add(controller);
    const abort = () => controller.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) controller.abort();
    const timeout = setTimeout(abort, 15000);
    const headers = new Headers({ Accept: "application/json" });
    if (authenticated) headers.set("Authorization", `Bearer ${capturedCredential}`);
    if (options.body !== undefined) headers.set("Content-Type", "application/json");
    if (options.idempotencyKey) headers.set("Idempotency-Key", options.idempotencyKey);
    if (options.version !== undefined) {
      headers.set("If-Match", `"${options.version}"`);
    }
    try {
      const response = await fetcher(path, { method: options.method ?? "GET", headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), signal: controller.signal, cache: "no-store", credentials: "omit", redirect: "error" });
      if (currentEpoch !== epoch || options.signal?.aborted) throw new ApiError("CANCELLED");
      if (!response.ok) {
        await response.body?.cancel();
        if (response.status === 401 && authenticated) clear("sessionEnded");
        throw new ApiError(statusCode(response.status), response.status);
      }
      const body = await boundedJSON(response);
      if (currentEpoch !== epoch || options.signal?.aborted) throw new ApiError("CANCELLED");
      return body;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(controller.signal.aborted ? "CANCELLED" : "NETWORK");
    } finally {
      clearTimeout(timeout);
      pending.delete(controller);
      options.signal?.removeEventListener("abort", abort);
    }
  }
  async function request<T>(validators: ContractValidators, kind: string, path: string, options?: RequestOptions): Promise<T> {
    if (options?.sessionId && options.sessionId !== account?.id) throw new ApiError("CANCELLED");
    const body = await transport(path, options);
    if (!matchesContract(validators, kind, body)) throw new ApiError("CONTRACT");
    function verifyScope(value: unknown) {
      if (!value || typeof value !== "object") return;
      const record = value as { scope?: { kind?: string; tenantId?: string } };
      if (record.scope) {
        if (record.scope.kind === "PLATFORM") {
          if (record.scope.tenantId !== undefined) throw new ApiError("SCOPE");
        } else if (!record.scope.tenantId || record.scope.tenantId !== account?.organizationId) throw new ApiError("SCOPE");
      }
      Object.values(value).forEach(verifyScope);
    }
    verifyScope(body);
    return body as T;
  }
  return {
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    snapshot: () => account,
    notice: () => notice,
    request,
    forSession(sessionId: string) {
      return {
        request<T>(validators: ContractValidators, kind: string, path: string, options?: RequestOptions) {
          if (!sessionId || account?.id !== sessionId) return Promise.reject<T>(new ApiError("CANCELLED"));
          return request<T>(validators, kind, path, { ...options, sessionId });
        },
      };
    },
    async login(loginName: string, password: string) {
      clear();
      const body = await transport("/api/iam/v1/auth/login", { method: "POST", body: { loginName, password, requestId: requestIdentity("ui-login-") } }, false);
      if (!matchesContract(iamValidators, "LoginResponse", body)) throw new ApiError("CONTRACT");
      const result = body as LoginResponse;
      const remaining = Date.parse(result.session.expiresAt) - Date.now();
      if (result.session.status !== "ACTIVE" || remaining <= 0 || remaining > 2147483647) throw new ApiError("SESSION");
      credential = result.credential;
      account = { ...result.session, loginName };
      expiry = setTimeout(() => clear("sessionEnded"), remaining);
      listeners.forEach(listener => listener());
    },
    async logout() {
      const current = credential;
      clear();
      if (!current) return;
      const attempt = epoch;
      try {
        const body = await transport("/api/iam/v1/auth/logout", { method: "POST", body: { requestId: requestIdentity("ui-logout-") } }, true, current);
        if (!matchesContract(iamValidators, "LogoutResponse", body)) throw new ApiError("CONTRACT");
      } catch {
        if (epoch === attempt) { notice = "logoutUncertain"; listeners.forEach(listener => listener()); }
      }
    },
    async changePassword(currentPassword: string, newPassword: string) {
      await request(iamValidators, "ChangePasswordResponse", "/api/iam/v1/auth/password", { method: "POST", body: { currentPassword, newPassword, requestId: requestIdentity("ui-password-") } });
      clear("passwordChanged");
    },
    async configurationDigest(values: Record<string, string>) {
      const body = await transport("/ui/v1/configuration-digest", { method: "POST", body: { values } }, false);
      const digest = body as { apiVersion?: unknown; kind?: unknown; contentDigest?: unknown };
      if (digest.apiVersion !== "ui.matrix.xiak.com/v1" || digest.kind !== "ConfigurationDigest" || typeof digest.contentDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest.contentDigest)) throw new ApiError("CONTRACT");
      return digest.contentDigest;
    },
    dispose: () => clear(),
  };
}
export type ApiSession = ReturnType<typeof createApiSession>;
