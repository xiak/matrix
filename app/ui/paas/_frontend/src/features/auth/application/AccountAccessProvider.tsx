"use client";

import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useSession, useSessionCredential } from "./SessionProvider";
import type { AccountCommand } from "../domain/accounts";
import type { AccountRepository } from "../repositories/iamRepository";
import { httpAccountRepository } from "../repositories/httpIamRepository";
import { buildAccountAccessScene, type AccountAccessScene } from "../scenes/accountAccessScene";

type AccountAccess = {
  scene: AccountAccessScene | null;
  loading: boolean;
  busy: boolean;
  error: string | null;
  success: string | null;
  reload(): void;
  usersPage(after: string): void;
  accountsPage(after: string): void;
  execute(command: AccountCommand): Promise<boolean>;
};

const AccountAccessContext = createContext<AccountAccess | null>(null);

function accountError(error: unknown): string {
  if (error instanceof HttpProblem) {
    if (error.status === 401) return "会话已失效，请注销后重新登录。";
    if (error.status === 403) return "当前身份没有此操作权限，或目标账号受到保护。";
    if (error.status === 409) return "名称已被占用或保留，或资源已变化。请刷新后检查输入。";
    if (error.status === 422 || error.status === 400) return "请检查账号格式、别名和密码规则。";
  }
  return "访问管理暂时不可用，未使用模拟数据。请刷新重试。";
}

export function AccountAccessProvider({ children, repository = httpAccountRepository }: { children: ReactNode; repository?: AccountRepository }) {
  const credential = useSessionCredential();
  const session = useSession();
  const tenantId = session.current?.session.organizationId;
  const principalId = session.current?.session.principalId;
  const [scene, setScene] = useState<AccountAccessScene | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [page, setPage] = useState({ users: "", accounts: "" });
  const mutationPending = useRef(false);

  useEffect(() => {
    if (!credential || !tenantId) return;
    let active = true;
    async function read() {
      const identity = await repository.currentIdentity(credential!);
      if (identity.account.organization.id !== tenantId || identity.principal.id !== principalId) throw new Error("INVALID_IAM_IDENTITY");
      const canManage = identity.roles.includes("ORGANIZATION_ADMIN") && !identity.principal.mustChangePassword;
      const [users, accounts] = await Promise.all([
        canManage ? repository.listUsers(credential!, page.users || undefined) : null,
        identity.canCreateOrganizations ? repository.listAccounts(credential!, page.accounts || undefined) : null
      ]);
      if (users?.items.some((entry) => entry.principal.organizationId !== tenantId)) throw new Error("INVALID_IAM_TENANT");
      return buildAccountAccessScene(identity, users, accounts);
    }
    read().then((loaded) => { if (active) { setScene(loaded); setError(null); } },
      (failure: unknown) => { if (active) { setScene(null); setError(accountError(failure)); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [credential, page, principalId, repository, revision, tenantId]);

  const value = useMemo<AccountAccess>(() => ({
    scene, loading, busy, error, success,
    reload() { setLoading(true); setRevision((current) => current + 1); },
    usersPage(after) { setLoading(true); setPage((current) => ({ ...current, users: after })); },
    accountsPage(after) { setLoading(true); setPage((current) => ({ ...current, accounts: after })); },
    async execute(command) {
      if (!credential || loading || mutationPending.current) return false;
      mutationPending.current = true;
      setBusy(true); setError(null); setSuccess(null);
      try {
        await repository.execute(credential, command);
        setSuccess("操作已完成。");
        setLoading(true); setRevision((current) => current + 1);
        return true;
      } catch (failure) { setError(accountError(failure)); return false; }
      finally { mutationPending.current = false; setBusy(false); }
    }
  }), [busy, credential, error, loading, repository, scene, success]);

  return <AccountAccessContext.Provider value={value}>{children}</AccountAccessContext.Provider>;
}

export function useAccountAccess(): AccountAccess {
  const value = useContext(AccountAccessContext);
  if (!value) throw new Error("useAccountAccess must be used inside AccountAccessProvider");
  return value;
}
