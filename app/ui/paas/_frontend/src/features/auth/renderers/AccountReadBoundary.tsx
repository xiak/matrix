"use client";

import type { ReactNode } from "react";
import { useTranslations } from "next-intl";
import { ReadBoundary, type ReadStatus } from "@ui/xiak";
import type { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountDirectoryKind } from "../scenes/accountAccessScene";

export type AccountReadStatus = ReadStatus;
type AccountFailureStatus = Exclude<AccountReadStatus, "loading" | "ready" | "empty">;

type StateCopy = { title: string; description: string; action?: ReactNode };

type AccountReadBoundaryProps = {
  children?: ReactNode;
  empty?: StateCopy;
  failure?: StateCopy;
  loading: ReactNode;
  onRetry?(): void;
  problem?: HttpProblem | null;
  retryDisabled?: boolean;
  retryLabel?: string;
  status: AccountReadStatus;
};

export function AccountReadBoundary({ children, empty, failure, loading, onRetry, problem, retryDisabled = false, retryLabel, status }: AccountReadBoundaryProps) {
  const t = useTranslations("AccountReadBoundary");
  const failureStatus: AccountFailureStatus = status === "loading" || status === "ready" || status === "empty" ? "unavailable" : status;
  const description = failure?.description ?? t(`descriptions.${failureStatus}`);
  return <ReadBoundary status={status} loading={loading} empty={empty}
    failure={{ ...failure, title: failure?.title ?? t(`titles.${failureStatus}`), description: status === "forbidden" ? `${description} ${t("forbiddenRecovery")}` : description }}
    labels={{ retry: retryLabel ?? t("retry"), copyDiagnostic: t("copyDiagnostic"), copied: t("copied"), copyFailed: t("copyFailed") }}
    diagnostic={problem ? { requestId: problem.requestId, status: problem.status, code: problem.code } : undefined}
    retryDisabled={retryDisabled} onRetry={status === "unavailable" ? onRetry : undefined}>{children}</ReadBoundary>;
}

export function AccountDirectoryReadFailure({ kind, onRetry }: { kind: AccountDirectoryKind; onRetry?(): void }) {
  const t = useTranslations("AccountAccess.directoryReadFailure");
  const access = useAccountAccess();
  return <AccountReadBoundary status="unavailable" loading={null} failure={{ title: t(`titles.${kind}`), description: t("hint") }}
    retryDisabled={access.loading || access.busy} retryLabel={t(access.loading ? "loading" : "retry")}
    onRetry={() => { onRetry?.(); void access.retryDirectory(kind); }}>
    {null}
  </AccountReadBoundary>;
}
