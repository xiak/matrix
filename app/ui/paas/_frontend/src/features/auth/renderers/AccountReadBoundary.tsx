"use client";

import { useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Button, EmptyState } from "@ui/xiak";
import type { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountDirectoryKind } from "../scenes/accountAccessScene";

export type AccountReadStatus = "loading" | "ready" | "empty" | "forbidden" | "notFound" | "routeUnavailable" | "unavailable" | "expired";

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

function safeDiagnostic(problem: HttpProblem): string {
  return JSON.stringify({ requestId: problem.requestId, status: problem.status, code: problem.code }, null, 2);
}

export function AccountReadBoundary({ children, empty, failure, loading, onRetry, problem, retryDisabled = false, retryLabel, status }: AccountReadBoundaryProps) {
  const t = useTranslations("AccountReadBoundary");
  const copyKey = `${status}:${problem?.requestId ?? ""}`;
  const [copyView, setCopyView] = useState<{ key: string; state: "copied" | "failed" } | null>(null);
  const copyState = copyView?.key === copyKey ? copyView.state : "idle";

  if (status === "loading") return <>{loading}</>;
  if (status === "ready") return <>{children}</>;
  if (status === "empty") return empty ? <EmptyState title={empty.title} description={empty.description} action={empty.action} /> : null;

  const canRetry = status === "unavailable" && onRetry;
  const canCopy = (status === "forbidden" || status === "notFound" || status === "routeUnavailable" || status === "unavailable") && problem?.requestId;
  const copyDiagnostic = async () => {
    if (!problem || !navigator.clipboard?.writeText) {
      setCopyView({ key: copyKey, state: "failed" });
      return;
    }
    try {
      await navigator.clipboard.writeText(safeDiagnostic(problem));
      setCopyView({ key: copyKey, state: "copied" });
    } catch {
      setCopyView({ key: copyKey, state: "failed" });
    }
  };
  const actions = canRetry || canCopy ? <>
    {canRetry ? <Button disabled={retryDisabled} variant="secondary" onClick={onRetry}>{retryLabel ?? t("retry")}</Button> : null}
    {canCopy ? <Button variant="secondary" onClick={() => void copyDiagnostic()}>{t(copyState === "copied" ? "copied" : copyState === "failed" ? "copyFailed" : "copyDiagnostic")}</Button> : null}
  </> : undefined;

  return <section aria-label={failure?.title} role="alert">
    <EmptyState title={failure?.title ?? t(`titles.${status}`)} description={failure?.description ?? t(`descriptions.${status}`)} action={actions} />
  </section>;
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
