"use client";

import { useState, type ReactNode } from "react";
import { ClockAlert, CloudOff, SearchX, ServerOff, ShieldAlert } from "lucide-react";
import { Button } from "../button/Button";
import { EmptyState } from "../empty-state/EmptyState";
import styles from "./ReadBoundary.module.css";

export type ReadStatus = "loading" | "ready" | "empty" | "forbidden" | "notFound" | "routeUnavailable" | "unavailable" | "expired";

export type ReadDiagnostic = {
  code: string;
  requestId: string | null;
  status: number;
};

export type ReadBoundaryLabels = {
  copied: string;
  copyDiagnostic: string;
  copyFailed: string;
  retry: string;
};

type StateCopy = { title: string; description?: string; action?: ReactNode };

type ReadBoundaryProps = {
  children?: ReactNode;
  diagnostic?: ReadDiagnostic | null;
  empty?: StateCopy;
  failure: StateCopy;
  labels: ReadBoundaryLabels;
  loading: ReactNode;
  onRetry?(): void;
  retryDisabled?: boolean;
  status: ReadStatus;
};

const problemCodePattern = /^(?:[a-z][a-z0-9]*(?:[.-][a-z0-9]+){1,15}|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){0,15})$/;
const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const failureIcons = {
  forbidden: ShieldAlert,
  notFound: SearchX,
  routeUnavailable: ServerOff,
  unavailable: CloudOff,
  expired: ClockAlert
};

function safeDiagnostic(value?: ReadDiagnostic | null): ReadDiagnostic | null {
  if (!value || !Number.isSafeInteger(value.status) || value.status < 400 || value.status > 599) return null;
  if (!requestIdPattern.test(value.requestId ?? "") || value.code.length > 96 || !problemCodePattern.test(value.code)) return null;
  return { code: value.code, requestId: value.requestId, status: value.status };
}

export function ReadBoundary({ children, diagnostic, empty, failure, labels, loading, onRetry, retryDisabled = false, status }: ReadBoundaryProps) {
  const safeProblem = safeDiagnostic(diagnostic);
  const copyKey = safeProblem ? JSON.stringify(safeProblem) : "";
  const [copyView, setCopyView] = useState<{ key: string; state: "copied" | "failed" } | null>(null);
  const copyState = copyView?.key === copyKey ? copyView.state : "idle";

  if (status === "loading") return <>{loading}</>;
  if (status === "ready") return <>{children}</>;
  if (status === "empty") return empty ? <EmptyState title={empty.title} description={empty.description} action={empty.action} /> : null;

  const copyDiagnostic = async () => {
    if (!safeProblem || !navigator.clipboard?.writeText) {
      setCopyView({ key: copyKey, state: "failed" });
      return;
    }
    try {
      await navigator.clipboard.writeText(JSON.stringify({
        requestId: safeProblem.requestId,
        status: safeProblem.status,
        code: safeProblem.code
      }, null, 2));
      setCopyView({ key: copyKey, state: "copied" });
    } catch {
      setCopyView({ key: copyKey, state: "failed" });
    }
  };

  const actions = failure.action || onRetry || safeProblem ? <div className={styles.actions}>
    {failure.action}
    {onRetry ? <Button disabled={retryDisabled} variant="secondary" onClick={onRetry}>{labels.retry}</Button> : null}
    {safeProblem ? <Button variant="secondary" onClick={() => void copyDiagnostic()}>{copyState === "copied" ? labels.copied : copyState === "failed" ? labels.copyFailed : labels.copyDiagnostic}</Button> : null}
  </div> : undefined;
  const FailureIcon = failureIcons[status];

  return <section aria-label={failure.title} role="alert">
    <EmptyState title={failure.title} description={failure.description} icon={<FailureIcon />} action={actions} />
  </section>;
}
