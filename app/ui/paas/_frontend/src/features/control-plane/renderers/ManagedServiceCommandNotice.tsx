"use client";

import { Alert, Button, Typography } from "@ui/xiak";
import { useTranslations } from "next-intl";
import { useControlPlane } from "../application/ControlPlaneProvider";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./ManagedServiceCommandNotice.module.css";

export function ManagedServiceCommandNotice() {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  const {
    clearManagedServiceCommandNotice,
    managedServiceCommand,
    retryManagedServiceCommand
  } = useControlPlane();

  if (!managedServiceCommand || (managedServiceCommand.phase === "submitting" && !managedServiceCommand.slow)) return null;
  const { intent, phase } = managedServiceCommand;
  const status = phase === "completed" ? "success" : phase === "failed" ? "danger" : "warning";
  const message = phase === "submitting"
    ? t("commandSlow")
    : phase === "unknown"
      ? t(managedServiceCommand.restored ? "commandRestoredUnknown" : "commandUnknown")
      : phase === "completed"
        ? t("commandCompleted")
        : t(`commandErrors.${managedServiceCommand.error ?? "unknown"}`);

  return (
    <Alert status={status}>
      <div className={styles.notice} aria-live="polite">
        <div className={styles.copy}>
          <strong>{t(`commandKinds.${intent.kind}`)} · {intent.targetLabel}</strong>
          <span>{message}</span>
          <span className={styles.meta}>
            {t("commandRequest")} <Typography.Code>{intent.requestId}</Typography.Code>
            <span aria-hidden="true">·</span>
            {format.timestamp(intent.startedAt)}
          </span>
        </div>
        <div className={styles.actions}>
          {phase === "unknown" ? (
            <Button onClick={() => void retryManagedServiceCommand()} size="small" variant="secondary">
              {t("retrySameCommand")}
            </Button>
          ) : null}
          {phase === "failed" || phase === "completed" ? (
            <Button onClick={clearManagedServiceCommandNotice} size="small" variant="ghost">
              {t("dismissCommandNotice")}
            </Button>
          ) : null}
        </div>
      </div>
    </Alert>
  );
}
