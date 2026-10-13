"use client";

import { useId, useState } from "react";
import { Alert, Button, Card, FormField, TextArea, Typography } from "@ui/xiak";
import { useTranslations } from "next-intl";
import { useControlPlane } from "../application/ControlPlaneProvider";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./ManagedServiceCommandNotice.module.css";

export function ManagedServiceCommandNotice() {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  const {
    clearManagedServiceCommandNotice,
    commandRecoveryAvailable,
    managedServiceCommand,
    restoreManagedServiceCommand,
    inspectManagedServiceCommand
  } = useControlPlane();
  const summaryId = useId();
  const [summary, setSummary] = useState("");
  const [importError, setImportError] = useState(false);

  if (!managedServiceCommand && !commandRecoveryAvailable) return null;
  const showNotice = managedServiceCommand && (managedServiceCommand.phase !== "submitting" || managedServiceCommand.slow);
  const { intent, phase, result, checking } = managedServiceCommand ?? {};
  const error = managedServiceCommand?.error;
  const lookupMessage = error === "expired" || error === "forbidden" || error === "notFound" || error === "unavailable" || error === "mismatch"
    ? t(`commandLookupErrors.${error}`) : null;
  const status = phase === "completed" ? "success" : phase === "failed" ? "danger" : "warning";
  const message = checking ? t("commandChecking") : phase === "submitting"
    ? t("commandSlow")
    : phase === "inProgress" ? t("commandInProgress")
    : phase === "unknown"
      ? t(managedServiceCommand?.restored ? "commandRestoredUnknown" : "commandUnknown")
      : phase === "completed"
        ? t(result ? "commandSucceeded" : "commandCompleted")
        : t(result ? "commandResultFailed" : `commandErrors.${managedServiceCommand?.error ?? "unknown"}`);

  async function restore() {
    if (!restoreManagedServiceCommand(summary)) { setImportError(true); return; }
    setImportError(false);
    setSummary("");
    await inspectManagedServiceCommand();
  }

  return <div className={styles.recovery}>
    {showNotice && intent ? <Alert status={status}>
      <div className={styles.notice} aria-live="polite">
        <div className={styles.copy}>
          <strong>{t(`commandKinds.${intent.kind}`)} · {intent.targetLabel}</strong>
          <span>{message}</span>
          {phase === "unknown" && lookupMessage ? <span>{lookupMessage}</span> : null}
          <span className={styles.meta}>
            {t("commandRequest")} <Typography.Code>{intent.requestId}</Typography.Code>
            <span aria-hidden="true">·</span>
            {format.timestamp(intent.startedAt)}
          </span>
          {result ? <dl className={styles.result}>
            <div><dt>{t("commandResultTarget")}</dt><dd><Typography.Code>{result.target.id}</Typography.Code></dd></div>
            {result.operation ? <div><dt>{t("commandResultOperation")}</dt><dd><Typography.Code>{result.operation.id}</Typography.Code></dd></div> : null}
            {result.bindingId ? <div><dt>{t("commandResultBinding")}</dt><dd><Typography.Code>{result.bindingId}</Typography.Code></dd></div> : null}
            <div><dt>{t("commandServerCommitment")}</dt><dd><Typography.Code>{result.inputDigest}</Typography.Code></dd></div>
            {result.completedAt ? <div><dt>{t("commandResultTime")}</dt><dd>{format.timestamp(result.completedAt)}</dd></div> : null}
          </dl> : null}
          {commandRecoveryAvailable ? <details><summary>{t("commandRecoveryExport")}</summary>
            <p>{t("commandSummaryExportHint")}</p>
            <TextArea aria-label={t("commandSummaryExportLabel")} readOnly rows={5} value={JSON.stringify(intent, null, 2)} />
          </details> : null}
        </div>
        <div className={styles.actions}>
          {commandRecoveryAvailable && (phase === "unknown" || phase === "inProgress") ? (
            <Button disabled={checking} onClick={() => void inspectManagedServiceCommand()} size="small" variant="secondary">
              {t(checking ? "commandChecking" : "inspectOriginalCommand")}
            </Button>
          ) : null}
          {phase === "failed" || phase === "completed" || phase === "inProgress" ? (
            <Button disabled={checking} onClick={clearManagedServiceCommandNotice} size="small" variant="ghost">
              {t("dismissCommandNotice")}
            </Button>
          ) : null}
        </div>
      </div>
    </Alert> : null}
    {commandRecoveryAvailable ? <details className={styles.import}>
      <summary>{t("recoverOriginalCommand")}</summary>
      <Card><Card.Header><Typography.Title as="h3" level={3}>{t("commandSummary")}</Typography.Title></Card.Header><Card.Body>
      <p>{t("commandRecoveryBoundary")}</p>
      <FormField id={summaryId} label={t("commandSummary")}>
        <TextArea disabled={checking || phase === "submitting"} id={summaryId} maxLength={16_384} rows={5} spellCheck={false}
          onChange={(event) => { setSummary(event.target.value); setImportError(false); }} value={summary} />
      </FormField>
      {importError ? <Alert status="danger">{t("commandRecoveryImportError")}</Alert> : null}
      </Card.Body><Card.Footer>
      <Button disabled={!summary.trim() || checking || phase === "submitting"} onClick={() => void restore()} type="button" variant="secondary">{t("restoreAndInspectOriginalCommand")}</Button>
      </Card.Footer></Card>
    </details> : null}
  </div>;
}
