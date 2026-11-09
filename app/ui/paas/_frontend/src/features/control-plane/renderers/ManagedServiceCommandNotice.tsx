"use client";

import { useId, useState, type Ref } from "react";
import { ActionMenu, Alert, Button, ContentPage, Dialog, FormField, TextArea, Typography, type PageCommand, type PageCommandsHandle } from "@ui/xiak";
import { useTranslations } from "next-intl";
import { useControlPlane } from "../application/ControlPlaneProvider";
import type { InstallationScene } from "../scenes/consoleScene";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./ManagedServiceCommandNotice.module.css";

export function ManagedServiceCommandNotice({ technical = false, installations, offeringId }: {
  technical?: boolean;
  installations?: InstallationScene[];
  offeringId?: string;
}) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  const {
    clearManagedServiceCommandNotice,
    commandRecoveryAvailable,
    managedServiceCommand,
    inspectManagedServiceCommand
  } = useControlPlane();
  if (!managedServiceCommand) return null;
  const { intent, phase, result, checking, error } = managedServiceCommand;
  if (phase === "submitting" && !managedServiceCommand.slow) return null;
  const trackCreation = !technical && installations !== undefined && intent.kind === "CREATE_INSTALLATION";
  if (trackCreation && (offeringId && intent.payload.offeringId !== offeringId ||
      (phase === "completed" || result) && installations.some(item => item.id === intent.targetId))) return null;
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

  const creationMessage = checking ? t("creationChecking") : phase === "unknown" ? t("creationUnconfirmed")
    : phase === "completed" || phase === "inProgress" ? t("creationAccepted") : message;
  return <div className={styles.recovery}>
    <Alert status={status}>
      <div className={styles.notice} aria-live="polite">
        <div className={styles.copy}>
          <strong>{t(`commandKinds.${intent.kind}`)} · {intent.targetLabel}</strong>
          <span>{trackCreation ? creationMessage : message}</span>
          {phase === "unknown" && lookupMessage && (!trackCreation || error === "forbidden" || error === "expired") ? <span>{lookupMessage}</span> : null}
          {technical ? <span className={styles.meta}>
            {t("commandRequest")} <Typography.Code>{intent.requestId}</Typography.Code>
            <span aria-hidden="true">·</span>
            {format.timestamp(intent.startedAt)}
          </span> : null}
          {technical && result ? <dl className={styles.result}>
            <div><dt>{t("commandResultTarget")}</dt><dd><Typography.Code>{result.target.id}</Typography.Code></dd></div>
            {result.operation ? <div><dt>{t("commandResultOperation")}</dt><dd><Typography.Code>{result.operation.id}</Typography.Code></dd></div> : null}
            {result.bindingId ? <div><dt>{t("commandResultBinding")}</dt><dd><Typography.Code>{result.bindingId}</Typography.Code></dd></div> : null}
            <div><dt>{t("commandServerCommitment")}</dt><dd><Typography.Code>{result.inputDigest}</Typography.Code></dd></div>
            {result.completedAt ? <div><dt>{t("commandResultTime")}</dt><dd>{format.timestamp(result.completedAt)}</dd></div> : null}
          </dl> : null}
          {technical && commandRecoveryAvailable ? <details><summary>{t("commandRecoveryExport")}</summary>
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
    </Alert>
  </div>;
}

export function ManagedServicePageActions({ primary, focusRef }: { primary?: PageCommand; focusRef?: Ref<PageCommandsHandle> }) {
  const t = useTranslations("ManagedService");
  const collection = useTranslations("Collection");
  const { managedServiceCommand, restoreManagedServiceCommand, inspectManagedServiceCommand, commandRecoveryAvailable } = useControlPlane();
  const [open, setOpen] = useState(false);
  const [summary, setSummary] = useState("");
  const [importError, setImportError] = useState(false);
  const summaryId = useId();
  const busy = managedServiceCommand?.checking || managedServiceCommand?.phase === "submitting";
  if (!commandRecoveryAvailable) return primary ? <ContentPage.Commands label={collection("pageActions")} primary={primary} focusRef={focusRef} /> : null;
  const recovery = { id: "recover-command", label: t("recoverOriginalCommand"), overflowOnly: true, onSelect: () => setOpen(true) };
  function close() {
    setOpen(false);
    setSummary("");
    setImportError(false);
  }
  function restore() {
    if (!restoreManagedServiceCommand(summary)) { setImportError(true); return; }
    setSummary("");
    setImportError(false);
    void inspectManagedServiceCommand();
  }
  return <>
    {primary ? <ContentPage.Commands label={collection("moreActions")} primary={primary} secondary={[recovery]} focusRef={focusRef} />
      : <ActionMenu label={collection("moreActions")} actions={[recovery]} size="small" iconOnly />}
    {open ? <Dialog open title={recovery.label} closeLabel={t("closeRecovery")} onClose={close} footer={
      <Button disabled={!summary.trim() || busy} onClick={restore} variant="primary">{t("restoreAndInspectOriginalCommand")}</Button>
    }>
      <ManagedServiceCommandNotice technical />
      <FormField id={summaryId} label={t("commandSummary")} hint={t("commandRecoveryBoundary")}>
        <TextArea disabled={busy} id={summaryId} maxLength={16_384} rows={5} spellCheck={false}
          onChange={(event) => { setSummary(event.target.value); setImportError(false); }} value={summary} />
      </FormField>
      {importError ? <Alert status="danger">{t("commandRecoveryImportError")}</Alert> : null}
    </Dialog> : null}
  </>;
}
