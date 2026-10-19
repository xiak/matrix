"use client";

import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, FormField, Input } from "@ui/xiak";
import type { UserManagementDraft, UserManagementMutation, UserManagementReceipt } from "../application/userManagementMutation";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import { userManagementDisplayNameValid } from "../domain/accounts";
import { WorkspaceInlineForm, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export function UserManagementReceiptNotice({ receipt }: { receipt: UserManagementReceipt }) {
  const t = useTranslations("UserManagementCommand");
  return <Alert status="success" role="status" aria-label={t("receiptTitle")}>
    <strong>{t("receiptTitle")}</strong><p>{t("receiptBoundary")}</p>
    <dl className={styles.facts}>
      <div><dt>{t("user")}</dt><dd><code>{receipt.result.id}</code></dd></div>
      <div><dt>{t("operation")}</dt><dd>{t(`operations.${receipt.intent.operation}`)}</dd></div>
      <div><dt>{t("request")}</dt><dd><code>{receipt.intent.commandRequestId}</code></dd></div>
      <div><dt>{t("resultingRevision")}</dt><dd>{receipt.result.resourceVersion}</dd></div>
      <div><dt>{t("intended")}</dt><dd>{receipt.intent.operation === "USER_UPDATE" ? receipt.result.displayName : t(receipt.result.status === "ACTIVE" ? "active" : "disabled")}</dd></div>
      {receipt.completion ? <><div><dt>{t("event")}</dt><dd><code>{receipt.completion.eventId}</code></dd></div><div><dt>{t("completedAt")}</dt><dd><WorkspaceTime value={receipt.completion.occurredAt} /></dd></div></> : null}
    </dl>
  </Alert>;
}

export function UserManagementEditor({ userId, user, mode, command, onClose, onCompleted, onStale }: {
  userId: string; user?: AccountUserScene; mode: "rename" | "status"; command: UserManagementMutation;
  onClose(): void; onCompleted(): void; onStale(): void;
}) {
  const t = useTranslations("UserManagementCommand"), a = useTranslations("AccountAccess");
  const id = useId();
  const [name, setName] = useState(user?.name ?? "");
  const [review, setReview] = useState<UserManagementDraft | null>(() => mode === "status" && user
    ? { operation: "USER_SET_STATUS", expectedResourceVersion: user.resourceVersion, intendedStatus: user.enabled ? "DISABLED" : "ACTIVE" } : null);
  const pending = command.pending;
  const operation = pending?.operation ?? (mode === "rename" ? "USER_UPDATE" : "USER_SET_STATUS");
  const allowed = Boolean(user && (mode === "rename" ? user.canUpdate : user.canSetStatus));
  const stale = Boolean(review && (!allowed || user?.resourceVersion !== review.expectedResourceVersion));
  const title = `${t(`operations.${operation}`)} · ${user?.loginName ?? userId}`;
  return <WorkspaceInlineForm title={title} backLabel={t(pending ? "backToUsers" : "backToUser")} onClose={onClose}
    operation={{ busy: command.busy, clearError: () => undefined }}
    draft={{ dirty: !pending && mode === "rename" && (Boolean(review) || name !== (user?.name ?? "")), title, description: t("leaveHint") }}
    cancelLabel={pending && !command.receipt ? t("later") : undefined}
    submitLabel={pending ? command.receipt ? t("finish") : t("inspect") : !review ? t("review") : review.operation === "USER_UPDATE" ? a("saveDisplayName") : a(review.intendedStatus === "DISABLED" ? "confirmDisable" : "confirmEnable")}
    submitVariant={!pending && review?.operation === "USER_SET_STATUS" && review.intendedStatus === "DISABLED" ? "danger" : "primary"}
    submitDisabled={pending && command.receipt ? false : !command.ready || !pending && (!allowed || stale || !review && (!userManagementDisplayNameValid(name.trim()) || name.trim() === user?.name))}
    onSubmit={async () => {
      if (pending && command.receipt) { if (command.acknowledge()) onCompleted(); return false; }
      if (pending) { const result = await command.inspect(); if (result.status === "applied" && command.acknowledge()) onCompleted(); return false; }
      if (!user || !allowed || stale) return false;
      if (!review) { setReview({ operation: "USER_UPDATE", expectedResourceVersion: user.resourceVersion, intendedDisplayName: name.trim() }); return false; }
      const result = await command.begin(review);
      if (result.status === "applied" && command.acknowledge()) onCompleted();
      else if (result.status === "rejected" && (result.reason === "conflict" || result.reason === "forbidden")) onStale();
      return false;
    }}>
    {command.recoveryError ? <Alert status="danger">{t("storageUnavailable")}</Alert> : null}
    {command.busy ? <p role="status">{t("working")}</p> : command.error && !pending ? <Alert status="danger">{a(`errors.${command.error}`)}</Alert> : null}
    {pending ? <>
      {!command.receipt && !command.busy && !command.recoveryError ? <Alert status="warning"><strong>{t("unknown")}</strong>{command.error ? <p>{t("lastInspection", { reason: a(`errors.${command.error}`) })}</p> : null}</Alert> : null}
      <dl className={styles.facts}>
        <div><dt>{t("account")}</dt><dd><code>{pending.accountId}</code></dd></div><div><dt>{t("actor")}</dt><dd><code>{pending.actorPrincipalId}</code></dd></div>
        <div><dt>{t("user")}</dt><dd><code>{pending.userId}</code></dd></div><div><dt>{t("request")}</dt><dd><code>{pending.commandRequestId}</code></dd></div>
        <div><dt>{t("expectedRevision")}</dt><dd>{pending.expectedResourceVersion}</dd></div>
        <div><dt>{t("intended")}</dt><dd>{pending.operation === "USER_UPDATE" ? pending.intendedDisplayName : t(pending.intendedStatus === "ACTIVE" ? "active" : "disabled")}</dd></div>
      </dl>
      {command.receipt ? <UserManagementReceiptNotice receipt={command.receipt} /> : <Alert>{t("lookupBoundary")}</Alert>}
      <p className={styles.note}>{t("leavePending")}</p>
    </> : review ? <>
      <dl className={styles.facts}><div><dt>{t("user")}</dt><dd><code>{userId}</code></dd></div><div><dt>{t("expectedRevision")}</dt><dd>{review.expectedResourceVersion}</dd></div>
        <div><dt>{t("before")}</dt><dd>{review.operation === "USER_UPDATE" ? user?.name : t(user?.enabled ? "active" : "disabled")}</dd></div>
        <div><dt>{t("intended")}</dt><dd>{review.operation === "USER_UPDATE" ? review.intendedDisplayName : t(review.intendedStatus === "ACTIVE" ? "active" : "disabled")}</dd></div></dl>
      {review.operation === "USER_SET_STATUS" ? <Alert status={review.intendedStatus === "DISABLED" ? "warning" : "info"}>{a(review.intendedStatus === "DISABLED" ? "disableHint" : "enableHint")}</Alert> : <p className={styles.note}>{a("immutableUserFieldsHint")}</p>}
      {stale ? <Alert status="warning">{t("staleReview")}</Alert> : null}
      {mode === "rename" ? <Button type="button" variant="secondary" onClick={() => setReview(null)}>{t("editDraft")}</Button> : null}
    </> : <FormField id={id} label={a("displayName")} hint={a("immutableUserFieldsHint")}><Input id={id} autoFocus required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} /></FormField>}
  </WorkspaceInlineForm>;
}
