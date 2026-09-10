"use client";

import { useState, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Checkbox, Table } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import type { UserBatchAction, UserBatchCommand } from "../domain/userBatch";
import { WorkspaceDialog, WorkspaceSelection } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export type DirectoryUser = AccountAccessScene["primaryUser"] | AccountAccessScene["users"][number];

export function UserBatchDialog({ action, users, onClose, onCompleted, fallbackFocusRef }: {
  action: UserBatchAction; users: DirectoryUser[]; onClose(): void; onCompleted(): void; fallbackFocusRef: RefObject<HTMLButtonElement | null>;
}) {
  const t = useTranslations("UserBatch");
  const a = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const choosing = action === "authorize" || action === "add-groups";
  const dangerous = action === "delete" || action === "disable";
  const [review, setReview] = useState(!choosing);
  const [confirmed, setConfirmed] = useState(false);
  const [ids, setIds] = useState<string[]>([]);
  const options = action === "add-groups" ? access.workspace?.groups ?? [] : access.workspace?.policies ?? [];
  const submitDisabled = choosing && !ids.length || review && dangerous && !confirmed;
  async function submit() {
    if (!review) { setReview(true); return false; }
    const targets = users.map((user) => ({ id: user.id, resourceVersion: user.accountType === "subuser" ? user.resourceVersion : null }));
    const command: UserBatchCommand = action === "authorize" ? { action, targets, policyIds: ids } : action === "add-groups" ? { action, targets, groupIds: ids } : { action, targets };
    if (!await access.executeUserBatch(command)) return false;
    onCompleted(); return true;
  }
  return <WorkspaceDialog title={t("title", { action: t(`actions.${action}`), count: users.length })} onClose={onClose} onSubmit={submit}
    fallbackFocusRef={fallbackFocusRef} submitDisabled={submitDisabled} submitVariant={review && dangerous ? "danger" : "primary"}
    submitLabel={t(review ? "confirm" : "review")}>
    <p className={styles.note}>{t(`hints.${action}`)}</p>
    <Table aria-label={t("targets")}><thead><tr><th>{a("user")}</th><th>{a("userType")}</th></tr></thead><tbody>{users.map((user) => <tr key={user.id}><td>{user.loginName}<small>{user.name}</small></td><td>{a(user.accountType === "primary" ? "primary" : "child")}</td></tr>)}</tbody></Table>
    {!review && choosing ? <WorkspaceSelection label={w(action === "authorize" ? "policies" : "groups")} options={options} value={ids} onChange={setIds} /> : null}
    {review && choosing ? <><div className={styles.identitySection}><h3>{w(action === "authorize" ? "policies" : "groups")}</h3><ul className={styles.batchChoices}>{ids.map((id) => <li key={id}>{options.find((option) => option.id === id)?.name ?? id}</li>)}</ul></div><Button variant="ghost" onClick={() => setReview(false)}>{t("back")}</Button></> : null}
    {review ? <Alert status={dangerous ? "warning" : "info"}>{t("atomicHint")}</Alert> : null}
    {review && dangerous ? <Checkbox checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>{t("acknowledge", { action: t(`actions.${action}`), count: users.length })}</Checkbox> : null}
  </WorkspaceDialog>;
}
