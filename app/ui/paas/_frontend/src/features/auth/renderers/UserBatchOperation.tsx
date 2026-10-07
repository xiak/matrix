"use client";

import { useState, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Checkbox, Table } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import type { UserBatchAction, UserBatchCommand } from "../domain/userBatch";
import { WorkspaceDialog, WorkspaceInlineForm, WorkspaceSelection } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export type DirectoryUser = AccountUserScene;
type AssociationAction = Extract<UserBatchAction, "add-groups" | "authorize">;
type ConfirmationAction = Exclude<UserBatchAction, AssociationAction>;

export function isUserBatchAssociationAction(action: UserBatchAction): action is AssociationAction {
  return action === "add-groups" || action === "authorize";
}

function BatchTargets({ users }: { users: DirectoryUser[] }) {
  const t = useTranslations("UserBatch");
  const account = useTranslations("AccountAccess");
  return (
    <Table aria-label={t("targets")} mobileLayout="stack">
      <thead><tr><th>{account("user")}</th><th>{account("userType")}</th></tr></thead>
      <tbody>{users.map((user) => (
        <tr key={user.id}>
          <td data-label={account("user")}>{user.loginName}<small>{user.name}</small></td>
          <td data-label={account("userType")}>{account("child")}</td>
        </tr>
      ))}</tbody>
    </Table>
  );
}

function targets(users: DirectoryUser[]) {
  return users.map((user) => ({ id: user.id, resourceVersion: user.resourceVersion }));
}

export function UserBatchWorkflow({ action, users, onClose, onCompleted }: {
  action: AssociationAction; users: DirectoryUser[]; onClose(): void; onCompleted(): void;
}) {
  const t = useTranslations("UserBatch");
  const workspace = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [review, setReview] = useState(false);
  const [ids, setIds] = useState<string[]>([]);
  const options = action === "add-groups" ? access.workspace?.groups ?? [] : access.workspace?.policies ?? [];
  const optionLabel = workspace(action === "authorize" ? "policies" : "groups");
  const title = t("title", { action: t(`actions.${action}`), count: users.length });

  async function submit() {
    if (!review) {
      setReview(true);
      return false;
    }
    const command: UserBatchCommand = action === "authorize"
      ? { action, targets: targets(users), policyIds: ids }
      : { action, targets: targets(users), groupIds: ids };
    if (!await access.executeUserBatch(command)) return false;
    onCompleted();
    return true;
  }

  return (
    <WorkspaceInlineForm title={title} backLabel={t("backToUsers")} onClose={onClose} onSubmit={submit}
      submitDisabled={!ids.length} submitLabel={t(review ? "confirm" : "review")}>
      <p className={styles.note}>{t(`hints.${action}`)}</p>
      <BatchTargets users={users} />
      {!review ? <WorkspaceSelection label={optionLabel} options={options} value={ids} onChange={setIds} /> : <>
        <div className={styles.identitySection}>
          <h3>{optionLabel}</h3>
          <ul className={styles.batchChoices}>{ids.map((id) => <li key={id}>{options.find((option) => option.id === id)?.name ?? id}</li>)}</ul>
        </div>
        <Button type="button" variant="ghost" onClick={() => setReview(false)}>{t("back")}</Button>
        <Alert status="info">{t("atomicHint")}</Alert>
      </>}
    </WorkspaceInlineForm>
  );
}

export function UserBatchConfirmationDialog({ action, users, onClose, onCompleted, fallbackFocusRef }: {
  action: ConfirmationAction; users: DirectoryUser[]; onClose(): void; onCompleted(): void; fallbackFocusRef: RefObject<HTMLButtonElement | null>;
}) {
  const t = useTranslations("UserBatch");
  const access = useAccountAccess();
  const dangerous = action === "delete" || action === "disable";
  const [confirmed, setConfirmed] = useState(false);
  async function submit() {
    const command: UserBatchCommand = { action, targets: targets(users) };
    if (!await access.executeUserBatch(command)) return false;
    onCompleted();
    return true;
  }
  return (
    <WorkspaceDialog title={t("title", { action: t(`actions.${action}`), count: users.length })} onClose={onClose} onSubmit={submit}
      fallbackFocusRef={fallbackFocusRef} submitDisabled={dangerous && !confirmed} submitVariant={dangerous ? "danger" : "primary"} submitLabel={t("confirm")}>
      <p className={styles.note}>{t(`hints.${action}`)}</p>
      <BatchTargets users={users} />
      <Alert status={dangerous ? "warning" : "info"}>{t("atomicHint")}</Alert>
      {dangerous ? <Checkbox checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>{t("acknowledge", { action: t(`actions.${action}`), count: users.length })}</Checkbox> : null}
    </WorkspaceDialog>
  );
}
