"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Table, TableActions, TableSelectionCell, TableToolbar, ContentPage, EmptyState, Badge, Button, Card } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { UserAccessDialog } from "./AccountUserDialogs";
import { AccountPrimaryWorkspace, AccountUserAccessMethods, AccountUserWorkspace } from "./AccountUserWorkspace";
import { UserBatchDialog, type DirectoryUser } from "./UserBatchDialog";
import { userBatchActions, userBatchDisabledReason, userBatchLimit, type UserBatchAction } from "../domain/userBatch";
import styles from "./AccountAccessRenderer.module.css";

function AccountUserRow({ user, principalId, workspace, grants, checked, disabled, onSelect, onOpen }: {
  user: DirectoryUser; principalId: string; workspace: AccessWorkspace | null;
  grants?: { direct: number; inherited: number }; checked: boolean; disabled: boolean;
  onSelect(checked: boolean): void; onOpen(): void;
}) {
  const t = useTranslations("AccountAccess"), w = useTranslations("IamWorkspace"), batch = useTranslations("UserBatch");
  return <tr data-selected={checked || undefined}>
    <TableSelectionCell label={batch("selectUser", { name: user.loginName })} checked={checked} disabled={disabled} onChange={onSelect} />
    <td><div className={styles.userIdentity}>
      <button className={styles.userLink} aria-label={t("viewUser", { name: user.loginName })} onClick={onOpen} type="button">{user.loginName}</button>
      {user.name && user.name !== user.loginName ? <span className={styles.userDisplayName}>{user.name}</span> : null}
    </div><small className={styles.userIdentifier}>{user.id}</small></td>
    <td>{t("child")}{user.id === principalId ? <small>{t("signedIn")}</small> : null}</td>
    <td><AccountUserAccessMethods user={user} workspace={workspace} /></td>
    <td>{workspace ? <div className={styles.permissionSources}>
      {grants!.direct > 0 ? <span>{w("directPolicyCount", { count: grants!.direct })}</span> : null}
      {grants!.inherited > 0 ? <span>{w("groupPolicyCount", { count: grants!.inherited })}</span> : null}
      {!grants!.direct && !grants!.inherited ? w("noPolicyGrants") : null}
    </div> : <div className={styles.roleTags}>{user.attachments.length ? <>
      {user.attachments.slice(0, 2).map((attachment) => <Badge key={attachment.id} status={attachment.policyStatus === "RETIRED" ? "neutral" : undefined}>{attachment.label}</Badge>)}
      {user.attachments.length > 2 ? <span>{t("morePolicyAttachments", { count: user.attachments.length - 2 })}</span> : null}
    </> : t("noGrantLabel")}</div>}</td>
    <td>{user.state ? <Badge status={user.state === "disabled" ? "neutral" : user.state === "passwordChangeRequired" ? "warning" : "success"}>{t(`states.${user.state}`)}</Badge> : t("unknown")}</td>
  </tr>;
}

function AccountOwnerSummary({ scene, onOpen }: { scene: AccountAccessScene; onOpen(): void }) {
  const t = useTranslations("AccountAccess");
  const owner = scene.accountOwner;
  return <section className={styles.accountOwner} aria-label={t("resourceOwner")}>
    <div className={styles.accountOwnerIdentity}>
      <span className={styles.accountOwnerLabel}>{t("resourceOwner")}</span>
      <div className={styles.userIdentity}>
        <button className={styles.userLink} aria-label={t("viewUser", { name: owner.loginName })} onClick={onOpen} type="button">{owner.loginName}</button>
        {owner.name && owner.name !== owner.loginName ? <span className={styles.userDisplayName}>{owner.name}</span> : null}
      </div>
      <small className={styles.userIdentifier}>{scene.accountName} · {scene.accountId}</small>
    </div>
    <div className={styles.accountOwnerMeta}>
      <Badge>{t("primary")}</Badge>
      {owner.isCurrent ? <Badge status="success">{t("signedIn")}</Badge> : null}
      <span>{t("ownerGrantSummary")}</span>
    </div>
  </section>;
}

export function AccountUserDirectory({ scene, entityId, onCreate, onOpen }: { scene: AccountAccessScene; entityId?: string; onCreate(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const batch = useTranslations("UserBatch");
  const toolbarLabels = useTableToolbarLabels();
  const access = useAccountAccess();
  const workspace = access.workspace;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { userDirectoryView } = access;
  const [query, setQuery] = useState(() => userDirectoryView.read().query);
  const [state, setState] = useState(() => userDirectoryView.read().state);
  const [role, setRole] = useState(() => userDirectoryView.read().role);
  useEffect(() => { if (!entityId) userDirectoryView.remember({ query, state, role }); }, [userDirectoryView, query, state, role, entityId]);
  const createRef = useRef<HTMLButtonElement>(null);
  const [selection, setSelection] = useState<{ scene: AccountAccessScene; ids: string[] }>({ scene, ids: [] });
  const [batchDialog, setBatchDialog] = useState<{ action: UserBatchAction; users: DirectoryUser[] } | null>(null);
  const checkedIds = new Set(selection.scene === scene ? selection.ids : []);
  const clearSelection = () => setSelection({ scene, ids: [] });
  const changeFilter = (change: () => void) => { clearSelection(); change(); };
  const selected = scene.users.find((user) => user.id === selectedId);
  const detail = scene.users.find((user) => user.id === entityId);
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const associations = new Map(scene.users.map((user) => [user.id, {
    direct: workspace?.userPolicies[user.id]?.length ?? 0,
    inherited: new Set(workspace?.groups.filter((group) => group.memberIds.includes(user.id)).flatMap((group) => group.policyIds)).size
  }]));
  const filtered = scene.users.filter((user) => {
    const text = [user.name, user.loginName, user.id, user.qualifiedName, t("child")].join(" ").normalize("NFKC").toLowerCase();
    const grants = associations.get(user.id);
    const roleMatches = workspace ?
      role === "all" || (role === "ungranted" ? !grants!.direct && !grants!.inherited : role === "direct" ? grants!.direct > 0 : grants!.inherited > 0) :
      role === "all" || (role === "ungranted" ? !user.attachments.length : role === "direct" ? user.attachments.length > 0 : user.attachments.some((attachment) => attachment.scope === "INSTALLATION"));
    return words.every((word) => text.includes(word)) && (state === "all" || state === user.state) && roleMatches;
  });
  const hasFilters = Boolean(query || state !== "all" || role !== "all");
  const clearFilters = () => { clearSelection(); setQuery(""); setState("all"); setRole("all"); };
  const checkedUsers = filtered.filter((user) => checkedIds.has(user.id));
  const allChecked = filtered.length > 0 && checkedUsers.length === filtered.length;
  const blocked = access.busy || access.loading || !access.supportsUserBatch;
  const batchContext = { canListUsers: scene.canListUsers, supported: access.supportsUserBatch, rootId: scene.accountOwner.id, actorId: scene.currentUserId, targets: checkedUsers.map((user) => ({ id: user.id, enabled: user.enabled, canSetStatus: user.canSetStatus, canAttachPolicy: user.canAttachTenantPolicy, protected: user.protected })) };
  if (entityId === scene.accountOwner.id) return <AccountPrimaryWorkspace scene={scene} onBack={() => onOpen("users")} onOpen={onOpen} />;
  if (entityId && !detail) return <EmptyState title={w("entityUnavailable")} description={w("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("users")}>{w("back")}</Button>} />;
  if (detail && access.workspace) return <AccountUserWorkspace user={detail} workspace={access.workspace} scene={scene} onBack={() => onOpen("users")} onOpen={onOpen} />;
  return <div className={styles.userDirectory}>
    <Card>
      <ContentPage.Heading title={t("usersTitle")} actions={<div className={styles.directoryActions}>{scene.canCreateUsers ? <Button ref={createRef} disabled={access.busy || access.loading} onClick={onCreate} size="small"><Plus aria-hidden="true" />{t("createUser")}</Button> : null}
          <TableActions label={batch("more")} disabled={blocked || !checkedUsers.length} hint={batch(access.supportsUserBatch ? "selectHint" : "unsupportedHint")}
            selectionLabel={checkedUsers.length ? batch("selected", { count: checkedUsers.length }) : undefined} clearLabel={batch("clear")} onClear={clearSelection}
            actions={userBatchActions.map((action) => { const reason = userBatchDisabledReason(action, batchContext); return { id: action, label: batch(`actions.${action}`), danger: action === "delete", disabledReason: reason ? batch(`reasons.${reason}`) : undefined, onSelect: () => setBatchDialog({ action, users: checkedUsers }) }; })} />
          </div>} />
      <AccountOwnerSummary scene={scene} onOpen={() => onOpen("users", scene.accountOwner.id)} />
      <TableToolbar labels={toolbarLabels} search={{ label: t("searchUsers"), placeholder: t("searchUsersPlaceholder"), value: query, onChange: (value) => changeFilter(() => setQuery(value)) }}
        status={t("userResults", { shown: filtered.length, loaded: scene.users.length })} filters={[
          { id: "state", label: t("filterUserState"), value: state, onChange: (value) => changeFilter(() => setState(value)), options: [{ value: "all", label: t("allStates") }, ...(["active", "passwordChangeRequired", "disabled"] as const).map((value) => ({ value, label: t(`states.${value}`) }))] },
          { id: "role", label: w("filterPolicySource"), value: role, onChange: (value) => changeFilter(() => setRole(value)), options: workspace ? [{ value: "all", label: w("allPolicySources") }, { value: "ungranted", label: w("noPolicyGrants") }, { value: "direct", label: w("directPolicies") }, { value: "inherited", label: w("groupPolicyGrants") }] : [{ value: "all", label: w("allPolicySources") }, { value: "ungranted", label: w("noPolicyGrants") }, { value: "direct", label: w("directPolicies") }, { value: "platform", label: t("platformPolicyAttachments") }] }
        ]} />
      {!access.supportsUserBatch || filtered.length > userBatchLimit ? <p className={styles.selectionHint}>{batch(!access.supportsUserBatch ? "unsupportedHint" : "limitHint", { limit: userBatchLimit })}</p> : null}
      {filtered.length ? <Table aria-label={t("userTable")} className={styles.userTable}>
          <thead><tr><TableSelectionCell header label={batch("selectPage")} checked={allChecked ? true : checkedUsers.length ? "mixed" : false} disabled={blocked || filtered.length > userBatchLimit} onChange={(checked) => setSelection({ scene, ids: checked ? filtered.map((user) => user.id) : [] })} /><th scope="col">{t("user")}</th><th scope="col">{t("userType")}</th><th scope="col">{t("accessMethods")}</th><th scope="col">{w("policyAssociations")}</th><th scope="col">{t("status")}</th></tr></thead>
          <tbody>{filtered.map((user) => <AccountUserRow key={user.id} user={user} principalId={scene.currentUserId} workspace={workspace} grants={associations.get(user.id)}
            checked={checkedIds.has(user.id)} disabled={blocked || !checkedIds.has(user.id) && checkedUsers.length >= userBatchLimit}
            onSelect={(checked) => setSelection({ scene, ids: checked ? [...checkedIds, user.id] : [...checkedIds].filter((id) => id !== user.id) })}
            onOpen={() => workspace ? onOpen("users", user.id) : setSelectedId(user.id)} />)}</tbody>
        </Table> : <EmptyState title={t(hasFilters ? "noMatchingUsers" : "noUsers")} description={t(hasFilters ? "noMatchingUsersHint" : "noUsersHint")} action={hasFilters ? <Button onClick={clearFilters} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} />}
      <Card.Footer><span className={styles.note}>{t("userPageHint")}</span><div className={styles.actions}><Button disabled={access.busy || access.loading} onClick={() => { setSelectedId(null); clearSelection(); access.usersPage(""); }} size="small" variant="ghost">{t("firstPage")}</Button><Button disabled={access.busy || access.loading || !scene.nextUserPage} onClick={() => { setSelectedId(null); clearSelection(); access.usersPage(scene.nextUserPage!); }} size="small" variant="secondary">{t("nextPage")}</Button></div></Card.Footer>
    </Card>
    {selected ? <UserAccessDialog key={selected.id} onClose={() => setSelectedId(null)} user={selected} /> : null}
    {batchDialog ? <UserBatchDialog action={batchDialog.action} users={batchDialog.users} fallbackFocusRef={createRef} onClose={() => setBatchDialog(null)} onCompleted={clearSelection} /> : null}
  </div>;
}
