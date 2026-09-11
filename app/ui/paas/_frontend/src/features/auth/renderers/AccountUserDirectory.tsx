"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Table, TableActions, TableSelectionCell, TableToolbar, ContentPage, EmptyState, Badge, Button, Card } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { userRoles, type AccountAccessView } from "../domain/accounts";
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
      {user.accountType === "subuser" && user.source === "wecom" ? <Badge>{w("wecom")}</Badge> : null}
    </div><small className={styles.userIdentifier}>{user.id}</small></td>
    <td>{t(user.accountType === "primary" ? "primary" : "child")}{user.id === principalId ? <small>{t("signedIn")}</small> : null}</td>
    <td>{user.accountType === "primary" ? t("primaryConsoleAccess") : <AccountUserAccessMethods user={user} workspace={workspace} />}</td>
    <td>{user.accountType === "primary" ? <>{t("resourceOwner")}<small>{t("ownerGrantSummary")}</small></> : workspace ? <div className={styles.permissionSources}>
      {grants!.direct > 0 ? <span>{w("directPolicyCount", { count: grants!.direct })}</span> : null}
      {grants!.inherited > 0 ? <span>{w("groupPolicyCount", { count: grants!.inherited })}</span> : null}
      {!grants!.direct && !grants!.inherited ? w("noPolicyGrants") : null}
    </div> : <div className={styles.roleTags}>{user.bindings.length ? user.bindings.map((binding) => <Badge key={binding.id}>{t(`roles.${binding.role}`)}</Badge>) : t("noGrantLabel")}</div>}</td>
    <td>{user.state ? <Badge status={user.state === "disabled" ? "neutral" : user.state === "passwordChangeRequired" ? "warning" : "success"}>{t(`states.${user.state}`)}</Badge> : t("unknown")}</td>
  </tr>;
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
  const [kind, setKind] = useState(() => userDirectoryView.read().kind);
  const [role, setRole] = useState(() => userDirectoryView.read().role);
  useEffect(() => { if (!entityId) userDirectoryView.remember({ query, state, kind, role }); }, [userDirectoryView, query, state, kind, role, entityId]);
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
  const identities = [scene.primaryUser, ...scene.users];
  const filtered = identities.filter((user) => {
    const text = [user.name, user.loginName, user.id, user.accountType === "primary" ? t("primary") : user.qualifiedName + " " + t("child")].join(" ").normalize("NFKC").toLowerCase();
    const grants = associations.get(user.id);
    const roleMatches = user.accountType === "primary" ? role === "all" || role === "owner" : role === "owner" ? false : workspace ?
      role === "all" || (role === "ungranted" ? !grants!.direct && !grants!.inherited : role === "direct" ? grants!.direct > 0 : grants!.inherited > 0) :
      role === "all" || (role === "ungranted" ? !user.bindings.length : user.bindings.some((binding) => binding.role === role));
    return words.every((word) => text.includes(word)) && (kind === "all" || kind === user.accountType) && (state === "all" || state === user.state) && roleMatches;
  });
  const hasFilters = Boolean(query || kind !== "all" || state !== "all" || role !== "all");
  const clearFilters = () => { clearSelection(); setQuery(""); setKind("all"); setState("all"); setRole("all"); };
  const checkedUsers = filtered.filter((user) => checkedIds.has(user.id));
  const allChecked = filtered.length > 0 && checkedUsers.length === filtered.length;
  const blocked = access.busy || access.loading || !access.supportsUserBatch;
  const batchContext = { canManage: scene.canManage, supported: access.supportsUserBatch, primaryId: scene.primaryUser.id, actorId: scene.principalId, targets: checkedUsers.map((user) => ({ id: user.id, enabled: user.accountType === "primary" ? null : user.enabled })) };
  if (entityId === scene.primaryUser.id) return <AccountPrimaryWorkspace scene={scene} workspace={workspace} onBack={() => onOpen("users")} onOpen={onOpen} />;
  if (entityId && !detail) return <EmptyState title={w("entityUnavailable")} description={w("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("users")}>{w("back")}</Button>} />;
  if (detail && access.workspace) return <AccountUserWorkspace user={detail} workspace={access.workspace} scene={scene} onBack={() => onOpen("users")} onOpen={onOpen} />;
  return <div className={styles.userDirectory}>
    <Card>
      <ContentPage.Heading title={t("usersTitle")} actions={<div className={styles.directoryActions}><Button ref={createRef} disabled={access.busy || access.loading} onClick={onCreate} size="small"><Plus aria-hidden="true" />{t("createUser")}</Button>
          <TableActions label={batch("more")} disabled={blocked || !checkedUsers.length} hint={batch(access.supportsUserBatch ? "selectHint" : "unsupportedHint")}
            selectionLabel={checkedUsers.length ? batch("selected", { count: checkedUsers.length }) : undefined} clearLabel={batch("clear")} onClear={clearSelection}
            actions={userBatchActions.map((action) => { const reason = userBatchDisabledReason(action, batchContext); return { id: action, label: batch(`actions.${action}`), danger: action === "delete", disabledReason: reason ? batch(`reasons.${reason}`) : undefined, onSelect: () => setBatchDialog({ action, users: checkedUsers }) }; })} />
        </div>} />
      <TableToolbar labels={toolbarLabels} search={{ label: t("searchUsers"), placeholder: t("searchUsersPlaceholder"), value: query, onChange: (value) => changeFilter(() => setQuery(value)) }}
        status={t("userResults", { shown: filtered.length, loaded: identities.length })} filters={[
          { id: "kind", label: t("userType"), value: kind, onChange: (value) => changeFilter(() => setKind(value)), options: [{ value: "all", label: t("allUserTypes") }, { value: "primary", label: t("primary") }, { value: "subuser", label: t("child") }] },
          { id: "state", label: t("filterUserState"), value: state, onChange: (value) => changeFilter(() => setState(value)), options: [{ value: "all", label: t("allStates") }, ...(["active", "passwordChangeRequired", "disabled"] as const).map((value) => ({ value, label: t(`states.${value}`) }))] },
          { id: "role", label: workspace ? w("filterPolicySource") : t("filterUserRole"), value: role, onChange: (value) => changeFilter(() => setRole(value)), options: workspace ? [{ value: "all", label: w("allPolicySources") }, { value: "owner", label: t("resourceOwner") }, { value: "ungranted", label: w("noPolicyGrants") }, { value: "direct", label: w("directPolicies") }, { value: "inherited", label: w("groupPolicyGrants") }] : [{ value: "all", label: t("allRoles") }, { value: "owner", label: t("resourceOwner") }, { value: "ungranted", label: t("noGrantLabel") }, ...userRoles.map((value) => ({ value, label: t(`roles.${value}`) }))] }
        ]} />
      {!access.supportsUserBatch || filtered.length > userBatchLimit ? <p className={styles.selectionHint}>{batch(!access.supportsUserBatch ? "unsupportedHint" : "limitHint", { limit: userBatchLimit })}</p> : null}
      {filtered.length ? <Table aria-label={t("userTable")} className={styles.userTable}>
          <thead><tr><TableSelectionCell header label={batch("selectPage")} checked={allChecked ? true : checkedUsers.length ? "mixed" : false} disabled={blocked || filtered.length > userBatchLimit} onChange={(checked) => setSelection({ scene, ids: checked ? filtered.map((user) => user.id) : [] })} /><th scope="col">{t("user")}</th><th scope="col">{t("userType")}</th><th scope="col">{t("accessMethods")}</th><th scope="col">{workspace ? w("policyAssociations") : t("role")}</th><th scope="col">{t("status")}</th></tr></thead>
          <tbody>{filtered.map((user) => <AccountUserRow key={user.id} user={user} principalId={scene.principalId} workspace={workspace} grants={associations.get(user.id)}
            checked={checkedIds.has(user.id)} disabled={blocked || !checkedIds.has(user.id) && checkedUsers.length >= userBatchLimit}
            onSelect={(checked) => setSelection({ scene, ids: checked ? [...checkedIds, user.id] : [...checkedIds].filter((id) => id !== user.id) })}
            onOpen={() => user.accountType === "primary" || workspace ? onOpen("users", user.id) : setSelectedId(user.id)} />)}</tbody>
        </Table> : <EmptyState title={t(hasFilters ? "noMatchingUsers" : "noUsers")} description={t(hasFilters ? "noMatchingUsersHint" : "noUsersHint")} action={hasFilters ? <Button onClick={clearFilters} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} />}
      <Card.Footer><span className={styles.note}>{t("userPageHint")}</span><div className={styles.actions}><Button disabled={access.busy || access.loading} onClick={() => { setSelectedId(null); clearSelection(); access.usersPage(""); }} size="small" variant="ghost">{t("firstPage")}</Button><Button disabled={access.busy || access.loading || !scene.nextUserPage} onClick={() => { setSelectedId(null); clearSelection(); access.usersPage(scene.nextUserPage!); }} size="small" variant="secondary">{t("nextPage")}</Button></div></Card.Footer>
    </Card>
    {selected ? <UserAccessDialog key={selected.id} onClose={() => setSelectedId(null)} user={selected} /> : null}
    {batchDialog ? <UserBatchDialog action={batchDialog.action} users={batchDialog.users} fallbackFocusRef={createRef} onClose={() => setBatchDialog(null)} onCompleted={clearSelection} /> : null}
  </div>;
}
