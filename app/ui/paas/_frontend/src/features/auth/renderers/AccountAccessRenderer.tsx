"use client";

import { useEffect, useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, ContentPage, FormField, Table, EmptyState, Badge, Button, Card, Input, Typography, PageSkeleton, Tabs } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { userRoles, type AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { AccountIdentifier, AccountOverview } from "./AccountOverview";
import { AccountUserDirectory } from "./AccountUserDirectory";
import { CreateTenantDialog } from "./AccountUserDialogs";
import { CreateUserWizard } from "./CreateUserWizard";
import { AccessGroups } from "./AccessGroups";
import { GroupCreationWizard } from "./GroupCreationWizard";
import { AccessPolicies } from "./AccessPolicies";
import { PolicyAuthoringWizard } from "./PolicyAuthoringWizard";
import { AccessSimulator } from "./AccessSimulator";
import { AccessRoles } from "./AccessRoles";
import { RoleCreationWizard } from "./RoleCreationWizard";
import { AccessProviders, AccessFederations } from "./AccessIdentity";
import { AccessCredentials } from "./AccessCredentials";
import { AccessSecuritySettings, AccessUserSso } from "./AccessSecuritySettings";
import { AccessEnterpriseAccounts } from "./AccessEnterpriseAccounts";
import styles from "./AccountAccessRenderer.module.css";

const aliasPattern = "[a-z][a-z0-9\\-]{1,61}[a-z0-9]";

function UserSettings({ scene }: { scene: AccountAccessScene }) {
  const t = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const aliasId = useId();
  const [alias, setAlias] = useState(scene.loginAlias ?? "");
  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("alias")}</Typography.Title><Typography.Text tone="muted">{t("aliasSubtitle")}</Typography.Text></div><Badge status={scene.loginAlias ? "success" : "neutral"}>{scene.loginAlias ? t("aliasSet") : t("aliasUnset")}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <p className={styles.note}>{t("aliasHint")}</p>
      <dl className={styles.facts}>
        <div><dt>{t("accountId")}</dt><dd><AccountIdentifier label={t("accountId")} value={scene.accountId} /></dd></div>
        <div><dt>{t("primaryLogin")}</dt><dd>{scene.primaryLoginName}</dd></div>
        <div><dt>{t("idLogin")}</dt><dd><AccountIdentifier label={t("idLogin")} value={`username@${scene.accountId}`} /></dd></div>
        <div><dt>{t("aliasLogin")}</dt><dd>{scene.loginAlias ? <AccountIdentifier label={t("aliasLogin")} value={`username@${scene.loginAlias}`} /> : t("aliasPending")}</dd></div>
      </dl>
      {scene.canManage ? <form className={styles.form} onSubmit={async (event) => { event.preventDefault(); await access.execute({ kind: "set-alias", alias: alias.trim(), resourceVersion: scene.accountVersion }); }}>
        <FormField id={aliasId} label={t("alias")} hint={t("aliasRule")}><Input id={aliasId} aria-describedby={`${aliasId}-hint`} autoComplete="off" maxLength={63} minLength={3} onChange={(event) => setAlias(event.target.value)} pattern={aliasPattern} placeholder={t("aliasPlaceholder")} required value={alias} /></FormField>
        <p className={styles.note}>{t("aliasChangeHint")}</p>
        <div><Button disabled={access.busy || access.loading || !alias.trim() || alias.trim() === scene.loginAlias} type="submit">{access.busy ? t("saving") : t("saveAlias")}</Button></div>
      </form> : <p className={styles.note}>{t("aliasAdminHint")}</p>}
    </Card.Body>
  </Card>;
}

function TenantDirectory({ scene }: { scene: AccountAccessScene }) {
  const t = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const [creating, setCreating] = useState(false);
  return <div className={styles.stack}>
    <Card>
      <ContentPage.Heading title={t("tenantAccounts")} actions={<Button disabled={access.busy || access.loading} onClick={() => setCreating(true)} size="small"><Plus aria-hidden="true" />{t("openTenant")}</Button>} />
      <Table aria-label={t("tenantTable")}><thead><tr><th scope="col">{t("tenant")}</th><th scope="col">{t("primaryLogin")}</th><th scope="col">{t("alias")}</th></tr></thead>
          <tbody>{scene.accounts.map((account) => <tr key={account.id}><td><strong>{account.name}</strong><small>{account.id}</small></td><td>{account.primaryLoginName}</td><td>{account.loginAlias ?? t("aliasUnset")}</td></tr>)}</tbody>
        </Table>
        {!scene.accounts.length ? <EmptyState title={t("noTenants")} /> : null}
      <Card.Footer><span className={styles.note}>{t("tenantScopeHint")}</span><div className={styles.actions}><Button disabled={access.busy || access.loading} onClick={() => access.accountsPage("")} size="small" variant="ghost">{t("firstPage")}</Button><Button disabled={access.busy || access.loading || !scene.nextAccountPage} onClick={() => access.accountsPage(scene.nextAccountPage!)} size="small" variant="secondary">{t("nextPage")}</Button></div></Card.Footer>
    </Card>
    {creating ? <CreateTenantDialog onClose={() => setCreating(false)} /> : null}
  </div>;
}

function PermissionCatalog() {
  const t = useTranslations("AccountAccess");
  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("permissions")}</Typography.Title><Typography.Text tone="muted">{t("permissionSubtitle")}</Typography.Text></div></Card.Header>
    <Card.Body className={styles.detail}>
      <p className={styles.note}>{t("defaultDenyHint")}</p>
      <Table aria-label={t("roleTable")}><thead><tr><th scope="col">{t("role")}</th><th scope="col">{t("roleScope")}</th><th scope="col">{t("roleCapabilities")}</th></tr></thead><tbody>{userRoles.map((role) => <tr key={role}><td><strong>{t(`roles.${role}`)}</strong><small>{role}</small></td><td><Badge status="neutral">{t("builtInRole")}</Badge><small>{t("currentAccountScope")}</small></td><td>{t(`roleDescriptions.${role}`)}</td></tr>)}</tbody></Table>
      <p className={styles.note}>{t("permissionLimits")}</p>
    </Card.Body>
  </Card>;
}


export function AccountAccessRenderer({ view = "overview", entityId, onNavigate }: { view?: AccountAccessView; entityId?: string; onNavigate(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const scene = access.scene;
  const workspace = access.workspace;
  const clearFeedback = access.clearFeedback;
  const workflow = view === "create-user" || view === "create-policy" || view === "create-group" || view === "create-role";
  useEffect(() => { clearFeedback(); }, [view, clearFeedback]);
  const denied = scene && ((!["overview", "settings", "roles", "tenants"].includes(view) && !scene.canManage) || (view === "tenants" && !scene.canCreateOrganizations));
  return <section aria-label={t("title")} aria-busy={access.loading || access.busy} className={styles.stack}>
    {access.error && !workflow ? <Alert status="danger">{t(`errors.${access.error}`)}</Alert> : null}
    {access.success && !workflow && view !== "policies" ? <Alert status="success">{t(access.success)}</Alert> : null}
    {access.workspaceError && !workflow && view !== "policies" ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}
    {access.loading ? scene ? <p className={styles.note} role="status">{t("loading")}</p> : <PageSkeleton label={t("loading")} layout={view === "overview" ? "dashboard" : "access"} /> : null}
    {scene ? denied ? <EmptyState title={t("accessDenied")} description={t("accessDeniedHint")} action={<Button onClick={() => onNavigate("overview")} variant="secondary">{t("backToOverview")}</Button>} /> :
      view === "overview" ? <AccountOverview scene={scene} onNavigate={onNavigate} /> :
      view === "users" ? <AccountUserDirectory key={entityId ?? "users"} entityId={entityId} scene={scene} onCreate={() => onNavigate("create-user")} onOpen={onNavigate} /> :
      view === "create-user" ? <CreateUserWizard onBack={() => onNavigate("users")} /> :
      view === "tenants" ? <TenantDirectory scene={scene} /> :
      view === "settings" ? <><UserSettings key={scene.accountVersion} scene={scene} />{workspace ? <AccessSecuritySettings workspace={workspace} /> : null}</> :
      view === "roles" ? workspace && scene.canManage ? <Tabs.Root defaultValue="roles"><Tabs.List aria-label={w("roles")}><Tabs.Trigger value="roles">{w("roles")}</Tabs.Trigger><Tabs.Trigger value="platform">{w("realRoles")}</Tabs.Trigger></Tabs.List><Tabs.Content value="roles"><AccessRoles key={entityId ?? "roles"} workspace={workspace} scene={scene} entityId={entityId} onCreate={() => onNavigate("create-role")} onOpen={onNavigate} /></Tabs.Content><Tabs.Content value="platform"><PermissionCatalog /></Tabs.Content></Tabs.Root> : <PermissionCatalog /> :
      !workspace ? <EmptyState title={w("notConnected")} description={w("notConnectedHint")} /> :
      view === "create-policy" ? <PolicyAuthoringWizard workspace={workspace} scene={scene} doneLabel={w("finishBack")} onBack={() => onNavigate("policies")} onDone={() => onNavigate("policies")} /> :
      view === "create-group" ? <GroupCreationWizard workspace={workspace} onBack={() => onNavigate("groups")} onDone={(id) => onNavigate("groups", id)} /> :
      view === "create-role" ? <RoleCreationWizard workspace={workspace} scene={scene} onBack={() => onNavigate("roles")} onDone={(id) => onNavigate("roles", id)} /> :
      view === "groups" ? <AccessGroups key={entityId ?? "groups"} entityId={entityId} workspace={workspace} scene={scene} onCreate={() => onNavigate("create-group")} onOpen={onNavigate} /> :
      view === "policies" ? <AccessPolicies key={entityId ?? "policies"} entityId={entityId} workspace={workspace} scene={scene} onCreate={() => onNavigate("create-policy")} onOpen={onNavigate} /> :
      view === "simulator" ? <AccessSimulator key={entityId ?? "simulator"} workspace={workspace} scene={scene} entityId={entityId} /> :
      view === "providers" ? <Tabs.Root defaultValue="providers"><Tabs.List aria-label={w("providers")}><Tabs.Trigger value="providers">{w("provider")}</Tabs.Trigger><Tabs.Trigger value="identities">{w("federatedIdentities")}</Tabs.Trigger></Tabs.List><Tabs.Content value="providers"><AccessProviders workspace={workspace} /></Tabs.Content><Tabs.Content value="identities"><AccessFederations workspace={workspace} /></Tabs.Content></Tabs.Root> :
      view === "federations" ? <AccessEnterpriseAccounts workspace={workspace} onUsers={() => onNavigate("users")} /> :
      view === "keys" ? <AccessCredentials workspace={workspace} scene={scene} /> :
      <AccessUserSso workspace={workspace} onProviders={() => onNavigate("providers")} /> : null}
  </section>;
}
