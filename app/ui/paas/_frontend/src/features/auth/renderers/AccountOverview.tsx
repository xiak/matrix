"use client";

import { useState } from "react";
import Link from "next/link";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight, Check, Copy, KeyRound, Plus, ShieldCheck, UserCheck, Users } from "lucide-react";
import { Alert, Badge, Button, Card, Statistic, Table, Typography } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { WorkspaceCollection, WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccessReports } from "./AccessReports";
import { policyUsageCounts } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import styles from "./AccountAccessRenderer.module.css";

// Only non-secret account identifiers may be passed to this control.
export function AccountIdentifier({ value, label }: { value: string; label: string }) {
  const t = useTranslations("AccountAccess");
  const [copied, setCopied] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  return <div className={styles.identifier}>
    <Typography.Code>{value}</Typography.Code>
    <Button aria-label={t(copied === value ? "copiedIdentifier" : "copyIdentifier", { name: label })} iconOnly size="small" variant="ghost" onClick={async () => {
      try { await navigator.clipboard.writeText(value); setCopied(value); setFailed(false); }
      catch { setCopied(null); setFailed(true); }
    }}>{copied === value ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}</Button>
    <span className={styles.copyFeedback} role="status">{failed ? t("copyFailed") : copied === value ? t("copied") : ""}</span>
  </div>;
}

function AccountIdentityCard({ scene }: { scene: AccountAccessScene }) {
  const t = useTranslations("AccountAccess");
  return <Card>
    <Card.Header><Typography.Title as="h2" level={3}>{t("accountIdentity")}</Typography.Title><Badge status="info">{scene.isPrimary ? t("primary") : t("child")}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <div className={styles.accountName}><span className={styles.accountAvatar}><ShieldCheck aria-hidden="true" /></span><div><strong>{scene.accountName}</strong><small>{t("ownership")}</small></div></div>
      <dl className={styles.compactFacts}>
        <div><dt>{t("signedIn")}</dt><dd>{scene.identityLabel}</dd></div>
        <div><dt>{t("currentLoginName")}</dt><dd>{scene.loginName}</dd></div>
        <div><dt>{t("accountId")}</dt><dd><AccountIdentifier label={t("accountId")} value={scene.accountId} /></dd></div>
        <div><dt>{t("directPolicyAttachments")}</dt><dd>{scene.identityAttachments.map((attachment) => attachment.label).join(" · ") || t("noGrantLabel")}</dd></div>
      </dl>
    </Card.Body>
  </Card>;
}

export function AccountOverview({ scene, onNavigate }: { scene: AccountAccessScene; onNavigate(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("AccountAccess");
  const format = useFormatter();
  const w = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const workspace = access.workspace;
  const [showEvents, setShowEvents] = useState(false);
  const pending = scene.users.filter((user) => user.state === "passwordChangeRequired").length;
  const ungranted = scene.users.filter((user) => user.attachments.length === 0).length;
  const highPolicies = workspace?.policies.filter((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)?.document;
    return document && includesPermissionManagement(document);
  }) ?? [];
  const highPolicyIds = new Set(highPolicies.map((policy) => policy.id));
  const elevatedUsers = workspace ? scene.users.filter((user) =>
    workspace.userPolicies[user.id]?.some((id) => highPolicyIds.has(id)) ||
    workspace.groups.some((group) => group.memberIds.includes(user.id) && group.policyIds.some((id) => highPolicyIds.has(id)))).length : null;
  const directlyAttachedUsers = scene.users.filter((user) => user.attachments.length > 0).length;
  const active = scene.users.filter((user) => user.enabled).length;
  const open = (view: AccountAccessView, id?: string) => ({ preventDefault }: { preventDefault(): void }) => { preventDefault(); onNavigate(view, id); };
if (showEvents && workspace) return <WorkspaceDetail title={w("sensitiveOperations")} onBack={() => setShowEvents(false)}><p className={styles.note}>{w("eventHistoryHint")}</p><WorkspaceCollection embedded title={w("sensitiveOperations")} description={w("eventHistoryHint")} items={workspace.events.map((event) => ({ ...event, name: w(`events.${event.action}`) }))} keywords={(event) => event.target} columns={[w("event"), w("target"), w("time")]} row={(event) => <><td>{event.name}</td><td>{event.target}</td><td><WorkspaceTime value={event.at} /></td></>} /></WorkspaceDetail>;
  return <div className={styles.accessOverview + " " + styles.stack}>
    {workspace ? <div className={styles.workspaceMetrics} aria-label={t("userSummary")}>{([
      ["users", "subusers", scene.users.length],
      ["groups", "groups", workspace.groups.length],
      ["policies", "customPolicyCount", workspace.policies.filter((policy) => policy.kind === "custom").length],
      ["roles", "roles", workspace.roles.length],
      ["providers", "providerCount", workspace.providers.length]
    ] as const).map(([view, label, count]) => <Link className={styles.metricLink} key={view} href={`/console/access/${view}/`} onNavigate={open(view)}><span>{w(label)}</span><strong>{format.number(count)}</strong></Link>)}</div> : null}
    <div className={styles.overviewGrid}>
      <div className={styles.stack}>
        <div className={styles.overviewToolbar}>
          <div><Typography.Title as="h2" level={3}>{t("overviewSummary")}</Typography.Title><p className={styles.note}>{t("accountWide")}</p></div>
          {scene.canManage ? <Button disabled={access.busy || access.loading} onClick={() => onNavigate("create-user")}><Plus aria-hidden="true" />{t("createUser")}</Button> : null}
        </div>
        {scene.canManage ? <>
          {!workspace ? <div aria-label={t("userSummary")} className={styles.overviewMetrics}>
            <Statistic label={t("totalUsers")} value={format.number(scene.users.length)} icon={<Users />} />
            <Statistic label={t("enabledUsers")} value={format.number(active)} icon={<UserCheck />} status="success" />
            <Statistic label={t("ungrantedUsers")} value={format.number(ungranted)} icon={<ShieldCheck />} />
            <Statistic label={t("pendingPasswords")} value={format.number(pending)} icon={<KeyRound />} status={pending ? "warning" : "neutral"} />
          </div> : null}
          {!scene.directoryComplete ? <Alert status="info">{t("partialSummary")}</Alert> : null}
          {workspace ? <Card><Card.Header><Typography.Title as="h2" level={3}>{w("sensitiveOperations")}</Typography.Title><Button variant="ghost" size="small" onClick={() => setShowEvents(true)}>{w("viewAllEvents")}<ArrowRight aria-hidden="true" /></Button></Card.Header><Table className={styles.compactTable} aria-label={w("sensitiveOperations")}><thead><tr><th scope="col">{w("event")}</th><th scope="col">{w("target")}</th><th scope="col">{w("time")}</th></tr></thead><tbody>{workspace.events.slice(0, 5).map((event) => <tr key={event.id}><td>{w(`events.${event.action}`)}</td><td>{event.target}</td><td><WorkspaceTime value={event.at} /></td></tr>)}</tbody></Table></Card> : null}
          <Card>
            <Card.Header><Typography.Title as="h2" level={3}>{t("accessChecklist")}</Typography.Title><Button asChild size="small" variant="ghost"><Link href="/console/access/users/" onNavigate={open("users")}>{t("viewUsers")}<ArrowRight aria-hidden="true" /></Link></Button></Card.Header>
            <Card.Body className={styles.checklist}>
              <div><span className={styles.checklistIcon}><Users aria-hidden="true" /></span><div><strong>{t("delegateTitle")}</strong><p>{t("delegateHint")}</p></div><Badge status={scene.users.length ? "success" : "neutral"}>{t("userCount", { count: scene.users.length })}</Badge></div>
              <div><span className={styles.checklistIcon}><ShieldCheck aria-hidden="true" /></span><div><strong>{workspace ? t("reviewAdmins") : t("reviewPolicyAttachments")}</strong><p>{workspace ? w("reviewPrivilegeHint") : t("managementSnapshotHint")}</p></div><Badge status={(elevatedUsers ?? directlyAttachedUsers) ? "warning" : "neutral"}>{t("userCount", { count: elevatedUsers ?? directlyAttachedUsers })}</Badge></div>
              <div><span className={styles.checklistIcon}><KeyRound aria-hidden="true" /></span><div><strong>{t("firstLoginTitle")}</strong><p>{t("firstLoginHint")}</p></div><Badge status={pending ? "warning" : "success"}>{t("pendingCount", { count: pending })}</Badge></div>
            </Card.Body>
          </Card>
        </> : <Alert>{t("ownAccountHint")}</Alert>}
        <Card>
          <Card.Header><Typography.Title as="h2" level={3}>{t("permissionPrinciples")}</Typography.Title><Button asChild size="small" variant="ghost"><Link href={workspace ? "/console/access/roles/" : "/console/access/policies/"} onNavigate={open(workspace ? "roles" : "policies")}>{t(workspace ? "viewRoles" : "viewPolicies")}<ArrowRight aria-hidden="true" /></Link></Button></Card.Header>
          <Card.Body><p className={styles.note}>{t("defaultDenyHint")}</p></Card.Body>
        </Card>
        {workspace ? <Card>
          <Card.Header><Typography.Title as="h2" level={3}>{w("highPolicies")}</Typography.Title></Card.Header>
          <Card.Body><p className={styles.note}>{w("highPoliciesHint")}</p></Card.Body>
          <Table className={styles.compactTable} aria-label={w("highPolicies")}>
            <thead><tr><th scope="col">{w("name")}</th><th scope="col">{w("associations")}</th></tr></thead>
            <tbody>{highPolicies.map((policy) => <tr key={policy.id}><td><Link className={styles.userLink} href={`/console/access/policies/?id=${encodeURIComponent(policy.id)}`} onNavigate={open("policies", policy.id)}>{policy.name}</Link></td><td>{policyUsageCounts(workspace, policy.id).total}</td></tr>)}</tbody>
          </Table>
        </Card> : null}
      </div>
      <aside className={styles.stack}>
        <AccountIdentityCard scene={scene} />
        <Card>
          <Card.Header><Typography.Title as="h2" level={3}>{t("subuserSignIn")}</Typography.Title><Button asChild size="small" variant="ghost"><Link href="/console/access/settings/" onNavigate={open("settings")}>{t("settings")}<ArrowRight aria-hidden="true" /></Link></Button></Card.Header>
          <Card.Body className={styles.detail}>
            <p className={styles.note}>{t("subuserSignInHint")}</p>
            <div><p className={styles.fieldCaption}>{t("idLogin")}</p><AccountIdentifier label={t("idLogin")} value={`username@${scene.accountId}`} /></div>
            {scene.loginAlias ? <div><p className={styles.fieldCaption}>{t("aliasLogin")}</p><AccountIdentifier label={t("aliasLogin")} value={`username@${scene.loginAlias}`} /></div> : <p className={styles.note}>{t("aliasPending")}</p>}
          </Card.Body>
        </Card>
        {workspace ? <><Card>
          <Card.Header><Typography.Title as="h2" level={3}>{w("securityGuide")}</Typography.Title></Card.Header>
          <Card.Body className={styles.checklist}>{([
            ["groups", "guideGroups", w("guideGroupsHint", { count: workspace.groups.filter((group) => group.memberIds.length > 0 && group.policyIds.length > 0).length })],
            ["keys", "guideKeys", w("guideKeysHint", { count: workspace.keys.filter((key) => key.enabled).length })],
            ["settings", "guideMfa", w(workspace.settings.loginProtection ? "guideProtectionSaved" : "guideProtectionUnset")]
          ] as const).map(([view, label, hint]) => <div key={view}><div><strong>{w(label)}</strong><p>{hint}</p></div><Button asChild variant="ghost" size="small"><Link aria-label={w(label)} href={`/console/access/${view}/`} onNavigate={open(view)}>{w("view")}<ArrowRight aria-hidden="true" /></Link></Button></div>)}</Card.Body>
        </Card><AccessReports workspace={workspace} scene={scene} /></> : null}
      </aside>
    </div>
  </div>;
}
