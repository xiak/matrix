"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Clock3, LogOut, Repeat2, ShieldCheck, UserRound } from "lucide-react";
import { Alert, Badge, Button, Card, ContentPage, FormField, PageSkeleton, Select, Typography } from "@ui/xiak";
import { useRoleSession } from "../application/RoleSessionProvider";
import { useSession } from "../application/SessionProvider";
import type { AssumableRole } from "../domain/roles";
import styles from "./RoleSelfServicePreview.module.css";

function durationOptions(maximum: number): number[] {
  const candidates = [900, 1800, 3600, 7200, 14400, maximum].filter((value) => value >= 60 && value <= maximum);
  return [...new Set(candidates)].sort((left, right) => left - right);
}

export function LiveRoleSelfService() {
  const t = useTranslations("RoleSelfServiceLive");
  const collection = useTranslations("Collection");
  const format = useFormatter();
  const roleSession = useRoleSession();
  const session = useSession();
  const durationId = useId();
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const activeHeading = useRef<HTMLHeadingElement>(null);
  const [localSelected, setSelected] = useState<AssumableRole | null>(null);
  const [localDuration, setDuration] = useState(3600);
  const [confirmingExit, setConfirmingExit] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current || roleSession.stage !== "idle" || !roleSession.supported) return;
    started.current = true;
    void roleSession.discover();
  }, [roleSession]);

  useEffect(() => {
    if (roleSession.stage === "role-active") window.setTimeout(() => activeHeading.current?.focus(), 0);
  }, [roleSession.stage]);

  const current = session.current;
  const formatTime = (value: string) => format.dateTime(new Date(value), {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZoneName: "short"
  });
  const selected = roleSession.intent?.role ?? localSelected;
  const duration = roleSession.intent?.durationSeconds ?? localDuration;
  const options = useMemo(() => selected ? durationOptions(selected.maxSessionDurationSeconds) : [], [selected]);
  const locked = Boolean(roleSession.intent) || roleSession.busy !== null;
  const sourceAccount = roleSession.directory?.accountId ?? current?.session.organizationId ?? "—";
  const sourceUserId = roleSession.directory?.sourceUserId ?? current?.session.principalId ?? "—";
  const actionSession = roleSession.identity?.session ?? roleSession.observedSession;
  const discoveryVisible = !selected && roleSession.stage !== "role-active" &&
    !["exit-unknown", "source-validation-unknown", "role-expired"].includes(roleSession.stage);

  const selectRole = (role: AssumableRole) => {
    const choices = durationOptions(role.maxSessionDurationSeconds);
    setSelected(role);
    setDuration(choices.includes(3600) ? 3600 : choices.at(-1) ?? 60);
    window.setTimeout(() => reviewHeading.current?.focus(), 0);
  };

  const restart = async () => {
    setSelected(null);
    roleSession.clearAttempt();
    await roleSession.discover();
  };

  const headingActions = roleSession.stage === "role-active" ? <ContentPage.Commands label={collection("pageActions")} secondary={[{
    id: "exit-role", label: t("exitRole"), icon: <LogOut aria-hidden="true" />, danger: true,
    onSelect: () => setConfirmingExit(true)
  }]} /> : undefined;

  return <section aria-label={t("title")} aria-busy={roleSession.busy !== null} className={styles.root}>
    <ContentPage.Heading title={t("title")} scrollKey="role-self-service-live" actions={headingActions} />
    <Alert status="info"><Repeat2 aria-hidden="true" />{t("liveBoundary")}</Alert>

    {roleSession.stage === "role-active" && roleSession.identity ? <Card>
      <Card.Header className={styles.sessionHeader}>
        <div><h2 className={styles.focusHeading} ref={activeHeading} tabIndex={-1}>{t("activeTitle")}</h2><Typography.Text tone="muted">{t("activeHint")}</Typography.Text></div>
        <Badge status="success">{t("roleIdentity")}</Badge>
      </Card.Header>
      <Card.Body className={styles.sessionBody}>
        <div className={styles.roleIdentity}><span aria-hidden="true"><ShieldCheck /></span><div><strong>{roleSession.identity.role.name}</strong><small>{roleSession.identity.role.id}</small></div></div>
        <dl className={styles.sessionFacts}>
          <div><dt>{t("account")}</dt><dd><strong>{roleSession.identity.account.displayName}</strong><span>{roleSession.identity.account.id}</span></dd></div>
          <div><dt>{t("sourceUser")}</dt><dd><strong>{roleSession.identity.sourceUser.displayName}</strong><span>{roleSession.identity.sourceUser.loginName}</span></dd></div>
          <div><dt>{t("issuedAt")}</dt><dd><time dateTime={roleSession.identity.session.issuedAt}>{formatTime(roleSession.identity.session.issuedAt)}</time></dd></div>
          <div><dt>{t("expiresAt")}</dt><dd><time dateTime={roleSession.identity.session.expiresAt}>{formatTime(roleSession.identity.session.expiresAt)}</time></dd></div>
        </dl>
        <Alert status="warning">{t("continuousAuthorization")}</Alert>
        {confirmingExit ? <Alert className={styles.confirmation} status="warning"><div><strong>{t("confirmExitTitle")}</strong><span>{t("confirmExitHint")}</span></div><div><Button disabled={roleSession.busy !== null} onClick={() => { setConfirmingExit(false); void roleSession.exitRole(); }} size="small" variant="danger">{t("confirmExit")}</Button><Button disabled={roleSession.busy !== null} onClick={() => setConfirmingExit(false)} size="small" variant="ghost">{t("cancel")}</Button></div></Alert> : null}
      </Card.Body>
    </Card> : null}

    {roleSession.stage === "exit-unknown" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("exitUnknownTitle")}</strong><span>{t("exitUnknownHint", { id: roleSession.intent?.logoutRequestId ?? "—" })}</span></div><div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.retryExit()} size="small" variant="secondary">{t("retrySameExit")}</Button><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.revokeAndRestoreSource()} size="small" variant="danger">{t("revokeFromSource")}</Button></div></div></Alert> : null}

    {roleSession.stage === "source-validation-unknown" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("sourceUnknownTitle")}</strong><span>{t("sourceUnknownHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.restoreSource()} size="small" variant="secondary">{t("revalidateSource")}</Button></div></Alert> : null}

    {roleSession.stage === "role-expired" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("expiredTitle")}</strong><span>{t("expiredHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.restoreSource()} size="small" variant="secondary">{t("returnToSource")}</Button></div></Alert> : null}

    {roleSession.stage !== "role-active" && !["exit-unknown", "source-validation-unknown", "role-expired"].includes(roleSession.stage) ? <Card>
      <Card.Header className={styles.actorHeader}><div><Typography.Title as="h2" level={3}>{t("sourceTitle")}</Typography.Title><Typography.Text tone="muted">{t("sourceHint")}</Typography.Text></div><Badge status="neutral">{t("member")}</Badge></Card.Header>
      <Card.Body><dl className={styles.actorFacts}>
        <div><dt>{t("sourceUser")}</dt><dd><strong>{current?.loginName ?? "—"}</strong><span>{sourceUserId}</span></dd></div>
        <div><dt>{t("account")}</dt><dd><strong>{sourceAccount}</strong><span>{t("accountSelectedByCredential")}</span></dd></div>
        <div><dt>{t("managementAuthority")}</dt><dd><strong>{t("none")}</strong><span>{t("assumeOnly")}</span></dd></div>
      </dl></Card.Body>
    </Card> : null}

    {roleSession.error && (roleSession.directory || selected) && roleSession.stage !== "exit-unknown" && roleSession.stage !== "source-validation-unknown" ? <Alert status="danger">{t(`errors.${roleSession.error}`)}</Alert> : null}

    {discoveryVisible ? <div aria-busy={roleSession.busy === "discover" || undefined} className={styles.discovery}>
      <div className={styles.sectionHeading}><div><Typography.Title as="h2" level={3}>{t("discoveryTitle")}</Typography.Title><Typography.Text tone="muted">{t("discoveryHint")}</Typography.Text></div>{roleSession.directory ? <Badge status="neutral">{t("roleCount", { count: roleSession.directory.items.length })}</Badge> : null}</div>
      <Alert status="info"><ShieldCheck aria-hidden="true" />{t("discoveryBoundary")}</Alert>
      {roleSession.busy === "discover" && !roleSession.directory ? <PageSkeleton label={t("loadingRoles")} labelVisible={false} layout="cards" /> : null}
      {roleSession.error && !roleSession.directory && roleSession.busy === null ? <Alert className={styles.attempt} status="danger"><div><div><strong>{t("discoveryUnavailableTitle")}</strong><span>{t("discoveryUnavailableHint")}</span></div><Button onClick={() => void roleSession.discover()} size="small" variant="secondary">{t("retryDiscovery")}</Button></div></Alert> : null}
      {roleSession.directory?.items.length ? <div className={styles.roleGrid}>{roleSession.directory.items.map((role) => <Card key={role.roleId}>
        <Card.Header className={styles.roleHeader}><div><Typography.Title as="h3" level={3}>{role.name}</Typography.Title><code>{role.roleId}</code></div><Badge status="success">{t("eligible")}</Badge></Card.Header>
        <Card.Body className={styles.roleBody}><p>{t("eligibleHint")}</p><div className={styles.roleMeta}><span><Clock3 aria-hidden="true" />{t("maxDuration", { max: Math.floor(role.maxSessionDurationSeconds / 60) })}</span><span>{t("resourceVersion", { version: role.resourceVersion })}</span></div><Button aria-label={t("reviewRoleNamed", { name: role.name })} onClick={() => selectRole(role)} variant="secondary">{t("reviewRole")}</Button></Card.Body>
      </Card>)}</div> : roleSession.directory ? <Alert status="info">{roleSession.directory.nextAfter ? t("sparsePage") : t("noRoles")}</Alert> : null}
      {roleSession.directory?.nextAfter ? <Button disabled={roleSession.busy !== null} onClick={() => void roleSession.discover(false)} variant="secondary">{roleSession.busy === "more" ? t("loadingMore") : t("loadMore")}</Button> : null}
    </div> : null}

    {selected && roleSession.stage !== "role-active" && !["exit-unknown", "source-validation-unknown", "role-expired"].includes(roleSession.stage) ? <Card>
      <Card.Header><div><h2 className={styles.focusHeading} ref={reviewHeading} tabIndex={-1}>{t("reviewTitle")}</h2><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div></Card.Header>
      <Card.Body className={styles.reviewBody}>
        <dl className={styles.reviewFacts}>
          <div><dt>{t("role")}</dt><dd><strong>{selected.name}</strong><span>{selected.roleId} · {t("resourceVersion", { version: selected.resourceVersion })}</span></dd></div>
          <div><dt>{t("account")}</dt><dd><strong>{selected.accountId}</strong><span>{t("accountSelectedByCredential")}</span></dd></div>
          <div><dt>{t("sourceUser")}</dt><dd><strong>{current?.loginName ?? "—"}</strong><span>{sourceUserId}</span></dd></div>
        </dl>
        <FormField id={durationId} label={t("duration")} hint={t("durationHint", { max: Math.floor(selected.maxSessionDurationSeconds / 60) })}><Select disabled={locked} id={durationId} value={String(duration)} options={options.map((seconds) => ({ value: String(seconds), label: t("minutes", { max: Math.ceil(seconds / 60) }) }))} onValueChange={(value) => setDuration(Number(value))} /></FormField>
        <Alert status="warning">{t("intentBoundary", { id: roleSession.intent?.requestId ?? t("assignedOnSubmit") })}</Alert>

        {roleSession.stage === "denied" ? <Alert className={styles.attempt} status="danger"><div><div><strong>{t("deniedTitle")}</strong><span>{t("deniedHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void restart()} size="small" variant="secondary">{t("refreshEligibility")}</Button></div></Alert> : null}
        {roleSession.stage === "conflict" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("conflictTitle")}</strong><span>{t("conflictHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.locateOriginal()} size="small" variant="secondary">{t("queryOriginal")}</Button></div></Alert> : null}
        {roleSession.stage === "assume-unknown" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("uncertainTitle")}</strong><span>{t("uncertainHint", { id: roleSession.intent?.requestId ?? "—" })}</span></div><div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.locateOriginal()} size="small" variant="secondary">{t("queryOriginal")}</Button><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.retryAssume()} size="small" variant="ghost">{t("retryExactIntent")}</Button></div></div></Alert> : null}
        {roleSession.stage === "not-found" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("notFoundTitle")}</strong><span>{t("notFoundHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.retryAssume()} size="small" variant="secondary">{t("retryExactIntent")}</Button></div></Alert> : null}
        {roleSession.stage === "located" && actionSession ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("locatedTitle")}</strong><span>{t("locatedHint", { id: actionSession.id })}</span><span>{t("credentialUnavailable")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.revokeOriginal()} size="small" variant="danger">{t("revokeOriginal")}</Button></div></Alert> : null}
        {roleSession.stage === "revoked" ? <Alert className={styles.attempt} status="success"><div><div><strong>{t("revokedTitle")}</strong><span>{t("revokedHint")}</span></div><Button disabled={roleSession.busy !== null} onClick={() => void restart()} size="small" variant="secondary">{t("newIntent")}</Button></div></Alert> : null}
        {roleSession.stage === "activation-unknown" ? <Alert className={styles.attempt} status="warning"><div><div><strong>{t("activationUnknownTitle")}</strong><span>{t("activationUnknownHint")}</span></div><div><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.retryActivation()} size="small" variant="secondary">{t("recheckRoleIdentity")}</Button><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.exitRole()} size="small" variant="danger">{t("terminateUnverifiedRole")}</Button></div></div></Alert> : null}

        {(roleSession.stage === "ready" || roleSession.stage === "idle") && !roleSession.intent ? <div className={styles.reviewActions}><Button disabled={roleSession.busy !== null} onClick={() => void roleSession.assume(selected, duration)}><UserRound aria-hidden="true" />{roleSession.busy === "assume" ? t("assuming") : t("assume")}</Button><Button disabled={roleSession.busy !== null} onClick={() => setSelected(null)} variant="ghost">{t("cancel")}</Button></div> : null}
      </Card.Body>
    </Card> : null}
  </section>;
}
