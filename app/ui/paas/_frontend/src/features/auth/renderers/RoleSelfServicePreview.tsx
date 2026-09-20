"use client";

import { useId, useRef, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Clock3, LogOut, Repeat2, ShieldCheck, UserRound } from "lucide-react";
import { Alert, Badge, Button, Card, ContentPage, FormField, Select, Typography } from "@ui/xiak";
import styles from "./RoleSelfServicePreview.module.css";

type PreviewRole = Readonly<{
  id: string;
  name: string;
  purpose: "productionLogs" | "releaseObserver";
  maxMinutes: number;
  resourceVersion: number;
}>;

type PreviewRoleSession = Readonly<{
  id: string;
  role: PreviewRole;
  issuedAt: string;
  expiresAt: string;
  requestId: string;
}>;

type PreviewScenario = "success" | "denied" | "conflict" | "uncertain";
type AttemptState = "idle" | "denied" | "conflict" | "uncertain" | "located" | "revoked";

const roles: readonly PreviewRole[] = [
  { id: "role-log-reviewer", name: "AssumeLogReviewRole", purpose: "productionLogs", maxMinutes: 60, resourceVersion: 4 },
  { id: "role-release-observer", name: "ReleaseObserverRole", purpose: "releaseObserver", maxMinutes: 30, resourceVersion: 2 }
];

const sourceUser = { id: "principal-qiao", loginName: "qiao", displayName: "乔发布工程师" } as const;
const account = { id: "org-xiak", name: "Xiak 科技" } as const;

export function RoleSelfServicePreview() {
  const t = useTranslations("RoleSelfService");
  const collection = useTranslations("Collection");
  const format = useFormatter();
  const durationId = useId();
  const scenarioId = useId();
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const activeHeading = useRef<HTMLHeadingElement>(null);
  const [selected, setSelected] = useState<PreviewRole | null>(null);
  const [duration, setDuration] = useState("30");
  const [scenario, setScenario] = useState<PreviewScenario>("success");
  const [attemptState, setAttemptState] = useState<AttemptState>("idle");
  const [intentNumber, setIntentNumber] = useState(1);
  const [catalogRevision, setCatalogRevision] = useState(0);
  const [activeSession, setActiveSession] = useState<PreviewRoleSession | null>(null);
  const [confirmingExit, setConfirmingExit] = useState(false);

  const requestId = selected ? `ux-assume-${selected.id}-${String(intentNumber).padStart(3, "0")}` : "";
  const attemptLocked = attemptState !== "idle";

  const selectRole = (role: PreviewRole) => {
    setSelected(role);
    setDuration(String(Math.min(30, role.maxMinutes)));
    setAttemptState("idle");
    setConfirmingExit(false);
    window.setTimeout(() => reviewHeading.current?.focus(), 0);
  };

  const assume = () => {
    if (!selected) return;
    if (scenario !== "success") {
      setAttemptState(scenario);
      return;
    }
    const issuedAt = "2026-09-20T10:00:00+08:00";
    const expiresAt = new Date(Date.parse(issuedAt) + Number(duration) * 60_000).toISOString();
    setActiveSession({ id: `MOCK-RS-${selected.id}`, role: selected, issuedAt, expiresAt, requestId });
    setConfirmingExit(false);
    window.setTimeout(() => activeHeading.current?.focus(), 0);
  };

  const exit = () => {
    setActiveSession(null);
    setSelected(null);
    setAttemptState("idle");
    setIntentNumber((current) => current + 1);
    setConfirmingExit(false);
  };

  const refreshEligibility = () => {
    setSelected(null);
    setAttemptState("idle");
    setIntentNumber((current) => current + 1);
  };

  const refreshAfterConflict = () => {
    setSelected(null);
    setAttemptState("idle");
    setIntentNumber((current) => current + 1);
    setCatalogRevision((current) => current + 1);
  };

  const startNewIntent = () => {
    setIntentNumber((current) => current + 1);
    setAttemptState("idle");
    setScenario("success");
  };

  const formatTime = (value: string) => format.dateTime(new Date(value), {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZoneName: "short"
  });

  const headingActions = activeSession ? <ContentPage.Commands label={collection("pageActions")} secondary={[{
    id: "exit-role", label: t("exitRole"), icon: <LogOut aria-hidden="true" />, danger: true,
    onSelect: () => setConfirmingExit(true)
  }]} /> : undefined;

  return <section aria-label={t("title")} className={styles.root}>
    <ContentPage.Heading title={t("title")} scrollKey="role-self-service-preview" actions={headingActions} />
    <Alert status="info"><Repeat2 aria-hidden="true" />{t("mockBoundary")}</Alert>

    <Card>
      <Card.Header className={styles.actorHeader}>
        <div><Typography.Title as="h2" level={3}>{t("actorTitle")}</Typography.Title><Typography.Text tone="muted">{t("actorHint")}</Typography.Text></div>
        <Badge status="neutral">{t("scenarioActor")}</Badge>
      </Card.Header>
      <Card.Body>
        <dl className={styles.actorFacts}>
          <div><dt>{t("sourceUser")}</dt><dd><strong>{sourceUser.displayName}</strong><span>{sourceUser.loginName} · {sourceUser.id}</span></dd></div>
          <div><dt>{t("account")}</dt><dd><strong>{account.name}</strong><span>{account.id}</span></dd></div>
          <div><dt>{t("managementAuthority")}</dt><dd><strong>{t("none")}</strong><span>{t("assumeOnly")}</span></dd></div>
        </dl>
        <div className={styles.scenarioControl}>
          <FormField id={scenarioId} label={t("scenario")} hint={t("scenarioHint")}>
            <Select disabled={attemptLocked} id={scenarioId} value={scenario} options={([
              "success", "denied", "conflict", "uncertain"
            ] as const).map((value) => ({ value, label: t(`scenarios.${value}`) }))} onValueChange={(value) => {
              setScenario(value as PreviewScenario);
              setAttemptState("idle");
            }} />
          </FormField>
        </div>
      </Card.Body>
    </Card>

    {activeSession ? <Card>
      <Card.Header className={styles.sessionHeader}>
        <div><h2 className={styles.focusHeading} ref={activeHeading} tabIndex={-1}>{t("activeTitle")}</h2><Typography.Text tone="muted">{t("activeHint")}</Typography.Text></div>
        <Badge status="success">{t("previewRoleIdentity")}</Badge>
      </Card.Header>
      <Card.Body className={styles.sessionBody}>
        <div className={styles.roleIdentity}><span aria-hidden="true"><ShieldCheck /></span><div><strong>{activeSession.role.name}</strong><small>{activeSession.role.id}</small></div></div>
        <dl className={styles.sessionFacts}>
          <div><dt>{t("sessionId")}</dt><dd><code>{activeSession.id}</code></dd></div>
          <div><dt>{t("issuedAt")}</dt><dd><time dateTime={activeSession.issuedAt}>{formatTime(activeSession.issuedAt)}</time></dd></div>
          <div><dt>{t("expiresAt")}</dt><dd><time dateTime={activeSession.expiresAt}>{formatTime(activeSession.expiresAt)}</time></dd></div>
          <div><dt>{t("sourceUser")}</dt><dd>{sourceUser.loginName}</dd></div>
        </dl>
        <Alert status="warning">{t("noCredential")}</Alert>
        {confirmingExit ? <Alert className={styles.confirmation} status="warning">
          <div><strong>{t("confirmExitTitle")}</strong><span>{t("confirmExitHint")}</span></div>
          <div><Button onClick={exit} size="small" variant="danger">{t("confirmExit")}</Button><Button onClick={() => setConfirmingExit(false)} size="small" variant="ghost">{t("cancel")}</Button></div>
        </Alert> : null}
      </Card.Body>
    </Card> : !selected ? <div className={styles.discovery}>
      <div className={styles.sectionHeading}><div><Typography.Title as="h2" level={3}>{t("discoveryTitle")}</Typography.Title><Typography.Text tone="muted">{t("discoveryHint")}</Typography.Text></div><Badge status="neutral">{t("roleCount", { count: roles.length })}</Badge></div>
      <div className={styles.roleGrid}>{roles.map((role) => {
        const presentedRole = { ...role, resourceVersion: role.resourceVersion + catalogRevision };
        return <Card key={role.id}>
          <Card.Header className={styles.roleHeader}><div><Typography.Title as="h3" level={3}>{presentedRole.name}</Typography.Title><code>{presentedRole.id}</code></div><Badge status="success">{t("eligible")}</Badge></Card.Header>
          <Card.Body className={styles.roleBody}>
            <p>{t(`purposes.${presentedRole.purpose}`)}</p>
            <div className={styles.roleMeta}><span><Clock3 aria-hidden="true" />{t("maxDuration", { max: presentedRole.maxMinutes })}</span><span>{t("resourceVersion", { version: presentedRole.resourceVersion })}</span></div>
            <Button aria-label={t("reviewRoleNamed", { name: presentedRole.name })} onClick={() => selectRole(presentedRole)} variant="secondary">{t("reviewRole")}</Button>
          </Card.Body>
        </Card>;
      })}</div>
      <Alert status="info"><ShieldCheck aria-hidden="true" />{t("discoveryBoundary")}</Alert>
    </div> : null}

    {selected && !activeSession ? <Card>
      <Card.Header><div><h2 className={styles.focusHeading} ref={reviewHeading} tabIndex={-1}>{t("reviewTitle")}</h2><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div></Card.Header>
      <Card.Body className={styles.reviewBody}>
        <dl className={styles.reviewFacts}>
          <div><dt>{t("role")}</dt><dd><strong>{selected.name}</strong><span>{selected.id} · {t("resourceVersion", { version: selected.resourceVersion })}</span></dd></div>
          <div><dt>{t("account")}</dt><dd><strong>{account.name}</strong><span>{account.id}</span></dd></div>
          <div><dt>{t("sourceUser")}</dt><dd><strong>{sourceUser.displayName}</strong><span>{sourceUser.id}</span></dd></div>
        </dl>
        <FormField id={durationId} label={t("duration")} hint={t("durationHint", { max: selected.maxMinutes })}><Select disabled={attemptState !== "idle"} id={durationId} value={duration} options={[15, 30, 60].filter((minutes) => minutes <= selected.maxMinutes).map((minutes) => ({ value: String(minutes), label: t("minutes", { max: minutes }) }))} onValueChange={setDuration} /></FormField>
        <Alert status="warning">{t("unknownOutcome", { id: requestId })}</Alert>

        {attemptState === "denied" ? <Alert className={styles.attempt} status="danger">
          <div><strong>{t("deniedTitle")}</strong><code>iam.authorization.denied</code><span>{t("deniedHint")}</span></div>
          <Button onClick={refreshEligibility} size="small" variant="secondary">{t("refreshEligibility")}</Button>
        </Alert> : null}

        {attemptState === "conflict" ? <Alert className={styles.attempt} status="warning">
          <div><strong>{t("conflictTitle")}</strong><code>iam.state.conflict</code><span>{t("conflictHint")}</span></div>
          <Button onClick={refreshAfterConflict} size="small" variant="secondary">{t("refreshAfterConflict")}</Button>
        </Alert> : null}

        {attemptState === "uncertain" ? <Alert className={styles.attempt} status="warning">
          <div><strong>{t("uncertainTitle")}</strong><span>{t("uncertainHint", { id: requestId })}</span></div>
          <Button onClick={() => setAttemptState("located")} size="small" variant="secondary">{t("queryOriginal")}</Button>
        </Alert> : null}

        {attemptState === "located" ? <Alert className={styles.attempt} status="warning">
          <div><strong>{t("locatedTitle")}</strong><span>{t("locatedHint", { id: `MOCK-RS-${selected.id}` })}</span><span>{t("credentialUnavailable")}</span></div>
          <Button onClick={() => setAttemptState("revoked")} size="small" variant="danger">{t("revokeOriginal")}</Button>
        </Alert> : null}

        {attemptState === "revoked" ? <Alert className={styles.attempt} status="success">
          <div><strong>{t("revokedTitle")}</strong><span>{t("revokedHint")}</span></div>
          <Button onClick={startNewIntent} size="small" variant="secondary">{t("newIntent")}</Button>
        </Alert> : null}

        {attemptState === "idle" ? <div className={styles.reviewActions}><Button onClick={assume}><UserRound aria-hidden="true" />{t("assumePreview")}</Button><Button onClick={() => setSelected(null)} variant="ghost">{t("cancel")}</Button></div> : null}
      </Card.Body>
    </Card> : null}
  </section>;
}
