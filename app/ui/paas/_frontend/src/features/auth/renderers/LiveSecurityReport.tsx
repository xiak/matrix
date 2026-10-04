"use client";

import { useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Download, FilePlus2 } from "lucide-react";
import { Alert, Badge, Button, Card, ContentPage, FormField, Input, TableSkeleton, Tabs, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { SecurityReportClient } from "../application/AccountAccessProvider";
import { accountSecurityReportLimits, type AccountSecurityReport, type AccountSecurityReportCreation } from "../domain/securityReports";
import { WorkspaceCollection, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type Operation = "create" | "read" | "download";
type ReportFailure = { operation: Operation; kind: "forbidden" | "notFound" | "conflict" | "invalid" | "unavailable" };

function reportFailure(operation: Operation, failure: unknown): ReportFailure {
  if (failure instanceof HttpProblem) {
    if (failure.status === 403) return { operation, kind: "forbidden" };
    if (failure.status === 404) return { operation, kind: "notFound" };
    if (failure.status === 409) return { operation, kind: "conflict" };
    if (failure.status === 400 || failure.status === 422) return { operation, kind: "invalid" };
  }
  if (failure instanceof Error && failure.message === "INVALID_IAM_RESPONSE") return { operation, kind: "invalid" };
  return { operation, kind: "unavailable" };
}

function saveSecurityReport(bytes: Uint8Array, filename: string) {
  const fileBytes = Uint8Array.from(bytes);
  const url = URL.createObjectURL(new Blob([fileBytes.buffer], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function SecurityReportDocument({ report }: { report: AccountSecurityReport }) {
  const t = useTranslations("IamWorkspace.securityReportPreview");
  const live = useTranslations("IamWorkspace.securityReportLive");
  const users = report.users.map((user) => ({ ...user, name: user.displayName }));
  const accessKeys = report.accessKeys.map((key) => ({ ...key, name: key.id }));
  return <Tabs.Root defaultValue="overview">
    <Tabs.List aria-label={t("reportSections")}>
      <Tabs.Trigger value="overview">{t("overviewTab")}</Tabs.Trigger>
      <Tabs.Trigger value="users">{t("usersTab", { count: report.users.length })}</Tabs.Trigger>
      <Tabs.Trigger value="accessKeys">{t("accessKeysTab", { count: report.accessKeys.length })}</Tabs.Trigger>
    </Tabs.List>
    <Tabs.Content className={styles.stack} value="overview">
      <Card>
        <Card.Header><div><Typography.Title as="h2" level={3}>{t("scopeTitle")}</Typography.Title><Typography.Text tone="muted">{t("scopeHint")}</Typography.Text></div><Badge status="success">{live("verifiedSnapshot")}</Badge></Card.Header>
        <Card.Body className={styles.securityReportBody}>
          <dl className={styles.securityReportSummary} aria-label={t("limitsTitle")}>
            <div><dt>{t("users")}</dt><dd>{report.metadata.userCount} / {accountSecurityReportLimits.users}</dd></div>
            <div><dt>{t("accessKeys")}</dt><dd>{report.metadata.accessKeyCount} / {accountSecurityReportLimits.accessKeys}</dd></div>
            <div><dt>{t("rows")}</dt><dd>{report.metadata.rowCount} / {accountSecurityReportLimits.rows}</dd></div>
            <div><dt>{t("content")}</dt><dd>{report.metadata.csvBytes.toLocaleString()} B</dd></div>
          </dl>
          <Alert status="info">{live("integrityVerified")}</Alert>
          <dl className={styles.activityEvidence} aria-label={live("integrityTitle")}>
            <div><dt>{live("documentDigest")}</dt><dd><code>{report.metadata.documentDigest}</code></dd></div>
            <div><dt>{live("csvDigest")}</dt><dd><code>{report.metadata.csvContentDigest}</code></dd></div>
          </dl>
        </Card.Body>
      </Card>
      <Card>
        <Card.Header><div><Typography.Title as="h2" level={3}>{t("evidenceTitle")}</Typography.Title><Typography.Text tone="muted">{t("evidenceHint")}</Typography.Text></div></Card.Header>
        <Card.Body className={styles.securityReportBody}>
          <ul className={styles.securityChecks}>
            {report.coverage.map((coverage) => <li key={coverage.source}><div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`coverageSources.${coverage.source}.title`)}</strong><Badge status={coverage.state === "COMPLETE" ? "success" : "neutral"}>{t(`coverage.${coverage.state}`)}</Badge></div><p>{t(`coverageSources.${coverage.source}.hint`)}</p></div></li>)}
          </ul>
        </Card.Body>
      </Card>
    </Tabs.Content>
    <Tabs.Content value="users">
      <WorkspaceCollection embedded title={t("userEvidenceTitle")} description={t("userEvidenceHint")} items={users}
        columns={[t("user"), t("status"), t("rootIdentity"), t("mfa"), t("passwordLogin")]}
        keywords={(user) => `${user.loginName} ${user.displayName} ${user.status} ${user.mfa.enrollmentState} ${user.lastPasswordLogin.state}`}
        row={(user) => <><td><strong>{user.displayName}</strong><small><code>{user.loginName}</code> · {user.id}</small></td><td><Badge status={user.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${user.status}`)}</Badge>{user.mustChangePassword ? <small>{t("mustChangePassword")}</small> : null}</td><td>{user.root ? <Badge status="info">{t("root")}</Badge> : t("member")}</td><td><span>{t(`mfaStates.${user.mfa.enrollmentState}`)}</span><small>{t("resourceVersion", { version: user.resourceVersion })}</small></td><td><Badge status={user.lastPasswordLogin.state === "OBSERVED" ? "success" : user.lastPasswordLogin.state === "UNKNOWN" ? "warning" : "neutral"}>{t(`observations.${user.lastPasswordLogin.state}`)}</Badge>{user.lastPasswordLogin.observedAt ? <small><WorkspaceTime value={user.lastPasswordLogin.observedAt} /></small> : null}</td></>}
        footerNote={t("userEvidenceHint")} />
    </Tabs.Content>
    <Tabs.Content value="accessKeys">
      <WorkspaceCollection embedded title={t("keyEvidenceTitle")} description={t("keyEvidenceHint")} items={accessKeys}
        columns={[t("accessKey"), t("owner"), t("status"), t("network"), t("authorizationObservation")]}
        keywords={(key) => `${key.id} ${key.userId} ${key.status} ${key.networkRestrictions.allowedSourceCidrs.join(" ")} ${key.lastAuthorization?.product ?? ""} ${key.lastAuthorization?.action ?? ""}`}
        row={(key) => <><td><code>{key.id}</code><small>{t("resourceVersion", { version: key.resourceVersion })} · <WorkspaceTime value={key.createdAt} /></small></td><td><code>{key.userId}</code></td><td><Badge status={key.status === "ENABLED" ? "success" : "neutral"}>{t(`keyStates.${key.status}`)}</Badge></td><td>{key.networkRestrictions.allowedSourceCidrs.length ? key.networkRestrictions.allowedSourceCidrs.map((cidr) => <code key={cidr}>{cidr}</code>) : t("allNetworks")}</td><td><Badge status={key.lastAuthorization ? key.lastAuthorization.allowed ? "success" : "warning" : "neutral"}>{key.lastAuthorization ? t(key.lastAuthorization.allowed ? "allowed" : "denied") : t("observations.NOT_OBSERVED_IN_RETAINED_IAM_STATE")}</Badge>{key.lastAuthorization ? <><small>{key.lastAuthorization.product} · <code>{key.lastAuthorization.action}</code></small><small>{t("sourceIp")} · <code>{key.lastAuthorization.sourceIp}</code></small><small><WorkspaceTime value={key.lastAuthorization.evaluatedAt} /></small></> : null}</td></>}
        footerNote={t("keyEvidenceHint")} />
    </Tabs.Content>
  </Tabs.Root>;
}

export function LiveSecurityReport({ client }: { client: SecurityReportClient }) {
  const t = useTranslations("IamWorkspace.securityReportLive");
  const preview = useTranslations("IamWorkspace.securityReportPreview");
  const inputId = useId();
  const requestId = useRef(requestToken("ui-security-report-"));
  const [openedAt] = useState(() => Date.now());
  const [knownReportId, setKnownReportId] = useState("");
  const [creation, setCreation] = useState<AccountSecurityReportCreation | null>(null);
  const [report, setReport] = useState<AccountSecurityReport | null>(null);
  const [busy, setBusy] = useState<Operation | null>(null);
  const [failure, setFailure] = useState<ReportFailure | null>(null);
  const [downloaded, setDownloaded] = useState(false);

  const read = async (reportId: string, preserveCreation = false) => {
    setBusy("read"); setFailure(null); setDownloaded(false);
    if (!preserveCreation) setCreation(null);
    setReport(null);
    try {
      const result = await client.read(reportId);
      setKnownReportId(result.metadata.id);
      setReport(result);
    } catch (error) { setFailure(reportFailure("read", error)); }
    finally { setBusy(null); }
  };

  const generate = async () => {
    if (creation || busy) return;
    setBusy("create"); setFailure(null); setDownloaded(false); setReport(null);
    try {
      const created = await client.create({ formatVersion: 1, requestId: requestId.current });
      setCreation(created);
      setKnownReportId(created.metadata.id);
      setBusy(null);
      await read(created.metadata.id, true);
    } catch (error) { setFailure(reportFailure("create", error)); setBusy(null); }
  };

  const download = async () => {
    if (!report || busy) return;
    setBusy("download"); setFailure(null); setDownloaded(false);
    try {
      const result = await client.download(report.metadata.id);
      saveSecurityReport(result.bytes, result.filename);
      setDownloaded(true);
    } catch (error) { setFailure(reportFailure("download", error)); }
    finally { setBusy(null); }
  };

  const expired = report ? openedAt >= Date.parse(report.metadata.expiresAt) : false;
  return <div className={styles.stack}>
    <ContentPage.Heading title={t("title")} scrollKey={`security-report-live:${client.accountId}:${client.sessionRevision}`} actions={<ContentPage.Commands label={t("pageActions")} primary={{ id: "generate", label: t("generate"), icon: <FilePlus2 aria-hidden="true" />, disabled: Boolean(creation || busy), disabledReason: creation ? t("singleIntent") : undefined, onSelect: () => void generate() }} />} />
    <Alert status="info">{t("boundary")}</Alert>
    {failure ? <Alert status="danger"><strong>{t("errorTitle", { operation: t(`operations.${failure.operation}`) })}</strong><p>{t(`errors.${failure.kind}`)}</p></Alert> : null}
    {downloaded ? <Alert status="success">{t("downloaded")}</Alert> : null}
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("scopeTitle")}</Typography.Title><Typography.Text tone="muted">{t("scopeHint")}</Typography.Text></div><Badge status="info">{t("synchronous")}</Badge></Card.Header>
      <Card.Body className={styles.securityReportBody}>
        <dl className={styles.securityReportSummary} aria-label={t("limitsTitle")}>
          <div><dt>{preview("users")}</dt><dd>≤ {accountSecurityReportLimits.users}</dd></div>
          <div><dt>{preview("accessKeys")}</dt><dd>≤ {accountSecurityReportLimits.accessKeys}</dd></div>
          <div><dt>{preview("rows")}</dt><dd>≤ {accountSecurityReportLimits.rows}</dd></div>
          <div><dt>{preview("content")}</dt><dd>≤ 4 MiB</dd></div>
        </dl>
        <p className={styles.note}>{preview("beforeGenerateHint")}</p>
        <Alert status="warning">{preview("noRealtimeConclusion")}</Alert>
      </Card.Body>
    </Card>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("knownReportTitle")}</Typography.Title><Typography.Text tone="muted">{t("knownReportHint")}</Typography.Text></div></Card.Header>
      <Card.Body>
        <form className={styles.form} onSubmit={(event) => { event.preventDefault(); const target = knownReportId.trim(); if (target) void read(target); }}>
          <FormField id={inputId} label={t("reportId")} hint={t("reportIdHint")}><Input id={inputId} autoComplete="off" maxLength={128} onChange={(event) => setKnownReportId(event.target.value)} pattern="[A-Za-z0-9][A-Za-z0-9._:-]{0,127}" required value={knownReportId} /></FormField>
          <div><Button disabled={Boolean(busy || !knownReportId.trim())} type="submit" variant="secondary">{t("read")}</Button></div>
        </form>
      </Card.Body>
    </Card>
    {creation ? <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("createdTitle")}</Typography.Title><Typography.Text tone="muted">{t("createdHint")}</Typography.Text></div><Badge status="success">{t(`outcomes.${creation.outcome}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}><dl className={styles.facts}>
        <div><dt>{t("reportId")}</dt><dd><code>{creation.metadata.id}</code></dd></div>
        <div><dt>{preview("observedAt")}</dt><dd><WorkspaceTime value={creation.metadata.observedAt} /></dd></div>
        <div><dt>{preview("expiresAt")}</dt><dd><WorkspaceTime value={creation.metadata.expiresAt} /></dd></div>
        <div><dt>{preview("rows")}</dt><dd>{creation.metadata.rowCount}</dd></div>
      </dl></Card.Body>
    </Card> : null}
    {busy === "read" ? <Card><TableSkeleton header label={t("loadingReport")} rows={4} /></Card> : null}
    {report ? <>
      <Card>
        <Card.Header><div><Typography.Title as="h2" level={3}>{report.metadata.id}</Typography.Title><Typography.Text tone="muted">{t("detailHint")}</Typography.Text></div><div className={styles.actions}><Badge status={expired ? "warning" : "success"}>{t(expired ? "expired" : "readable")}</Badge><Button disabled={Boolean(busy || expired)} onClick={() => void download()} variant="secondary"><Download aria-hidden="true" />{busy === "download" ? t("downloading") : t("download")}</Button></div></Card.Header>
        <Card.Body className={styles.detail}><dl className={styles.facts}>
          <div><dt>{preview("account")}</dt><dd><code>{report.metadata.accountId}</code></dd></div>
          <div><dt>{preview("observedAt")}</dt><dd><WorkspaceTime value={report.metadata.observedAt} /></dd></div>
          <div><dt>{preview("expiresAt")}</dt><dd><WorkspaceTime value={report.metadata.expiresAt} /></dd></div>
          <div><dt>{preview("settingsVersion")}</dt><dd>v{report.accountSecuritySettingsVersion}</dd></div>
          <div><dt>{preview("format")}</dt><dd>{preview("formatV1")}</dd></div>
          <div><dt>{t("csvBytes")}</dt><dd>{report.metadata.csvBytes.toLocaleString()} B</dd></div>
        </dl>{expired ? <Alert status="warning">{t("expiredHint")}</Alert> : null}</Card.Body>
      </Card>
      <SecurityReportDocument report={report} />
    </> : null}
  </div>;
}
