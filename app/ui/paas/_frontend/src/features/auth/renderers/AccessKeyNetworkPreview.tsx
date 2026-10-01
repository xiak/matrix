"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Network, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, TextArea, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { accessKeyNetworkDraftValue, accessKeyNetworkRestrictionsEqual, parseAccessKeyNetworkDraft, type AccessKeyNetworkDraftIssue, type AccessKeyNetworkRestrictions } from "../domain/accessKeyNetwork";
import type { AccessKey, AccessWorkspace } from "../domain/accessWorkspace";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import { SecurityStepUpPreview } from "./SecurityStepUpPreview";
import styles from "./AccessCredentials.module.css";

export function AccessKeyNetworkRestrictionValues({ value }: { value: AccessKeyNetworkRestrictions }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  return value.allowedSourceCidrs.length ? <ul className={styles.networkValues}>{value.allowedSourceCidrs.map((cidr) => <li key={cidr}><code>{cidr}</code></li>)}</ul> : <span className={styles.note}>{t("unrestrictedLayer")}</span>;
}

export function AccessKeyNetworkDraftField({ id, value, issue, onChange }: { id: string; value: string; issue: AccessKeyNetworkDraftIssue | null; onChange(value: string): void }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  return <FormField id={id} label={t("allowedCidrs")} hint={t("cidrHint")} error={issue ? t(`issues.${issue}`) : undefined}>
    <TextArea aria-describedby={`${id}-hint${issue ? ` ${id}-error` : ""}`} id={id} invalid={Boolean(issue)} rows={6} spellCheck={false} value={value} onChange={(event) => onChange(event.target.value)} />
  </FormField>;
}

export function AccountAccessKeyNetworkPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  const access = useAccountAccess();
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [stage, setStage] = useState<"summary" | "edit" | "review" | "verify">("summary");
  const [draft, setDraft] = useState(() => accessKeyNetworkDraftValue(workspace.settings.accessKeyNetwork));
  const [next, setNext] = useState<AccessKeyNetworkRestrictions | null>(null);
  const [issue, setIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  const [saved, setSaved] = useState(false);
  const factorReady = workspace.personalMfa.factorState === "bound" && workspace.personalMfa.recoveryState === "idle";
  const canChange = factorReady && !workspace.personalMfa.reauthenticationRequired;
  const changed = next ? !accessKeyNetworkRestrictionsEqual(workspace.settings.accessKeyNetwork, next) : false;

  useEffect(() => { if (stage !== "summary") heading.current?.focus({ preventScroll: true }); }, [stage]);

  function start() {
    setDraft(accessKeyNetworkDraftValue(workspace.settings.accessKeyNetwork));
    setNext(null);
    setIssue(null);
    setSaved(false);
    setStage("edit");
  }

  function review() {
    const parsed = parseAccessKeyNetworkDraft(draft);
    if (!parsed.ok) {
      setIssue(parsed.issue);
      document.getElementById(id)?.focus();
      return;
    }
    setIssue(null);
    setNext(parsed.restrictions);
    setStage("review");
  }

  async function save() {
    if (!next) return false;
    const result = await access.executeWorkspace({ kind: "save-account-key-network-preview", expectedRuleVersion: workspace.settings.accountRuleVersion, accessKeyNetwork: next });
    if (!result) return false;
    setSaved(true);
    setStage("summary");
    return true;
  }

  return <section aria-labelledby="access-key-account-network" className={styles.networkSection}>
    <div className={styles.networkSectionHeading}><div><p>{t("accountEyebrow")}</p><h2 id="access-key-account-network">{t("accountTitle")}</h2><span>{t("accountHint")}</span></div><div className={styles.networkBadges}><Badge status={workspace.settings.accessKeyNetwork.allowedSourceCidrs.length ? "info" : "neutral"}>{t(workspace.settings.accessKeyNetwork.allowedSourceCidrs.length ? "limited" : "allSources")}</Badge><Badge status="warning">MOCK</Badge></div></div>
    {saved ? <Alert status="success">{t("accountSaved")}</Alert> : null}
    {stage === "verify" ? <SecurityStepUpPreview action="securitySettings" onCancel={() => setStage("review")} onVerified={save} /> : null}
    {stage === "summary" ? <Card><Card.Header><div className={styles.cardHeading}><ShieldCheck aria-hidden="true" /><div><Typography.Title as="h3" level={3}>{t("accountControl")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.networkBody}>
      <AccessKeyNetworkRestrictionValues value={workspace.settings.accessKeyNetwork} />
      <dl className={styles.networkFacts}><div><dt>{t("settingsVersion")}</dt><dd>v{workspace.settings.accountRuleVersion}</dd></div><div><dt>{t("appliesTo")}</dt><dd>{t("accountKeys")}</dd></div></dl>
      <Alert>{t("accountMockBoundary")}</Alert>
      {!factorReady ? <Alert status="warning">{t("factorRequired")}</Alert> : workspace.personalMfa.reauthenticationRequired ? <Alert status="warning">{t("reauthenticationRequired")}</Alert> : null}
      <div className={styles.actions}><Button disabled={!canChange || access.busy} onClick={start} variant="secondary">{t("editAccount")}</Button></div>
    </Card.Body></Card> : null}
    {stage === "edit" ? <Card><Card.Header><div><h3 className={styles.focusHeading} ref={heading} tabIndex={-1}>{t("editAccountTitle")}</h3><Typography.Text tone="muted">{t("fullReplacement")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header><Card.Body><form className={styles.networkBody} onSubmit={(event) => { event.preventDefault(); review(); }}>
      <AccessKeyNetworkDraftField id={id} issue={issue} value={draft} onChange={(value) => { setDraft(value); setIssue(null); }} />
      <Alert>{t("emptyLayerMeaning")}</Alert>
      <div className={styles.actions}><Button disabled={access.busy} type="submit">{t("review")}</Button><Button disabled={access.busy} onClick={() => setStage("summary")} type="button" variant="ghost">{t("cancel")}</Button></div>
    </form></Card.Body></Card> : null}
    {stage === "review" && next ? <Card><Card.Header><div><h3 className={styles.focusHeading} ref={heading} tabIndex={-1}>{t("reviewAccountTitle")}</h3><Typography.Text tone="muted">{t("reviewAccountHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header><Card.Body className={styles.networkBody}>
      <div className={styles.networkComparison}><section><h4>{t("current")}</h4><AccessKeyNetworkRestrictionValues value={workspace.settings.accessKeyNetwork} /></section><section><h4>{t("afterChange")}</h4><AccessKeyNetworkRestrictionValues value={next} /></section></div>
      {!changed ? <Alert status="info">{t("noChange")}</Alert> : null}
      <Alert status="warning">{t("accountReviewBoundary")}</Alert>
      <div className={styles.actions}><Button disabled={access.busy || !changed} onClick={() => setStage("verify")}>{t("verifyAndApply")}</Button><Button disabled={access.busy} onClick={() => setStage("edit")} variant="secondary">{t("backToEdit")}</Button></div>
    </Card.Body></Card> : null}
  </section>;
}

export function AccessKeyNetworkLayers({ account, keyValue }: { account: AccessKeyNetworkRestrictions; keyValue: AccessKeyNetworkRestrictions }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  return <div className={styles.networkLayers}><section><h3>{t("accountLayer")}</h3><AccessKeyNetworkRestrictionValues value={account} /></section><section><h3>{t("keyLayer")}</h3><AccessKeyNetworkRestrictionValues value={keyValue} /></section></div>;
}

export function AccessKeyNetworkDetail({ account, keyValue }: { account: AccessKeyNetworkRestrictions; keyValue: AccessKey }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  return <Card><Card.Header><div className={styles.cardHeading}><Network aria-hidden="true" /><div><Typography.Title as="h2" level={3}>{t("keyTitle")}</Typography.Title><Typography.Text tone="muted">{t("keyHint")}</Typography.Text></div></div><Badge status="warning">MOCK</Badge></Card.Header><Card.Body className={styles.networkBody}>
    <AccessKeyNetworkLayers account={account} keyValue={keyValue.networkRestrictions} />
    <Alert status="info">{t("andBoundary")}</Alert>
    <p className={styles.note}>{t("familyBoundary")}</p>
  </Card.Body></Card>;
}

export function AccessKeyUsagePreview({ usage }: { usage: AccessKey["usage"] }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  const authorization = usage.lastAuthorization;
  return <Card><Card.Header><div><Typography.Title as="h2" level={3}>{t("usageTitle")}</Typography.Title><Typography.Text tone="muted">{t("usageHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header><Card.Body className={styles.networkBody}>
    <dl className={styles.networkFacts}><div><dt>{t("observedAt")}</dt><dd><WorkspaceTime value={usage.observedAt} /></dd></div>{authorization ? <><div><dt>{t("lastResult")}</dt><dd><Badge status={authorization.allowed ? "success" : "danger"}>{t(authorization.allowed ? "allowed" : "denied")}</Badge></dd></div><div><dt>Action</dt><dd><code>{authorization.action}</code></dd></div><div><dt>{t("product")}</dt><dd>{authorization.product}</dd></div><div><dt>{t("sourceIp")}</dt><dd><code>{authorization.sourceIp}</code></dd></div><div><dt>{t("evaluatedAt")}</dt><dd><WorkspaceTime value={authorization.evaluatedAt} /></dd></div></> : null}</dl>
    <Alert status="warning">{authorization ? t("observationBoundary") : t("observationUnknown")}</Alert>
  </Card.Body></Card>;
}

export function AccessKeyNetworkEditor({ keyValue, onClose }: { keyValue: AccessKey; onClose(): void }) {
  const t = useTranslations("AccessKeyNetworkPreview");
  const access = useAccountAccess();
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [stage, setStage] = useState<"edit" | "review">("edit");
  const [draft, setDraft] = useState(() => accessKeyNetworkDraftValue(keyValue.networkRestrictions));
  const [next, setNext] = useState<AccessKeyNetworkRestrictions | null>(null);
  const [issue, setIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  const changed = next ? !accessKeyNetworkRestrictionsEqual(keyValue.networkRestrictions, next) : false;
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [stage]);

  function review() {
    const parsed = parseAccessKeyNetworkDraft(draft);
    if (!parsed.ok) {
      setIssue(parsed.issue);
      document.getElementById(id)?.focus();
      return;
    }
    setIssue(null);
    setNext(parsed.restrictions);
    setStage("review");
  }

  async function save() {
    if (!next) return;
    if (await access.executeWorkspace({ kind: "save-key-network-preview", id: keyValue.id, resourceVersion: keyValue.resourceVersion, networkRestrictions: next })) onClose();
  }

  return <Card><Card.Header><div><h2 className={styles.focusHeading} ref={heading} tabIndex={-1}>{t(stage === "edit" ? "editKeyTitle" : "reviewKeyTitle")}</h2><Typography.Text tone="muted">{t("keyEditorHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header><Card.Body className={styles.networkBody}>
    {stage === "edit" ? <form className={styles.networkBody} onSubmit={(event) => { event.preventDefault(); review(); }}><AccessKeyNetworkDraftField id={id} issue={issue} value={draft} onChange={(value) => { setDraft(value); setIssue(null); }} /><Alert>{t("emptyLayerMeaning")}</Alert><div className={styles.actions}><Button disabled={access.busy} type="submit">{t("review")}</Button><Button disabled={access.busy} onClick={onClose} type="button" variant="ghost">{t("cancel")}</Button></div></form> : null}
    {stage === "review" && next ? <><dl className={styles.networkFacts}><div><dt>{t("keyId")}</dt><dd><code>{keyValue.id}</code></dd></div><div><dt>{t("keyVersion")}</dt><dd>v{keyValue.resourceVersion}</dd></div></dl><div className={styles.networkComparison}><section><h3>{t("current")}</h3><AccessKeyNetworkRestrictionValues value={keyValue.networkRestrictions} /></section><section><h3>{t("afterChange")}</h3><AccessKeyNetworkRestrictionValues value={next} /></section></div>{!changed ? <Alert status="info">{t("noChange")}</Alert> : null}<Alert status="warning">{t("keyReviewBoundary")}</Alert><div className={styles.actions}><Button disabled={access.busy || !changed} onClick={() => void save()}>{t("applyMock")}</Button><Button disabled={access.busy} onClick={() => setStage("edit")} variant="secondary">{t("backToEdit")}</Button></div></> : null}
  </Card.Body></Card>;
}
