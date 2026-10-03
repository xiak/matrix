"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { KeyRound, Network, RefreshCcw, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, FormField, Input, PasswordInput, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AccountSecuritySettingsClient, AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import { usePersonalSecurity } from "../application/PersonalSecurityProvider";
import {
  accessKeyNetworkDraftValue,
  accessKeyNetworkRestrictionsEqual,
  parseAccessKeyNetworkDraft,
  type AccessKeyNetworkDraftIssue,
  type AccessKeyNetworkRestrictions
} from "../domain/accessKeyNetwork";
import { AccessKeyNetworkDraftField, AccessKeyNetworkRestrictionValues } from "./AccessKeyNetworkPreview";
import accessStyles from "./AccessCredentials.module.css";
import styles from "./MfaPreviewExperience.module.css";

type ViewState = { client: AccountSecuritySettingsClient | null; result: AccountSecuritySettingsLoad | { status: "loading" } };
type EditorStage = "summary" | "edit" | "review";
type FlowError = "factorRequired" | "startRejected" | "startUnknown" | "inspect" | "notFound" | "verifyRejected" | "verifyUnknown" | "applyUnknown" | null;

function knownRejection(value: unknown): value is HttpProblem {
  return value instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(value.status);
}

export function LiveAccountSecuritySettings({ client }: { client: AccountSecuritySettingsClient | null }) {
  const t = useTranslations("MfaPreview");
  const network = useTranslations("AccessKeyNetworkPreview");
  const password = useTranslations("PasswordRulesPreview");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const personalSecurity = usePersonalSecurity();
  const networkFieldId = useId();
  const passwordId = useId();
  const codeId = useId();
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const verifyRequest = useRef(requestToken("ui-account-security-settings-verify-"));
  const [retry, setRetry] = useState(0);
  const [view, setView] = useState<ViewState>({ client, result: { status: "loading" } });
  const [stage, setStage] = useState<EditorStage>("summary");
  const [draft, setDraft] = useState("");
  const [nextNetwork, setNextNetwork] = useState<AccessKeyNetworkRestrictions | null>(null);
  const [draftIssue, setDraftIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  const [passwordValue, setPasswordValue] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [flowError, setFlowError] = useState<FlowError>(null);

  useEffect(() => {
    if (!client) return;
    let current = true;
    void client.load().then((result) => {
      if (current) setView({ client, result });
    }, () => {
      if (current) setView({ client, result: { status: "unavailable" } });
    });
    return () => { current = false; };
  }, [client, retry]);

  const refreshing = view.result.status === "ready" && view.client !== client && Boolean(view.client && client &&
    view.client.accountId === client.accountId && view.client.principalId === client.principalId &&
    view.client.sessionId === client.sessionId);
  const result = view.client === client || refreshing ? view.result : { status: "loading" as const };
  const update = client?.update;
  const mutation = update?.intent ?? null;
  const currentSettings = result.status === "ready" ? result.settings : null;

  useEffect(() => {
    if (stage !== "summary" || mutation) flowHeading.current?.focus({ preventScroll: true });
  }, [mutation, stage]);

  const retryRead = () => { setView({ client, result: { status: "loading" } }); setRetry((value) => value + 1); };
  const canRetry = result.status === "routeUnavailable" || result.status === "unavailable";
  const passwordRules = currentSettings?.password ?? null;
  const requiredClasses = passwordRules ? (["requireLowercase", "requireUppercase", "requireDigit", "requireSymbol"] as const)
    .filter((field) => passwordRules[field]).map((field) => password(field)).join(password("listSeparator")) : "";

  function editNetwork() {
    if (!currentSettings || !update || mutation) return;
    setDraft(accessKeyNetworkDraftValue(currentSettings.accessKeyNetwork));
    setNextNetwork(null);
    setDraftIssue(null);
    setFlowError(null);
    setStage("edit");
  }

  function reviewNetwork() {
    const parsed = parseAccessKeyNetworkDraft(draft);
    if (!parsed.ok) {
      setDraftIssue(parsed.issue);
      document.getElementById(networkFieldId)?.focus();
      return;
    }
    setDraftIssue(null);
    setNextNetwork(parsed.restrictions);
    setStage("review");
  }

  async function beginUpdate() {
    if (!currentSettings || !nextNetwork || !update || !personalSecurity) {
      setFlowError("factorRequired");
      return;
    }
    setBusy(true); setFlowError(null);
    try {
      const factor = await personalSecurity.authenticatorState();
      if (factor.enrollmentState !== "BOUND") {
        setFlowError("factorRequired");
        return;
      }
      await update.begin(currentSettings, nextNetwork, factor.factorRevision);
    } catch (failure) {
      setFlowError(knownRejection(failure) ? "startRejected" : "startUnknown");
    } finally { setBusy(false); }
  }

  async function retryStepUp() {
    if (!update) return;
    setBusy(true); setFlowError(null);
    try { await update.retryStepUp(); }
    catch (failure) { setFlowError(knownRejection(failure) ? "startRejected" : "startUnknown"); }
    finally { setBusy(false); }
  }

  async function inspectStepUp() {
    if (!update) return;
    setBusy(true); setFlowError(null);
    try { await update.inspectStepUp(); }
    catch (failure) { setFlowError(failure instanceof HttpProblem && failure.status === 404 ? "notFound" : "inspect"); }
    finally { setBusy(false); }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!update) return;
    setBusy(true); setFlowError(null);
    try {
      await update.verifyStepUp({ requestId: verifyRequest.current, password: passwordValue, code });
      setPasswordValue(""); setCode("");
    } catch (failure) {
      setPasswordValue(""); setCode(""); verifyRequest.current = requestToken("ui-account-security-settings-verify-");
      setFlowError(failure instanceof HttpProblem && [400, 401, 413, 415, 422, 429].includes(failure.status) ? "verifyRejected" : "verifyUnknown");
    } finally { setBusy(false); }
  }

  async function apply() {
    if (!update) return;
    setBusy(true); setFlowError(null);
    try { await update.apply(); }
    catch { setFlowError("applyUnknown"); }
    finally { setBusy(false); }
  }

  async function inspectChange() {
    if (!update) return;
    setBusy(true); setFlowError(null);
    try { await update.inspectChange(); }
    catch (failure) { setFlowError(failure instanceof HttpProblem && failure.status === 404 ? "notFound" : "inspect"); }
    finally { setBusy(false); }
  }

  function finishMutation() {
    if (!update || !mutation || !update.clear(mutation.requestId)) return;
    setStage("summary"); setNextNetwork(null); setFlowError(null); retryRead();
  }

  const renderNetworkEditor = () => {
    if (!currentSettings) return null;
    const changed = nextNetwork ? !accessKeyNetworkRestrictionsEqual(currentSettings.accessKeyNetwork, nextNetwork) : false;
    if (mutation) {
      const expiresAt = mutation.stepUp?.expiresAt;
      return <div aria-live="polite" className={accessStyles.networkBody}>
        <div><h4 className={accessStyles.focusHeading} ref={flowHeading} tabIndex={-1}>{network("live.flowTitle")}</h4><Typography.Text tone="muted">{network("live.flowHint")}</Typography.Text></div>
        {flowError ? <Alert status="danger">{network(`live.errors.${flowError}`)}</Alert> : null}
        <dl className={accessStyles.networkFacts}>
          <div><dt>{network("live.requestId")}</dt><dd><code>{mutation.requestId}</code></dd></div>
          <div><dt>{network("live.stateLabel")}</dt><dd>{network(`live.states.${mutation.state}`)}</dd></div>
          {expiresAt ? <div><dt>{network("live.expiresAt")}</dt><dd><time dateTime={expiresAt}>{format.dateTime(new Date(expiresAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></dd></div> : null}
        </dl>
        <div className={accessStyles.networkComparison}><section><h4>{network("current")}</h4><AccessKeyNetworkRestrictionValues value={currentSettings.accessKeyNetwork} /></section><section><h4>{network("afterChange")}</h4><AccessKeyNetworkRestrictionValues value={mutation.settings.accessKeyNetwork} /></section></div>

        {mutation.state === "STEP_UP_UNKNOWN" ? <><Alert status="warning">{network("live.stepUpUnknown")}</Alert><div className={accessStyles.actions}><Button disabled={busy} onClick={() => void retryStepUp()} type="button" variant="ghost">{network("live.retryExact")}</Button><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectStepUp")}</Button></div></> : null}

        {mutation.state === "PENDING" ? <form className={styles.form} onSubmit={(event) => void verify(event)}>
          <Alert>{network("live.verifyBoundary")}</Alert>
          <FormField id={passwordId} label={network("live.password")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => setPasswordValue(event.target.value)} required showLabel={auth("showPassword")} value={passwordValue} /></FormField>
          <FormField id={codeId} label={network("live.code")} hint={network("live.codeHint")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={code} /></FormField>
          <div className={accessStyles.actions}><Button disabled={busy || !passwordValue || code.length !== 6} type="submit"><KeyRound aria-hidden="true" />{network(busy ? "live.verifying" : "live.verify")}</Button></div>
        </form> : null}

        {mutation.state === "VERIFICATION_UNKNOWN" ? <><Alert status="warning">{network("live.verificationUnknown")}</Alert><div className={accessStyles.actions}><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectStepUp")}</Button></div></> : null}

        {mutation.state === "PROVED" ? <><Alert status="warning">{network("live.applyWarning")}</Alert><div className={accessStyles.actions}><Button disabled={busy} onClick={() => void apply()} type="button">{network(busy ? "live.applying" : "live.apply")}</Button></div></> : null}

        {mutation.state === "APPLY_UNKNOWN" ? <><Alert status="warning">{network("live.applyUnknown")}</Alert><div className={accessStyles.actions}><Button disabled={busy} onClick={() => void inspectChange()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectChange")}</Button></div></> : null}

        {mutation.state === "COMPLETED" ? <><Alert status="success">{network("live.completed")}</Alert><Alert>{network("live.completedBoundary")}</Alert><div className={accessStyles.actions}><Button onClick={finishMutation} type="button" variant="secondary">{network("live.finish")}</Button></div></> : null}

        {mutation.state === "EXPIRED" ? <><Alert status="warning">{network("live.expired")}</Alert><div className={accessStyles.actions}><Button onClick={finishMutation} type="button" variant="secondary">{network("live.newChange")}</Button></div></> : null}
      </div>;
    }
    if (stage === "edit") return <form className={accessStyles.networkBody} onSubmit={(event) => { event.preventDefault(); reviewNetwork(); }}>
      <div><h4 className={accessStyles.focusHeading} ref={flowHeading} tabIndex={-1}>{network("live.editTitle")}</h4><Typography.Text tone="muted">{network("fullReplacement")}</Typography.Text></div>
      <AccessKeyNetworkDraftField id={networkFieldId} issue={draftIssue} value={draft} onChange={(value) => { setDraft(value); setDraftIssue(null); }} />
      <Alert>{network("emptyLayerMeaning")}</Alert>
      <div className={accessStyles.actions}><Button type="submit">{network("review")}</Button><Button onClick={() => setStage("summary")} type="button" variant="ghost">{network("cancel")}</Button></div>
    </form>;
    if (stage === "review" && nextNetwork) return <div className={accessStyles.networkBody}>
      <div><h4 className={accessStyles.focusHeading} ref={flowHeading} tabIndex={-1}>{network("live.reviewTitle")}</h4><Typography.Text tone="muted">{network("live.reviewHint")}</Typography.Text></div>
      {flowError ? <Alert status="danger">{network(`live.errors.${flowError}`)}</Alert> : null}
      <div className={accessStyles.networkComparison}><section><h4>{network("current")}</h4><AccessKeyNetworkRestrictionValues value={currentSettings.accessKeyNetwork} /></section><section><h4>{network("afterChange")}</h4><AccessKeyNetworkRestrictionValues value={nextNetwork} /></section></div>
      {!changed ? <Alert status="info">{network("noChange")}</Alert> : null}
      <Alert status="warning">{network("live.reviewBoundary")}</Alert>
      <div className={accessStyles.actions}><Button disabled={busy || !changed} onClick={() => void beginUpdate()}>{network(busy ? "live.starting" : "live.continue")}</Button><Button disabled={busy} onClick={() => setStage("edit")} variant="secondary">{network("backToEdit")}</Button></div>
    </div>;
    return <div className={accessStyles.networkBody}>
      <AccessKeyNetworkRestrictionValues value={currentSettings.accessKeyNetwork} />
      <dl className={accessStyles.networkFacts}><div><dt>{network("settingsVersion")}</dt><dd>v{currentSettings.resourceVersion}</dd></div><div><dt>{network("appliesTo")}</dt><dd>{network("accountKeys")}</dd></div></dl>
      <Alert>{network("live.boundary")}</Alert>
      {!update ? <Alert status="warning">{network("live.updateUnavailable")}</Alert> : null}
      {update ? <div className={accessStyles.actions}><Button onClick={editNetwork} variant="secondary">{network("live.edit")}</Button></div> : null}
    </div>;
  };

  return <section aria-labelledby="live-account-security" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div><p>{t("accountEyebrow")}</p><h2 id="live-account-security" tabIndex={-1}>{t("liveAccountTitle")}</h2><span>{t("liveAccountHint")}</span></div>
      <Badge status="success">LIVE</Badge>
    </div>
    <Card>
      <Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("accountControlTitle")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm} aria-busy={result.status === "loading" || refreshing}>
        {!client ? <Alert status="warning">{t("accountReadUnavailable")}</Alert> : null}
        {client && result.status === "loading" ? <Typography.Text role="status" tone="muted">{t("accountReadLoading")}</Typography.Text> : null}
        {refreshing ? <Typography.Text role="status" tone="muted">{t("accountReadRefreshing")}</Typography.Text> : null}
        {currentSettings ? <>
          <dl className={styles.facts}>
            <div><dt>{t("currentRule")}</dt><dd>{t(currentSettings.mfa.requiredForUsers ? "required" : "optional")}</dd></div>
            <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
            <div><dt>{t("accountTarget")}</dt><dd><code>{currentSettings.accountId}</code></dd></div>
            <div><dt>{t("accountReadVersion")}</dt><dd>{currentSettings.resourceVersion}</dd></div>
            <div><dt>{t("accountReadUpdated")}</dt><dd><time dateTime={currentSettings.updatedAt}>{format.dateTime(new Date(currentSettings.updatedAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</time></dd></div>
          </dl>
          <Alert>{t("accountReadBoundary")}</Alert>
          <div className={styles.livePasswordRule}>
            <h4>{password("liveTitle")}</h4>
            {passwordRules ? <><dl className={styles.facts}><div><dt>{password("editMinimumLength")}</dt><dd>{password("effectiveMinimum", { count: passwordRules.minimumLength })}</dd></div><div><dt>{password("characterRules")}</dt><dd>{requiredClasses || password("noneRequired")}</dd></div><div><dt>{password("editHistoryCount")}</dt><dd>{password("effectiveHistory", { count: passwordRules.historyCount })}</dd></div></dl><Typography.Text tone="muted">{password("liveBoundary")}</Typography.Text></> : <Alert status="warning">{password("liveUnavailable")}</Alert>}
          </div>
          <section aria-labelledby="live-account-access-key-network" className={accessStyles.networkSection}>
            <div className={accessStyles.networkSectionHeading}><div><p>{network("accountEyebrow")}</p><h3 id="live-account-access-key-network"><Network aria-hidden="true" />{network("accountTitle")}</h3><span>{network("accountHint")}</span></div><Badge status={currentSettings.accessKeyNetwork.allowedSourceCidrs.length ? "info" : "neutral"}>{network(currentSettings.accessKeyNetwork.allowedSourceCidrs.length ? "limited" : "allSources")}</Badge></div>
            {renderNetworkEditor()}
          </section>
        </> : null}
        {result.status === "forbidden" ? <Alert status="warning">{t("accountReadDenied")}</Alert> : null}
        {canRetry ? <Alert status="danger">{t(result.status === "routeUnavailable" ? "accountReadRouteUnavailable" : "accountReadUnavailable")} <Button onClick={retryRead} size="small" variant="ghost"><RefreshCcw aria-hidden="true" />{t("accountReadRetry")}</Button></Alert> : null}
      </Card.Body>
    </Card>
  </section>;
}
