"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { KeyRound, RefreshCcw, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, FormField, Input, LoadingNotice, PasswordInput, Select, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { AccountSecuritySettingsReviewRejected, type AccountSecuritySettingsClient, type AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import { usePersonalSecurity } from "../application/PersonalSecurityProvider";
import { accessKeyNetworkDraftValue, parseAccessKeyNetworkDraft, type AccessKeyNetworkDraftIssue } from "../domain/accessKeyNetwork";
import { sameSecuritySettingsIntent, type AccountSecuritySettings, type SecuritySettingsUpdateIntent } from "../domain/accounts";
import { useAccessDraft } from "./useAccessDraft";
import { AccessKeyNetworkDraftField, AccessKeyNetworkRestrictionValues } from "./AccessKeyNetworkPreview";
import accessStyles from "./AccessCredentials.module.css";
import styles from "./MfaPreviewExperience.module.css";

type ViewState = { client: AccountSecuritySettingsClient | null; result: AccountSecuritySettingsLoad | { status: "loading" } };
type EditorStage = "summary" | "edit" | "review";
type FlowError = "factorRequired" | "factorUnavailable" | "startRejected" | "startUnknown" | "inspect" | "notFound" | "verifyRejected" | "verifyUnknown" | "applyUnknown" | "stale" | null;

const characterFields = ["requireLowercase", "requireUppercase", "requireDigit", "requireSymbol"] as const;
const numericFields = [
  { key: "minimumLength", min: 15, max: 128 }, { key: "historyCount", min: 0, max: 24 },
  { key: "maxAgeDays", min: 0, max: 365 }, { key: "idleTimeoutMinutes", min: 5, max: 60 }
] as const;

function currentIntent(value: AccountSecuritySettings): SecuritySettingsUpdateIntent {
  return { expectedResourceVersion: value.resourceVersion, mfa: value.mfa, password: value.password,
    session: value.session, accessKeyNetwork: value.accessKeyNetwork };
}

function AccountSecurityRulesValues({ value }: { value: Pick<SecuritySettingsUpdateIntent, "mfa" | "password" | "session" | "accessKeyNetwork"> }) {
  const t = useTranslations("AccountSecuritySettingsEditor");
  const password = useTranslations("PasswordRulesPreview");
  const mfa = useTranslations("MfaPreview");
  return <dl className={styles.facts}>
    <div><dt>{t("mfa")}</dt><dd>{mfa(value.mfa.requiredForUsers ? "required" : "optional")}</dd></div>
    <div><dt>{t("minimumLength")}</dt><dd>{password("effectiveMinimum", { count: value.password.minimumLength })}</dd></div>
    {characterFields.map((field) => <div key={field}><dt>{password(field)}</dt><dd>{t(value.password[field] ? "yes" : "no")}</dd></div>)}
    <div><dt>{t("historyCount")}</dt><dd>{password("effectiveHistory", { count: value.password.historyCount })}</dd></div>
    <div><dt>{t("maxAgeDays")}</dt><dd>{value.password.maxAgeDays === 0 ? t("noExpiry") : t("ageDays", { days: value.password.maxAgeDays })}</dd></div>
    <div><dt>{t("expiryMode")}</dt><dd>{t(value.password.expiryMode)}</dd></div>
    <div><dt>{t("idleTimeoutMinutes")}</dt><dd>{t("idleMinutes", { minutes: value.session.idleTimeoutMinutes })}</dd></div>
    <div><dt>{t("network")}</dt><dd><AccessKeyNetworkRestrictionValues value={value.accessKeyNetwork} /></dd></div>
  </dl>;
}

function AccountSecurityRulesEditor({ current, initial, onReview, onCancel }: {
  current: AccountSecuritySettings; initial: SecuritySettingsUpdateIntent; onReview(value: SecuritySettingsUpdateIntent): void; onCancel(): void;
}) {
  const t = useTranslations("AccountSecuritySettingsEditor");
  const password = useTranslations("PasswordRulesPreview");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [rules, setRules] = useState(() => structuredClone(initial));
  const [numbers, setNumbers] = useState(() => ({ minimumLength: String(initial.password.minimumLength), historyCount: String(initial.password.historyCount),
    maxAgeDays: String(initial.password.maxAgeDays), idleTimeoutMinutes: String(initial.session.idleTimeoutMinutes) }));
  const [network, setNetwork] = useState(accessKeyNetworkDraftValue(initial.accessKeyNetwork));
  const [issue, setIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  const [invalidField, setInvalidField] = useState<string | null>(null);
  const dirty = !sameSecuritySettingsIntent(currentIntent(current), rules) ||
    numericFields.some(({ key }) => numbers[key] !== String(key === "idleTimeoutMinutes" ? current.session[key] : current.password[key])) ||
    network !== accessKeyNetworkDraftValue(current.accessKeyNetwork);
  const leave = useAccessDraft({ dirty, busy: false, title: t("editTitle"), description: t("leaveHint"), form });
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);
  return <form ref={form} className={accessStyles.networkBody} aria-label={t("editTitle")} noValidate onSubmit={(event) => {
    event.preventDefault();
    const invalid = numericFields.find(({ key, min, max }) => !/^\d+$/.test(numbers[key]) || !Number.isSafeInteger(Number(numbers[key])) || Number(numbers[key]) < min || Number(numbers[key]) > max);
    if (invalid) { setInvalidField(invalid.key); document.getElementById(`${id}-${invalid.key}`)?.focus(); return; }
    setInvalidField(null);
    const parsed = parseAccessKeyNetworkDraft(network);
    if (!parsed.ok) { setIssue(parsed.issue); document.getElementById(`${id}-network`)?.focus(); return; }
    onReview({ ...rules, password: { ...rules.password, minimumLength: Number(numbers.minimumLength), historyCount: Number(numbers.historyCount), maxAgeDays: Number(numbers.maxAgeDays) },
      session: { idleTimeoutMinutes: Number(numbers.idleTimeoutMinutes) }, accessKeyNetwork: parsed.restrictions });
  }}>
    <h4 ref={heading} tabIndex={-1} className={accessStyles.focusHeading}>{t("editTitle")}</h4>
    <Alert>{t("fullReplacement")}</Alert>
    <fieldset className={styles.ruleFields}><legend>{t("mfa")}</legend>
      <Checkbox checked={rules.mfa.requiredForUsers} onChange={(event) => setRules({ ...rules, mfa: { requiredForUsers: event.target.checked } })}>{t("requiredForUsers")}</Checkbox>
    </fieldset>
    <fieldset className={styles.ruleFields}><legend>{t("password")}</legend>
      {numericFields.filter(({ key }) => key !== "idleTimeoutMinutes").map(({ key, min, max }) => <FormField key={key} id={`${id}-${key}`} label={t(key)}
        hint={t(key === "maxAgeDays" ? "ageHint" : "range", { min, max })} error={invalidField === key ? t("invalidNumber", { min, max }) : undefined}>
        <Input className={styles.ruleNumber} id={`${id}-${key}`} inputMode="numeric" value={numbers[key]} invalid={invalidField === key} aria-describedby={`${id}-${key}-hint`}
          onChange={(event) => { setNumbers({ ...numbers, [key]: event.target.value }); setInvalidField(null); }} />
      </FormField>)}
      {characterFields.map((field) => <Checkbox key={field} checked={rules.password[field]} onChange={(event) => setRules({ ...rules, password: { ...rules.password, [field]: event.target.checked } })}>{password(field)}</Checkbox>)}
      <FormField id={`${id}-expiry`} label={t("expiryMode")}><Select id={`${id}-expiry`} value={rules.password.expiryMode}
        options={[{ value: "CHANGE_PASSWORD", label: t("CHANGE_PASSWORD") }, { value: "ADMIN_RESET", label: t("ADMIN_RESET") }]}
        onValueChange={(value) => { if (value === "CHANGE_PASSWORD" || value === "ADMIN_RESET") setRules({ ...rules, password: { ...rules.password, expiryMode: value } }); }} /></FormField>
    </fieldset>
    <fieldset className={styles.ruleFields}><legend>{t("session")}</legend><FormField id={`${id}-idleTimeoutMinutes`} label={t("idleTimeoutMinutes")} hint={t("range", { min: 5, max: 60 })}
      error={invalidField === "idleTimeoutMinutes" ? t("invalidNumber", { min: 5, max: 60 }) : undefined}>
      <Input className={styles.ruleNumber} id={`${id}-idleTimeoutMinutes`} inputMode="numeric" value={numbers.idleTimeoutMinutes} invalid={invalidField === "idleTimeoutMinutes"}
        aria-describedby={`${id}-idleTimeoutMinutes-hint`} onChange={(event) => { setNumbers({ ...numbers, idleTimeoutMinutes: event.target.value }); setInvalidField(null); }} />
    </FormField></fieldset>
    <fieldset className={styles.ruleFields}><legend>{t("network")}</legend><AccessKeyNetworkDraftField id={`${id}-network`} value={network} issue={issue} onChange={(value) => { setNetwork(value); setIssue(null); }} /></fieldset>
    <Alert status="warning">{t("protectedBoundary")}</Alert>
    <div className={accessStyles.actions}><Button type="submit" disabled={!dirty}>{t("review")}</Button><Button type="button" variant="ghost" onClick={() => leave(onCancel)}>{t("cancel")}</Button></div>
  </form>;
}

function knownRejection(value: unknown): value is HttpProblem {
  return value instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(value.status);
}

export function LiveAccountSecuritySettings({ client }: { client: AccountSecuritySettingsClient | null }) {
  return <AccountSecuritySettingsWorkspace key={client?.identity ?? "unavailable"} client={client} />;
}

function AccountSecuritySettingsWorkspace({ client }: { client: AccountSecuritySettingsClient | null }) {
  const t = useTranslations("MfaPreview");
  const security = useTranslations("AccountSecuritySettingsEditor");
  const network = useTranslations("AccessKeyNetworkPreview");
  const password = useTranslations("PasswordRulesPreview");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const personalSecurity = usePersonalSecurity();
  const passwordId = useId();
  const codeId = useId();
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const workspace = useRef<HTMLElement>(null);
  const editButton = useRef<HTMLButtonElement>(null);
  const returnToEdit = useRef(false);
  const alive = useRef(true);
  useLayoutEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const verifyRequest = useRef(requestToken("ui-account-security-settings-verify-"));
  const [retry, setRetry] = useState(0);
  const [view, setView] = useState<ViewState>({ client, result: { status: "loading" } });
  const [stage, setStage] = useState<EditorStage>("summary");
  const [original, setOriginal] = useState<AccountSecuritySettings | null>(null);
  const [nextSettings, setNextSettings] = useState<SecuritySettingsUpdateIntent | null>(null);
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
    view.client.identity === client.identity);
  const result = view.client === client || refreshing ? view.result : { status: "loading" as const };
  const update = client?.update;
  const mutation = update?.intent ?? null;
  const currentSettings = result.status === "ready" ? result.settings : null;
  const flowErrorMessage = !flowError ? null : flowError === "stale" || flowError === "factorUnavailable" ? security(flowError) : network(`live.errors.${flowError}`);
  const currentRead = useRef<AccountSecuritySettings | null>(null);
  useLayoutEffect(() => { currentRead.current = refreshing ? null : currentSettings; }, [currentSettings, refreshing]);
  useLayoutEffect(() => {
    if (stage === "summary" && !mutation && currentSettings && returnToEdit.current) {
      returnToEdit.current = false; editButton.current?.focus({ preventScroll: true });
    }
  }, [stage, mutation, currentSettings]);
  const leaveReview = useAccessDraft({ dirty: stage === "review" && !mutation, busy, title: security("reviewTitle"), description: security("leaveHint"), form: workspace });

  useEffect(() => {
    if (stage !== "summary" || mutation) flowHeading.current?.focus({ preventScroll: true });
  }, [mutation, stage]);

  const retryRead = () => { setView({ client, result: { status: "loading" } }); setRetry((value) => value + 1); };
  const canRetry = result.status === "routeUnavailable" || result.status === "unavailable";
  function editSettings() {
    if (!currentSettings || !update || mutation || refreshing) return;
    setOriginal(structuredClone(currentSettings));
    setNextSettings(structuredClone(currentIntent(currentSettings)));
    setFlowError(null);
    setStage("edit");
  }

  async function beginUpdate() {
    if (!original || !currentSettings || !nextSettings || !update || refreshing) { setFlowError("stale"); return; }
    if (!personalSecurity) { setFlowError("factorUnavailable"); return; }
    let starting = false;
    setBusy(true); setFlowError(null);
    try {
      if (!currentRead.current || !sameSecuritySettingsIntent(currentIntent(original), currentIntent(currentRead.current))) { setFlowError("stale"); return; }
      const factor = await personalSecurity.authenticatorState();
      if (!alive.current) return;
      if (factor.enrollmentState !== "BOUND") {
        setFlowError("factorRequired");
        return;
      }
      if (!Number.isSafeInteger(factor.factorRevision) || factor.factorRevision < 2) { setFlowError("factorUnavailable"); return; }
      if (!currentRead.current || !sameSecuritySettingsIntent(currentIntent(original), currentIntent(currentRead.current))) { setFlowError("stale"); return; }
      starting = true; await update.begin(original, structuredClone(nextSettings), factor.factorRevision);
    } catch (failure) {
      if (!alive.current) return;
      setFlowError(!starting ? "factorUnavailable" : failure instanceof AccountSecuritySettingsReviewRejected || failure instanceof HttpProblem && failure.status === 409 ? "stale" : knownRejection(failure) ? "startRejected" : "startUnknown");
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
    setStage("summary"); setOriginal(null); setNextSettings(null); setFlowError(null); retryRead();
  }

  const renderSettingsFlow = () => {
    const changed = original && nextSettings ? !sameSecuritySettingsIntent(currentIntent(original), nextSettings) : false;
    if (mutation) {
      const expiresAt = mutation.stepUp?.expiresAt;
      return <div aria-live="polite" className={accessStyles.networkBody}>
        <div><h4 className={accessStyles.focusHeading} ref={flowHeading} tabIndex={-1}>{security("flowTitle")}</h4><Typography.Text tone="muted">{network("live.flowHint")}</Typography.Text></div>
        {!client?.canUpdate ? <Alert status="warning">{t("accountUpdateDenied")}</Alert> : null}
        {flowErrorMessage ? <Alert status="danger">{flowErrorMessage}</Alert> : null}
        <dl className={accessStyles.networkFacts}>
          <div><dt>{network("live.requestId")}</dt><dd><code>{mutation.requestId}</code></dd></div>
          <div><dt>{network("live.stateLabel")}</dt><dd>{busy ? <LoadingNotice label={security("working")} /> : network(`live.states.${mutation.state}`)}</dd></div>
          {expiresAt ? <div><dt>{network("live.expiresAt")}</dt><dd><time dateTime={expiresAt}>{format.dateTime(new Date(expiresAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></dd></div> : null}
        </dl>
        <Alert>{security("intentOnly")}</Alert>
        <section aria-label={security("frozenTarget")}><h4>{security("frozenTarget")}</h4><AccountSecurityRulesValues value={mutation.settings} /></section>

        {mutation.state === "STEP_UP_UNKNOWN" ? <>{!busy ? <Alert status="warning">{network("live.stepUpUnknown")}</Alert> : null}<div className={accessStyles.actions}><Button disabled={busy} onClick={() => void retryStepUp()} type="button" variant="ghost">{network("live.retryExact")}</Button><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectStepUp")}</Button></div></> : null}

        {mutation.state === "PENDING" ? <form className={styles.form} onSubmit={(event) => void verify(event)}>
          <Alert>{network("live.verifyBoundary")}</Alert>
          <FormField id={passwordId} label={network("live.password")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} disabled={busy} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => setPasswordValue(event.target.value)} required showLabel={auth("showPassword")} value={passwordValue} /></FormField>
          <FormField id={codeId} label={network("live.code")} hint={network("live.codeHint")}><Input autoComplete="one-time-code" disabled={busy} id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={code} /></FormField>
          <div className={accessStyles.actions}><Button disabled={busy || !passwordValue || code.length !== 6} type="submit"><KeyRound aria-hidden="true" />{network(busy ? "live.verifying" : "live.verify")}</Button></div>
        </form> : null}

        {mutation.state === "VERIFICATION_UNKNOWN" ? <>{!busy ? <Alert status="warning">{network("live.verificationUnknown")}</Alert> : null}<div className={accessStyles.actions}><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectStepUp")}</Button></div></> : null}

        {mutation.state === "PROVED" ? <><Alert status="warning">{security("applyWarning")}</Alert><div className={accessStyles.actions}><Button disabled={busy || !client?.canUpdate} onClick={() => void apply()} type="button">{busy ? network("live.applying") : security("apply")}</Button></div></> : null}

        {mutation.state === "APPLY_UNKNOWN" ? <>{!busy ? <Alert status="warning">{network("live.applyUnknown")}</Alert> : null}<div className={accessStyles.actions}><Button disabled={busy} onClick={() => void inspectChange()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{network("live.inspectChange")}</Button></div></> : null}

        {mutation.state === "COMPLETED" ? <><Alert status="success">{network("live.completed")}</Alert><Alert>{network("live.completedBoundary")}</Alert><div className={accessStyles.actions}><Button onClick={finishMutation} type="button" variant="secondary">{network("live.finish")}</Button></div></> : null}

        {mutation.state === "EXPIRED" ? <><Alert status="warning">{network("live.expired")}</Alert><div className={accessStyles.actions}><Button onClick={finishMutation} type="button" variant="secondary">{network("live.newChange")}</Button></div></> : null}
      </div>;
    }
    if (stage === "edit" && original && nextSettings) return <AccountSecurityRulesEditor current={original} initial={nextSettings}
      onReview={(value) => { setNextSettings(structuredClone(value)); setFlowError(null); setStage("review"); }} onCancel={() => { returnToEdit.current = true; setStage("summary"); }} />;
    if (stage === "review" && original && nextSettings) return <div className={accessStyles.networkBody} role="group" aria-label={security("reviewTitle")}>
      <div><h4 className={accessStyles.focusHeading} ref={flowHeading} tabIndex={-1}>{security("reviewTitle")}</h4><Typography.Text tone="muted">{security("reviewHint", { revision: original.resourceVersion })}</Typography.Text></div>
      {flowErrorMessage ? <Alert status="danger">{flowErrorMessage}</Alert> : null}
      {!currentSettings ? <Alert status="warning">{security("readRequired")}</Alert> : null}
      <div className={accessStyles.networkComparison}><section aria-label={security("before")}><h4>{security("before")}</h4><AccountSecurityRulesValues value={original} /></section><section aria-label={security("after")}><h4>{security("after")}</h4><AccountSecurityRulesValues value={nextSettings} /></section></div>
      {!changed ? <Alert status="info">{network("noChange")}</Alert> : null}
      <Alert status="warning">{security("protectedBoundary")}</Alert>
      <Alert status="warning">{security("reviewBoundary")}</Alert>
      <div className={accessStyles.actions}><Button disabled={busy || !changed || !currentSettings || refreshing || flowError === "stale"} onClick={() => void beginUpdate()}>{network(busy ? "live.starting" : "live.continue")}</Button><Button disabled={busy || flowError === "stale"} onClick={() => setStage("edit")} variant="secondary">{network("backToEdit")}</Button>
        <Button disabled={busy} variant="ghost" onClick={() => leaveReview(() => { returnToEdit.current = true; setStage("summary"); setOriginal(null); setNextSettings(null); setFlowError(null); retryRead(); })}>{security("cancel")}</Button></div>
    </div>;
    return null;
  };

  return <section ref={workspace} aria-labelledby="live-account-security" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div><p>{t("accountEyebrow")}</p><h2 id="live-account-security" tabIndex={-1}>{t("liveAccountTitle")}</h2><span>{t("liveAccountHint")}</span></div>
      <Badge status="success">LIVE</Badge>
    </div>
    <Card>
      <Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{security("controlTitle")}</Typography.Title><Typography.Text tone="muted">{security("fullReplacement")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm} aria-busy={result.status === "loading" || refreshing}>
        {!client ? <Alert status="warning">{t("accountReadUnavailable")}</Alert> : null}
        {client && result.status === "loading" ? <LoadingNotice className={accessStyles.note} label={t("accountReadLoading")} /> : null}
        {refreshing ? <Typography.Text role="status" tone="muted">{t("accountReadRefreshing")}</Typography.Text> : null}
        {currentSettings ? <>
          <dl className={styles.facts}>
            <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
            <div><dt>{t("accountTarget")}</dt><dd><code>{currentSettings.accountId}</code></dd></div>
            <div><dt>{t("accountReadVersion")}</dt><dd>{currentSettings.resourceVersion}</dd></div>
            <div><dt>{t("accountReadUpdated")}</dt><dd><time dateTime={currentSettings.updatedAt}>{format.dateTime(new Date(currentSettings.updatedAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</time></dd></div>
          </dl>
          <Alert>{t("accountReadBoundary")}</Alert>
          {stage === "summary" && !mutation ? <>
            <AccountSecurityRulesValues value={currentSettings} />
            <Typography.Text tone="muted">{password("liveBoundary")}</Typography.Text>
            <Alert>{network("live.boundary")}</Alert>
            {!update ? <Alert status="warning">{client?.canUpdate ? network("live.updateUnavailable") : t("accountUpdateDenied")}</Alert> : <div className={accessStyles.actions}><Button ref={editButton} disabled={refreshing} onClick={editSettings} variant="secondary">{security("edit")}</Button></div>}
          </> : null}
        </> : null}
        {renderSettingsFlow()}
        {result.status === "forbidden" ? <Alert status="warning">{t("accountReadDenied")}</Alert> : null}
        {canRetry ? <Alert status="danger">{t(result.status === "routeUnavailable" ? "accountReadRouteUnavailable" : "accountReadUnavailable")} <Button onClick={retryRead} size="small" variant="ghost"><RefreshCcw aria-hidden="true" />{t("accountReadRetry")}</Button></Alert> : null}
      </Card.Body>
    </Card>
  </section>;
}
