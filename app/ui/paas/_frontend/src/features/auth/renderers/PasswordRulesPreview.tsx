"use client";

import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { KeyRound } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, FormField, Input, Select, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

type RuleDraft = {
  minimumLength: string;
  historyCount: string;
  requireLowercase: boolean;
  requireUppercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
};
type IdentityScenario = "ordinary" | "forced" | "challenge" | "protected";
type ExceptionScenario = "denied" | "conflict" | "unknown";

const sampleRule: RuleDraft = {
  minimumLength: "15", historyCount: "1",
  requireLowercase: false, requireUppercase: false, requireDigit: false, requireSymbol: false
};
const characterRules = ["requireLowercase", "requireUppercase", "requireDigit", "requireSymbol"] as const;

/** Isolated MOCK design flow. It does not read, save, or derive a permit from IAM settings. */
export function PasswordRulesPreview({ accountId }: { accountId: string }) {
  const t = useTranslations("PasswordRulesPreview");
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [phase, setPhase] = useState<"summary" | "edit" | "review">("summary");
  const [draft, setDraft] = useState<RuleDraft>(sampleRule);
  const [identity, setIdentity] = useState<IdentityScenario>("ordinary");
  const [exception, setException] = useState<ExceptionScenario>("conflict");
  const minimum = Number(draft.minimumLength);
  const history = Number(draft.historyCount);
  const valid = Number.isInteger(minimum) && minimum >= 15 && minimum <= 128 &&
    Number.isInteger(history) && history >= 0 && history <= 24;
  const scenarioUsesDraft = phase !== "summary" && identity !== "protected" && valid;
  const scenarioRule = scenarioUsesDraft ? draft : sampleRule;

  useLayoutEffect(() => {
    if (phase !== "summary") heading.current?.focus({ preventScroll: true });
  }, [phase]);

  const setCharacterRule = (field: typeof characterRules[number], checked: boolean) => {
    setDraft((current) => ({ ...current, [field]: checked }));
  };
  const begin = () => { setDraft({ ...sampleRule }); setPhase("edit"); };

  return <section aria-labelledby="password-rules-preview" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div><p>{t("eyebrow")}</p><h2 id="password-rules-preview">{t("title")}</h2><span>{t("hint")}</span></div>
      <Badge status="warning">{t("badge")}</Badge>
    </div>
    <Card>
      <Card.Header><div className={styles.cardTitle}><span><KeyRound aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("summaryTitle")}</Typography.Title><Typography.Text tone="muted">{t("summaryHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm}>
        <Alert>{t("previewBoundary")}</Alert>
        {phase === "summary" ? <>
          <dl className={styles.facts}>
            <div><dt>{t("minimumLength")}</dt><dd>{t("minimumLengthValue")}</dd></div>
            <div><dt>{t("characterClasses")}</dt><dd>{t("characterClassesValue")}</dd></div>
            <div><dt>{t("reuse")}</dt><dd>{t("reuseValue")}</dd></div>
            <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
            <div><dt>{t("protectedScope")}</dt><dd>{t("protectedScopeValue")}</dd></div>
          </dl>
          <Alert status="warning">{t("changeBoundary")}</Alert>
          <div className={styles.flowActions}><Button onClick={begin} variant="secondary">{t("exploreEdit")}</Button></div>
        </> : null}
        {phase === "edit" ? <form className={styles.policyForm} onSubmit={(event) => { event.preventDefault(); if (valid) setPhase("review"); }}>
          <h3 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t("editTitle")}</h3>
          <Typography.Text tone="muted">{t("draftBoundary")}</Typography.Text>
          <FormField id={`${id}-minimum`} label={t("editMinimumLength")} hint={t("minimumHint")} error={!Number.isInteger(minimum) || minimum < 15 || minimum > 128 ? t("minimumError") : undefined}>
            <Input className={styles.ruleNumber} id={`${id}-minimum`} type="number" min={15} max={128} step={1} value={draft.minimumLength} onChange={(event) => setDraft((current) => ({ ...current, minimumLength: event.target.value }))} />
          </FormField>
          <fieldset className={styles.ruleFields}>
            <legend>{t("characterRules")}</legend>
            {characterRules.map((field) => <Checkbox key={field} checked={draft[field]} onChange={(event) => setCharacterRule(field, event.target.checked)}>{t(field)}</Checkbox>)}
          </fieldset>
          <FormField id={`${id}-history`} label={t("editHistoryCount")} hint={t("historyHint")} error={!Number.isInteger(history) || history < 0 || history > 24 ? t("historyError") : undefined}>
            <Input className={styles.ruleNumber} id={`${id}-history`} type="number" min={0} max={24} step={1} value={draft.historyCount} onChange={(event) => setDraft((current) => ({ ...current, historyCount: event.target.value }))} />
          </FormField>
          <div className={styles.flowActions}><Button disabled={!valid} type="submit">{t("reviewDraft")}</Button><Button onClick={() => setPhase("summary")} type="button" variant="ghost">{t("closePreview")}</Button></div>
        </form> : null}
        {phase === "review" ? <div className={styles.policyForm}>
          <h3 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t("reviewTitle")}</h3>
          <Alert status="warning">{t("reviewBoundary")}</Alert>
          <dl className={styles.facts}>
            <div><dt>{t("targetAccount")}</dt><dd><code>{accountId}</code></dd></div>
            <div><dt>{t("editMinimumLength")}</dt><dd>{t("minimumComparison", { before: 15, after: minimum })}</dd></div>
            <div><dt>{t("characterRules")}</dt><dd>{characterRules.filter((field) => draft[field]).map((field) => t(field)).join(t("listSeparator")) || t("noneRequired")}</dd></div>
            <div><dt>{t("editHistoryCount")}</dt><dd>{t("historyComparison", { before: 1, after: history })}</dd></div>
          </dl>
          <Alert>{t("reviewEffect")}</Alert>
          <details className={styles.scenarioDetails}>
            <summary>{t("exceptionPreview")}</summary>
            <FormField id={`${id}-exception`} label={t("exceptionLabel")}><Select id={`${id}-exception`} value={exception} options={(["denied", "conflict", "unknown"] as const).map((value) => ({ value, label: t(`exceptions.${value}`) }))} onValueChange={(value) => setException(value as ExceptionScenario)} /></FormField>
            <Alert status="warning">{t(`exceptionHints.${exception}`)}</Alert>
          </details>
          <div className={styles.flowActions}><Button onClick={() => setPhase("edit")} variant="secondary">{t("backToEdit")}</Button><Button onClick={() => setPhase("summary")} variant="ghost">{t("closePreview")}</Button></div>
        </div> : null}
      </Card.Body>
    </Card>
    <Card>
      <Card.Header><Typography.Title as="h3" level={3}>{t("effectiveTitle")}</Typography.Title></Card.Header>
      <Card.Body className={styles.policyForm}>
        <FormField id={`${id}-identity`} label={t("identityScenario")} hint={t("identityBoundary")}><Select id={`${id}-identity`} value={identity} options={(["ordinary", "forced", "challenge", "protected"] as const).map((value) => ({ value, label: t(`identities.${value}`) }))} onValueChange={(value) => setIdentity(value as IdentityScenario)} /></FormField>
        <dl className={styles.facts}>
          <div><dt>{t("effectiveSource")}</dt><dd>{t(identity === "protected" ? "fixedProductFloor" : scenarioUsesDraft ? "draftAccountRule" : "sampleAccountRule")}</dd></div>
          <div><dt>{t("editMinimumLength")}</dt><dd>{t("effectiveMinimum", { count: scenarioRule.minimumLength })}</dd></div>
          <div><dt>{t("characterRules")}</dt><dd>{characterRules.filter((field) => scenarioRule[field]).map((field) => t(field)).join(t("listSeparator")) || t("noneRequired")}</dd></div>
          <div><dt>{t("editHistoryCount")}</dt><dd>{t("effectiveHistory", { count: scenarioRule.historyCount })}</dd></div>
        </dl>
        {!valid && phase === "edit" && identity !== "protected" ? <Alert status="warning">{t("invalidPreview")}</Alert> : null}
        <Alert>{t(`identityHints.${identity}`)}</Alert>
        <Typography.Text tone="muted">{t("effectiveBoundary")}</Typography.Text>
        <details className={styles.scenarioDetails}>
          <summary>{t("historicalResultTitle")}</summary>
          <Typography.Text tone="muted">{t("historicalResultMissing")}</Typography.Text>
          <Typography.Text tone="muted">{t("historicalSessionBoundary")}</Typography.Text>
        </details>
      </Card.Body>
    </Card>
  </section>;
}
