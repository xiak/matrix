"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Checkbox, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { SecurityStepUpPreview } from "./SecurityStepUpPreview";
import styles from "./MfaPreviewExperience.module.css";

type Stage = "summary" | "edit" | "review" | "verify" | "conflict";

export function AccountSecuritySettingsPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  const access = useAccountAccess();
  const [required, setRequired] = useState(workspace.settings.loginProtection);
  const [stage, setStage] = useState<Stage>("summary");
  const [feedback, setFeedback] = useState<"enabled" | "disabled" | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const focus = useRef<"trigger" | "heading" | "flow" | null>(null);
  const changed = required !== workspace.settings.loginProtection;

  useLayoutEffect(() => {
    if (!focus.current) return;
    const target = focus.current;
    focus.current = null;
    if (target === "trigger") trigger.current?.focus();
    else if (target === "flow") flowHeading.current?.focus();
    else heading.current?.focus();
  }, [stage, workspace.settings.loginProtection]);

  const review = () => {
    setFeedback(null);
    focus.current = "flow";
    setStage("review");
  };
  const backToEdit = () => {
    focus.current = "trigger";
    setStage("edit");
  };
  const save = async () => {
    const saved = await access.executeWorkspace(
      { kind: "save-settings", settings: { ...workspace.settings, loginProtection: required } },
      (error) => {
        if (error !== "conflict") return;
        access.clearWorkspaceError();
        focus.current = "flow";
        setStage("conflict");
      }
    );
    if (!saved) return false;
    setFeedback(required ? "enabled" : "disabled");
    focus.current = "heading";
    setStage("summary");
    return true;
  };

  return <section aria-labelledby="account-policy" className={styles.section}>
    <div className={styles.sectionHeading}><div><p>{t("accountEyebrow")}</p><h2 id="account-policy" ref={heading} tabIndex={-1}>{t("accountTitle")}</h2><span>{t("accountHint")}</span></div><div className={styles.headingBadges}><Badge status={workspace.settings.loginProtection ? "success" : "neutral"}>{t(workspace.settings.loginProtection ? "required" : "optional")}</Badge><Badge status="warning">MOCK</Badge></div></div>
    {feedback ? <Alert status="success">{t(`feedback.policy${feedback === "enabled" ? "Enabled" : "Disabled"}`)}</Alert> : null}
    {stage === "verify" ? <SecurityStepUpPreview action="securitySettings" onCancel={() => { focus.current = "flow"; setStage("review"); }} onVerified={save} /> : null}
    {stage === "review" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountReviewTitle")}</h3><Typography.Text tone="muted">{t("accountReviewHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("accountChange")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")} → {t(required ? "required" : "optional")}</dd></div>
          <div><dt>{t("accountTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
          <div><dt>{t("protectedIdentities")}</dt><dd>{t("protectedIdentitiesValue")}</dd></div>
          <div><dt>{t("sessionEffect")}</dt><dd>{t(required ? "sessionEffectTighten" : "sessionEffectRelax")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountReviewBoundary")}</Alert>
        <div className={styles.flowActions}><Button onClick={backToEdit} variant="ghost">{t("back")}</Button><Button onClick={() => setStage("verify")}>{t("verifyAccountChange")}</Button></div>
      </Card.Body>
    </Card> : null}
    {stage === "conflict" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountConflictTitle")}</h3><Typography.Text tone="muted">{t("accountConflictHint")}</Typography.Text></div><Badge status="warning">{t("staleReview")}</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("accountTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("attemptedChange")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")} → {t(required ? "required" : "optional")}</dd></div>
          <div><dt>{t("verificationState")}</dt><dd>{t("verificationDiscarded")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountConflictBoundary")}</Alert>
        <div className={styles.flowActions}><Button disabled={access.loading} onClick={() => { access.clearWorkspaceError(); setFeedback(null); setRequired(workspace.settings.loginProtection); focus.current = "heading"; setStage("summary"); access.reload(); }}>{t(access.loading ? "reloadingRule" : "reloadCurrentRule")}</Button></div>
      </Card.Body>
    </Card> : null}
    {stage === "summary" || stage === "edit" ? <Card><Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("accountControlTitle")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header><Card.Body>
      {stage === "summary" ? <div className={styles.policyForm}>
        <dl className={styles.facts}>
          <div><dt>{t("currentRule")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")}</dd></div>
          <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
          <div><dt>{t("protectedIdentities")}</dt><dd>{t("protectedIdentitiesValue")}</dd></div>
        </dl>
        <Alert>{t("accountMockBoundary")}</Alert>
        <div className={styles.flowActions}><Button disabled={access.loading || access.busy} ref={trigger} onClick={() => { setFeedback(null); setRequired(workspace.settings.loginProtection); setStage("edit"); }}>{t("editAccountRule")}</Button></div>
      </div> : <form className={styles.policyForm} onSubmit={(event) => { event.preventDefault(); review(); }}>
        <Checkbox checked={required} onChange={(event) => { setRequired(event.target.checked); setFeedback(null); }}>{t("requireForUsers")}</Checkbox>
        <p>{t("requireForUsersHint")}</p>
        {changed && required ? <Alert status="warning">{t("reauthenticationWarning")}</Alert> : null}
        <Alert>{t("accountMockBoundary")}</Alert>
        <div className={styles.flowActions}><Button disabled={!changed || access.busy} ref={trigger} type="submit">{t("reviewAccountChange")}</Button><Button disabled={access.busy} onClick={() => { setRequired(workspace.settings.loginProtection); setFeedback(null); focus.current = "trigger"; setStage("summary"); }} type="button" variant="ghost">{t("cancel")}</Button></div>
      </form>}
    </Card.Body></Card> : null}
  </section>;
}
