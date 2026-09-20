"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Checkbox, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { SecurityStepUpPreview } from "./SecurityStepUpPreview";
import styles from "./MfaPreviewExperience.module.css";

type Stage = "edit" | "review" | "verify";

export function AccountSecuritySettingsPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  const access = useAccountAccess();
  const [required, setRequired] = useState(workspace.settings.loginProtection);
  const [stage, setStage] = useState<Stage>("edit");
  const [feedback, setFeedback] = useState<"enabled" | "disabled" | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const focus = useRef<"trigger" | "heading" | null>(null);
  const changed = required !== workspace.settings.loginProtection;

  useLayoutEffect(() => {
    if (!focus.current) return;
    const target = focus.current;
    focus.current = null;
    if (target === "trigger") trigger.current?.focus();
    else heading.current?.focus();
  }, [stage, workspace.settings.loginProtection]);

  const review = () => {
    setFeedback(null);
    focus.current = "heading";
    setStage("review");
  };
  const backToEdit = () => {
    focus.current = "trigger";
    setStage("edit");
  };
  const save = async () => {
    const saved = await access.executeWorkspace({ kind: "save-settings", settings: { ...workspace.settings, loginProtection: required } });
    if (!saved) return false;
    setFeedback(required ? "enabled" : "disabled");
    focus.current = "heading";
    setStage("edit");
    return true;
  };

  if (stage === "verify") return <SecurityStepUpPreview action="securitySettings" onCancel={() => { focus.current = "heading"; setStage("review"); }} onVerified={save} />;

  if (stage === "review") return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t("accountReviewTitle")}</h2><Typography.Text tone="muted">{t("accountReviewHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
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
  </Card>;

  return <section aria-labelledby="account-policy" className={styles.section}>
    <div className={styles.sectionHeading}><div><p>{t("accountEyebrow")}</p><h2 id="account-policy" ref={heading} tabIndex={-1}>{t("accountTitle")}</h2><span>{t("accountHint")}</span></div><div className={styles.headingBadges}><Badge status={workspace.settings.loginProtection ? "success" : "neutral"}>{t(workspace.settings.loginProtection ? "required" : "optional")}</Badge><Badge status="warning">MOCK</Badge></div></div>
    {feedback ? <Alert status="success">{t(`feedback.policy${feedback === "enabled" ? "Enabled" : "Disabled"}`)}</Alert> : null}
    <Card><Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("accountControlTitle")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header><Card.Body><form className={styles.policyForm} onSubmit={(event) => { event.preventDefault(); review(); }}>
      <Checkbox checked={required} onChange={(event) => { setRequired(event.target.checked); setFeedback(null); }}>{t("requireForUsers")}</Checkbox>
      <p>{t("requireForUsersHint")}</p>
      {changed && required ? <Alert status="warning">{t("reauthenticationWarning")}</Alert> : null}
      <Alert>{t("accountMockBoundary")}</Alert>
      <div className={styles.flowActions}><Button disabled={!changed || access.busy} ref={trigger} type="submit">{t("reviewAccountChange")}</Button><Button disabled={!changed || access.busy} onClick={() => { setRequired(workspace.settings.loginProtection); setFeedback(null); }} type="button" variant="ghost">{t("cancel")}</Button></div>
    </form></Card.Body></Card>
  </section>;
}
