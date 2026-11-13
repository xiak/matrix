"use client";
import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountSettingsSection } from "../domain/accounts";
import { MfaSecurityPreview } from "./MfaPreviewExperience";
import { AccountSecuritySettingsPreview } from "./AccountSecuritySettingsPreview";
import { PasswordRulesPreview } from "./PasswordRulesPreview";
import { SessionIdleSettingsPreview } from "./SessionIdleSettingsPreview";
import { PasskeyConceptPreview } from "./PasskeyConceptPreview";
import { AccountAccessKeyNetworkPreview } from "./AccessKeyNetworkPreview";
import { FederationBoundaryOverview } from "./FederationBoundaryOverview";
import styles from "./AccountAccessRenderer.module.css";
import securityStyles from "./MfaPreviewExperience.module.css";

export function AccessSecuritySettings({ onOpenPersonalSecurity, section, workspace }: { onOpenPersonalSecurity(): void; section: Exclude<AccountSettingsSection, "sign-in">; workspace: AccessWorkspace }) {
  const t = useTranslations("AccountAccess");
  const mfa = useTranslations("MfaPreview");
  const personal = section === "personal-security";
  const title = t(personal ? "settingsPersonalSecurity" : "settingsAccountSecurity");
  const hint = t(personal ? "settingsPersonalSecurityHint" : "settingsAccountSecurityHint");

  return <section aria-labelledby="security-settings-workspace-title" className={securityStyles.securityRoot} id={`preview-${section}`} tabIndex={-1}>
    <div className={securityStyles.sectionHeading}>
      <div>
        <p>{t("securityWorkspaceEyebrow")}</p>
        <h2 id="security-settings-workspace-title">{title}</h2>
        <span>{hint}</span>
      </div>
      <Badge status="warning">MOCK</Badge>
    </div>
    <Alert>{mfa("mockBoundary")}</Alert>
    <div className={securityStyles.securityTabContent}>
      {personal ? <><MfaSecurityPreview workspace={workspace} /><PasskeyConceptPreview /></>
        : <><AccountSecuritySettingsPreview onOpenPersonalSecurity={onOpenPersonalSecurity} workspace={workspace} /><AccountAccessKeyNetworkPreview workspace={workspace} /><PasswordRulesPreview accountId={workspace.accountId} /><SessionIdleSettingsPreview /></>}
    </div>
  </section>;
}

export function AccessUserSso({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace.userSsoConcept");
  const titleId = useId();
  const journey = ["provider", "mapping", "session", "authorization"] as const;
  const readiness = ["installation", "trust", "identity", "recovery", "audit"] as const;

  return (
    <div className={styles.stack}>
      <FederationBoundaryOverview current="user" />
      <Card>
        <Card.Body className={styles.stack}>
    <section aria-labelledby={`${titleId}-journey`} className={styles.stack}>
      <div className={styles.securityCheckHeading}>
        <div className={styles.cardHeadingCopy}><h2 className={styles.stepTitle} id={`${titleId}-journey`}>{t("journeyTitle")}</h2><p className={styles.note}>{t("journeyHint")}</p></div>
        <Badge status="neutral">{workspace.accountId}</Badge>
      </div>
      <ol className={styles.securityChecks}>
        {journey.map((step, index) => <li key={step}>
          <Badge status="neutral">{index + 1}</Badge>
          <div className={styles.securityCheckCopy}>
            <div className={styles.securityCheckHeading}><strong>{t(`journey.${step}.title`)}</strong><Badge status={step === "provider" || step === "mapping" || step === "session" ? "warning" : "neutral"}>{t(`journey.${step}.state`)}</Badge></div>
            <p>{t(`journey.${step}.detail`)}</p>
          </div>
        </li>)}
      </ol>
    </section>

    <section aria-labelledby={`${titleId}-readiness`} className={styles.stack}>
      <div className={styles.cardHeadingCopy}><h2 className={styles.stepTitle} id={`${titleId}-readiness`}>{t("readinessTitle")}</h2><p className={styles.note}>{t("readinessHint")}</p></div>
      <ol className={styles.securityChecks}>
        {readiness.map((item, index) => <li key={item}>
          <Badge status="neutral">{index + 1}</Badge>
          <div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`readiness.${item}.title`)}</strong><Badge status="warning">{t("notReady")}</Badge></div><p>{t(`readiness.${item}.detail`)}</p></div>
        </li>)}
      </ol>
    </section>

        </Card.Body>
      </Card>
    </div>
  );
}
