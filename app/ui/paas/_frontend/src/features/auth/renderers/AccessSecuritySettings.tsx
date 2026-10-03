"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Tabs, Typography } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { MfaSecurityPreview } from "./MfaPreviewExperience";
import { AccountSecuritySettingsPreview } from "./AccountSecuritySettingsPreview";
import { PasswordRulesPreview } from "./PasswordRulesPreview";
import { SessionIdleSettingsPreview } from "./SessionIdleSettingsPreview";
import { PasskeyConceptPreview } from "./PasskeyConceptPreview";
import { AccountAccessKeyNetworkPreview } from "./AccessKeyNetworkPreview";
import styles from "./AccountAccessRenderer.module.css";
import securityStyles from "./MfaPreviewExperience.module.css";

export function AccessSecuritySettings({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("AccountAccess");
  const mfa = useTranslations("MfaPreview");
  const [section, setSection] = useState<"personal" | "account" | "session">("personal");
  const [mounted, setMounted] = useState({ personal: true, account: false, session: false });

  const openSection = (value: string) => {
    const next = value as "personal" | "account" | "session";
    setSection(next);
    setMounted((current) => current[next] ? current : { ...current, [next]: true });
  };

  return <section aria-labelledby="security-settings-workspace-title" className={securityStyles.securityRoot} id="security-settings-workspace" tabIndex={-1}>
    <div className={securityStyles.sectionHeading}>
      <div>
        <p>{t("securityWorkspaceEyebrow")}</p>
        <h2 id="security-settings-workspace-title">{t("securityWorkspaceTitle")}</h2>
        <span>{t("securityWorkspaceHint")}</span>
      </div>
      <Badge status="warning">MOCK</Badge>
    </div>
    <Alert>{mfa("mockBoundary")}</Alert>
    <Tabs.Root className={securityStyles.securityTabs} onValueChange={openSection} value={section}>
      <Tabs.List aria-label={t("securityWorkspaceSections")}>
        <Tabs.Trigger value="personal">{t("settingsPersonalSecurity")}</Tabs.Trigger>
        <Tabs.Trigger value="account">{t("securityWorkspaceAccountPolicy")}</Tabs.Trigger>
        <Tabs.Trigger value="session">{t("securityWorkspaceSession")}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className={securityStyles.securityTabContent} forceMount={mounted.personal || undefined} value="personal">
        {mounted.personal ? <><MfaSecurityPreview workspace={workspace} /><PasskeyConceptPreview /></> : null}
      </Tabs.Content>
      <Tabs.Content className={securityStyles.securityTabContent} forceMount={mounted.account || undefined} value="account">
        {mounted.account ? <><AccountSecuritySettingsPreview workspace={workspace} /><AccountAccessKeyNetworkPreview workspace={workspace} /><PasswordRulesPreview accountId={workspace.accountId} /></> : null}
      </Tabs.Content>
      <Tabs.Content className={securityStyles.securityTabContent} forceMount={mounted.session || undefined} value="session">
        {mounted.session ? <SessionIdleSettingsPreview /> : null}
      </Tabs.Content>
    </Tabs.Root>
  </section>;
}

export function AccessUserSso({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace.userSsoConcept");
  const titleId = useId();
  const journey = ["provider", "mapping", "session", "authorization"] as const;
  const readiness = ["installation", "trust", "identity", "recovery", "audit"] as const;
  const samlRequirements = ["metadata", "serviceProvider", "signature", "subject"] as const;
  const oidcRequirements = ["issuer", "client", "proof", "subject"] as const;

  return <Card><Card.Header>
    <div className={styles.cardHeadingCopy}>
      <Typography.Title as="h2" id={titleId} level={3}>{t("title")}</Typography.Title>
      <Typography.Text tone="muted">{t("subtitle")}</Typography.Text>
    </div>
    <div className={styles.headingBadges}><Badge status="warning">MOCK</Badge><Badge status="neutral">{t("state")}</Badge></div>
  </Card.Header><Card.Body className={styles.stack}>
    <Alert status="info">{t("boundary")}</Alert>

    <section aria-labelledby={`${titleId}-journey`} className={styles.stack}>
      <div className={styles.securityCheckHeading}>
        <div className={styles.cardHeadingCopy}><h3 className={styles.stepTitle} id={`${titleId}-journey`}>{t("journeyTitle")}</h3><p className={styles.note}>{t("journeyHint")}</p></div>
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

    <section aria-labelledby={`${titleId}-protocols`} className={styles.stack}>
      <div className={styles.cardHeadingCopy}><h3 className={styles.stepTitle} id={`${titleId}-protocols`}>{t("protocolsTitle")}</h3><p className={styles.note}>{t("protocolsHint")}</p></div>
      <div className={styles.settingsGrid}>
        <section className={styles.conceptPanel} aria-labelledby={`${titleId}-saml`}>
          <div className={styles.securityCheckHeading}><strong id={`${titleId}-saml`}>{t("protocols.saml.title")}</strong><Badge status="neutral">SAML 2.0</Badge></div>
          <p>{t("protocols.saml.hint")}</p>
          <ul>{samlRequirements.map((item) => <li key={item}>{t(`protocols.saml.items.${item}`)}</li>)}</ul>
        </section>
        <section className={styles.conceptPanel} aria-labelledby={`${titleId}-oidc`}>
          <div className={styles.securityCheckHeading}><strong id={`${titleId}-oidc`}>{t("protocols.oidc.title")}</strong><Badge status="neutral">OIDC</Badge></div>
          <p>{t("protocols.oidc.hint")}</p>
          <ul>{oidcRequirements.map((item) => <li key={item}>{t(`protocols.oidc.items.${item}`)}</li>)}</ul>
        </section>
      </div>
    </section>

    <section aria-labelledby={`${titleId}-readiness`} className={styles.stack}>
      <div className={styles.cardHeadingCopy}><h3 className={styles.stepTitle} id={`${titleId}-readiness`}>{t("readinessTitle")}</h3><p className={styles.note}>{t("readinessHint")}</p></div>
      <ol className={styles.securityChecks}>
        {readiness.map((item, index) => <li key={item}>
          <Badge status="neutral">{index + 1}</Badge>
          <div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`readiness.${item}.title`)}</strong><Badge status="warning">{t("notReady")}</Badge></div><p>{t(`readiness.${item}.detail`)}</p></div>
        </li>)}
      </ol>
    </section>

    <section aria-labelledby={`${titleId}-comparison`} className={styles.stack}>
      <div className={styles.cardHeadingCopy}><h3 className={styles.stepTitle} id={`${titleId}-comparison`}>{t("comparisonTitle")}</h3><p className={styles.note}>{t("comparisonHint")}</p></div>
      <dl className={styles.facts}>
        <div><dt>{t("comparison.user.title")}</dt><dd>{t("comparison.user.detail")}</dd></div>
        <div><dt>{t("comparison.role.title")}</dt><dd>{t("comparison.role.detail")}</dd></div>
      </dl>
    </section>
  </Card.Body></Card>;
}
