"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Table, Tabs, Typography } from "@ui/xiak";
import { externalIdentityProjectionIssue, type AccessWorkspace } from "../domain/accessWorkspace";
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
  const providers = workspace.providers.filter((provider) => provider.accountId === workspace.accountId);
  const identityIssues = workspace.externalIdentities.map((identity) => ({ identity, issue: externalIdentityProjectionIssue(identity, workspace) }));
  const identities = identityIssues.filter((entry) => entry.issue === null).map((entry) => entry.identity);
  const providerName = (providerId: string) => providers.find((provider) => provider.id === providerId)?.name ?? providerId;
  const providerEnabled = (providerId: string) => Boolean(providers.find((provider) => provider.id === providerId)?.enabled);

  return <Card><Card.Header>
    <div className={styles.cardHeadingCopy}>
      <Typography.Title as="h2" id={titleId} level={3}>{t("title")}</Typography.Title>
      <Typography.Text tone="muted">{t("subtitle")}</Typography.Text>
    </div>
    <div className={styles.headingBadges}><Badge status="warning">MOCK</Badge><Badge status="neutral">{t("state")}</Badge></div>
  </Card.Header><Card.Body className={styles.stack}>
    <Alert status="info">{t("boundary")}</Alert>

    <section aria-labelledby={`${titleId}-projection`} className={styles.stack}>
      <div className={styles.cardHeadingCopy}><h3 className={styles.stepTitle} id={`${titleId}-projection`}>{t("projectionTitle")}</h3><p className={styles.note}>{t("projectionHint")}</p></div>
      {identityIssues.some((entry) => entry.issue !== null) ? <Alert status="warning">{t("invalidProjection")}</Alert> : null}
      <Table aria-label={t("providerDirectory")} className={styles.federationProviderTable} mobileLayout="stack">
        <thead><tr><th scope="col">{t("providerId")}</th><th scope="col">{t("accountProtocol")}</th><th scope="col">{t("endpoints")}</th><th scope="col">{t("providerState")}</th></tr></thead>
        <tbody>{providers.map((provider) => <tr key={provider.id}>
          <td data-label={t("providerId")}><strong>{provider.name}</strong><small><code>{provider.id}</code></small></td>
          <td data-label={t("accountProtocol")}><code>{provider.accountId}</code><small>{provider.protocol}</small></td>
          <td data-label={t("endpoints")}><dl className={styles.federationEndpoints}><div><dt>{t("issuer")}</dt><dd><code>{provider.issuer}</code></dd></div><div><dt>{t("redirectUri")}</dt><dd><code>{provider.redirectUri}</code></dd></div></dl></td>
          <td data-label={t("providerState")}><Badge status={provider.enabled ? "neutral" : "warning"}>{t(provider.enabled ? "projectionAvailable" : "newSessionBlocked")}</Badge></td>
        </tr>)}</tbody>
      </Table>
      <Table aria-label={t("externalIdentityDirectory")} mobileLayout="stack">
        <thead><tr><th scope="col">{t("externalIdentity")}</th><th scope="col">{t("provider")}</th><th scope="col">{t("account")}</th><th scope="col">{t("targetUser")}</th><th scope="col">{t("mappingState")}</th></tr></thead>
        <tbody>{identities.map((identity) => <tr key={identity.id}>
          <td data-label={t("externalIdentity")}><code>{identity.subject}</code></td>
          <td data-label={t("provider")}>{providerName(identity.providerId)}</td>
          <td data-label={t("account")}><code>{identity.accountId}</code></td>
          <td data-label={t("targetUser")}><code>{identity.userId}</code></td>
          <td data-label={t("mappingState")}><Badge status={identity.enabled && providerEnabled(identity.providerId) ? "neutral" : "warning"}>{t(identity.enabled && providerEnabled(identity.providerId) ? "mappingConfigured" : "newSessionBlocked")}</Badge></td>
        </tr>)}</tbody>
      </Table>
      <Alert status={providers.some((provider) => !provider.enabled) ? "warning" : "info"}>{t(providers.some((provider) => !provider.enabled) ? "disabledProviderEffect" : "enabledProviderBoundary")}</Alert>
    </section>

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
