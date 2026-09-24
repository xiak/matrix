"use client";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Checkbox, FormField, Input, Select, TextArea, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, UserSsoConfiguration } from "../domain/accessWorkspace";
import { MfaSecurityPreview } from "./MfaPreviewExperience";
import { AccountSecuritySettingsPreview } from "./AccountSecuritySettingsPreview";
import styles from "./AccountAccessRenderer.module.css";
import securityStyles from "./MfaPreviewExperience.module.css";

export function AccessSecuritySettings({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  return <div className={securityStyles.securityRoot}>
    <Alert>{t("mockBoundary")}</Alert>
    <MfaSecurityPreview workspace={workspace} />
    <AccountSecuritySettingsPreview workspace={workspace} />
  </div>;
}

const emptySaml: UserSsoConfiguration = { protocol: "SAML", metadata: "", mappingClaim: "NameID" };
const emptyOidc: UserSsoConfiguration = { protocol: "OIDC", issuer: "", clientId: "", authorizationEndpoint: "", mappingClaim: "", jwks: "" };

export function AccessUserSso({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [phase, setPhase] = useState<"summary" | "edit" | "review">("summary");
  const [enabled, setEnabled] = useState(workspace.settings.userSsoEnabled);
  const [configuration, setConfiguration] = useState<UserSsoConfiguration>(workspace.settings.userSsoConfiguration ?? emptySaml);
  const changed = enabled !== workspace.settings.userSsoEnabled || JSON.stringify(configuration) !== JSON.stringify(workspace.settings.userSsoConfiguration);
  const current = workspace.settings.userSsoConfiguration;
  useLayoutEffect(() => { if (phase !== "summary") heading.current?.focus({ preventScroll: true }); }, [phase]);
  function edit() {
    setEnabled(workspace.settings.userSsoEnabled);
    setConfiguration(workspace.settings.userSsoConfiguration ?? emptySaml);
    access.clearWorkspaceError();
    setPhase("edit");
  }
  async function save() {
    const result = await access.executeWorkspace({ kind: "save-sso-settings", userSsoEnabled: enabled, userSsoConfiguration: configuration });
    if (result) setPhase("summary");
  }
  return <Card><Card.Header><Typography.Title as="h2" level={3}>{t("userSso")}</Typography.Title><Badge status={workspace.settings.userSsoEnabled ? "success" : "neutral"}>{t(workspace.settings.userSsoEnabled ? "enabled" : "disabled")}</Badge></Card.Header><Card.Body className={styles.stack}>
    {phase === "summary" ? <><Alert>{t("ssoHint")}</Alert><p className={styles.note}>{t("ssoFlow")}</p></> : null}
    {phase === "summary" ? <section className={styles.stack}>
      <h3 className={styles.stepTitle}>{t("userSsoConfiguration")}</h3>
      {current ? <dl className={styles.facts}><div><dt>{t("protocol")}</dt><dd>{current.protocol}</dd></div><div><dt>{t("issuer")}</dt><dd>{current.protocol === "OIDC" ? current.issuer : t("samlIssuerFromMetadata")}</dd></div><div><dt>{t("userSsoMapping")}</dt><dd>{current.mappingClaim}</dd></div></dl> : <p className={styles.note}>{t("userSsoNotConfigured")}</p>}
      <div className={styles.actions}><Button onClick={edit} variant="secondary">{t(current ? "edit" : "configure")}</Button></div>
    </section> : null}
    {phase === "edit" ? <form className={styles.form} onSubmit={(event) => { event.preventDefault(); setPhase("review"); }}>
      <h3 className={styles.stepTitle} ref={heading} tabIndex={-1}>{t("userSsoConfiguration")}</h3>
      <p className={styles.note}>{t("userSsoEditBoundary")}</p>
      <fieldset className={styles.editorFields} disabled={access.busy}>
        <FormField id={id + "-protocol"} label={t("protocol")}><Select id={id + "-protocol"} value={configuration.protocol} options={[{ value: "SAML", label: "SAML 2.0" }, { value: "OIDC", label: "OIDC" }]} onValueChange={(value) => setConfiguration(value === "OIDC" ? emptyOidc : emptySaml)} /></FormField>
        {configuration.protocol === "SAML" ? <FormField id={id + "-metadata"} label={t("userSsoSamlMetadata")} hint={t("userSsoLocalOnly")}><TextArea id={id + "-metadata"} required maxLength={65536} rows={6} spellCheck={false} value={configuration.metadata} onChange={(event) => setConfiguration({ protocol: "SAML", metadata: event.target.value, mappingClaim: "NameID" })} /></FormField> : <>
          <FormField id={id + "-issuer"} label={t("issuer")}><Input id={id + "-issuer"} required type="url" value={configuration.issuer} onChange={(event) => setConfiguration((current) => current.protocol === "OIDC" ? { ...current, issuer: event.target.value } : current)} /></FormField>
          <FormField id={id + "-client"} label={t("userSsoClientId")}><Input id={id + "-client"} required maxLength={256} value={configuration.clientId} onChange={(event) => setConfiguration((current) => current.protocol === "OIDC" ? { ...current, clientId: event.target.value } : current)} /></FormField>
          <FormField id={id + "-endpoint"} label={t("userSsoAuthorizationEndpoint")}><Input id={id + "-endpoint"} required type="url" value={configuration.authorizationEndpoint} onChange={(event) => setConfiguration((current) => current.protocol === "OIDC" ? { ...current, authorizationEndpoint: event.target.value } : current)} /></FormField>
          <FormField id={id + "-claim"} label={t("userSsoMapping")}><Input id={id + "-claim"} required maxLength={128} value={configuration.mappingClaim} onChange={(event) => setConfiguration((current) => current.protocol === "OIDC" ? { ...current, mappingClaim: event.target.value } : current)} /></FormField>
          <FormField id={id + "-jwks"} label={t("userSsoJwks")} hint={t("userSsoLocalOnly")}><TextArea id={id + "-jwks"} required maxLength={65536} rows={5} spellCheck={false} value={configuration.jwks} onChange={(event) => setConfiguration((current) => current.protocol === "OIDC" ? { ...current, jwks: event.target.value } : current)} /></FormField>
        </>}
        <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("ssoEnable")}</Checkbox>
        <div className={styles.actions}><Button disabled={!changed || access.busy} type="submit">{t("userSsoReview")}</Button><Button type="button" variant="secondary" onClick={() => setPhase("summary")}>{t("cancel")}</Button></div>
      </fieldset>
    </form> : null}
    {phase === "review" ? <section className={styles.stack}>
      <h3 className={styles.stepTitle} ref={heading} tabIndex={-1}>{t("userSsoReviewTitle")}</h3>
      <Alert status="warning">{t(enabled ? "userSsoEnableImpact" : "userSsoDisableImpact")}</Alert>
      <dl className={styles.facts}><div><dt>{t("userSsoTarget")}</dt><dd>{workspace.accountId}</dd></div><div><dt>{t("userSsoPreviousState")}</dt><dd>{t(workspace.settings.userSsoEnabled ? "enabled" : "disabled")}</dd></div><div><dt>{t("userSsoNewState")}</dt><dd>{t(enabled ? "enabled" : "disabled")}</dd></div><div><dt>{t("protocol")}</dt><dd>{configuration.protocol}</dd></div><div><dt>{t("userSsoMapping")}</dt><dd>{configuration.mappingClaim}</dd></div>{configuration.protocol === "SAML" ? <div><dt>{t("userSsoSamlMetadata")}</dt><dd>{t("userSsoMaterialPresent")}</dd></div> : <><div><dt>{t("issuer")}</dt><dd>{configuration.issuer}</dd></div><div><dt>{t("userSsoClientId")}</dt><dd>{configuration.clientId}</dd></div><div><dt>{t("userSsoAuthorizationEndpoint")}</dt><dd>{configuration.authorizationEndpoint}</dd></div><div><dt>{t("userSsoJwks")}</dt><dd>{t("userSsoMaterialPresent")}</dd></div></>}</dl>
      <p className={styles.note}>{t("userSsoReviewBoundary")}</p>
      <div className={styles.actions}><Button disabled={access.busy} onClick={() => void save()}>{t("save")}</Button><Button disabled={access.busy} onClick={() => { access.clearWorkspaceError(); setPhase("edit"); }} variant="secondary">{t("userSsoBackToEdit")}</Button></div>
    </section> : null}
  </Card.Body></Card>;
}
