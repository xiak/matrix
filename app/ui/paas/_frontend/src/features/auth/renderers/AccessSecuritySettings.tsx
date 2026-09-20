"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, Card, Checkbox, FormField, Select, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessSettings, AccessWorkspace } from "../domain/accessWorkspace";
import { MfaSecurityPreview } from "./MfaPreviewExperience";
import styles from "./AccountAccessRenderer.module.css";

export function AccessSecuritySettings({ workspace }: { workspace: AccessWorkspace }) {
  return <MfaSecurityPreview workspace={workspace} />;
}

export function AccessUserSso({ workspace, onProviders }: { workspace: AccessWorkspace; onProviders(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [enabled, setEnabled] = useState(workspace.settings.userSsoEnabled);
  const [providerId, setProviderId] = useState(workspace.settings.userSsoProviderId);
  const changed = enabled !== workspace.settings.userSsoEnabled || providerId !== workspace.settings.userSsoProviderId;
  const settings: AccessSettings = { ...workspace.settings, userSsoEnabled: enabled, userSsoProviderId: providerId };
  return <Card><Card.Header><Typography.Title as="h2" level={3}>{t("userSso")}</Typography.Title><Badge status={workspace.settings.userSsoEnabled ? "success" : "neutral"}>{t(workspace.settings.userSsoEnabled ? "enabled" : "disabled")}</Badge></Card.Header><Card.Body className={styles.stack}>
    <p className={styles.note}>{t("ssoHint")}</p><p className={styles.flow}>{t("ssoFlow")}</p>
    {workspace.providers.length ? <form className={styles.form} onSubmit={async (event) => { event.preventDefault(); await access.executeWorkspace({ kind: "save-settings", settings }); }}>
      <fieldset className={styles.editorFields} disabled={access.busy}>
        <FormField id={id} label={t("ssoProvider")}><Select id={id} required={enabled} value={providerId} options={[{ value: "", label: t("ssoProvider") }, ...workspace.providers.filter((provider) => provider.enabled).map((provider) => ({ value: provider.id, label: provider.name + " · " + provider.protocol }))]} onValueChange={(value) => setProviderId(value)} /></FormField>
        <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("ssoEnable")}</Checkbox>
        <div className={styles.actions}><Button disabled={!changed || access.busy} type="submit">{t("save")}</Button><Button variant="secondary" onClick={onProviders}>{t("providers")}</Button></div>
      </fieldset>
    </form> : <div className={styles.stack}><p className={styles.note}>{t("ssoMissing")}</p><div><Button onClick={onProviders}>{t("createProvider")}</Button></div></div>}
  </Card.Body></Card>;
}
