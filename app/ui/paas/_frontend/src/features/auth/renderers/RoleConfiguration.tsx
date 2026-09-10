"use client";
import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Checkbox, FormField, Input, Select, TagEditor } from "@ui/xiak";
import type { AccessRole, AccessWorkspace } from "../domain/accessWorkspace";
import { roleServicePrincipals, type RoleTrust } from "../domain/roleTrust";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import styles from "./PolicyAuthoringWizard.module.css";

export function RoleTrustFields({ value, onChange, workspace, users, locked = false }: { value: RoleTrust; onChange(value: RoleTrust): void; workspace: AccessWorkspace; users: { id: string; name: string }[]; locked?: boolean }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const id = useId();
  return <div className={styles.stack}>
    <FormField id={id + "-type"} label={w("principalType")}><Select id={id + "-type"} disabled={locked} value={value.principalType} options={(["account", "service", "provider"] as const).map((type) => ({ value: type, label: w(type === "service" ? "servicePrincipal" : type) }))} onValueChange={(type) => onChange({ principalType: type as RoleTrust["principalType"], principal: type === "account" ? workspace.accountId : "", trustedUserIds: [] })} /></FormField>
    <Alert>{t(`trustHints.${value.principalType}`)}</Alert>
    {value.principalType === "account" ? <><p className={styles.note}>{t("tenant", { id: workspace.accountId })}</p><WorkspaceSelection label={t("trustedUsers")} options={users} value={value.trustedUserIds} onChange={(trustedUserIds) => onChange({ ...value, trustedUserIds })} /></> : <FormField id={id + "-principal"} label={w("principal")}><Select id={id + "-principal"} value={value.principal} placeholder={t("choosePrincipal")} options={value.principalType === "service" ? roleServicePrincipals.map((value) => ({ value, label: value })) : workspace.providers.filter((provider) => provider.enabled).map((provider) => ({ value: provider.id, label: provider.name }))} onValueChange={(principal) => onChange({ ...value, principal })} /></FormField>}
  </div>;
}
export function RoleSessionSettings({ value, onChange, service }: { value: Pick<AccessRole, "sessionMinutes" | "consoleAccess">; onChange(value: Pick<AccessRole, "sessionMinutes" | "consoleAccess">): void; service: boolean }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const id = useId();
  return <div className={styles.stack}><FormField id={id} label={w("sessionMinutes")} hint={t("durationHint")}><Input id={id} type="number" min={15} max={720} required value={value.sessionMinutes} aria-describedby={id + "-hint"} onChange={(event) => onChange({ ...value, sessionMinutes: Number(event.target.value) })} /></FormField><Checkbox checked={value.consoleAccess} disabled={service} onChange={(event) => onChange({ ...value, consoleAccess: event.target.checked })}>{w("consoleAccess")}</Checkbox><p className={styles.note}>{service ? w("serviceNoConsole") : t("consoleHint")}</p></div>;
}
export function RoleTags({ value, onChange }: { value: AccessRole["tags"]; onChange(tags: AccessRole["tags"]): void }) {
  const t = useTranslations("UserWizard");
  return <TagEditor value={value} onChange={onChange} labels={{ key: (index) => t("tagKey", { index }), value: (index) => t("tagValue", { index }), remove: (index) => t("removeTag", { index }), add: t("addTag"), empty: t("noTagsHint"), count: t("tagCount", { count: value.length }) }} />;
}
