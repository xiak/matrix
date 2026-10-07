"use client";
import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Checkbox, FormField, Input, TagEditor } from "@ui/xiak";
import type { AccessRole, AccessWorkspace } from "../domain/accessWorkspace";
import type { RoleTrust } from "../domain/roleTrust";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import styles from "./PolicyAuthoringWizard.module.css";

export function RoleTrustFields({ value, onChange, workspace, users }: { value: RoleTrust; onChange(value: RoleTrust): void; workspace: AccessWorkspace; users: { id: string; name: string }[] }) {
  const t = useTranslations("RoleWorkspace");
  return <div className={styles.stack}>
    <Alert>{t("trustHints.user")}</Alert>
    <p className={styles.note}>{t("tenant", { id: workspace.accountId })}</p>
    <WorkspaceSelection label={t("trustedUsers")} options={users} value={value.trustedUserIds} onChange={(trustedUserIds) => onChange({ trustedUserIds })} />
  </div>;
}
export function RoleSessionSettings({ value, onChange }: { value: Pick<AccessRole, "sessionMinutes" | "consoleAccess">; onChange(value: Pick<AccessRole, "sessionMinutes" | "consoleAccess">): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const id = useId();
  return <div className={styles.stack}><FormField id={id} label={w("sessionMinutes")} hint={t("durationHint")}><Input id={id} type="number" min={15} max={720} required value={value.sessionMinutes} aria-describedby={id + "-hint"} onChange={(event) => onChange({ ...value, sessionMinutes: Number(event.target.value) })} /></FormField><Checkbox checked={value.consoleAccess} onChange={(event) => onChange({ ...value, consoleAccess: event.target.checked })}>{w("consoleAccess")}</Checkbox><p className={styles.note}>{t("consoleHint")}</p></div>;
}
export function RoleTags({ value, onChange, disabled = false }: { value: AccessRole["tags"]; onChange(tags: AccessRole["tags"]): void; disabled?: boolean }) {
  const t = useTranslations("UserWizard");
  return <TagEditor value={value} disabled={disabled} onChange={onChange} labels={{ key: (index) => t("tagKey", { index }), value: (index) => t("tagValue", { index }), remove: (index) => t("removeTag", { index }), add: t("addTag"), empty: t("noTagsHint"), count: t("tagCount", { count: value.length }) }} />;
}
