"use client";
import { useTranslations } from "next-intl";
import { FormField, Input } from "@ui/xiak";
import styles from "../platform/Workspace.module.css";
export function ResourceIdentityFields({ id, name, onId, onName }: { id: string; name: string; onId(value: string): void; onName(value: string): void }) {
  const t = useTranslations("Collection");
  return <div className={styles.fields}><FormField label={t("id")}><Input required maxLength={128} pattern="[a-z0-9][a-z0-9._-]{0,127}" value={id} onChange={event => onId(event.target.value)} /></FormField><FormField label={t("name")}><Input required maxLength={128} value={name} onChange={event => onName(event.target.value)} /></FormField></div>;
}
