"use client";
import { useId } from "react";
import { useTranslations } from "next-intl";
import { FormField, Input } from "@ui/xiak";
import styles from "../platform/Workspace.module.css";
export function ResourceIdentityFields({ id, name, onId, onName }: { id: string; name: string; onId(value: string): void; onName(value: string): void }) {
  const t = useTranslations("Collection");
  const fieldId = useId();
  const nameId = useId();
  return <div className={styles.fields}>
    <FormField id={fieldId} label={t("id")} hint={t("idHint")}><Input id={fieldId} aria-describedby={`${fieldId}-hint`} required maxLength={128} pattern={"[A-Za-z0-9][A-Za-z0-9._:\\-]{0,127}"} title={t("idHint")} value={id} onChange={event => onId(event.target.value)} /></FormField>
    <FormField id={nameId} label={t("name")} hint={t("nameHint")}><Input id={nameId} aria-describedby={`${nameId}-hint`} required maxLength={63} pattern={"[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?"} title={t("nameHint")} value={name} onChange={event => onName(event.target.value)} /></FormField>
  </div>;
}
