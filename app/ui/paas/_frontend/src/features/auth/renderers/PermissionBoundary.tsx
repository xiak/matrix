"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, FormField, Select } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { WorkspaceDialog } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export function BoundarySelector({ workspace, value, onChange }: { workspace: AccessWorkspace; value?: string; onChange(id: string | undefined): void }) {
  const t = useTranslations("RoleWorkspace");
  const id = useId();
  return <FormField id={id} label={t("boundary")} hint={t("boundaryHint")}><Select id={id} value={value ?? ""} aria-describedby={id + "-hint"} options={[{ value: "", label: t("noBoundary") }, ...workspace.policies.map((policy) => ({ value: policy.id, label: policy.name }))]} onValueChange={(id) => onChange(id || undefined)} /></FormField>;
}
function BoundaryEditor({ workspace, current, onSave, onClose }: { workspace: AccessWorkspace; current?: string; onSave(id: string | undefined): Promise<unknown>; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const [value, setValue] = useState(current);
  const [review, setReview] = useState(false);
  const label = (id?: string) => workspace.policies.find((policy) => policy.id === id)?.name ?? id ?? t("noBoundary");
  return <WorkspaceDialog title={t("editBoundary")} onClose={onClose} submitDisabled={value === current} submitLabel={review ? w("save") : t("reviewChange")} onSubmit={async () => { if (!review) { setReview(true); return false; } return Boolean(await onSave(value)); }}>
    {review ? <><Alert status="warning">{t("boundaryChangeHint")}</Alert><dl className={styles.facts}><div><dt>{t("before")}</dt><dd>{label(current)}</dd></div><div><dt>{t("after")}</dt><dd>{label(value)}</dd></div></dl><Button variant="ghost" onClick={() => setReview(false)}>{t("backToSelection")}</Button></> : <BoundarySelector workspace={workspace} value={value} onChange={setValue} />}
  </WorkspaceDialog>;
}
export function PermissionBoundary({ workspace, value, onSave, onOpen }: { workspace: AccessWorkspace; value?: string; onSave(id: string | undefined): Promise<unknown>; onOpen(id: string): void }) {
  const t = useTranslations("RoleWorkspace");
  const [editing, setEditing] = useState(false);
  return <section className={styles.stack} aria-label={t("boundary")}><div className={styles.actionHeader}><h3>{t("boundary")}</h3><Button variant="ghost" onClick={() => setEditing(true)}>{t("editBoundary")}</Button></div><p className={styles.note}>{t("boundaryHint")}</p>{value ? <div><button className={styles.userLink} onClick={() => onOpen(value)}>{workspace.policies.find((policy) => policy.id === value)?.name ?? value}</button></div> : <p className={styles.note}>{t("noBoundary")}</p>}{editing ? <BoundaryEditor workspace={workspace} current={value} onSave={onSave} onClose={() => setEditing(false)} /> : null}</section>;
}
