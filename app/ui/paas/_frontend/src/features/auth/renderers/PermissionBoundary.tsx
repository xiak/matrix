"use client";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, FormField, Select, Typography } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { accountError, type UserBoundaryClient, type UserBoundarySnapshot } from "../application/AccountAccessProvider";
import type { UserPermissionBoundary } from "../domain/accounts";
import { useAccessDraft } from "./useAccessDraft";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { WorkspaceDialog } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export function BoundarySelector({ workspace, value, onChange, autoFocus = false }: { workspace: AccessWorkspace; value?: string; onChange(id: string | undefined): void; autoFocus?: boolean }) {
  const t = useTranslations("RoleWorkspace");
  const id = useId();
  return <FormField id={id} label={t("boundary")} hint={t("boundaryHint")}><Select autoFocus={autoFocus} id={id} value={value ?? ""} aria-describedby={id + "-hint"} options={[{ value: "", label: t("noBoundary") }, ...workspace.policies.map((policy) => ({ value: policy.id, label: policy.name }))]} onValueChange={(id) => onChange(id || undefined)} /></FormField>;
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

export function UserBoundarySummary({ boundary }: { boundary: UserPermissionBoundary }) {
  const t = useTranslations("UserBoundary");
  return boundary.policy ? <dl className={styles.facts}>
    <div><dt>{t("policyId")}</dt><dd><Typography.Code>{boundary.policy.policyId}</Typography.Code></dd></div>
    <div><dt>{t("defaultVersion")}</dt><dd>{boundary.policy.versionId}</dd></div>
    <div><dt>{t("contentDigest")}</dt><dd><Typography.Code>{boundary.policy.contentDigest}</Typography.Code></dd></div>
  </dl> : <p className={styles.note}>{t("none")}</p>;
}

type BoundaryIntent =
  | { kind: "set"; policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string; versionId: string }
  | { kind: "remove"; resourceVersion: number; requestId: string };
type BoundaryOperation = { state: "idle" | "pending" | "uncertain" | "conflict" | "refreshFailed" | "completed"; error?: ReturnType<typeof accountError> };

// The live lifecycle owns its exact request and authoritative outcome. It does
// not use the MOCK evaluator, infer grants, or resend a confirmed mutation.
export function LivePermissionBoundary({ client, snapshot, onChanged }: {
  client: UserBoundaryClient; snapshot: UserBoundarySnapshot; onChanged(snapshot: UserBoundarySnapshot): void;
}) {
  const t = useTranslations("UserBoundary"), r = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const editTrigger = useRef<HTMLButtonElement>(null);
  const restoreEditFocus = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(snapshot.boundary.policy?.policyId ?? "");
  const [review, setReview] = useState(false);
  const [confirmed, setConfirmed] = useState<UserPermissionBoundary | null>(null);
  const [reviewedVersion, setReviewedVersion] = useState<string | null>(null);
  const [operation, setOperation] = useState<BoundaryOperation>({ state: "idle" });
  const intent = useRef<BoundaryIntent | null>(null);
  const boundary = confirmed ?? snapshot.boundary;
  const policies = snapshot.policies.filter((policy) => policy.status === "ACTIVE" && policy.scope === "TENANT" && (policy.accountId === null || policy.accountId === client.accountId));
  const selected = policies.find((policy) => policy.id === value);
  const canChange = snapshot.user.canSetPermissionBoundary || (boundary.policy !== null && snapshot.user.canRemovePermissionBoundary);
  const eligible = value !== (boundary.policy?.policyId ?? "") && (value
    ? selected !== undefined && snapshot.user.canSetPermissionBoundary
    : boundary.policy !== null && snapshot.user.canRemovePermissionBoundary);
  const locked = operation.state === "pending" || operation.state === "uncertain" || operation.state === "conflict" || operation.state === "refreshFailed";
  useAccessDraft({ dirty: editing && (value !== (boundary.policy?.policyId ?? "") || review || operation.state === "uncertain"), busy: operation.state === "pending", title: r("editBoundary"), description: t("changeHint"), form });
  useLayoutEffect(() => {
    if (!editing && restoreEditFocus.current) {
      restoreEditFocus.current = false;
      editTrigger.current?.focus({ preventScroll: true });
    }
  }, [editing, operation.state]);

  const refresh = async (purpose: "conflict" | "confirmed") => {
    setOperation({ state: "pending" });
    try {
      const latest = await client.load(snapshot.user.id);
      if (!mounted.current) return;
      onChanged(latest);
      setConfirmed(null); intent.current = null; setReview(false);
      if (purpose === "confirmed") { setValue(latest.boundary.policy?.policyId ?? ""); restoreEditFocus.current = true; setEditing(false); }
      setOperation({ state: purpose === "confirmed" ? "completed" : "idle" });
    } catch (failure) {
      if (mounted.current) setOperation({ state: purpose === "confirmed" ? "refreshFailed" : "conflict", error: accountError(failure) });
    }
  };

  const submit = async () => {
    if (operation.state === "pending" || operation.state === "conflict" || operation.state === "refreshFailed") return;
    if (!review) {
      if (!eligible) return;
      intent.current = selected && value ? { kind: "set", policyId: selected.id, policyResourceVersion: selected.resourceVersion, versionId: selected.defaultVersionId, resourceVersion: boundary.resourceVersion, requestId: requestToken("boundary-") }
        : { kind: "remove", resourceVersion: boundary.resourceVersion, requestId: requestToken("boundary-") };
      setReviewedVersion(selected && value ? selected.defaultVersionId : null);
      setReview(true); setOperation({ state: "idle" });
      return;
    }
    const original = intent.current;
    if (!original) return;
    setOperation({ state: "pending" });
    try {
      const result = original.kind === "set"
        ? await client.set(snapshot.user.id, { policyId: original.policyId, policyResourceVersion: original.policyResourceVersion, resourceVersion: original.resourceVersion, requestId: original.requestId })
        : await client.remove(snapshot.user.id, { resourceVersion: original.resourceVersion, requestId: original.requestId });
      if (!mounted.current) return;
      if (original.kind === "set" && result.policy?.versionId !== original.versionId) throw new Error("INVALID_IAM_RESPONSE");
      setConfirmed(result); intent.current = null; restoreEditFocus.current = true; setEditing(false); setReview(false);
    } catch (failure) {
      if (!mounted.current) return;
      const error = accountError(failure);
      if (error === "expired") { intent.current = null; setEditing(false); setReview(false); }
      else if (error !== "unavailable" && error !== "conflict") { intent.current = null; setReview(false); }
      setOperation({ state: error === "unavailable" ? "uncertain" : error === "conflict" ? "conflict" : "idle", error });
      return;
    }
    // A read failure after an acknowledged write is not an unknown write.
    await refresh("confirmed");
  };

  return <section className={styles.identitySection} aria-label={r("boundary")}>
    <div className={styles.actionHeader}><h3>{r("boundary")}</h3>{!editing && canChange ? <Button ref={editTrigger} variant="secondary" disabled={locked} onClick={() => { setValue(boundary.policy?.policyId ?? ""); setEditing(true); setOperation({ state: "idle" }); }}>{r("editBoundary")}</Button> : null}</div>
    <p className={styles.note}>{t("hint")}</p>
    <UserBoundarySummary boundary={boundary} />
    <p className={styles.note}>{t("userRevision", { version: boundary.resourceVersion })}</p>
    {!canChange ? <p className={styles.note}>{t("readOnly")}</p> : null}
    {operation.state === "completed" ? <Alert status="success">{t("completed")}</Alert> : null}
    {operation.error || operation.state === "uncertain" || operation.state === "refreshFailed" ? <Alert status="warning">
      {operation.state === "uncertain" ? t("uncertain") : operation.state === "refreshFailed" ? t("refreshFailed") : operation.state === "conflict" ? t("conflict") : w(`errors.${operation.error!}`)}
      {operation.state === "conflict" || operation.state === "refreshFailed" ? <div><Button variant="secondary" onClick={() => void refresh(operation.state === "conflict" ? "conflict" : "confirmed")}>{t(operation.state === "conflict" ? "refreshReview" : "retryRead")}</Button></div> : null}
    </Alert> : null}
    {editing ? <form ref={form} className={styles.stack} aria-label={r("editBoundary")} onSubmit={(event) => { event.preventDefault(); void submit(); }}>
      {review ? <><Alert status="warning">{t("changeHint")}</Alert><dl className={styles.facts}><div><dt>{r("before")}</dt><dd>{snapshot.boundary.policy?.policyId ?? t("none")}</dd></div><div><dt>{r("after")}</dt><dd>{value || t("none")}</dd></div>{reviewedVersion ? <div><dt>{t("defaultVersion")}</dt><dd>{reviewedVersion}</dd></div> : null}</dl></> : <FormField id={id} label={r("boundary")} hint={t("selectorHint")}>
        <Select autoFocus id={id} disabled={locked} value={value} aria-describedby={`${id}-hint`} options={[{ value: "", label: t("none") }, ...policies.map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${policy.id}` })), ...(!selected && value ? [{ value, label: value, disabled: true }] : [])]} onValueChange={(next) => { setValue(next); intent.current = null; setOperation({ state: "idle" }); }} />
      </FormField>}
      {!snapshot.policiesAvailable ? <p className={styles.note}>{t("directoryUnavailable")}</p> : null}
      <div className={styles.actions}>
        <Button type="submit" disabled={operation.state === "pending" || operation.state === "conflict" || operation.state === "refreshFailed" || (!review && !eligible)}>{operation.state === "pending" ? t("saving") : operation.state === "uncertain" ? t("retryOriginal") : review ? t("confirm") : r("reviewChange")}</Button>
        {review ? <Button variant="secondary" disabled={locked} onClick={() => { intent.current = null; setReview(false); }}>{r("backToSelection")}</Button> : null}
        <Button variant="ghost" disabled={locked} onClick={() => { intent.current = null; restoreEditFocus.current = true; setEditing(false); setReview(false); setOperation({ state: "idle" }); }}>{w("cancel")}</Button>
      </div>
    </form> : null}
  </section>;
}
