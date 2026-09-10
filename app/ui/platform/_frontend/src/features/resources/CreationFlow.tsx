"use client";
import { useRef, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Button, ContentPage, Wizard, useUnsavedChanges } from "@ui/xiak";
import { requestIdentity } from "@/api/client";
import { RequestFeedback } from "../platform/RequestFeedback";
import styles from "../platform/Workspace.module.css";

/** Fields and payload belong to the product. This owns only review/submit/leave behavior. */
export function CreationFlow({ title, dirty, writable, fields, review, submit, onCancel, onDone }: {
  title: string; dirty: boolean; writable: boolean; fields: ReactNode; review: ReactNode;
  submit(idempotencyKey: string): Promise<ReactNode>; onCancel(): void; onDone(): void;
}) {
  const t = useTranslations("Collection");
  const d = useTranslations("Draft");
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [result, setResult] = useState<ReactNode>();
  const key = useRef("");
  const form = useRef<HTMLFormElement>(null);
  const leave = useUnsavedChanges({ dirty: dirty && !result, busy, focusRef: form, copy: { title: d("title"), description: d("description"), stay: d("stay"), leave: d("leave"), close: d("close"), busyTitle: d("busyTitle"), busyDescription: d("busyDescription"), failure: d("failure"), retry: d("retry") } });
  return <><ContentPage.Heading title={title} back={{ label: t("cancel"), onClick: () => leave(onCancel) }} />
    <Wizard label={title} title={result ? t("result") : t(step === 0 ? "draft" : "preview")} steps={[{ id: "details", label: t("draft") }, { id: "review", label: t("preview") }]} currentStep={step} onStepChange={next => { if (next < step && !busy) { key.current = ""; setStep(next); } }} busy={busy} completed={Boolean(result)} formRef={form}
      onSubmit={async event => {
        event.preventDefault();
        if (busy || !writable || result) return;
        if (step === 0) { if (!form.current?.reportValidity()) return; setError(undefined); setStep(1); return; }
        key.current ||= requestIdentity("ui-");
        setBusy(true); setError(undefined);
        try { setResult(await submit(key.current)); } catch (cause) { setError(cause); } finally { setBusy(false); }
      }}
      actions={result ? <Button onClick={onDone}>{t("back")}</Button> : <><Button variant="ghost" disabled={busy} onClick={() => leave(onCancel)}>{t("cancel")}</Button>{step > 0 ? <Button variant="secondary" disabled={busy} onClick={() => { key.current = ""; setStep(0); }}>{t("previous")}</Button> : null}<Button type="submit" disabled={busy || !writable}>{busy ? t("saving") : t(step === 0 ? "next" : "save")}</Button></>}
      hint={t("notSaved")}>
      <div className={styles.stack}>{result ?? (step === 0 ? fields : review)}<RequestFeedback error={error} busy={busy} /></div>
    </Wizard>
  </>;
}
