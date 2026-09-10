"use client";
import { useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Button, Dialog, useUnsavedChanges } from "@ui/xiak";
import { requestIdentity } from "@/api/client";
import { RequestFeedback } from "../platform/RequestFeedback";
export function ResourceCommand({ label, description, disabled, danger, run }: { label: string; description?: string; disabled: boolean; danger?: boolean; run(key: string): Promise<void> }) {
  const t = useTranslations("Collection");
  const d = useTranslations("Draft");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const key = useRef("");
  const trigger = useRef<HTMLButtonElement>(null);
  useUnsavedChanges({ dirty: false, busy, focusRef: trigger, copy: { title: d("title"), description: d("description"), stay: d("stay"), leave: d("leave"), close: d("close"), busyTitle: d("busyTitle"), busyDescription: d("busyDescription"), failure: d("failure"), retry: d("retry") } });
  return <><Button ref={trigger} variant={danger ? "danger" : "secondary"} disabled={disabled} onClick={() => { key.current = requestIdentity("ui-"); setError(undefined); setOpen(true); }}>{label}</Button>
    <Dialog open={open} busy={busy} title={label} closeLabel={t("cancel")} onClose={() => { if (!busy) setOpen(false); }} footer={<><Button variant="ghost" disabled={busy} onClick={() => setOpen(false)}>{t("cancel")}</Button><Button variant={danger ? "danger" : "primary"} disabled={busy || disabled} onClick={async () => { setBusy(true); setError(undefined); try { await run(key.current); setOpen(false); } catch (cause) { setError(cause); } finally { setBusy(false); } }}>{busy ? t("saving") : label}</Button></>}>
      <p>{description ?? label}</p><RequestFeedback error={error} busy={busy} />
    </Dialog>
  </>;
}
