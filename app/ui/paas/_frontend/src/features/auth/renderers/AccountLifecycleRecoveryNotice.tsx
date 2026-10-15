"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Card, FormField, TextArea, Typography } from "@ui/xiak";
import type { AccountLifecycleClient } from "../application/AccountAccessProvider";
import styles from "./AccountAccessRenderer.module.css";

export function AccountLifecycleRecoveryNotice({ client }: { client: AccountLifecycleClient }) {
  const t = useTranslations("AccountAccess.lifecycleRecovery");
  const inputId = useId();
  const [summary, setSummary] = useState("");
  const [invalid, setInvalid] = useState(false);
  const pending = client.pending;
  const phase = pending?.phase;
  const titleRef = useRef<HTMLElement>(null);
  const importRef = useRef<HTMLElement>(null);
  const previousPhase = useRef(phase);
  const locked = (!client.ready && !client.recoveryError) || Boolean(pending && (pending.checking || pending.phase !== "unknown"));
  useEffect(() => {
    const previous = previousPhase.current;
    previousPhase.current = phase;
    if (phase === "confirmed" && previous !== "confirmed") titleRef.current?.focus({ preventScroll: true });
    else if (!phase && (previous === "confirmed" || previous === "rejected")) importRef.current?.focus({ preventScroll: true });
  }, [phase]);

  async function restore() {
    if (!client.restore(summary)) { setInvalid(true); return; }
    setSummary(""); setInvalid(false);
    await client.inspect();
  }

  return <div aria-busy={pending?.checking || pending?.phase === "submitting" || undefined} className={styles.stack}>
    {client.recoveryError ? <Alert status="warning">{t("storageUnavailable")}</Alert> : null}
    {pending ? <Alert status={pending.phase === "confirmed" ? "success" : "warning"}>
      <div className={styles.confirmation}>
        <strong ref={titleRef} tabIndex={-1}>{t(`phase.${pending.phase}`)}</strong>
        <p>{t("boundary")}</p>
        <dl className={styles.facts}>
          <div><dt>{t("operation")}</dt><dd>{t(`operations.${pending.intent.operation}`)}</dd></div>
          <div><dt>{t("account")}</dt><dd><code>{pending.intent.accountId}</code></dd></div>
          <div><dt>{t("command")}</dt><dd><code className={styles.resetRequestId}>{pending.intent.commandRequestId}</code></dd></div>
          <div><dt>{t("expectedVersion")}</dt><dd>{pending.intent.expectedResourceVersion}</dd></div>
          {pending.completion ? <>
            <div><dt>{t("resultingVersion")}</dt><dd>{pending.completion.resultingResourceVersion}</dd></div>
            <div><dt>{t("completedStatus")}</dt><dd>{t(`status.${pending.completion.status}`)}</dd></div>
            {"rootPrincipalId" in pending.completion ? <div><dt>{t("root")}</dt><dd><code>{pending.completion.rootPrincipalId}</code></dd></div> : null}
            <div><dt>{t("event")}</dt><dd><code>{pending.completion.eventId}</code></dd></div>
            <div><dt>{t("occurredAt")}</dt><dd>{pending.completion.occurredAt}</dd></div>
          </> : null}
        </dl>
        {pending.error ? <p role="status">{t(pending.phase === "confirmed" || pending.phase === "rejected" ? "cleanupUnavailable" : `errors.${pending.error}`)}</p> : null}
        <details><summary>{t("export")}</summary>
          <p>{t("summaryHint")}</p>
          <TextArea aria-label={t("exportLabel")} readOnly rows={5} value={JSON.stringify(pending.intent, null, 2)} />
        </details>
        <div className={styles.actions}>
          {pending.phase === "unknown" ? <Button disabled={pending.checking} onClick={() => void client.inspect()} variant="secondary">
            {t(pending.checking ? "checking" : "inspect")}
          </Button> : null}
          {pending.phase === "confirmed" || pending.phase === "rejected" ? <Button onClick={client.acknowledge} variant="ghost">{t("acknowledge")}</Button> : null}
        </div>
      </div>
    </Alert> : null}
    <details><summary ref={importRef}>{t("title")}</summary>
      <Card><Card.Header><Typography.Title as="h3" level={3}>{t("summaryTitle")}</Typography.Title></Card.Header><Card.Body className={styles.form}>
        <p>{t("importHint")}</p>
        <FormField id={inputId} label={t("summary")}>
          <TextArea disabled={locked} id={inputId} maxLength={16_384} onChange={(event) => { setSummary(event.target.value); setInvalid(false); }} rows={5} spellCheck={false} value={summary} />
        </FormField>
        {invalid ? <Alert status="danger">{t("invalidSummary")}</Alert> : null}
      </Card.Body><Card.Footer>
        <Button disabled={locked || !summary.trim()} onClick={() => void restore()} variant="secondary">{t("import")}</Button>
      </Card.Footer></Card>
    </details>
  </div>;
}
