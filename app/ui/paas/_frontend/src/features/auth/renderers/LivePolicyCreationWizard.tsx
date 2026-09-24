"use client";

import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Card, FormField, Input } from "@ui/xiak";
import type { PolicyCreateClient, PolicyCreateIntent } from "../application/AccountAccessProvider";
import type { AccountPolicyDocument } from "../domain/accounts";
import { visualDraftHasIncompleteFields } from "../domain/accountPolicyVisualAuthoring";
import { AccountPolicyDocumentAuthor, type PolicyAuthorMode } from "./AccountPolicyDocumentAuthor";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

const emptyDocument: AccountPolicyDocument = { languageVersion: "1", scope: "TENANT", statements: [] };
const initialText = JSON.stringify(emptyDocument, null, 2);

export function PolicyCreateRecovery({ client, pending, onDone, onInspect }: {
  client: PolicyCreateClient; pending: PolicyCreateIntent; onDone(id: string): void; onInspect?(): void;
}) {
  const t = useTranslations("LivePolicyCreate");
  const heading = useRef<HTMLHeadingElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [pending.phase]);
  const busy = pending.phase === "submitting";
  const retry = async () => {
    setFeedback(null); setAcknowledged(false);
    const result = await client.retry();
    if (result.status === "applied") onDone(result.detail.policy.id);
    else if (result.status === "blocked") setFeedback(t("blocked"));
  };
  return <section className={styles.policyVersionRecovery} aria-label={t("recoveryTitle")}>
    <h2 ref={heading} tabIndex={-1} className={styles.stepTitle}>{t("recoveryTitle")}</h2>
    <Alert status="warning">{t(busy ? "submitting" : "unknown", { name: pending.displayName })}</Alert>
    <p className={styles.note}>{t("unknownExplanation")}</p>
    {feedback ? <Alert status="warning">{feedback}</Alert> : null}
    <div className={styles.actions}>
      <Button variant="secondary" disabled={busy} onClick={() => void retry()}>{t("retryOriginal")}</Button>
      {onInspect ? <Button variant="ghost" onClick={onInspect}>{t("inspectDirectory")}</Button> : null}
    </div>
    {!busy ? <div className={styles.policyVersionAcknowledge}>
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> {t("acknowledgeUnknown")}</label>
      <Button variant="secondary" disabled={!acknowledged} onClick={() => { if (client.acknowledge()) onInspect?.(); }}>{t("endOldIntent")}</Button>
    </div> : null}
  </section>;
}

export function LivePolicyCreationWizard({ client, onBack, onDone }: {
  client: PolicyCreateClient; onBack(): void; onDone(id: string): void;
}) {
  const t = useTranslations("LivePolicyCreate");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const [name, setName] = useState("");
  const [text, setText] = useState(initialText);
  const [mode, setMode] = useState<PolicyAuthorMode>("json");
  const [visualReady, setVisualReady] = useState(false);
  const [review, setReview] = useState<{ name: string; document: AccountPolicyDocument } | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const requestLeave = useAccessDraft({ dirty: Boolean(name || text !== initialText) && !client.pending && !createdId, busy,
    title: t("cancelTitle"), description: t("cancelHint"), form });
  useLayoutEffect(() => { if (review) reviewHeading.current?.focus({ preventScroll: true }); }, [review]);
  const inspect = () => onBack();
  if (client.pending) return <WorkspaceDetail title={t("title")} onBack={inspect}>
    <PolicyCreateRecovery client={client} pending={client.pending} onDone={setCreatedId} onInspect={inspect} />
  </WorkspaceDetail>;
  if (createdId) return <WorkspaceDetail title={t("title")} onBack={onBack}>
    <Card><Card.Body className={styles.catalogNotice}>
      <Alert status="success">{t("created", { id: createdId })}</Alert>
      <p className={styles.note}>{t("createdNotice")}</p>
      <div className={styles.actions}><Button onClick={() => onDone(createdId)}>{t("viewPolicy")}</Button><Button variant="secondary" onClick={onBack}>{t("backToDirectory")}</Button></div>
    </Card.Body></Card>
  </WorkspaceDetail>;

  const openReview = () => {
    setError(null);
    const displayName = name.trim();
    if (!displayName || new TextEncoder().encode(displayName).length > 128 || /[<>\p{Cc}]/u.test(displayName)) { setError(t("invalidName")); return; }
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { setError(t("invalidJson")); return; }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
        Object.keys(parsed).some((key) => !["languageVersion", "scope", "statements"].includes(key)) ||
        !('languageVersion' in parsed) || parsed.languageVersion !== "1" || !('scope' in parsed) || parsed.scope !== "TENANT" ||
        !('statements' in parsed) || !Array.isArray(parsed.statements) || !parsed.statements.length || parsed.statements.length > 64) {
      setError(t("invalidDocument")); return;
    }
    if (mode === "visual" && (!visualReady || visualDraftHasIncompleteFields(parsed as AccountPolicyDocument))) { setError(t("incompleteVisual")); return; }
    const document = parsed as AccountPolicyDocument;
    const bytes = new TextEncoder().encode(JSON.stringify({ displayName, document, requestId: `ui-policy-create-${"x".repeat(36)}` })).length;
    if (bytes > 64 * 1024) { setError(t("tooLarge")); return; }
    setReview({ name: displayName, document });
  };
  const create = async () => {
    if (!review || busy) return;
    setBusy(true); setError(null);
    try {
      const result = await client.begin({ displayName: review.name, document: review.document });
      if (result.status === "applied") setCreatedId(result.detail.policy.id);
      else if (result.status === "rejected") setError(t(`errors.${result.reason}`));
      else if (result.status === "blocked") setError(t("blocked"));
    } finally { setBusy(false); }
  };
  return <WorkspaceDetail title={t("title")} onBack={() => requestLeave(onBack)}>
    <Card><Card.Body className={styles.catalogNotice}>
      <Alert status="info">{t("scopeNotice")}</Alert>
      <form ref={form} className={styles.catalogNotice} onSubmit={(event) => { event.preventDefault(); if (review) void create(); else openReview(); }}>
        {review ? <>
          <h2 ref={reviewHeading} tabIndex={-1} className={styles.stepTitle}>{t("reviewTitle")}</h2>
          <dl className={styles.catalogFacts}><div><dt>{t("name")}</dt><dd>{review.name}</dd></div><div><dt>{t("scope")}</dt><dd>{t("tenant")}</dd></div></dl>
          <Alert status="warning">{t("reviewNotice")}</Alert>
          <section className={styles.policyRawDocument}><h3>{t("document")}</h3><pre tabIndex={0}>{JSON.stringify(review.document, null, 2)}</pre></section>
        </> : <>
          <FormField id={id + "-name"} label={t("name")} hint={t("nameHint")}>
            <Input id={id + "-name"} maxLength={128} value={name} onChange={(event) => { setName(event.target.value); setError(null); }} />
          </FormField>
          <AccountPolicyDocumentAuthor text={text} onChange={setText} error={Boolean(error)} onClearError={() => setError(null)}
            mode={mode} onModeChange={setMode} onVisualReadyChange={setVisualReady} allowEmpty label={t("document")} hint={t("documentHint")} />
        </>}
        {error ? <Alert status="danger" tabIndex={-1}>{error}</Alert> : null}
        <div className={styles.actions}>
          <Button type="submit" disabled={busy}>{review ? t("confirmCreate") : t("review")}</Button>
          <Button type="button" variant="secondary" disabled={busy} onClick={() => { if (review) { setReview(null); setError(null); } else requestLeave(onBack); }}>{review ? t("backToEdit") : t("cancel")}</Button>
        </div>
      </form>
    </Card.Body></Card>
  </WorkspaceDetail>;
}
