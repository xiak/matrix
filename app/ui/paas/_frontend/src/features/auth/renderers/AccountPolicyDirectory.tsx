"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ActionMenu, Alert, Badge, Button, Card, ContentPage, EmptyState, FormField, Table, TablePagination, TableSkeleton, TableToolbar, Tabs, TextArea } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess, type AccountPolicyReadClient, type AccountPolicyReadLoad, type AccountPolicyVersionDirectoryLoad, type AuthorizationProfileLoad, type PolicyVersionMutationClient, type PolicyVersionMutationResult } from "../application/AccountAccessProvider";
import type { AccountPolicy, AccountPolicyDetail, AccountPolicyDocument, AccountPolicyVersion, AuthorizationProfileDirectory } from "../domain/accounts";
import { visualDraftFromJSON, visualDraftHasIncompleteFields } from "../domain/accountPolicyVisualAuthoring";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccountAuthorizationProfileCatalog } from "./AccountAuthorizationProfileCatalog";
import { AccountPolicyVisualEditor } from "./AccountPolicyVisualEditor";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

type PolicyDetailState = { status: "loading" } | AccountPolicyReadLoad;
type PolicyVersionDirectoryState = { status: "loading" } | AccountPolicyVersionDirectoryLoad;
type VersionReview = { kind: "set-default" | "retire"; versionId: string };

function PolicyVersionRecovery({ mutation, onApplied, onInspect }: { mutation: PolicyVersionMutationClient; onApplied(): void; onInspect(policyId: string): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const pending = mutation.pending;
  const [acknowledged, setAcknowledged] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [showBusy, setShowBusy] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (pending?.phase !== "submitting") return;
    const timer = window.setTimeout(() => setShowBusy(true), 250);
    return () => window.clearTimeout(timer);
  }, [pending?.phase, pending?.requestId]);
  useEffect(() => {
    if (pending?.phase !== "unknown") return;
    const timer = window.setTimeout(() => heading.current?.focus({ preventScroll: true }), 0);
    return () => window.clearTimeout(timer);
  }, [pending?.phase]);
  if (!pending) return null;
  if (pending.phase === "submitting" && !showBusy) return null;
  const busy = pending.phase !== "unknown";
  const handleRetry = async () => {
    setFeedback(null); setAcknowledged(false); setShowBusy(true);
    const result = await mutation.retry();
    if (result.status === "applied") onApplied();
    else if (result.status === "blocked") setFeedback(t("mutationBlocked"));
  };
  return <section className={styles.policyVersionRecovery} aria-label={t("recoveryTitle")}>
    <Alert status="warning">{t(pending.phase === "submitting" ? "mutationSubmitting" : pending.phase === "observing" ? "observationLoading" : "mutationUnknown")}</Alert>
    <h2 ref={heading} tabIndex={-1} className={styles.stepTitle}>{t("recoveryTitle")}</h2>
    <p>{pending.kind === "publish" ? t("pendingPublishIntent", { policy: pending.policyId }) : t("pendingIntent", { kind: t(pending.kind === "set-default" ? "setDefault" : "retireVersion"), policy: pending.policyId, version: pending.versionId })}</p>
    <p className={styles.note}>{t("unknownExplanation")}</p>
    {pending.observation ? <div className={styles.catalogNotice}>
      <p>{t("observedCurrent", { version: pending.observation.defaultVersionId, revision: pending.observation.resourceVersion })}</p>
      <p>{t("observedVersions", { versions: pending.observation.versionIds.join(", ") || "—" })}</p>
      <Alert status="warning">{t("observationNotProof")}</Alert>
    </div> : null}
    {pending.observationError ? <Alert status="danger">{t(`observationErrors.${pending.observationError}`)}</Alert> : null}
    {feedback ? <Alert status="warning">{feedback}</Alert> : null}
    <div className={styles.actions}>
      <Button variant="secondary" disabled={busy} onClick={() => void handleRetry()}>{t("retryOriginal")}</Button>
      <Button variant="secondary" disabled={busy} onClick={() => { setFeedback(null); setAcknowledged(false); void mutation.observe(); }}>{t("rereadCurrent")}</Button>
      <Button variant="ghost" onClick={() => onInspect(pending.policyId)}>{t("inspectAffectedPolicy")}</Button>
    </div>
    {pending.observation ? <div className={styles.policyVersionAcknowledge}>
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> {t("acknowledgeUnknown")}</label>
      <Button variant="secondary" disabled={!acknowledged || busy} onClick={() => { if (mutation.acknowledge()) onApplied(); }}>{t("endOldIntent")}</Button>
    </div> : null}
  </section>;
}

function VersionMutationReview({ review, policy, versions, busy, error, onSubmit, onCancel }: {
  review: VersionReview; policy: AccountPolicy; versions: AccountPolicyVersion[]; busy: boolean; error: string | null;
  onSubmit(): void; onCancel(): void;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const heading = useRef<HTMLHeadingElement>(null);
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);
  const current = versions.find((item) => item.versionId === policy.defaultVersionId);
  const target = versions.find((item) => item.versionId === review.versionId);
  if (!current || !target || current.versionId === target.versionId) return <Alert status="danger">{t("reviewStale")}</Alert>;
  return <section className={styles.policyVersionReview} aria-label={t("reviewTitle")}>
    <div className={styles.catalogDetailHeading}><h3 ref={heading} tabIndex={-1} className={styles.stepTitle}>{t(review.kind === "set-default" ? "reviewSetDefault" : "reviewRetire", { version: review.versionId })}</h3><Badge>{t("revisionLabel", { revision: policy.resourceVersion })}</Badge></div>
    <Alert status="warning">{t(review.kind === "set-default" ? "setDefaultImpact" : "retireImpact")}</Alert>
    <p className={styles.note}>{t("authorizationNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("currentDefault")}</dt><dd><code>{current.versionId}</code></dd></div>
      <div><dt>{t("targetVersion")}</dt><dd><code>{target.versionId}</code></dd></div>
      <div><dt>{t("digest")}</dt><dd><code>{target.contentDigest}</code></dd></div>
    </dl>
    <details className={styles.policyRawDocument}><summary>{t("compareDocuments")}</summary><div className={styles.policyComparison}>
      <section><h4>{t("currentDocument", { version: current.versionId })}</h4><pre tabIndex={0}>{JSON.stringify(current.document, null, 2)}</pre></section>
      <section><h4>{t("targetDocument", { version: target.versionId })}</h4><pre tabIndex={0}>{JSON.stringify(target.document, null, 2)}</pre></section>
    </div></details>
    {error ? <Alert status="danger">{error}</Alert> : null}
    <div className={styles.actions}><Button variant={review.kind === "retire" ? "danger" : "primary"} disabled={busy || Boolean(error)} onClick={onSubmit}>{t(review.kind === "set-default" ? "confirmSetDefault" : "confirmRetire")}</Button><Button variant="secondary" disabled={busy} onClick={onCancel}>{t("cancel")}</Button></div>
  </section>;
}

function PolicyStatementTable({ version }: { version: AccountPolicyVersion }) {
  const t = useTranslations("AccountPolicyDirectory");
  return <section className={styles.catalogNotice}>
    <h3 className={styles.stepTitle}>{t("statementTitle", { count: version.document.statements.length })}</h3>
    <Table aria-label={t("statementTable")} mobileLayout="stack" className={styles.policyStatementTable}>
      <thead><tr><th scope="col">{t("statement")}</th><th scope="col">{t("effect")}</th><th scope="col">{t("declaredActions")}</th><th scope="col">{t("resources")}</th><th scope="col">{t("conditions")}</th></tr></thead>
      <tbody>{version.document.statements.map((statement) => {
        const resolved = version.compilation?.resolvedStatements.find((entry) => entry.sid === statement.sid);
        return <tr key={statement.sid}>
          <td data-label={t("statement")}><code>{statement.sid}</code></td>
          <td data-label={t("effect")}><Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(statement.effect === "DENY" ? "deny" : "allow")}</Badge></td>
          <td data-label={t("declaredActions")}><div className={styles.policyStackedValues}>{statement.actions.map((action) => <code key={action}>{action}</code>)}
            {resolved ? <div className={styles.policyResolved}><strong>{t("frozenActions")}</strong>{resolved.actions.map((action) => <code key={action}>{action}</code>)}</div> : null}</div></td>
          <td data-label={t("resources")}><div className={styles.policyStackedValues}>{statement.resources.map((resource) => <code key={`${resource.kind}:${resource.match}:${resource.id ?? ""}`}>{resource.kind} · {t(`matches.${resource.match}`)}{resource.id ? ` · ${resource.id}` : ""}</code>)}</div></td>
          <td data-label={t("conditions")}><div className={styles.policyStackedValues}>{statement.conditions?.map((condition) => <code key={`${condition.key}:${condition.operator}`}>{condition.key} · {condition.operator} · {condition.values.join(", ")}</code>) ?? t("none")}</div></td>
        </tr>;
      })}</tbody>
    </Table>
  </section>;
}

function PolicyVersionDocument({ version, title }: { version: AccountPolicyVersion; title: string }) {
  const t = useTranslations("AccountPolicyDirectory");
  return <section className={styles.catalogNotice} aria-label={title}>
    <div className={styles.catalogDetailHeading}><h2>{title}</h2><Badge>{t("contractVersion", { version: version.contractVersion })}</Badge></div>
    <p className={styles.note}>{t("documentNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("digest")}</dt><dd><code>{version.contentDigest}</code></dd></div>
      <div><dt>{t("frozenProfiles")}</dt><dd>{version.compilation ? version.compilation.profiles.map((item) => `${item.product} @ ${item.revision}`).join(" · ") : t("legacyVersion")}</dd></div>
    </dl>
    <PolicyStatementTable version={version} />
    <details className={styles.policyRawDocument}><summary>{t("rawDocument")}</summary><pre tabIndex={0}>{JSON.stringify(version.document, null, 2)}</pre></details>
  </section>;
}

function PolicyVersionPublisher({ policy, defaultVersion, mutation, onPublished, onConflict, onClose }: {
  policy: AccountPolicy; defaultVersion: AccountPolicyVersion; mutation: PolicyVersionMutationClient;
  onPublished(detail: AccountPolicyDetail): void; onConflict(): void; onClose(): void;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const access = useAccountAccess();
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [initialText] = useState(() => JSON.stringify(defaultVersion.document, null, 2));
  const [text, setText] = useState(initialText);
  const [review, setReview] = useState<{ document: AccountPolicyDocument; resourceVersion: number; defaultVersionId: string } | null>(null);
  const reviewing = Boolean(review);
  const [error, setError] = useState<string | null>(null);
  const [visualError, setVisualError] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<"json" | "visual">("json");
  const [catalog, setCatalog] = useState<{ status: "idle" | "loading" } | AuthorizationProfileLoad>({ status: "idle" });
  const [visualDocument, setVisualDocument] = useState<AccountPolicyDocument | null>(null);
  const catalogRequest = useRef(0);
  const [busy, setBusy] = useState(false);
  const requestLeave = useAccessDraft({ dirty: text !== initialText, busy, title: t("publishCancelTitle"),
    description: t("publishCancelHint"), form: heading });
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [reviewing]);
  useEffect(() => () => { catalogRequest.current += 1; }, []);
  const setVisualFromCatalog = (directory: AuthorizationProfileDirectory) => {
    const result = visualDraftFromJSON(text, directory);
    if (result.status !== "ready") { setVisualError(t(`visualErrors.${result.status}`)); return; }
    setVisualError(null); setVisualDocument(result.document); setEditorMode("visual");
  };
  const openVisual = () => {
    setError(null); setVisualError(null);
    if (catalog.status === "ready") { setVisualFromCatalog(catalog.directory); return; }
    if (!access.authorizationProfiles) { setVisualError(t("visualCatalogUnavailable")); return; }
    setEditorMode("visual"); setCatalog({ status: "loading" });
    const current = ++catalogRequest.current;
    void access.authorizationProfiles.load().then((result) => {
      if (current !== catalogRequest.current) return;
      setCatalog(result);
      if (result.status === "ready") setVisualFromCatalog(result.directory);
    });
  };
  const openReview = () => {
    setError(null);
    if (new TextEncoder().encode(text).length > 64 * 1024) { setError(t("publishTooLarge")); return; }
    if (editorMode === "visual") {
      const visual = catalog.status === "ready" ? visualDraftFromJSON(text, catalog.directory) : null;
      if (!visual || visual.status !== "ready" || visualDraftHasIncompleteFields(visual.document)) {
        setError(t("visualDraftIncomplete")); return;
      }
    }
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { setError(t("publishJsonInvalid")); return; }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
        !Object.hasOwn(parsed, "languageVersion") || !Object.hasOwn(parsed, "scope") || !Object.hasOwn(parsed, "statements") ||
        (parsed as Record<string, unknown>).languageVersion !== "1" || (parsed as Record<string, unknown>).scope !== "TENANT" ||
        !Array.isArray((parsed as Record<string, unknown>).statements)) {
      setError(t("publishShapeInvalid")); return;
    }
    setReview({ document: parsed as AccountPolicyDocument, resourceVersion: policy.resourceVersion, defaultVersionId: policy.defaultVersionId });
  };
  const publish = async () => {
    if (!review || busy) return;
    if (mutation.pending || review.resourceVersion !== policy.resourceVersion || review.defaultVersionId !== policy.defaultVersionId) {
      setError(t("reviewStale")); return;
    }
    setBusy(true); setError(null);
    try {
      const result = await mutation.begin({ kind: "publish", policyId: policy.id, document: review.document,
        resourceVersion: review.resourceVersion, expectedDefaultVersionId: review.defaultVersionId });
      if (result.status === "applied") onPublished(result.detail);
      else if (result.status === "unknown") onClose();
      else if (result.status === "rejected" && result.reason === "conflict") onConflict();
      else if (result.status === "rejected") setError(t(`mutationErrors.${result.reason}`));
      else setError(t("mutationBlocked"));
    } finally { setBusy(false); }
  };
  return <section className={styles.policyVersionReview} aria-label={t("publishTitle")}>
    <div className={styles.catalogDetailHeading}><h3 ref={heading} tabIndex={-1} className={styles.stepTitle}>{t(review ? "reviewPublish" : "publishTitle")}</h3><Badge>{t("revisionLabel", { revision: policy.resourceVersion })}</Badge></div>
    <Alert status="info">{t("publishNoDefault")}</Alert>
    <p className={styles.note}>{t("publishValidationNotice")}</p>
    {review ? <>
      <dl className={styles.catalogFacts}>
        <div><dt>{t("currentDefault")}</dt><dd><code>{review.defaultVersionId}</code></dd></div>
        <div><dt>{t("statementCount")}</dt><dd>{review.document.statements.length}</dd></div>
      </dl>
      <div className={styles.policyComparison}>
        <section className={styles.policyRawDocument}><h4>{t("currentDocument", { version: defaultVersion.versionId })}</h4><pre tabIndex={0}>{JSON.stringify(defaultVersion.document, null, 2)}</pre></section>
        <section className={styles.policyRawDocument}><h4>{t("proposedDocument")}</h4><pre tabIndex={0}>{JSON.stringify(review.document, null, 2)}</pre></section>
      </div>
    </> : <>
      <Tabs.Root value={editorMode} onValueChange={(next) => { if (next === "json") { catalogRequest.current += 1; setEditorMode("json"); setVisualError(null); } else if (next === "visual") openVisual(); }}>
        <Tabs.List aria-label={t("editorModes")}><Tabs.Trigger value="json">{t("jsonMode")}</Tabs.Trigger><Tabs.Trigger value="visual">{t("visualMode")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="visual">{catalog.status === "ready" && visualDocument ?
          <AccountPolicyVisualEditor document={visualDocument} directory={catalog.directory} onChange={(document) => {
            setVisualDocument(document); setText(JSON.stringify(document, null, 2)); setError(null);
          }} /> : catalog.status === "loading" ? <p className={styles.note} role="status">{t("visualLoading")}</p> :
            <div className={styles.policyVisualFailure}><Alert status="warning">{visualError ?? (catalog.status === "idle" || catalog.status === "ready" ? t("visualCatalogUnavailable") : t(`visualCatalogErrors.${catalog.status}`))}</Alert>
              {visualError ? <Button variant="secondary" onClick={() => { setEditorMode("json"); setVisualError(null); }}>{t("returnToJson")}</Button> :
                catalog.status !== "expired" ? <Button variant="secondary" onClick={openVisual}>{t("retryCatalog")}</Button> : null}</div>}</Tabs.Content>
        <Tabs.Content value="json"><FormField id={id + "-document"} label={t("proposedDocument")} hint={t("publishEditorHint")}>
          <TextArea id={id + "-document"} className={styles.policyVersionEditor} rows={16} maxLength={65536} spellCheck={false} value={text} invalid={Boolean(error)}
            onChange={(event) => { setText(event.target.value); setError(null); }} />
        </FormField></Tabs.Content>
      </Tabs.Root>
      {visualError && editorMode === "json" ? <Alert status="warning">{visualError}</Alert> : null}
    </>}
    {error ? <Alert status="danger">{error}</Alert> : null}
    <div className={styles.actions}>
      {review ? <><Button disabled={busy || Boolean(error)} onClick={() => void publish()}>{t("confirmPublish")}</Button>
        <Button variant="secondary" disabled={busy} onClick={() => { setReview(null); setError(null); }}>{t("editDraft")}</Button></> :
        <Button disabled={busy} onClick={openReview}>{t("reviewDraft")}</Button>}
      <Button variant="ghost" disabled={busy} onClick={() => requestLeave(onClose)}>{t("cancel")}</Button>
    </div>
  </section>;
}

function AccountPolicyVersions({ policy, listVersions, readVersion, mutation, onApplied, refreshRevision }: {
  policy: AccountPolicy;
  listVersions: NonNullable<AccountPolicyReadClient["listVersions"]>;
  readVersion: NonNullable<AccountPolicyReadClient["readVersion"]>;
  mutation: PolicyVersionMutationClient | null;
  onApplied(): void;
  refreshRevision: number;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const [state, setState] = useState<PolicyVersionDirectoryState>({ status: "loading" });
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<PolicyDetailState>({ status: "loading" });
  const [selectedRevision, setSelectedRevision] = useState(0);
  const [review, setReview] = useState<VersionReview | null>(null);
  const [publisherOpen, setPublisherOpen] = useState(false);
  const [published, setPublished] = useState<{ versionId: string; defaultVersionId: string } | null>(null);
  const [mutationBusy, setMutationBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const opener = useRef<string | null>(null);
  const reviewOpener = useRef<string | null>(null);
  const publishButton = useRef<HTMLButtonElement>(null);
  const publishedHeading = useRef<HTMLHeadingElement>(null);
  const returnToPublish = useRef(false);
  useEffect(() => {
    let current = true;
    void listVersions(policy.id).then((result) => { if (current) setState(result); });
    return () => { current = false; };
  }, [listVersions, policy.id, revision, refreshRevision]);
  useEffect(() => {
    if (!selectedId) return;
    let current = true;
    void readVersion(policy.id, selectedId).then((result) => { if (current) setSelected(result); });
    return () => { current = false; };
  }, [readVersion, policy.id, selectedId, selectedRevision]);
  useEffect(() => {
    if (selectedId) title.current?.focus();
    else if (opener.current) {
      const target = Array.from(list.current?.querySelectorAll<HTMLButtonElement>("button[data-version-id]") ?? [])
        .find((item) => item.dataset.versionId === opener.current);
      target?.focus(); opener.current = null;
    }
  }, [selectedId]);
  useLayoutEffect(() => {
    if (review || !reviewOpener.current) return;
    const button = Array.from(list.current?.querySelectorAll<HTMLButtonElement>("button[aria-label]") ?? [])
      .find((item) => item.getAttribute("aria-label") === t("versionActions", { version: reviewOpener.current! }));
    (button ?? list.current)?.focus({ preventScroll: true });
    reviewOpener.current = null;
  }, [review, t]);
  useLayoutEffect(() => {
    if (published) publishedHeading.current?.focus({ preventScroll: true });
    else if (!publisherOpen && returnToPublish.current) { publishButton.current?.focus({ preventScroll: true }); returnToPublish.current = false; }
  }, [publisherOpen, published]);
  const submit = async () => {
    if (!review || !mutation || state.status !== "ready" || mutationBusy) return;
    const snapshot = state.directory;
    if (!snapshot.items.some((item) => item.versionId === review.versionId) ||
        snapshot.policy.defaultVersionId === review.versionId || mutation.pending) {
      setMutationError(t("reviewStale")); return;
    }
    setMutationBusy(true); setMutationError(null);
    let result: PolicyVersionMutationResult;
    try {
      result = await mutation.begin({ ...review, policyId: policy.id,
        expectedDefaultVersionId: snapshot.policy.defaultVersionId, resourceVersion: snapshot.policy.resourceVersion });
    } finally { setMutationBusy(false); }
    if (result.status === "applied") {
      setReview(null);
      setState({ status: "ready", directory: { policy: result.detail.policy,
        items: review.kind === "retire" ? snapshot.items.filter((item) => item.versionId !== review.versionId) : snapshot.items } });
      setRevision((value) => value + 1); onApplied();
    } else if (result.status === "unknown") {
      setReview(null);
    } else if (result.status === "rejected" && result.reason === "conflict") {
      setReview(null); setMutationError(t("mutationErrors.conflict")); setState({ status: "loading" }); setRevision((value) => value + 1);
    } else if (result.status === "rejected") {
      setMutationError(t(`mutationErrors.${result.reason}`));
    } else {
      setMutationError(t("mutationBlocked"));
    }
  };
  if (review && state.status === "ready") return <div className={styles.catalogNotice}>
    <Button variant="ghost" onClick={() => { setReview(null); setMutationError(null); }} disabled={mutationBusy}>{t("backToVersions")}</Button>
    <VersionMutationReview review={review} policy={state.directory.policy} versions={state.directory.items} busy={mutationBusy} error={mutationError} onSubmit={() => void submit()} onCancel={() => { setReview(null); setMutationError(null); }} />
  </div>;
  if (publisherOpen && state.status === "ready" && mutation) {
    const defaultVersion = state.directory.items.find((item) => item.versionId === state.directory.policy.defaultVersionId);
    if (defaultVersion) return <PolicyVersionPublisher policy={state.directory.policy} defaultVersion={defaultVersion} mutation={mutation}
      onPublished={(detail) => {
        setState({ status: "ready", directory: { policy: detail.policy,
          items: [...state.directory.items, detail.version].sort((left, right) => left.versionId.localeCompare(right.versionId)) } });
        setPublished({ versionId: detail.version.versionId, defaultVersionId: detail.policy.defaultVersionId });
        setPublisherOpen(false); onApplied();
      }} onConflict={() => { setPublisherOpen(false); setMutationError(t("mutationErrors.conflict")); setState({ status: "loading" }); setRevision((value) => value + 1); }}
      onClose={() => { returnToPublish.current = true; setPublisherOpen(false); }} />;
  }
  if (selectedId) return <div className={styles.catalogNotice}>
    <div><Button variant="secondary" onClick={() => setSelectedId(null)}>{t("backToVersions")}</Button></div>
    <h2 ref={title} tabIndex={-1} className={styles.stepTitle}>{t("versionInspection", { version: selectedId })}</h2>
    {selected.status === "loading" ? <TableSkeleton label={t("loadingVersion")} rows={3} header={false} /> :
      selected.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={selected.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${selected.status}`)}</Alert>
        {selected.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setSelected({ status: "loading" }); setSelectedRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> :
      <PolicyVersionDocument version={selected.detail.version} title={t("versionDocument", { version: selectedId })} />}
  </div>;
  return <div ref={list} tabIndex={-1} className={styles.catalogNotice}>
    <p className={styles.note}>{t("versionDirectoryNotice")}</p>
    {published ? <Alert status="success"><h3 ref={publishedHeading} tabIndex={-1} className={styles.stepTitle}>{t("publishSucceeded", { version: published.versionId })}</h3><p>{t("publishSucceededDetail", { version: published.defaultVersionId })}</p></Alert> : null}
    {mutationError ? <Alert status="danger">{mutationError}</Alert> : null}
    {state.status === "loading" ? <TableSkeleton label={t("loadingVersions")} rows={3} header={false} /> :
      state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${state.status}`)}</Alert>
        {state.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setState({ status: "loading" }); setRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> : <>
        <div className={styles.catalogDetailHeading}><p>{t("versionCount", { count: state.directory.items.length })}</p>
          {mutation?.canPublish && state.directory.items.length < 5 ? <Button ref={publishButton} variant="secondary" disabled={Boolean(mutation.pending)} onClick={() => { setPublished(null); setMutationError(null); setPublisherOpen(true); }}>{t("publishVersion")}</Button> : null}
        </div>
        <Table aria-label={t("versionTable")} mobileLayout="stack" className={styles.policyVersionTable}>
          <thead><tr><th scope="col">{t("versionId")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("versionContract")}</th><th scope="col">{t("digest")}</th>{mutation ? <th scope="col">{t("actions")}</th> : null}</tr></thead>
          <tbody>{state.directory.items.map((item) => <tr key={item.versionId}>
            <td data-label={t("versionId")}><button className={styles.userLink} data-version-id={item.versionId} onClick={() => { opener.current = item.versionId; setSelected({ status: "loading" }); setSelectedId(item.versionId); }}>{item.versionId}</button></td>
            <td data-label={t("defaultVersion")}>{item.versionId === state.directory.policy.defaultVersionId ? <Badge status="success">{t("currentDefault")}</Badge> : "—"}</td>
            <td data-label={t("versionContract")}>{t("contractVersion", { version: item.contractVersion })}</td>
            <td data-label={t("digest")}><code>{item.contentDigest}</code></td>
            {mutation ? <td data-label={t("actions")}>{item.versionId !== state.directory.policy.defaultVersionId ? <ActionMenu iconOnly label={t("versionActions", { version: item.versionId })} actions={[
              { id: "set-default", label: t("setDefault"), disabledReason: mutation.pending ? t("mutationBlocked") : undefined, onSelect: () => { reviewOpener.current = item.versionId; setMutationError(null); setReview({ kind: "set-default", versionId: item.versionId }); } },
              { id: "retire", label: t("retireVersion"), danger: true, disabledReason: mutation.pending ? t("mutationBlocked") : undefined, onSelect: () => { reviewOpener.current = item.versionId; setMutationError(null); setReview({ kind: "retire", versionId: item.versionId }); } }
            ]} /> : <span aria-hidden="true">—</span>}</td> : null}
          </tr>)}</tbody>
        </Table>
      </>}
  </div>;
}

function AccountPolicyDetailView({ policy, client, mutation, refreshRevision, onApplied, onBack }: { policy: AccountPolicy; client: AccountPolicyReadClient | null; mutation: PolicyVersionMutationClient | null; refreshRevision: number; onApplied(): void; onBack(): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const [state, setState] = useState<PolicyDetailState>({ status: "loading" });
  const [revision, setRevision] = useState(0);
  const [section, setSection] = useState("document");
  const [versionsMounted, setVersionsMounted] = useState(false);
  useEffect(() => {
    if (policy.scope !== "TENANT" || !client) return;
    let current = true;
    void client.read(policy.id).then((result) => { if (current) setState(result); });
    return () => { current = false; };
  }, [client, policy.id, policy.scope, revision, refreshRevision]);
  const detail = state.status === "ready" ? state.detail : null;
  const documentRegion = policy.scope === "INSTALLATION" ? <Alert status="info">{t("platformDetailUnavailable")}</Alert> :
    !client ? <Alert status="danger">{t("errors.unavailable")}</Alert> :
    state.status === "loading" ? <TableSkeleton label={t("loadingDetail")} rows={3} header={false} /> :
    state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`errors.${state.status}`)}</Alert>
      {state.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setState({ status: "loading" }); setRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> :
    detail ? <PolicyVersionDocument version={detail.version} title={t("defaultDocument")} /> : null;
  return <WorkspaceDetail title={policy.displayName} onBack={onBack}>
    <p className={styles.note}>{t("detailNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("policyId")}</dt><dd><code>{policy.id}</code></dd></div>
      <div><dt>{t("management")}</dt><dd>{t(policy.management === "SYSTEM" ? "system" : "customer")}</dd></div>
      <div><dt>{t("scope")}</dt><dd>{t(policy.scope === "TENANT" ? "tenant" : "installation")}</dd></div>
      <div><dt>{t("defaultVersion")}</dt><dd><code>{detail?.version.versionId ?? policy.defaultVersionId}</code></dd></div>
      <div><dt>{t("updated")}</dt><dd><WorkspaceTime value={detail?.policy.updatedAt ?? policy.updatedAt} /></dd></div>
    </dl>
    {policy.management === "CUSTOMER" && policy.scope === "TENANT" && client?.listVersions && client.readVersion ?
      <Tabs.Root value={section} onValueChange={(next) => { setSection(next); if (next === "versions") setVersionsMounted(true); }}>
        <Tabs.List aria-label={t("detailSections")}><Tabs.Trigger value="document">{t("defaultDocument")}</Tabs.Trigger><Tabs.Trigger value="versions">{t("versionsTab")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="document">{documentRegion}</Tabs.Content>
        <Tabs.Content value="versions" forceMount={versionsMounted || undefined}>{versionsMounted ? <AccountPolicyVersions policy={policy} listVersions={client.listVersions} readVersion={client.readVersion} mutation={mutation} refreshRevision={refreshRevision} onApplied={onApplied} /> : null}</Tabs.Content>
      </Tabs.Root> : documentRegion}
  </WorkspaceDetail>;
}

export function AccountPolicyDirectory({ scene, entityId, onOpen }: { scene: AccountAccessScene; entityId?: string; onOpen(id?: string): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const toolbarLabels = useTableToolbarLabels();
  const access = useAccountAccess();
  const client = access.policyRead;
  const mutation = access.policyVersionMutation;
  const [refreshRevision, setRefreshRevision] = useState(0);
  const onApplied = () => setRefreshRevision((value) => value + 1);
  const selected = entityId ? scene.policies.find((policy) => policy.id === entityId) : null;
  const [query, setQuery] = useState("");
  const [management, setManagement] = useState("all");
  const [scope, setScope] = useState("all");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [section, setSection] = useState("policies");
  const [catalogMounted, setCatalogMounted] = useState(false);
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const filtered = scene.policies.filter((policy) => {
    const text = `${policy.displayName} ${policy.id}`.normalize("NFKC").toLowerCase();
    return words.every((word) => text.includes(word)) &&
      (management === "all" || policy.management === management) &&
      (scope === "all" || policy.scope === scope) &&
      (status === "all" || policy.status === status);
  });
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  const rows = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const change = (update: () => void) => { update(); setPage(1); };
  const reset = () => { setQuery(""); setManagement("all"); setScope("all"); setStatus("all"); setPage(1); };
  const partial = !scene.tenantPoliciesAvailable || !scene.platformPoliciesAvailable;

  const recovery = mutation?.pending ? <PolicyVersionRecovery key={mutation.pending.requestId} mutation={mutation} onApplied={onApplied} onInspect={(id) => onOpen(id)} /> : null;
  if (entityId) return <>{recovery}{selected
    ? <AccountPolicyDetailView key={`${client?.accountId ?? scene.accountId}:${client?.sessionRevision ?? "none"}:${entityId}`} policy={selected} client={client} mutation={mutation} refreshRevision={refreshRevision} onApplied={onApplied} onBack={() => onOpen()} />
    : <EmptyState title={t("notFound")} description={t("notFoundHint")} action={<Button variant="secondary" onClick={() => onOpen()}>{t("back")}</Button>} />}</>;

  return <>{recovery}<Card>
    <ContentPage.Heading title={t("title")} scrollKey="policy-directory" />
    <Tabs.Root value={section} onValueChange={(next) => { setSection(next); if (next === "profiles") setCatalogMounted(true); }}>
      <Tabs.List aria-label={t("sections")} className={styles.policyDirectoryTabs}><Tabs.Trigger value="policies">{t("policiesTab")}</Tabs.Trigger><Tabs.Trigger value="profiles">{t("profilesTab")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content value="policies">
        <div className={styles.policyDirectoryIntro}>
          <p>{t("description")}</p>
          <p>{t("managementSnapshot")}</p>
        </div>
        {partial ? <Alert status="warning">{t(scene.tenantPoliciesAvailable ? "platformUnavailable" : "tenantUnavailable")}</Alert> : null}
        <TableToolbar labels={toolbarLabels}
          search={{ label: t("search"), placeholder: t("searchPlaceholder"), value: query, onChange: (value) => change(() => setQuery(value)) }}
          status={t("resultCount", { count: filtered.length })}
          filters={[
            { id: "management", label: t("management"), value: management, onChange: (value) => change(() => setManagement(value)), options: [{ value: "all", label: t("all") }, { value: "SYSTEM", label: t("system") }, { value: "CUSTOMER", label: t("customer") }] },
            { id: "scope", label: t("scope"), value: scope, onChange: (value) => change(() => setScope(value)), options: [{ value: "all", label: t("all") }, { value: "TENANT", label: t("tenant") }, { value: "INSTALLATION", label: t("installation") }] },
            { id: "status", label: t("status"), value: status, onChange: (value) => change(() => setStatus(value)), options: [{ value: "all", label: t("all") }, { value: "ACTIVE", label: t("active") }, { value: "RETIRED", label: t("retired") }] }
          ]} />
        {rows.length ? <Table aria-label={t("table")} className={styles.policyMetadataTable}>
          <thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("management")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("status")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("updated")}</th></tr></thead>
          <tbody>{rows.map((policy) => <tr key={policy.id}>
            <td><button className={styles.userLink} onClick={() => onOpen(policy.id)}>{policy.displayName}</button><small className={styles.userIdentifier}>{policy.id}</small></td>
            <td><Badge>{t(policy.management === "SYSTEM" ? "system" : "customer")}</Badge></td>
            <td>{t(policy.scope === "TENANT" ? "tenant" : "installation")}</td>
            <td><Badge status={policy.status === "ACTIVE" ? "success" : "neutral"}>{t(policy.status === "ACTIVE" ? "active" : "retired")}</Badge></td>
            <td>{policy.defaultVersionId}</td>
            <td><WorkspaceTime value={policy.updatedAt} /></td>
          </tr>)}</tbody>
        </Table> : <EmptyState title={t(scene.policies.length ? "noResults" : "empty")} description={t(scene.policies.length ? "noResultsHint" : "emptyHint")} action={scene.policies.length ? <Button variant="secondary" onClick={reset}>{toolbarLabels.resetQuery}</Button> : undefined} />}
        <Table.Footer note={t("completeSnapshot", { count: scene.policies.length })}><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>
      </Tabs.Content>
      <Tabs.Content forceMount={catalogMounted || undefined} value="profiles">{catalogMounted ? <AccountAuthorizationProfileCatalog /> : null}</Tabs.Content>
    </Tabs.Root>
  </Card></>;
}
