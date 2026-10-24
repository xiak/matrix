"use client";

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, ContentPage, EmptyState, FormField, Input, Table, TablePagination, TableSkeleton, TableToolbar, Tabs, type PageCommandsHandle } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess, type AccountPolicyReadClient, type AccountPolicyReadLoad, type AccountPolicyVersionDirectoryLoad, type AccountPolicyVersionReadLoad, type PolicyVersionMutationClient, type PolicyVersionMutationResult } from "../application/AccountAccessProvider";
import type { PolicyMutationClient } from "../application/policyMutation";
import { policyDisplayNameValid, policyVersionLimit } from "../domain/accounts";
import type { AccountPolicy, AccountPolicyDetail, AccountPolicyDocument, AccountPolicyVersion, ActionCapability, AuthorizationProfileDirectory, IamAction } from "../domain/accounts";
import { visualDraftHasIncompleteFields } from "../domain/accountPolicyVisualAuthoring";
import { findActionCapability, type AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDetail, WorkspaceInlineForm, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccountAuthorizationProfileCatalog } from "./AccountAuthorizationProfileCatalog";
import { AccountPolicyDocumentAuthor, type PolicyAuthorMode } from "./AccountPolicyDocumentAuthor";
import { PolicyVisualReview } from "./AccountPolicyVisualEditor";
import { PolicyCreateRecovery } from "./LivePolicyCreationWizard";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";
import { AccountDirectoryReadFailure } from "./AccountReadBoundary";

type PolicyDetailState = { status: "loading" } | AccountPolicyReadLoad;
type PolicyVersionDetailState = { status: "loading" } | AccountPolicyVersionReadLoad;
type PolicyVersionDirectoryState = { status: "loading" } | AccountPolicyVersionDirectoryLoad;
type VersionReview = { kind: "set-default" | "retire"; versionId: string };

function policyCapability(capabilities: ActionCapability[], action: IamAction, policyId: string) {
  return findActionCapability(capabilities, action, "POLICY", policyId);
}

function PolicyMetadataEditor({ detail, kind, mutation, authorizationReady, onBack, onApplied }: {
  detail: AccountPolicyDetail; kind: "update" | "retire"; mutation: PolicyMutationClient;
  authorizationReady: boolean;
  onBack(outcome?: "known" | "unknown"): void; onApplied(): void;
}) {
  const t = useTranslations("AccountPolicyDirectory.metadata");
  const id = useId();
  const [displayName, setDisplayName] = useState(detail.policy.displayName);
  const [typedName, setTypedName] = useState("");
  const [review, setReview] = useState(kind === "retire");
  const [failure, setFailure] = useState<string | undefined>();
  const [stale, setStale] = useState(false);
  const outcome = useRef<"known" | "unknown" | undefined>(undefined);
  const clearError = useCallback(() => setFailure(undefined), []);
  const valid = kind === "update" ? policyDisplayNameValid(displayName) && displayName !== detail.policy.displayName : typedName === detail.policy.displayName;
  const title = t(kind === "retire" ? "retireTitle" : review ? "renameReview" : "renameTitle", { name: detail.policy.displayName });
  return <WorkspaceInlineForm title={title} onClose={() => onBack(outcome.current)}
    operation={{ busy: mutation.busy, error: failure, clearError }}
    draft={{ dirty: kind === "update" ? displayName !== detail.policy.displayName : Boolean(typedName), title, description: t("leaveHint") }}
    submitLabel={t(kind === "retire" ? "confirmRetire" : review ? "confirmRename" : "review")}
    submitVariant={kind === "retire" ? "danger" : "primary"}
    submitDisabled={!valid || stale || !authorizationReady || !mutation.ready || Boolean(mutation.pending)} onSubmit={async () => {
      if (!valid || stale || !authorizationReady) return false;
      if (!review) { setReview(true); return false; }
      const result = await mutation.begin(detail, kind === "update" ? { kind, displayName } : { kind });
      if (result.status === "applied") { outcome.current = "known"; onApplied(); return true; }
      if (result.status === "unknown") { outcome.current = "unknown"; return true; }
      if (result.status === "rejected") {
        setFailure(t(`errors.${result.reason}`));
        if (result.reason === "conflict" || result.reason === "notFound") setStale(true);
      } else setFailure(t("blocked"));
      return false;
    }}>
    <p className={styles.note}>{t("authorizationNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("policyId")}</dt><dd><code>{detail.policy.id}</code></dd></div>
      <div><dt>{t("accountId")}</dt><dd><code>{detail.policy.accountId}</code></dd></div>
      <div><dt>{t("revision")}</dt><dd>{detail.policy.resourceVersion}</dd></div>
    </dl>
    {kind === "update" ? <>
      <Alert status="info">{t("renameImpact")}</Alert>
      {review ? <><dl className={styles.catalogFacts}>
        <div><dt>{t("previousName")}</dt><dd>{detail.policy.displayName}</dd></div>
        <div><dt>{t("nextName")}</dt><dd>{displayName}</dd></div>
      </dl><Button variant="ghost" onClick={() => setReview(false)}>{t("editName")}</Button></> : <FormField id={`${id}-name`} label={t("nextName")} hint={t("nameHint")} error={displayName && !policyDisplayNameValid(displayName) ? t("invalidName") : undefined}>
        <Input id={`${id}-name`} value={displayName} onChange={(event) => setDisplayName(event.target.value)}
          aria-describedby={`${id}-name-hint`} invalid={Boolean(displayName && !policyDisplayNameValid(displayName))} autoComplete="off" />
      </FormField>}
    </> : <>
      <Alert status="warning">{t("retireImpact")}</Alert>
      <p>{t("retireReferences")}</p>
      <FormField id={`${id}-confirm`} label={t("typeName", { name: detail.policy.displayName })} hint={t("typeNameHint")}>
        <Input id={`${id}-confirm`} value={typedName} onChange={(event) => setTypedName(event.target.value)} aria-describedby={`${id}-confirm-hint`} autoComplete="off" />
      </FormField>
    </>}
  </WorkspaceInlineForm>;
}

function PolicyMetadataRecovery({ mutation, onApplied, onInspect }: { mutation: PolicyMutationClient; onApplied(kind: "update" | "retire"): void; onInspect(id: string): void }) {
  const t = useTranslations("AccountPolicyDirectory.metadata");
  const pending = mutation.pending;
  const [acknowledged, setAcknowledged] = useState(false);
  const [showBusy, setShowBusy] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (!mutation.busy) return;
    const timer = window.setTimeout(() => setShowBusy(true), 250);
    return () => window.clearTimeout(timer);
  }, [mutation.busy]);
  useEffect(() => {
    if (!pending || mutation.busy) return;
    heading.current?.focus({ preventScroll: true });
  }, [pending?.requestId, mutation.busy, pending]);
  if (mutation.recoveryError) return <Alert status="danger">{t("recoveryUnavailable")}</Alert>;
  if (!pending || mutation.busy && !showBusy) return null;
  return <section className={styles.policyVersionRecovery} aria-label={t("recoveryTitle")} aria-busy={mutation.busy || undefined}>
    <h2 ref={heading} tabIndex={-1} className={styles.stepTitle}>{t("recoveryTitle")}</h2>
    <Alert status="warning">{t(mutation.busy ? "submitting" : "unknown")}</Alert>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("originalOperation")}</dt><dd>{t(pending.kind === "update" ? "renameAction" : "retireAction")}</dd></div>
      <div><dt>{t("policyId")}</dt><dd><code>{pending.policy.id}</code></dd></div>
      <div><dt>{t("requestId")}</dt><dd><code>{pending.requestId}</code></dd></div>
      <div><dt>{t("previousName")}</dt><dd>{pending.policy.displayName}</dd></div>
      {pending.kind === "update" ? <div><dt>{t("nextName")}</dt><dd>{pending.displayName}</dd></div> : null}
      <div><dt>{t("revision")}</dt><dd>{pending.policy.resourceVersion}</dd></div>
    </dl>
    <p className={styles.note}>{t("recoveryHint")}</p>
    {mutation.lastError ? <Alert status="warning">{t(`errors.${mutation.lastError}`)}</Alert> : null}
    <div className={styles.actions}>
      <Button variant="secondary" disabled={mutation.busy || !mutation.ready} onClick={async () => {
        setAcknowledged(false); setShowBusy(true); const result = await mutation.retry(); if (result.status === "applied") onApplied(pending.kind);
      }}>{t("retryOriginal")}</Button>
      <Button variant="ghost" disabled={mutation.busy} onClick={() => onInspect(pending.policy.id)}>{t("inspect")}</Button>
    </div>
    <div className={styles.policyVersionAcknowledge}>
      <label><input type="checkbox" checked={acknowledged} disabled={mutation.busy} onChange={(event) => setAcknowledged(event.target.checked)} /> {t("abandonAcknowledgement")}</label>
      <Button variant="secondary" disabled={!acknowledged || mutation.busy} onClick={async () => { setShowBusy(true); if (await mutation.abandon()) onInspect(pending.policy.id); }}>{t("abandon")}</Button>
    </div>
  </section>;
}

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
      <Button variant="secondary" disabled={busy || mutation.blockedByAuthority || mutation.retryBlockedByAuthority} onClick={() => void handleRetry()}>{t("retryOriginal")}</Button>
      <Button variant="secondary" disabled={busy || mutation.blockedByAuthority} onClick={() => { setFeedback(null); setAcknowledged(false); void mutation.observe(); }}>{t("rereadCurrent")}</Button>
      <Button variant="ghost" onClick={() => onInspect(pending.policyId)}>{t("inspectAffectedPolicy")}</Button>
    </div>
    {pending.observation ? <div className={styles.policyVersionAcknowledge}>
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> {t("acknowledgeUnknown")}</label>
      <Button variant="secondary" disabled={!acknowledged || busy} onClick={() => void mutation.acknowledge().then((cleared) => { if (cleared) onApplied(); })}>{t("endOldIntent")}</Button>
    </div> : null}
  </section>;
}

function VersionMutationReview({ review, policy, versions, busy, blocked, error, onSubmit, onCancel }: {
  review: VersionReview; policy: AccountPolicy; versions: AccountPolicyVersion[]; busy: boolean; blocked: boolean; error: string | null;
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
    {blocked ? <Alert status="warning">{t("metadata.blocked")}</Alert> : null}
    <div className={styles.actions}><Button variant={review.kind === "retire" ? "danger" : "primary"} disabled={busy || blocked || Boolean(error)} onClick={onSubmit}>{t(review.kind === "set-default" ? "confirmSetDefault" : "confirmRetire")}</Button><Button variant="secondary" disabled={busy} onClick={onCancel}>{t("cancel")}</Button></div>
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

function PolicyCompilationProvenance({ version }: { version: AccountPolicyVersion }) {
  const t = useTranslations("AccountPolicyDirectory");
  const compilation = version.compilation;
  return <section className={styles.policyCompilation} aria-label={t("compilationProvenanceTitle")}>
    <div className={styles.catalogDetailHeading}>
      <h3 className={styles.stepTitle}>{t("compilationProvenanceTitle")}</h3>
      {compilation ? <Badge>{t("compilationContractVersion", { version: compilation.compilationVersion })}</Badge> : <Badge>{t("legacyCompilation")}</Badge>}
    </div>
    <p className={styles.note}>{t(compilation ? "compilationProvenanceHint" : "legacyCompilationHint")}</p>
    {compilation ? <Table aria-label={t("compilationProfilesTable")} mobileLayout="stack" className={styles.policyCompilationTable}>
      <thead><tr><th scope="col">{t("product")}</th><th scope="col">{t("revision")}</th><th scope="col">{t("profileDigest")}</th></tr></thead>
      <tbody>{compilation.profiles.map((profile) => <tr key={`${profile.product}:${profile.revision}:${profile.contentDigest}`}>
        <td data-label={t("product")}><code>{profile.product}</code></td>
        <td data-label={t("revision")}><code>{profile.revision}</code></td>
        <td data-label={t("profileDigest")}><code>{profile.contentDigest}</code></td>
      </tr>)}</tbody>
    </Table> : null}
  </section>;
}

function PolicyVersionDocument({ version, title }: { version: AccountPolicyVersion; title: string }) {
  const t = useTranslations("AccountPolicyDirectory");
  return <section className={styles.catalogNotice} aria-label={title}>
    <div className={styles.catalogDetailHeading}><h2>{title}</h2><Badge>{t("contractVersion", { version: version.contractVersion })}</Badge></div>
    <p className={styles.note}>{t("documentNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div className={styles.catalogDigest}><dt>{t("digest")}</dt><dd><code>{version.contentDigest}</code></dd></div>
    </dl>
    <PolicyCompilationProvenance version={version} />
    <PolicyStatementTable version={version} />
    <details className={styles.policyRawDocument}><summary>{t("rawDocument")}</summary><pre tabIndex={0}>{JSON.stringify(version.document, null, 2)}</pre></details>
  </section>;
}

function PolicyVersionPublisher({ policy, defaultVersion, mutation, authorizationReady, onPublished, onConflict, onClose }: {
  policy: AccountPolicy; defaultVersion: AccountPolicyVersion; mutation: PolicyVersionMutationClient;
  authorizationReady: boolean;
  onPublished(detail: AccountPolicyDetail): void; onConflict(): void; onClose(): void;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const heading = useRef<HTMLHeadingElement>(null);
  const [initialText] = useState(() => JSON.stringify(defaultVersion.document, null, 2));
  const [text, setText] = useState(initialText);
  const [review, setReview] = useState<{ document: AccountPolicyDocument; resourceVersion: number; defaultVersionId: string;
    directory?: AuthorizationProfileDirectory } | null>(null);
  const reviewing = Boolean(review);
  const [error, setError] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<PolicyAuthorMode>("json");
  const [visualReady, setVisualReady] = useState(false);
  const [visualDirectory, setVisualDirectory] = useState<AuthorizationProfileDirectory | null>(null);
  const [busy, setBusy] = useState(false);
  const requestLeave = useAccessDraft({ dirty: text !== initialText, busy, title: t("publishCancelTitle"),
    description: t("publishCancelHint"), form: heading });
  // The editor and review have different heights. Move the scroll container
  // with the focused heading so a transition never opens midway through the
  // incoming view.
  useLayoutEffect(() => { heading.current?.focus(); }, [reviewing]);
  const openReview = () => {
    if (!authorizationReady || busy) return;
    setError(null);
    if (new TextEncoder().encode(text).length > 64 * 1024) { setError(t("publishTooLarge")); return; }
    if (editorMode === "visual") {
      if (!visualReady || !visualDirectory) { setError(t("visualDraftIncomplete")); return; }
      let visual: AccountPolicyDocument;
      try { visual = JSON.parse(text) as AccountPolicyDocument; } catch { setError(t("visualDraftIncomplete")); return; }
      if (visualDraftHasIncompleteFields(visual)) {
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
    setReview({ document: parsed as AccountPolicyDocument, resourceVersion: policy.resourceVersion, defaultVersionId: policy.defaultVersionId,
      directory: editorMode === "visual" ? visualDirectory! : undefined });
  };
  const publish = async () => {
    if (!review || busy || !authorizationReady) return;
    if (mutation.pending || mutation.blockedByMetadata || mutation.blockedByAuthority || review.resourceVersion !== policy.resourceVersion || review.defaultVersionId !== policy.defaultVersionId) {
      setError(t("reviewStale")); return;
    }
    setBusy(true); setError(null);
    try {
      const result = await mutation.begin({ kind: "publish", policyId: policy.id, document: review.document,
        resourceVersion: review.resourceVersion, expectedDefaultVersionId: review.defaultVersionId });
      if (result.status === "applied") onPublished(result.detail);
      else if (result.status === "unknown") onClose();
      else if (result.status === "rejected" && result.reason === "conflict") {
        setReview(null);
        setError(t("mutationErrors.conflict"));
        onConflict();
      }
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
      {editorMode === "visual" && review.directory ? <PolicyVisualReview document={review.document} directory={review.directory} headingLevel={4} /> : null}
      {editorMode === "visual" ? <details className={styles.policyRawDocument}><summary>{t("compareDocuments")}</summary><div className={styles.policyComparison}>
        <section><h4>{t("currentDocument", { version: defaultVersion.versionId })}</h4><pre tabIndex={0}>{JSON.stringify(defaultVersion.document, null, 2)}</pre></section>
        <section><h4>{t("proposedDocument")}</h4><pre tabIndex={0}>{JSON.stringify(review.document, null, 2)}</pre></section>
      </div></details> : <div className={styles.policyComparison}>
        <section className={styles.policyRawDocument}><h4>{t("currentDocument", { version: defaultVersion.versionId })}</h4><pre tabIndex={0}>{JSON.stringify(defaultVersion.document, null, 2)}</pre></section>
        <section className={styles.policyRawDocument}><h4>{t("proposedDocument")}</h4><pre tabIndex={0}>{JSON.stringify(review.document, null, 2)}</pre></section>
      </div>}
    </> : null}
    <div hidden={Boolean(review)}><AccountPolicyDocumentAuthor text={text} onChange={setText} error={Boolean(error)} onClearError={() => setError(null)}
      mode={editorMode} onModeChange={setEditorMode} onVisualReadyChange={setVisualReady} onVisualDirectoryChange={setVisualDirectory}
      label={t("proposedDocument")} hint={t("publishEditorHint")} /></div>
    {error ? <Alert status="danger">{error}</Alert> : null}
    {mutation.blockedByMetadata ? <Alert status="warning">{t("metadata.blocked")}</Alert> : null}
    <div className={styles.actions}>
      {review ? <><Button disabled={busy || !authorizationReady || mutation.blockedByMetadata || mutation.blockedByAuthority || Boolean(error)} onClick={() => void publish()}>{t("confirmPublish")}</Button>
        <Button variant="secondary" disabled={busy} onClick={() => { setReview(null); setError(null); }}>{t("editDraft")}</Button></> :
        <Button disabled={busy || !authorizationReady} onClick={openReview}>{t("reviewDraft")}</Button>}
      <Button variant="ghost" disabled={busy} onClick={() => requestLeave(onClose)}>{t("cancel")}</Button>
    </div>
  </section>;
}

function AccountPolicyVersions({ policy, capabilities, authorizedCapabilities, listVersions, readVersion, mutation, authorizationReady, onApplied, onConflictRefresh, refreshRevision }: {
  policy: AccountPolicy;
  capabilities: ActionCapability[];
  authorizedCapabilities: ActionCapability[];
  listVersions: NonNullable<AccountPolicyReadClient["listVersions"]>;
  readVersion: NonNullable<AccountPolicyReadClient["readVersion"]>;
  mutation: PolicyVersionMutationClient | null;
  authorizationReady: boolean;
  onApplied(): void;
  onConflictRefresh(): void;
  refreshRevision: number;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const [state, setState] = useState<PolicyVersionDirectoryState>({ status: "loading" });
  const [directoryAuthority, setDirectoryAuthority] = useState<{ listVersions: typeof listVersions; refreshRevision: number; revision: number } | null>(null);
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<PolicyVersionDetailState>({ status: "loading" });
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
  const canReadVersion = policyCapability(capabilities, "iam.policy-version.read", policy.id)?.available === true;
  const canPublish = policyCapability(capabilities, "iam.policy-version.create", policy.id)?.available === true;
  const canSetDefault = policyCapability(capabilities, "iam.policy.set-default-version", policy.id)?.available === true;
  const canRetireVersion = policyCapability(capabilities, "iam.policy-version.delete", policy.id)?.available === true;
  const publishAuthorized = policyCapability(authorizedCapabilities, "iam.policy-version.create", policy.id)?.available === true;
  const setDefaultAuthorized = policyCapability(authorizedCapabilities, "iam.policy.set-default-version", policy.id)?.available === true;
  const retireAuthorized = policyCapability(authorizedCapabilities, "iam.policy-version.delete", policy.id)?.available === true;
  const versionLimitReached = state.status === "ready" && state.directory.items.length >= policyVersionLimit;
  useEffect(() => {
    let current = true;
    void listVersions(policy.id).then((result) => { if (current) { setState(result); setDirectoryAuthority({ listVersions, refreshRevision, revision }); } });
    return () => { current = false; };
  }, [listVersions, policy.id, revision, refreshRevision]);
  const writesAuthorized = authorizationReady && directoryAuthority?.listVersions === listVersions &&
    directoryAuthority.refreshRevision === refreshRevision && directoryAuthority.revision === revision && state.status === "ready" &&
    state.directory.policy.id === policy.id && state.directory.policy.accountId === policy.accountId &&
    state.directory.policy.resourceVersion === policy.resourceVersion &&
    state.directory.policy.defaultVersionId === policy.defaultVersionId;
  useEffect(() => {
    if (!selectedId || !canReadVersion) return;
    let current = true;
    void readVersion(policy.id, selectedId).then((result) => { if (current) setSelected(result); });
    return () => { current = false; };
  }, [canReadVersion, readVersion, policy.id, selectedId, selectedRevision]);
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
    if (!review || !mutation || !writesAuthorized || state.status !== "ready" || mutationBusy ||
        review.kind === "set-default" && (!canSetDefault || !setDefaultAuthorized) || review.kind === "retire" && (!canRetireVersion || !retireAuthorized)) return;
    const snapshot = state.directory;
    if (!snapshot.items.some((item) => item.versionId === review.versionId) ||
        snapshot.policy.defaultVersionId === review.versionId || mutation.pending || mutation.blockedByMetadata) {
      setMutationError(t("reviewStale")); return;
    }
    setMutationBusy(true); setMutationError(null);
    let result: PolicyVersionMutationResult;
    try {
      result = await mutation.begin({ ...review, policyId: policy.id,
        expectedDefaultVersionId: snapshot.policy.defaultVersionId, resourceVersion: snapshot.policy.resourceVersion });
    } finally { setMutationBusy(false); }
    if (result.status === "applied") {
      setPublished(null);
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
    <VersionMutationReview review={review} policy={state.directory.policy} versions={state.directory.items} busy={mutationBusy} blocked={!writesAuthorized || review.kind === "set-default" && !setDefaultAuthorized || review.kind === "retire" && !retireAuthorized || mutation?.blockedByMetadata === true || mutation?.blockedByAuthority === true} error={mutationError} onSubmit={() => void submit()} onCancel={() => { setReview(null); setMutationError(null); }} />
  </div>;
  if (publisherOpen && state.status === "ready" && mutation && canPublish) {
    const defaultVersion = state.directory.items.find((item) => item.versionId === state.directory.policy.defaultVersionId);
    if (defaultVersion) return <PolicyVersionPublisher policy={state.directory.policy} defaultVersion={defaultVersion} mutation={mutation} authorizationReady={writesAuthorized && publishAuthorized}
      onPublished={(detail) => {
        setState({ status: "ready", directory: { policy: detail.policy,
          items: [...state.directory.items, detail.version].sort((left, right) => left.versionId.localeCompare(right.versionId)) } });
        setPublished({ versionId: detail.version.versionId, defaultVersionId: detail.policy.defaultVersionId });
        setPublisherOpen(false);
        setRevision((value) => value + 1);
        onApplied();
      }} onConflict={onConflictRefresh}
      onClose={() => { returnToPublish.current = true; setPublisherOpen(false); }} />;
  }
  if (selectedId) return <div className={styles.catalogNotice}>
    <div><Button variant="secondary" onClick={() => setSelectedId(null)}>{t("backToVersions")}</Button></div>
    <h2 ref={title} tabIndex={-1} className={styles.stepTitle}>{t("versionInspection", { version: selectedId })}</h2>
    {selected.status === "loading" ? <TableSkeleton label={t("loadingVersion")} rows={3} header={false} /> :
      selected.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={selected.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${selected.status}`)}</Alert>
        {selected.status !== "expired" && selected.status !== "notFound" ? <div><Button variant="secondary" onClick={() => { setSelected({ status: "loading" }); setSelectedRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> :
      <PolicyVersionDocument version={selected.detail.version} title={t("versionDocument", { version: selectedId })} />}
  </div>;
  return <div ref={list} tabIndex={-1} className={styles.catalogNotice}>
    <p className={styles.note}>{t("versionDirectoryNotice")}</p>
    {published && state.status === "ready" && state.directory.policy.defaultVersionId === published.defaultVersionId && state.directory.items.some((item) => item.versionId === published.versionId) ? <Alert status="success"><h3 ref={publishedHeading} tabIndex={-1} className={styles.stepTitle}>{t("publishSucceeded", { version: published.versionId })}</h3><p>{t("publishSucceededDetail", { version: published.defaultVersionId })}</p></Alert> : null}
    {mutationError ? <Alert status="danger">{mutationError}</Alert> : null}
    {state.status === "loading" ? <TableSkeleton label={t("loadingVersions")} rows={3} header={false} /> :
      state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${state.status}`)}</Alert>
        {state.status !== "expired" && state.status !== "notFound" ? <div><Button variant="secondary" onClick={() => { setState({ status: "loading" }); setRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> : <>
        <div className={styles.catalogDetailHeading}><p>{t("versionCount", { count: state.directory.items.length, limit: policyVersionLimit })}</p>
          {mutation?.canPublish && canPublish ? <Button ref={publishButton} variant="secondary" disabled={versionLimitReached || !writesAuthorized || !publishAuthorized || Boolean(mutation.pending) || mutation.blockedByMetadata || mutation.blockedByAuthority} onClick={() => { setPublished(null); setMutationError(null); setPublisherOpen(true); }}>{t("publishVersion")}</Button> : null}
        </div>
        {versionLimitReached ? <Alert status="warning">{t("versionLimitReached", { limit: policyVersionLimit })}</Alert> : null}
        <Table aria-label={t("versionTable")} mobileLayout="stack" className={styles.policyVersionTable}>
          <thead><tr><th scope="col">{t("versionId")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("versionContract")}</th><th scope="col">{t("digest")}</th></tr></thead>
          <tbody>{state.directory.items.map((item) => <tr key={item.versionId}>
            <td data-label={t("versionId")}><div className={styles.rowActionCell}>{canReadVersion
              ? <Table.PrimaryAction data-version-id={item.versionId} onClick={() => { opener.current = item.versionId; setSelected({ status: "loading" }); setSelectedId(item.versionId); }}>{item.versionId}</Table.PrimaryAction>
              : <code>{item.versionId}</code>}{mutation && item.versionId !== state.directory.policy.defaultVersionId && (canSetDefault || canRetireVersion) ? <ActionMenu iconOnly label={t("versionActions", { version: item.versionId })} actions={[
              ...(canSetDefault ? [{ id: "set-default", label: t("setDefault"), disabledReason: !writesAuthorized || !setDefaultAuthorized || mutation.blockedByAuthority ? t("metadata.readRequired") : mutation.blockedByMetadata ? t("metadata.blocked") : mutation.pending ? t("mutationBlocked") : undefined, onSelect: () => { reviewOpener.current = item.versionId; setPublished(null); setMutationError(null); setReview({ kind: "set-default" as const, versionId: item.versionId }); } }] : []),
              ...(canRetireVersion ? [{ id: "retire", label: t("retireVersion"), danger: true, disabledReason: !writesAuthorized || !retireAuthorized || mutation.blockedByAuthority ? t("metadata.readRequired") : mutation.blockedByMetadata ? t("metadata.blocked") : mutation.pending ? t("mutationBlocked") : undefined, onSelect: () => { reviewOpener.current = item.versionId; setPublished(null); setMutationError(null); setReview({ kind: "retire" as const, versionId: item.versionId }); } }] : [])
            ]} /> : null}</div></td>
            <td data-label={t("defaultVersion")}>{item.versionId === state.directory.policy.defaultVersionId ? <Badge status="success">{t("currentDefault")}</Badge> : "—"}</td>
            <td data-label={t("versionContract")}>{t("contractVersion", { version: item.contractVersion })}</td>
            <td data-label={t("digest")}><code>{item.contentDigest}</code></td>
          </tr>)}</tbody>
        </Table>
      </>}
  </div>;
}

function AccountPolicyDetailView({ policyId, policy, client, mutation, metadataMutation, authorityPending, refreshRevision, onMetadataApplied, onVersionConflict, onBack }: {
  policyId: string; policy?: AccountPolicy; client: AccountPolicyReadClient | null; mutation: PolicyVersionMutationClient | null;
  metadataMutation: PolicyMutationClient | null; authorityPending: boolean; refreshRevision: number; onMetadataApplied(kind: "update" | "retire"): void; onVersionConflict(): void; onBack(): void;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const [snapshot, setSnapshot] = useState<{ client: AccountPolicyReadClient; revision: number; refreshRevision: number; state: PolicyDetailState } | null>(null);
  const [retained, setRetained] = useState<{ continuityIdentity: object; access: NonNullable<Extract<AccountPolicyReadLoad, { status: "ready" }>["access"]> } | null>(null);
  const [revision, setRevision] = useState(0);
  const [section, setSection] = useState("document");
  const [versionsMounted, setVersionsMounted] = useState(false);
  const [workflow, setWorkflow] = useState<{ identity: object; detail: AccountPolicyDetail; kind: "update" | "retire" } | null>(null);
  const actionFocus = useRef<PageCommandsHandle>(null);
  useEffect(() => {
    if (policy?.scope === "INSTALLATION" || !client) return;
    let current = true;
    void client.read(policyId).then((result) => { if (current) {
      setSnapshot({ client, revision, refreshRevision, state: result });
      if (result.status === "ready") setRetained((previous) => ({
        continuityIdentity: client.continuityIdentity,
        access: previous?.continuityIdentity === client.continuityIdentity
          ? { detail: result.access.detail, capabilities: previous.access.capabilities }
          : result.access
      }));
    } });
    return () => { current = false; };
  }, [client, policy?.scope, policyId, revision, refreshRevision]);
  const state: PolicyDetailState = snapshot?.client === client && snapshot.revision === revision && snapshot.refreshRevision === refreshRevision
    ? snapshot.state : { status: "loading" };
  const access = state.status === "ready" ? state.access : null;
  const retainedAccess = client && retained?.continuityIdentity === client.continuityIdentity ? retained.access : null;
  const displayAccess = access ? { detail: access.detail, capabilities: retainedAccess?.capabilities ?? access.capabilities } : retainedAccess;
  const detail = access?.detail ?? null;
  const source = displayAccess?.detail.policy ?? policy;
  const renameCapability = access ? policyCapability(access.capabilities, "iam.policy.update", policyId) : null;
  const retireCapability = access ? policyCapability(access.capabilities, "iam.policy.delete", policyId) : null;
  const canRename = renameCapability?.available === true;
  const canRetire = retireCapability?.available === true;
  const eligibleForMetadata = Boolean(source && source.management === "CUSTOMER" && source.scope === "TENANT" &&
    source.accountId === client?.accountId && source.status === "ACTIVE");
  const workflowCapability = workflow && access ? policyCapability(access.capabilities,
    workflow.kind === "update" ? "iam.policy.update" : "iam.policy.delete", policyId) : null;
  const workflowAuthorizationReady = Boolean(!authorityPending && workflow && access && workflowCapability?.available &&
    access.detail.policy.id === workflow.detail.policy.id && access.detail.policy.accountId === workflow.detail.policy.accountId &&
    access.detail.policy.resourceVersion === workflow.detail.policy.resourceVersion &&
    access.detail.policy.defaultVersionId === workflow.detail.policy.defaultVersionId &&
    access.detail.version.versionId === workflow.detail.version.versionId &&
    access.detail.version.contentDigest === workflow.detail.version.contentDigest);
  if (workflow && metadataMutation && workflow.identity === metadataMutation.identity) return <PolicyMetadataEditor
    detail={workflow.detail} kind={workflow.kind} mutation={metadataMutation} authorizationReady={workflowAuthorizationReady}
    onApplied={() => onMetadataApplied(workflow.kind)}
    onBack={(outcome) => { setWorkflow(null); setRevision((value) => value + 1); if (outcome !== "unknown") window.requestAnimationFrame(() => actionFocus.current?.focus()); }} />;
  const sharedDisabledReason = !source ? t("metadata.readRequired") : !eligibleForMetadata ? t("metadata.ineligible") : !detail ? t("metadata.readRequired")
    : metadataMutation && (!metadataMutation.ready || metadataMutation.recoveryError) ? t("metadata.recoveryUnavailable")
      : metadataMutation?.pending || mutation?.pending ? t("metadata.blocked") : undefined;
  const documentRegion = policy?.scope === "INSTALLATION" ? <Alert status="info">{t("platformDetailUnavailable")}</Alert> :
    !client ? <Alert status="danger">{t("errors.unavailable")}</Alert> :
    state.status === "loading" ? <TableSkeleton label={t("loadingDetail")} rows={3} header={false} /> :
    state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`errors.${state.status}`)}</Alert>
      {state.status !== "expired" && state.status !== "notFound" ? <div><Button variant="secondary" onClick={() => setRevision((value) => value + 1)}>{t("retry")}</Button></div> : null}</div> :
    detail ? <PolicyVersionDocument version={detail.version} title={t("defaultDocument")} /> : null;
  const metadataActions = metadataMutation ? { secondary: [
    { id: "rename-policy", label: t("metadata.renameAction"),
      disabledReason: sharedDisabledReason ?? (!canRename ? t("metadata.noAuthority") : undefined),
      onSelect: () => { if (detail && canRename) setWorkflow({ identity: metadataMutation.identity, detail: structuredClone(detail), kind: "update" }); } },
    { id: "retire-policy", label: t("metadata.retireAction"), danger: true,
      disabledReason: sharedDisabledReason ?? (!canRetire ? t("metadata.noAuthority") : undefined),
      onSelect: () => { if (detail && canRetire) setWorkflow({ identity: metadataMutation.identity, detail: structuredClone(detail), kind: "retire" }); } }
  ] } : undefined;
  const onVersionApplied = () => setRevision((value) => value + 1);
  return <WorkspaceDetail title={source?.displayName ?? policyId} onBack={onBack} actionFocusRef={actionFocus} actions={metadataActions}>
    <p className={styles.note}>{t("detailNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("policyId")}</dt><dd><code>{policyId}</code></dd></div>
      {source ? <><div><dt>{t("management")}</dt><dd>{t(source.management === "SYSTEM" ? "system" : "customer")}</dd></div>
      <div><dt>{t("scope")}</dt><dd>{t(source.scope === "TENANT" ? "tenant" : "installation")}</dd></div>
      <div><dt>{t("defaultVersion")}</dt><dd><code>{detail?.version.versionId ?? source.defaultVersionId}</code></dd></div>
      <div><dt>{t("updated")}</dt><dd><WorkspaceTime value={detail?.policy.updatedAt ?? source.updatedAt} /></dd></div></> : null}
    </dl>
    {source?.management === "CUSTOMER" && source.scope === "TENANT" && Boolean(displayAccess && policyCapability(displayAccess.capabilities, "iam.policy-version.list", policyId)?.available) && client?.listVersions && client.readVersion ?
      <Tabs.Root value={section} onValueChange={(next) => { setSection(next); if (next === "versions") setVersionsMounted(true); }}>
        <Tabs.List aria-label={t("detailSections")}><Tabs.Trigger value="document">{t("defaultDocument")}</Tabs.Trigger><Tabs.Trigger value="versions">{t("versionsTab")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="document">{documentRegion}</Tabs.Content>
        <Tabs.Content value="versions" forceMount={versionsMounted || undefined}>{versionsMounted ? <AccountPolicyVersions policy={source} capabilities={displayAccess!.capabilities} authorizedCapabilities={access?.capabilities ?? []} listVersions={client.listVersions} readVersion={client.readVersion} mutation={mutation} authorizationReady={!authorityPending && Boolean(access)} refreshRevision={refreshRevision} onApplied={onVersionApplied} onConflictRefresh={onVersionConflict} /> : null}</Tabs.Content>
      </Tabs.Root> : documentRegion}
  </WorkspaceDetail>;
}

export function AccountPolicyDirectory({ scene, entityId, onOpen, onCreate }: { scene: AccountAccessScene; entityId?: string; onOpen(id?: string): void; onCreate(): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const collection = useTranslations("Collection");
  const toolbarLabels = useTableToolbarLabels();
  const access = useAccountAccess();
  const client = access.policyRead;
  const mutation = access.policyVersionMutation;
  const metadataMutation = access.policyMutation;
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [retiredPolicyId, setRetiredPolicyId] = useState<string | null>(null);
  useEffect(() => { if (retiredPolicyId && entityId === retiredPolicyId) onOpen(); }, [retiredPolicyId, entityId, onOpen]);
  const onApplied = () => setRefreshRevision((value) => value + 1);
  const onMetadataApplied = (kind?: "update" | "retire") => {
    onApplied();
    void access.refreshPolicyDirectory();
    if (kind === "retire") setRetiredPolicyId(entityId ?? null);
  };
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
  const failedDirectory = scene.directoryFailures?.tenantPolicies ? "tenantPolicies" : scene.directoryFailures?.platformPolicies ? "platformPolicies" : null;

  const recovery = mutation?.pending ? <PolicyVersionRecovery key={mutation.pending.requestId} mutation={mutation} onApplied={onApplied} onInspect={(id) => onOpen(id)} /> : null;
  const createRecovery = access.policyCreate?.pending ? <PolicyCreateRecovery key={access.policyCreate.pending.requestId} client={access.policyCreate}
    pending={access.policyCreate.pending} onDone={(id) => onOpen(id)} onInspect={() => onOpen()} /> : null;
  const metadataRecovery = metadataMutation ? <PolicyMetadataRecovery key={metadataMutation.pending?.requestId ?? "none"} mutation={metadataMutation} onApplied={onMetadataApplied} onInspect={(id) => { onApplied(); onOpen(id); }} /> : null;
  if (entityId) return <>{metadataRecovery}{recovery}{createRecovery}
    <AccountPolicyDetailView key={`${client?.accountId ?? scene.accountId}:${client?.sessionRevision ?? "none"}:${entityId}`}
      policyId={entityId} policy={selected ?? undefined} client={client} mutation={mutation} metadataMutation={metadataMutation}
      authorityPending={access.authorityPending} refreshRevision={refreshRevision} onMetadataApplied={onMetadataApplied} onVersionConflict={onApplied} onBack={() => onOpen()} /></>;

  return <>{metadataRecovery}{recovery}{createRecovery}<Card>
    <ContentPage.Heading title={t("title")} scrollKey="policy-directory" actions={access.policyCreate ?
      <ContentPage.Commands label={collection("pageActions")} primary={{ id: "create", label: t("createPolicy"), icon: <Plus aria-hidden="true" />,
        disabled: Boolean(access.policyCreate.pending), onSelect: onCreate }} /> : undefined} />
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
          status={failedDirectory ? undefined : t("resultCount", { count: filtered.length })}
          filters={[
            { id: "management", label: t("management"), value: management, onChange: (value) => change(() => setManagement(value)), options: [{ value: "all", label: t("all") }, { value: "SYSTEM", label: t("system") }, { value: "CUSTOMER", label: t("customer") }] },
            { id: "scope", label: t("scope"), value: scope, onChange: (value) => change(() => setScope(value)), options: [{ value: "all", label: t("all") }, { value: "TENANT", label: t("tenant") }, { value: "INSTALLATION", label: t("installation") }] },
            { id: "status", label: t("status"), value: status, onChange: (value) => change(() => setStatus(value)), options: [{ value: "all", label: t("all") }, { value: "ACTIVE", label: t("active") }, { value: "RETIRED", label: t("retired") }] }
          ]} />
        {failedDirectory ? <AccountDirectoryReadFailure kind={failedDirectory} /> : rows.length ? <Table aria-label={t("table")} className={styles.policyMetadataTable} mobileLayout="stack">
          <thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("management")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("status")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("updated")}</th></tr></thead>
          <tbody>{rows.map((policy) => <tr key={policy.id}>
            <td data-label={t("policy")}><Table.PrimaryAction onClick={() => onOpen(policy.id)}>{policy.displayName}</Table.PrimaryAction><small className={styles.userIdentifier}>{policy.id}</small></td>
            <td data-label={t("management")}><Badge>{t(policy.management === "SYSTEM" ? "system" : "customer")}</Badge></td>
            <td data-label={t("scope")}>{t(policy.scope === "TENANT" ? "tenant" : "installation")}</td>
            <td data-label={t("status")}><Badge status={policy.status === "ACTIVE" ? "success" : "neutral"}>{t(policy.status === "ACTIVE" ? "active" : "retired")}</Badge></td>
            <td data-label={t("defaultVersion")}>{policy.defaultVersionId}</td>
            <td data-label={t("updated")}><WorkspaceTime value={policy.updatedAt} /></td>
          </tr>)}</tbody>
        </Table> : <EmptyState title={t(scene.policies.length ? "noResults" : "empty")} description={t(scene.policies.length ? "noResultsHint" : "emptyHint")} action={scene.policies.length ? <Button variant="secondary" onClick={reset}>{toolbarLabels.resetQuery}</Button> : undefined} />}
        <Table.Footer note={failedDirectory ? undefined : t("completeSnapshot", { count: scene.policies.length })}>{failedDirectory ? null : <TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} />}</Table.Footer>
      </Tabs.Content>
      <Tabs.Content forceMount={catalogMounted || undefined} value="profiles">{catalogMounted ? <AccountAuthorizationProfileCatalog /> : null}</Tabs.Content>
    </Tabs.Root>
  </Card></>;
}
