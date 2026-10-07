"use client";

import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, FileCode2, LockKeyhole, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Steps, Table, TablePagination, Tabs } from "@ui/xiak";
import {
  authorizationResourceShapeKind,
  type AuthorizationProfileAction,
  type AuthorizationProfileEntry
} from "../domain/accounts";
import { reviewServiceTemplateProfile, type ServiceTemplateProfileCheck } from "../domain/serviceAuthorization";
import { previewManagedServiceRoleTemplate } from "../repositories/previewServiceAuthorizationContract";
import { AuthorizationActionTable } from "./AuthorizationActionTable";
import styles from "./AuthorizationProfilePublishingPreview.module.css";

const stageIds = ["declaration", "validation", "release"] as const;
const validationSectionIds = ["checks", "changes", "actions"] as const;
type ValidationSection = typeof validationSectionIds[number];

const declarationFields = [
  "resourceKind", "scope", "resourceShapes", "subjectTypes", "userAuthenticationMethods",
  "conditions", "resultResourceKind", "instanceListBatch"
] as const;
type DeclarationField = typeof declarationFields[number];
type ProfileChange = {
  id: string;
  kind: "added" | "removed" | "changed";
  action: string;
  fields: DeclarationField[] | ["callingService"];
  before?: AuthorizationProfileAction;
  after?: AuthorizationProfileAction;
  beforeCallingService?: string;
  afterCallingService?: string;
};
export type AuthorizationProfileComparison =
  | { status: "ready"; changes: ProfileChange[]; added: number; removed: number; changed: number }
  | { status: "unavailable"; reason: "product" | "revision" | "duplicate-action" };

function normalizedField(action: AuthorizationProfileAction, field: DeclarationField): unknown {
  if (field === "resourceShapes") return action.resourceShapes.map((shape) => ({
    mode: shape.mode,
    prefixAllowed: shape.prefixAllowed,
    collectionUsage: shape.collectionUsage ?? null
  })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  if (field === "conditions") return action.conditions ? action.conditions.map((condition) => ({
    key: condition.key,
    source: condition.source,
    valueType: condition.valueType
  })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))) : null;
  if (field === "subjectTypes") return action.subjectTypes ? [...action.subjectTypes].sort() : null;
  if (field === "userAuthenticationMethods") return action.userAuthenticationMethods ? [...action.userAuthenticationMethods].sort() : null;
  return action[field] ?? null;
}

function actionMap(actions: AuthorizationProfileAction[]): Map<string, AuthorizationProfileAction> | null {
  const result = new Map<string, AuthorizationProfileAction>();
  for (const action of actions) {
    if (result.has(action.action)) return null;
    result.set(action.action, action);
  }
  return result;
}

function presentDeclarationFields(action: AuthorizationProfileAction): DeclarationField[] {
  return declarationFields.filter((field) => normalizedField(action, field) !== null);
}

// This is a structural MOCK comparison only. It never recomputes a digest,
// evaluates a Policy, predicts migration, or produces a publish decision.
export function compareAuthorizationProfileEntries(
  current: AuthorizationProfileEntry,
  candidate: AuthorizationProfileEntry
): AuthorizationProfileComparison {
  if (current.profile.product !== candidate.profile.product) return { status: "unavailable", reason: "product" };
  if (!Number.isSafeInteger(current.profile.revision) || current.profile.revision < 1 ||
    !Number.isSafeInteger(candidate.profile.revision) || candidate.profile.revision < 1) {
    return { status: "unavailable", reason: "revision" };
  }
  const currentActions = actionMap(current.profile.actions);
  const candidateActions = actionMap(candidate.profile.actions);
  if (!currentActions || !candidateActions) return { status: "unavailable", reason: "duplicate-action" };
  const changes: ProfileChange[] = [];
  if (current.profile.callingService !== candidate.profile.callingService) changes.push({
    id: "@profile/callingService",
    kind: "changed",
    action: "AuthorizationProfile.callingService",
    fields: ["callingService"],
    beforeCallingService: current.profile.callingService,
    afterCallingService: candidate.profile.callingService
  });
  const actionIds = [...new Set([...currentActions.keys(), ...candidateActions.keys()])].sort();
  for (const actionId of actionIds) {
    const before = currentActions.get(actionId);
    const after = candidateActions.get(actionId);
    if (!before && after) {
      changes.push({ id: `added:${actionId}`, kind: "added", action: actionId, fields: presentDeclarationFields(after), after });
      continue;
    }
    if (before && !after) {
      changes.push({ id: `removed:${actionId}`, kind: "removed", action: actionId, fields: presentDeclarationFields(before), before });
      continue;
    }
    if (!before || !after) continue;
    const fields = declarationFields.filter((field) => JSON.stringify(normalizedField(before, field)) !== JSON.stringify(normalizedField(after, field)));
    if (fields.length) changes.push({ id: `changed:${actionId}`, kind: "changed", action: actionId, fields, before, after });
  }
  return {
    status: "ready",
    changes,
    added: changes.filter((change) => change.kind === "added").length,
    removed: changes.filter((change) => change.kind === "removed").length,
    changed: changes.filter((change) => change.kind === "changed").length
  };
}

function syntheticCandidate(entry: AuthorizationProfileEntry): AuthorizationProfileEntry {
  const actions = entry.profile.actions.map((action) => structuredClone(action));
  const first = actions[0];
  if (first) first.userAuthenticationMethods = first.userAuthenticationMethods?.includes("ACCESS_KEY")
    ? first.userAuthenticationMethods.filter((method) => method !== "ACCESS_KEY")
    : [...(first.userAuthenticationMethods ?? []), "ACCESS_KEY"];
  if (actions.length > 1) actions.pop();
  actions.push({
    action: `${entry.profile.product}.candidate-preview.read`,
    resourceKind: first?.resourceKind ?? "PREVIEW_RESOURCE",
    scope: first?.scope ?? "TENANT",
    resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }],
    subjectTypes: ["USER"],
    userAuthenticationMethods: ["LOGIN_SESSION"]
  });
  return {
    profile: { ...entry.profile, revision: entry.profile.revision + 1, actions },
    contentDigest: `sha256:${"c".repeat(64)}`
  };
}

function fieldValue(
  action: AuthorizationProfileAction | undefined,
  field: DeclarationField,
  omitted: string
): string {
  if (!action) return omitted;
  if (field === "resourceShapes") return action.resourceShapes.map(authorizationResourceShapeKind).join(" · ") || omitted;
  if (field === "conditions") return action.conditions?.map((condition) => `${condition.key} / ${condition.source} / ${condition.valueType}`).join(" · ") || omitted;
  if (field === "subjectTypes") return action.subjectTypes?.join(" · ") || omitted;
  if (field === "userAuthenticationMethods") return action.userAuthenticationMethods?.join(" · ") || omitted;
  if (field === "instanceListBatch") return action.instanceListBatch === undefined ? omitted : String(action.instanceListBatch);
  return String(action[field] ?? omitted);
}

function ProfileChangeImpactReview({ current, candidate }: {
  current: AuthorizationProfileEntry;
  candidate: AuthorizationProfileEntry;
}) {
  const t = useTranslations("AuthorizationProfilePublishingPreview.validation.changeImpact");
  const catalog = useTranslations("AuthorizationProfileCatalog");
  const comparison = useMemo(() => compareAuthorizationProfileEntries(current, candidate), [candidate, current]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  if (comparison.status === "unavailable") return <section aria-labelledby="authorization-profile-change-impact-title" className={styles.changeReview}>
    <div className={styles.changeReviewHeading}><div><h4 id="authorization-profile-change-impact-title">{t("title")}</h4><p>{t("hint")}</p></div><Badge status="warning">{t("unavailable")}</Badge></div>
    <Alert status="warning">{t(`reasons.${comparison.reason}`)}</Alert>
  </section>;
  const pages = Math.max(1, Math.ceil(comparison.changes.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visible = comparison.changes.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  return <section aria-labelledby="authorization-profile-change-impact-title" className={styles.changeReview}>
    <div className={styles.changeReviewHeading}>
      <div><h4 id="authorization-profile-change-impact-title">{t("title")}</h4><p>{t("hint")}</p></div>
      <Badge status="warning">{t("synthetic")}</Badge>
    </div>
    <Alert status="info">{t("boundary")}</Alert>
    <dl className={styles.changeReferences}>
      <div><dt>{t("current")}</dt><dd><code>{current.profile.product}@{current.profile.revision}</code><small><code>{current.contentDigest}</code></small></dd></div>
      <div><dt>{t("candidate")}</dt><dd><code>{candidate.profile.product}@{candidate.profile.revision}</code><small><code>{candidate.contentDigest}</code></small></dd></div>
    </dl>
    <div className={styles.changeSummary} aria-label={t("summaryLabel")}>
      <Badge status="warning">{t("summary.added", { count: comparison.added })}</Badge>
      <Badge status="info">{t("summary.removed", { count: comparison.removed })}</Badge>
      <Badge status="neutral">{t("summary.changed", { count: comparison.changed })}</Badge>
    </div>
    {comparison.changes.length ? <>
      <Table aria-label={t("table")} mobileLayout="stack" className={styles.changeTable}>
        <thead><tr><th scope="col">{t("columns.action")}</th><th scope="col">{t("columns.review")}</th><th scope="col">{t("columns.fields")}</th></tr></thead>
        <tbody>{visible.map((change) => <tr key={change.id}>
          <td data-label={t("columns.action")}><Badge status={change.kind === "removed" ? "info" : "warning"}>{t(`kinds.${change.kind}`)}</Badge><code>{change.action}</code></td>
          <td data-label={t("columns.review")}><strong>{t(`reviews.${change.kind}`)}</strong><small>{t("reviewBoundary")}</small></td>
          <td data-label={t("columns.fields")}><ul className={styles.changeDetails}>{change.fields.map((field) => <li key={field}>
            <strong>{t(`fields.${field}`)}</strong>
            <code>{field === "callingService" ? change.beforeCallingService : fieldValue(change.before, field, t("omitted"))}</code>
            <span aria-hidden="true">→</span>
            <code>{field === "callingService" ? change.afterCallingService : fieldValue(change.after, field, t("omitted"))}</code>
          </li>)}</ul></td>
        </tr>)}</tbody>
      </Table>
      <Table.Footer note={t("footer")}><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: catalog("page", { page: currentPage, pages }), pageSize: catalog("pageSize"), previous: catalog("previous"), next: catalog("next") }} /></Table.Footer>
    </> : <div className={styles.noChanges}><strong>{t("noChanges")}</strong><p>{t("noChangesHint")}</p></div>}
  </section>;
}

function ServiceTemplateCompatibilityReview({ entry }: { entry: AuthorizationProfileEntry }) {
  const t = useTranslations("AuthorizationProfilePublishingPreview.validation.templateReview");
  const template = previewManagedServiceRoleTemplate;
  const review = reviewServiceTemplateProfile(template, entry);
  const checkHint = (check: ServiceTemplateProfileCheck) => check.action
    ? t(`checks.${check.id}.hint`, { action: check.action, resource: check.resourceKind ?? "—" })
    : t(`checks.${check.id}.hint`, {
      template: check.id === "product" ? template.spec.product : template.spec.servicePurpose,
      profile: check.id === "product" ? entry.profile.product : entry.profile.callingService
    });
  return <section aria-labelledby="authorization-profile-template-review-title" className={styles.templateReview}>
    <div className={styles.templateReviewHeading}>
      <div><h4 id="authorization-profile-template-review-title">{t("title")}</h4><p>{t("hint")}</p></div>
      <Badge status={review.compatible ? "success" : "warning"}>{t(review.compatible ? "compatible" : "mismatch")}</Badge>
    </div>
    <Alert status="info">{t("boundary")}</Alert>
    <dl className={styles.templateReferences}>
      <div><dt>{t("profileReference")}</dt><dd><code>{entry.profile.product}@{entry.profile.revision}</code><small><code>{entry.contentDigest}</code></small></dd></div>
      <div><dt>{t("templateReference")}</dt><dd><code>{template.id}@v{template.version}</code><small><code>{template.contentDigest}</code></small></dd></div>
      <div><dt>{t("permissionCeiling")}</dt><dd><code>{template.spec.policyVersion.policyId}</code><small><code>{template.spec.policyVersion.versionId}</code></small></dd></div>
    </dl>
    <ul className={styles.templateChecks}>{review.checks.map((check, index) => <li key={`${check.id}:${check.action ?? index}`}>
      <span aria-hidden="true">{index + 1}</span>
      <div><strong>{t(`checks.${check.id}.title`)}</strong><p>{checkHint(check)}</p></div>
      <Badge status={check.passed ? "success" : "warning"}>{t(check.passed ? "matched" : "notMatched")}</Badge>
    </li>)}</ul>
    <p className={styles.templateCeilingHint}>{t("ceilingBoundary")}</p>
  </section>;
}

export function AuthorizationProfilePublishingPreview({ entry, candidate: suppliedCandidate, onClose }: {
  entry: AuthorizationProfileEntry;
  candidate?: AuthorizationProfileEntry;
  onClose(): void;
}) {
  const t = useTranslations("AuthorizationProfilePublishingPreview");
  const catalog = useTranslations("AuthorizationProfileCatalog");
  const [stage, setStage] = useState(0);
  const [validationSection, setValidationSection] = useState<ValidationSection>("checks");
  const [actionPage, setActionPage] = useState(1);
  const [actionPageSize, setActionPageSize] = useState(10);
  const heading = useRef<HTMLHeadingElement>(null);
  const stageHeading = useRef<HTMLHeadingElement>(null);
  const previousStage = useRef(stage);
  const steps = useMemo(() => stageIds.map((id) => ({ id, label: t(`steps.${id}`) })), [t]);
  useLayoutEffect(() => {
    const target = previousStage.current === stage ? heading.current : stageHeading.current;
    previousStage.current = stage;
    target?.focus({ preventScroll: true });
    target?.scrollIntoView?.({ block: "start", inline: "nearest" });
  }, [stage]);

  const profile = entry.profile;
  const candidate = useMemo(() => suppliedCandidate ?? syntheticCandidate(entry), [entry, suppliedCandidate]);
  const scopes = [...new Set(profile.actions.map((action) => action.scope))];
  const resources = [...new Set(profile.actions.map((action) => action.resourceKind))];
  const conditions = [...new Set(profile.actions.flatMap((action) => action.conditions?.map((condition) => condition.key) ?? []))];
  const conditionFacts = [...new Map(profile.actions.flatMap((action) => action.conditions ?? []).map((condition) => [`${condition.key}:${condition.source}:${condition.valueType}`, condition])).values()];
  const actionPages = Math.max(1, Math.ceil(profile.actions.length / actionPageSize));
  const currentActionPage = Math.min(actionPage, actionPages);
  const reviewActions = profile.actions.slice((currentActionPage - 1) * actionPageSize, currentActionPage * actionPageSize);

  return <section aria-labelledby="authorization-profile-publishing-title" className={styles.root}>
    <div className={styles.heading}>
      <Button variant="ghost" size="small" onClick={onClose}><ArrowLeft aria-hidden="true" />{t("back")}</Button>
      <div className={styles.headingCopy}>
        <h2 id="authorization-profile-publishing-title" ref={heading} tabIndex={-1}>{t("title", { product: profile.product })}</h2>
        <p>{t("subtitle")}</p>
      </div>
      <div className={styles.badges}><Badge status="warning">MOCK</Badge><Badge>{t("internal")}</Badge></div>
    </div>

    <Alert status="warning">{t("boundary")}</Alert>
    <div className={styles.steps}><Steps label={t("progress")} items={steps} current={stage} onChange={setStage} /></div>

    {stage === 0 ? <Card className={styles.stageCard}>
      <Card.Header className={styles.stageHeader}><span className={styles.stageIcon}><FileCode2 aria-hidden="true" /></span><div><span>{t("stageLabel", { current: 1, total: 3 })}</span><h3 ref={stageHeading} tabIndex={-1}>{t("declaration.title")}</h3></div></Card.Header>
      <Card.Body className={styles.stageBody}>
        <p className={styles.lead}>{t("declaration.lead")}</p>
        <dl className={styles.facts}>
          <div><dt>{t("fields.product")}</dt><dd><code>{profile.product}</code></dd></div>
          <div><dt>{t("fields.callingService")}</dt><dd><code>{profile.callingService}</code></dd></div>
          <div><dt>{t("fields.revision")}</dt><dd>{profile.revision}</dd></div>
          <div><dt>{t("fields.actions")}</dt><dd>{profile.actions.length}</dd></div>
          <div><dt>{t("fields.scopes")}</dt><dd>{scopes.join(" · ")}</dd></div>
          <div><dt>{t("fields.resources")}</dt><dd>{resources.join(" · ") || "—"}</dd></div>
          <div className={styles.fullFact}><dt>{t("fields.digest")}</dt><dd><code>{entry.contentDigest}</code></dd></div>
        </dl>
        <div className={styles.responsibility}><strong>{t("declaration.owner")}</strong><p>{t("declaration.ownerHint")}</p></div>
      </Card.Body>
    </Card> : null}

    {stage === 1 ? <Card className={styles.stageCard}>
      <Card.Header className={styles.stageHeader}><span className={styles.stageIcon}><ShieldCheck aria-hidden="true" /></span><div><span>{t("stageLabel", { current: 2, total: 3 })}</span><h3 ref={stageHeading} tabIndex={-1}>{t("validation.title")}</h3></div></Card.Header>
      <Card.Body className={styles.stageBody}>
        <p className={styles.lead}>{t("validation.lead")}</p>
        <div className={styles.snapshot}>
          <div><span>{t("validation.snapshot.actions")}</span><strong>{profile.actions.length}</strong></div>
          <div><span>{t("validation.snapshot.resources")}</span><strong>{resources.length}</strong></div>
          <div><span>{t("validation.snapshot.conditions")}</span><strong>{conditions.length}</strong></div>
        </div>
        <Tabs.Root value={validationSection} onValueChange={(value) => setValidationSection(value as ValidationSection)}>
          <Tabs.List aria-label={t("validation.sections.label")}>
            {validationSectionIds.map((section) => <Tabs.Trigger key={section} value={section}>{t(`validation.sections.${section}`)}</Tabs.Trigger>)}
          </Tabs.List>
          <Tabs.Content className={styles.validationPanel} value="checks">
            {validationSection === "checks" ? <>
              <ul className={styles.reviewList}>
                {(["namespace", "resources", "subjects", "conditions", "enforcement"] as const).map((item, index) => <li key={item}><span aria-hidden="true">{index + 1}</span><div><strong>{t(`validation.items.${item}.title`)}</strong><p>{t(`validation.items.${item}.hint`)}</p></div><Badge status="neutral">{t("validation.pending")}</Badge></li>)}
              </ul>
              <section className={styles.diagnostics} aria-labelledby="authorization-profile-diagnostics-title">
                <div className={styles.diagnosticsHeading}><h4 id="authorization-profile-diagnostics-title">{t("validation.diagnostics.title")}</h4><p>{t("validation.diagnostics.hint")}</p></div>
                <dl className={styles.diagnosticGrid}>
                  <div><dt>{t("validation.diagnostics.profileReference")}</dt><dd><code>{profile.product}@{profile.revision}</code><small><code>{entry.contentDigest}</code></small></dd></div>
                  <div><dt>{t("validation.diagnostics.conditionSources")}</dt><dd>{conditionFacts.length ? conditionFacts.map((condition) => <span key={`${condition.key}:${condition.source}:${condition.valueType}`}><code>{condition.key}</code><small>{catalog(`conditionSources.${condition.source}`)} · {catalog(`conditionValueTypes.${condition.valueType}`)}</small></span>) : t("validation.diagnostics.noConditionSources")}</dd></div>
                  <div><dt>{t("validation.diagnostics.pepOwner")}</dt><dd><code>{profile.callingService}</code><small>{t("validation.diagnostics.pepOwnerHint")}</small></dd></div>
                  <div><dt>{t("validation.diagnostics.runtimeEvidence")}</dt><dd><Badge status="warning">{t("validation.diagnostics.notVerified")}</Badge><small>{t("validation.diagnostics.runtimeEvidenceHint")}</small></dd></div>
                </dl>
              </section>
              {profile.product === previewManagedServiceRoleTemplate.spec.product ? <ServiceTemplateCompatibilityReview entry={entry} /> : null}
            </> : null}
          </Tabs.Content>
          <Tabs.Content className={styles.validationPanel} value="changes">
            {validationSection === "changes" ? <ProfileChangeImpactReview current={entry} candidate={candidate} /> : null}
          </Tabs.Content>
          <Tabs.Content className={styles.validationPanel} value="actions">
            {validationSection === "actions" ? <section aria-label={t("validation.reviewActionsTitle")} className={styles.reviewActions}>
              <div><h4>{t("validation.reviewActionsTitle")}</h4><p>{t("validation.reviewActionsHint")}</p></div>
              <AuthorizationActionTable actions={reviewActions} label={t("validation.reviewActionsTitle")} />
              <Table.Footer note={catalog("completeActions", { count: profile.actions.length })}><TablePagination page={currentActionPage} pages={actionPages} pageSize={actionPageSize} onPageChange={setActionPage} onPageSizeChange={(size) => { setActionPageSize(size); setActionPage(1); }} labels={{ summary: catalog("page", { page: currentActionPage, pages: actionPages }), pageSize: catalog("pageSize"), previous: catalog("previous"), next: catalog("next") }} /></Table.Footer>
            </section> : null}
          </Tabs.Content>
        </Tabs.Root>
        <Alert status="info">{t("validation.notProof")}</Alert>
      </Card.Body>
    </Card> : null}

    {stage === 2 ? <Card className={styles.stageCard}>
      <Card.Header className={styles.stageHeader}><span className={styles.stageIcon}><LockKeyhole aria-hidden="true" /></span><div><span>{t("stageLabel", { current: 3, total: 3 })}</span><h3 ref={stageHeading} tabIndex={-1}>{t("release.title")}</h3></div></Card.Header>
      <Card.Body className={styles.stageBody}>
        <p className={styles.lead}>{t("release.lead")}</p>
        <div className={styles.releaseReference}>
          <div><span>{t("fields.product")}</span><strong><code>{profile.product}</code></strong></div>
          <div><span>{t("fields.revision")}</span><strong>{profile.revision}</strong></div>
          <div><span>{t("fields.digest")}</span><strong><code>{entry.contentDigest}</code></strong></div>
        </div>
        <ul className={styles.boundaries}>
          <li>{t("release.boundaries.noGrant")}</li>
          <li>{t("release.boundaries.immutable")}</li>
          <li>{t("release.boundaries.noExpansion")}</li>
          <li>{t("release.boundaries.serviceConsent")}</li>
        </ul>
        <section className={styles.releaseGates} aria-labelledby="authorization-profile-release-gates-title">
          <div className={styles.releaseGatesHeading}>
            <h4 id="authorization-profile-release-gates-title">{t("release.gates.title")}</h4>
            <p>{t("release.gates.hint")}</p>
          </div>
          <dl className={styles.releaseGateGrid}>
            {(["declaration", "contract", "runtime", "registry"] as const).map((gate) => <div key={gate}>
              <dt>{t(`release.gates.items.${gate}.title`)}</dt>
              <dd><Badge status={gate === "declaration" ? "info" : gate === "registry" ? "neutral" : "warning"}>{t(`release.gates.items.${gate}.state`)}</Badge><small>{t(`release.gates.items.${gate}.hint`)}</small></dd>
            </div>)}
          </dl>
        </section>
        <Alert status="warning">{t("release.unavailable")}</Alert>
      </Card.Body>
    </Card> : null}

    <div className={styles.actions}>
      {stage > 0 ? <Button variant="secondary" onClick={() => setStage((current) => current - 1)}>{t("previous")}</Button> : <span />}
      <div>
        {stage < stageIds.length - 1 ? <Button onClick={() => setStage((current) => current + 1)}>{t("next")}</Button> : <>
          <Button disabled title={t("release.unavailable")}>{t("release.publishDisabled")}</Button>
          <Button variant="secondary" onClick={onClose}>{t("finish")}</Button>
        </>}
      </div>
    </div>
  </section>;
}
