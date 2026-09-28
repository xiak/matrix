"use client";

import { useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";
import { ArrowLeft, Boxes, KeyRound, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Steps, Table } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountPolicyDocument } from "../domain/accounts";
import styles from "./ServiceAuthorizationPreview.module.css";

type PreviewView = "directory" | "detail" | "review";

// UX-only projection of the FEAT-IAM-008 service-delegation boundary. The
// sample permission content is separate from tenant-editable MOCK policies.
// Neither these identities nor the snapshot revision are a published contract.
const previewTemplate = {
  id: "preview.service-role-template.application-operations-read.v1",
  product: "Application operations review",
  servicePrincipal: "preview.paas.service",
  roleName: "PreviewServiceRoleForApplicationOperationsRead",
  purpose: "application-operations-read",
  revision: 1,
  snapshotName: "PreviewPaaSOperationsRead",
} as const;

const stageIds = ["identity", "permissions", "consent"] as const;

// Only already-declared PaaS read Actions are used here. Exact sample IDs
// illustrate the resource boundary; they do not grant access to those IDs.
const previewSnapshot: AccountPolicyDocument = {
  languageVersion: "1", scope: "TENANT", statements: [
    { sid: "read-application", effect: "ALLOW", actions: ["paas.application.read"],
      resources: [{ kind: "APPLICATION", match: "EXACT", id: "application-example" }] },
    { sid: "read-deployment", effect: "ALLOW", actions: ["paas.deployment.read"],
      resources: [{ kind: "DEPLOYMENT", match: "EXACT", id: "deployment-example" }] },
    { sid: "read-operation", effect: "ALLOW", actions: ["paas.operation.read"],
      resources: [{ kind: "OPERATION", match: "EXACT", id: "operation-example" }] }
  ]
};

function TemplateDirectory({ triggerRef, onOpen }: {
  triggerRef: RefObject<HTMLButtonElement | null>;
  onOpen(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><h3>{t("directory.title")}</h3><p>{t("directory.hint")}</p></div><Badge status="warning">{t("states.notAuthorized")}</Badge></div>
    <Table aria-label={t("directory.tableLabel")} mobileLayout="stack">
      <thead><tr><th scope="col">{t("fields.product")}</th><th scope="col">{t("fields.purpose")}</th><th scope="col">{t("fields.policySnapshot")}</th><th scope="col">{t("fields.state")}</th></tr></thead>
      <tbody><tr>
        <td data-label={t("fields.product")}><button className={styles.link} ref={triggerRef} onClick={onOpen}>{previewTemplate.product}</button><small><code>{previewTemplate.id}</code></small></td>
        <td data-label={t("fields.purpose")}>{t("template.purpose")}<small><code>{previewTemplate.servicePrincipal}</code></small></td>
        <td data-label={t("fields.policySnapshot")}>{previewTemplate.snapshotName}<small>v{previewTemplate.revision} · {t("previewOnly")}</small></td>
        <td data-label={t("fields.state")}><Badge status="warning">{t("states.notAuthorized")}</Badge></td>
      </tr></tbody>
    </Table>
    <p className={styles.note}>{t("directory.separation")}</p>
  </div>;
}

function TemplateDetail({ accountId, reviewRef, onReview }: {
  accountId: string;
  reviewRef: RefObject<HTMLButtonElement | null>;
  onReview(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><span>{t("detail.eyebrow")}</span><h3>{previewTemplate.product}</h3><p>{t("detail.hint")}</p></div><Badge status="warning">{t("states.notAuthorized")}</Badge></div>
    <dl className={styles.facts}>
      <div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div>
      <div><dt>{t("fields.templateRevision")}</dt><dd>v{previewTemplate.revision}</dd></div>
      <div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div>
      <div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div>
      <div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div>
    </dl>
    <div className={styles.detailGrid}>
      <Card><Card.Header className={styles.cardHeading}><KeyRound aria-hidden="true" /><div><span>{t("detail.trustLabel")}</span><h4>{t("detail.trustTitle")}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.trustHint")}</p><code>{previewTemplate.servicePrincipal}</code></Card.Body></Card>
      <Card><Card.Header className={styles.cardHeading}><ShieldCheck aria-hidden="true" /><div><span>{t("detail.permissionLabel")}</span><h4>{previewTemplate.snapshotName} · v{previewTemplate.revision}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.permissionHint")}</p><Alert status="info">{t("detail.snapshotBoundary")}</Alert></Card.Body></Card>
    </div>
    <div className={styles.snapshot}><div><strong>{t("detail.snapshotTitle")}</strong><span>{t("detail.snapshotCount", { count: previewSnapshot.statements.length })}</span></div><ul>{previewSnapshot.statements.flatMap((statement) => statement.actions).map((action) => <li key={action}><code>{action}</code></li>)}</ul></div>
    <Alert status="info">{t("detail.ordinaryRole")}</Alert>
    <div className={styles.actions}><Button ref={reviewRef} onClick={onReview}>{t("detail.review")}</Button></div>
  </div>;
}

function ConsentReview({ accountId, stage, onStageChange, onClose }: {
  accountId: string;
  stage: number;
  onStageChange(stage: number): void;
  onClose(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const steps = useMemo(() => stageIds.map((id) => ({ id, label: t(`steps.${id}`) })), [t]);
  const currentStage = stageIds[stage] ?? "identity";
  const statements = previewSnapshot.statements;
  return <div className={styles.stack}>
    <div className={styles.steps}><Steps label={t("progress")} items={steps} current={stage} onChange={onStageChange} /></div>
    <Card className={styles.reviewCard}>
      <Card.Header className={styles.cardHeading}>{stage === 0 ? <KeyRound aria-hidden="true" /> : stage === 1 ? <ShieldCheck aria-hidden="true" /> : <Boxes aria-hidden="true" />}<div><span>{t("stageLabel", { current: stage + 1, total: stageIds.length })}</span><h3>{t(`review.${currentStage}.title`)}</h3></div></Card.Header>
      <Card.Body className={styles.cardBody}>
        <p className={styles.lead}>{t(`review.${currentStage}.lead`)}</p>
        {stage === 0 ? <><dl className={styles.facts}><div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div><div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div><div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div><div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div></dl><Alert status="info">{t("review.identity.passRoleBoundary")}</Alert></> : null}
        {stage === 1 ? <><div className={styles.permissionReference}><div><span>{t("fields.policySnapshot")}</span><strong>{previewTemplate.snapshotName} · v{previewTemplate.revision}</strong></div><Badge>{t("review.permissions.illustrative")}</Badge></div>
          <div className={styles.permissionStatements}>{statements.map((statement, index) => <section aria-label={t("review.permissions.statement", { number: index + 1 })} className={styles.permissionStatement} key={index}>
            <div className={styles.permissionStatementHeading}><strong>{t("review.permissions.statement", { number: index + 1 })}</strong><Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(`review.permissions.${statement.effect === "DENY" ? "deny" : "allow"}`)}</Badge></div>
            <dl><div><dt>{t("review.permissions.actionPatterns")}</dt><dd><ul className={styles.permissionList}>{statement.actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.resources")}</dt><dd><ul className={styles.resourceList}>{statement.resources.map((resource) => <li key={`${resource.kind}:${resource.id ?? ""}`}><code>{resource.kind}</code> · {t(`review.permissions.match.${resource.match}`)}{resource.id ? <> · <code>{resource.id}</code></> : null}</li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.conditions")}</dt><dd>{statement.conditions?.length ? statement.conditions.map((condition) => <code key={condition.key}>{condition.key} · {condition.operator} · {condition.values.join(", ")}</code>) : t("review.permissions.noConditions")}</dd></div></dl>
          </section>)}</div>
          <Alert status="info">{t("review.permissions.snapshotBoundary")}</Alert></> : null}
        {stage === 2 ? <><ul className={styles.boundaries}>{(["explicit", "shortTerm", "noExpansion", "cleanup"] as const).map((item) => <li key={item}><strong>{t(`review.consent.items.${item}.title`)}</strong><p>{t(`review.consent.items.${item}.hint`)}</p></li>)}</ul><Alert status="warning">{t("review.consent.unavailable")}</Alert></> : null}
      </Card.Body>
    </Card>
    <div className={styles.reviewActions}>
      {stage > 0 ? <Button variant="secondary" onClick={() => onStageChange(stage - 1)}>{t("previous")}</Button> : <span />}
      <div>{stage < stageIds.length - 1 ? <Button onClick={() => onStageChange(stage + 1)}>{t("next")}</Button> : <><Button disabled title={t("review.consent.unavailable")}>{t("authorizeDisabled")}</Button><Button variant="secondary" onClick={onClose}>{t("finish")}</Button></>}</div>
    </div>
  </div>;
}

export function ServiceAuthorizationPreview({ workspace, onClose }: {
  workspace: AccessWorkspace;
  onClose(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const [view, setView] = useState<PreviewView>("directory");
  const [stage, setStage] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const templateTrigger = useRef<HTMLButtonElement>(null);
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const previousView = useRef<PreviewView>(view);

  useLayoutEffect(() => {
    const previous = previousView.current;
    previousView.current = view;
    if (previous === "review" && view === "detail") reviewTrigger.current?.focus({ preventScroll: true });
    else if (previous === "detail" && view === "directory") templateTrigger.current?.focus({ preventScroll: true });
    else {
      heading.current?.scrollIntoView?.({ block: "start" });
      heading.current?.focus({ preventScroll: true });
    }
  }, [stage, view]);

  const back = () => {
    if (view === "directory") onClose();
    else if (view === "detail") setView("directory");
    else setView("detail");
  };
  const backLabel = view === "directory" ? t("backToRoles") : view === "detail" ? t("backToDirectory") : t("backToTemplate");
  const title = view === "directory" ? t("title") : view === "detail" ? t("detail.title") : t("review.title");

  return <section aria-labelledby="service-authorization-preview-title" className={styles.root}>
    <div className={styles.heading}>
      <Button variant="ghost" size="small" onClick={back}><ArrowLeft aria-hidden="true" />{backLabel}</Button>
      <div className={styles.headingCopy}><h2 id="service-authorization-preview-title" ref={heading} tabIndex={-1}>{title}</h2><p>{t("subtitle")}</p></div>
      <div className={styles.badges}><Badge status="warning">MOCK</Badge><Badge>{t("previewOnly")}</Badge></div>
    </div>
    <Alert status="warning">{t("boundary")}</Alert>
    {view === "directory" ? <TemplateDirectory triggerRef={templateTrigger} onOpen={() => setView("detail")} /> : null}
    {view === "detail" ? <TemplateDetail accountId={workspace.accountId} reviewRef={reviewTrigger} onReview={() => { setStage(0); setView("review"); }} /> : null}
    {view === "review" ? <ConsentReview accountId={workspace.accountId} stage={stage} onStageChange={setStage} onClose={() => setView("detail")} /> : null}
  </section>;
}
