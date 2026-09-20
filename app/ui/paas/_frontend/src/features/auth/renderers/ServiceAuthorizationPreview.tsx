"use client";

import { useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";
import { ArrowLeft, Boxes, KeyRound, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Steps, Table } from "@ui/xiak";
import type { AccessPolicy, AccessWorkspace } from "../domain/accessWorkspace";
import styles from "./ServiceAuthorizationPreview.module.css";

type PreviewView = "directory" | "detail" | "review";

// UX-only projection of the FEAT-IAM-008 service-delegation boundary. It is
// intentionally not an IAM domain model or a future wire contract.
const previewTemplate = {
  id: "service-role-template.application-delivery.v1",
  product: "Application delivery",
  servicePrincipal: "devops.matrix.internal",
  roleName: "MatrixServiceRoleForApplicationDelivery",
  purpose: "application-delivery",
  revision: 1,
  policyId: "policy-delivery",
  policyVersion: 1,
} as const;

const stageIds = ["identity", "permissions", "consent"] as const;

function referencedPolicy(workspace: AccessWorkspace): AccessPolicy | undefined {
  return workspace.policies.find((policy) => policy.id === previewTemplate.policyId);
}

function pinnedPolicyVersion(policy?: AccessPolicy) {
  return policy?.versions.find((entry) => entry.id === previewTemplate.policyVersion);
}

function TemplateDirectory({ policy, triggerRef, onOpen }: {
  policy?: AccessPolicy;
  triggerRef: RefObject<HTMLButtonElement | null>;
  onOpen(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const version = pinnedPolicyVersion(policy);
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><h3>{t("directory.title")}</h3><p>{t("directory.hint")}</p></div><Badge status="warning">{t("states.notAuthorized")}</Badge></div>
    <Table aria-label={t("directory.tableLabel")} mobileLayout="stack">
      <thead><tr><th scope="col">{t("fields.product")}</th><th scope="col">{t("fields.purpose")}</th><th scope="col">{t("fields.policySnapshot")}</th><th scope="col">{t("fields.state")}</th></tr></thead>
      <tbody><tr>
        <td data-label={t("fields.product")}><button className={styles.link} ref={triggerRef} onClick={onOpen}>{previewTemplate.product}</button><small><code>{previewTemplate.id}</code></small></td>
        <td data-label={t("fields.purpose")}>{t("template.purpose")}<small><code>{previewTemplate.servicePrincipal}</code></small></td>
        <td data-label={t("fields.policySnapshot")}>{policy?.name ?? previewTemplate.policyId}<small>{version ? `v${previewTemplate.policyVersion}` : t("states.unavailable")}</small></td>
        <td data-label={t("fields.state")}><Badge status="warning">{t("states.notAuthorized")}</Badge></td>
      </tr></tbody>
    </Table>
    <p className={styles.note}>{t("directory.separation")}</p>
  </div>;
}

function TemplateDetail({ policy, reviewRef, onReview, onOpenPolicy }: {
  policy?: AccessPolicy;
  reviewRef: RefObject<HTMLButtonElement | null>;
  onReview(): void;
  onOpenPolicy(id: string): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const version = pinnedPolicyVersion(policy);
  const currentDefaultMatches = policy?.defaultVersion === previewTemplate.policyVersion;
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><span>{t("detail.eyebrow")}</span><h3>{previewTemplate.product}</h3><p>{t("detail.hint")}</p></div><Badge status="warning">{t("states.notAuthorized")}</Badge></div>
    <dl className={styles.facts}>
      <div><dt>{t("fields.templateRevision")}</dt><dd>v{previewTemplate.revision}</dd></div>
      <div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div>
      <div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div>
      <div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div>
    </dl>
    <div className={styles.detailGrid}>
      <Card><Card.Header className={styles.cardHeading}><KeyRound aria-hidden="true" /><div><span>{t("detail.trustLabel")}</span><h4>{t("detail.trustTitle")}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.trustHint")}</p><code>{previewTemplate.servicePrincipal}</code></Card.Body></Card>
      <Card><Card.Header className={styles.cardHeading}><ShieldCheck aria-hidden="true" /><div><span>{t("detail.permissionLabel")}</span><h4>{policy?.name ?? previewTemplate.policyId} · v{previewTemplate.policyVersion}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.permissionHint")}</p>{version && policy ? <><Button variant="ghost" size="small" onClick={() => onOpenPolicy(policy.id)}>{currentDefaultMatches ? t("detail.openPolicy", { version: previewTemplate.policyVersion }) : t("detail.openPolicyCurrent", { version: policy.defaultVersion })}</Button>{!currentDefaultMatches ? <Alert status="info">{t("detail.policyNavigationHint", { current: policy.defaultVersion, version: previewTemplate.policyVersion })}</Alert> : null}</> : <Alert status="warning">{t("detail.policyUnavailable")}</Alert>}</Card.Body></Card>
    </div>
    {version ? <div className={styles.snapshot}><div><strong>{t("detail.snapshotTitle")}</strong><span>{t("detail.snapshotCount", { count: version.document.statement.length })}</span></div><ul>{version.document.statement.flatMap((statement) => statement.action).map((action) => <li key={action}><code>{action}</code></li>)}</ul></div> : null}
    <Alert status="info">{t("detail.ordinaryRole")}</Alert>
    <div className={styles.actions}><Button ref={reviewRef} disabled={!version} title={!version ? t("detail.policyUnavailable") : undefined} onClick={onReview}>{t("detail.review")}</Button></div>
  </div>;
}

function ConsentReview({ policy, stage, onStageChange, onClose }: {
  policy?: AccessPolicy;
  stage: number;
  onStageChange(stage: number): void;
  onClose(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const steps = useMemo(() => stageIds.map((id) => ({ id, label: t(`steps.${id}`) })), [t]);
  const currentStage = stageIds[stage] ?? "identity";
  const version = pinnedPolicyVersion(policy);
  const actions = version?.document.statement.flatMap((statement) => statement.action) ?? [];
  return <div className={styles.stack}>
    <div className={styles.steps}><Steps label={t("progress")} items={steps} current={stage} onChange={onStageChange} /></div>
    <Card className={styles.reviewCard}>
      <Card.Header className={styles.cardHeading}>{stage === 0 ? <KeyRound aria-hidden="true" /> : stage === 1 ? <ShieldCheck aria-hidden="true" /> : <Boxes aria-hidden="true" />}<div><span>{t("stageLabel", { current: stage + 1, total: stageIds.length })}</span><h3>{t(`review.${currentStage}.title`)}</h3></div></Card.Header>
      <Card.Body className={styles.cardBody}>
        <p className={styles.lead}>{t(`review.${currentStage}.lead`)}</p>
        {stage === 0 ? <dl className={styles.facts}><div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div><div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div><div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div></dl> : null}
        {stage === 1 ? <><div className={styles.permissionReference}><div><span>{t("fields.policySnapshot")}</span><strong>{policy && version ? `${policy.name} · v${previewTemplate.policyVersion}` : "—"}</strong></div><Badge>{t("review.permissions.immutable")}</Badge></div><ul className={styles.permissionList}>{actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul><Alert status="warning">{t("review.permissions.crossProduct")}</Alert></> : null}
        {stage === 2 ? <><ul className={styles.boundaries}>{(["explicit", "shortTerm", "noExpansion", "cleanup"] as const).map((item) => <li key={item}><strong>{t(`review.consent.items.${item}.title`)}</strong><p>{t(`review.consent.items.${item}.hint`)}</p></li>)}</ul><Alert status="warning">{t("review.consent.unavailable")}</Alert></> : null}
      </Card.Body>
    </Card>
    <div className={styles.reviewActions}>
      {stage > 0 ? <Button variant="secondary" onClick={() => onStageChange(stage - 1)}>{t("previous")}</Button> : <span />}
      <div>{stage < stageIds.length - 1 ? <Button onClick={() => onStageChange(stage + 1)}>{t("next")}</Button> : <><Button disabled title={t("review.consent.unavailable")}>{t("authorizeDisabled")}</Button><Button variant="secondary" onClick={onClose}>{t("finish")}</Button></>}</div>
    </div>
  </div>;
}

export function ServiceAuthorizationPreview({ workspace, onClose, onOpenPolicy }: {
  workspace: AccessWorkspace;
  onClose(): void;
  onOpenPolicy(id: string): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const [view, setView] = useState<PreviewView>("directory");
  const [stage, setStage] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const templateTrigger = useRef<HTMLButtonElement>(null);
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const previousView = useRef<PreviewView>(view);
  const policy = referencedPolicy(workspace);

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
    {view === "directory" ? <TemplateDirectory policy={policy} triggerRef={templateTrigger} onOpen={() => setView("detail")} /> : null}
    {view === "detail" ? <TemplateDetail policy={policy} reviewRef={reviewTrigger} onReview={() => { setStage(0); setView("review"); }} onOpenPolicy={onOpenPolicy} /> : null}
    {view === "review" ? <ConsentReview policy={policy} stage={stage} onStageChange={setStage} onClose={() => setView("detail")} /> : null}
  </section>;
}
