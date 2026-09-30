"use client";

import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, FileCode2, LockKeyhole, ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Steps, Table, TablePagination } from "@ui/xiak";
import type { AuthorizationProfileEntry } from "../domain/accounts";
import { AuthorizationActionTable } from "./AuthorizationActionTable";
import styles from "./AuthorizationProfilePublishingPreview.module.css";

const stageIds = ["declaration", "validation", "release"] as const;

export function AuthorizationProfilePublishingPreview({ entry, onClose }: {
  entry: AuthorizationProfileEntry;
  onClose(): void;
}) {
  const t = useTranslations("AuthorizationProfilePublishingPreview");
  const catalog = useTranslations("AuthorizationProfileCatalog");
  const [stage, setStage] = useState(0);
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
  }, [stage]);

  const profile = entry.profile;
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
        <ul className={styles.reviewList}>
          {(["namespace", "resources", "subjects", "conditions", "enforcement"] as const).map((item, index) => <li key={item}><span aria-hidden="true">{index + 1}</span><div><strong>{t(`validation.items.${item}.title`)}</strong><p>{t(`validation.items.${item}.hint`)}</p></div></li>)}
        </ul>
        <div className={styles.snapshot}>
          <div><span>{t("validation.snapshot.actions")}</span><strong>{profile.actions.length}</strong></div>
          <div><span>{t("validation.snapshot.resources")}</span><strong>{resources.length}</strong></div>
          <div><span>{t("validation.snapshot.conditions")}</span><strong>{conditions.length}</strong></div>
        </div>
        <section className={styles.diagnostics} aria-labelledby="authorization-profile-diagnostics-title">
          <div className={styles.diagnosticsHeading}><h4 id="authorization-profile-diagnostics-title">{t("validation.diagnostics.title")}</h4><p>{t("validation.diagnostics.hint")}</p></div>
          <dl className={styles.diagnosticGrid}>
            <div><dt>{t("validation.diagnostics.profileReference")}</dt><dd><code>{profile.product}@{profile.revision}</code><small><code>{entry.contentDigest}</code></small></dd></div>
            <div><dt>{t("validation.diagnostics.conditionSources")}</dt><dd>{conditionFacts.length ? conditionFacts.map((condition) => <span key={`${condition.key}:${condition.source}:${condition.valueType}`}><code>{condition.key}</code><small>{catalog(`conditionSources.${condition.source}`)} · {catalog(`conditionValueTypes.${condition.valueType}`)}</small></span>) : t("validation.diagnostics.noConditionSources")}</dd></div>
            <div><dt>{t("validation.diagnostics.pepOwner")}</dt><dd><code>{profile.callingService}</code><small>{t("validation.diagnostics.pepOwnerHint")}</small></dd></div>
            <div><dt>{t("validation.diagnostics.runtimeEvidence")}</dt><dd><Badge status="warning">{t("validation.diagnostics.notVerified")}</Badge><small>{t("validation.diagnostics.runtimeEvidenceHint")}</small></dd></div>
          </dl>
        </section>
        <section aria-label={t("validation.reviewActionsTitle")} className={styles.reviewActions}>
          <div><h4>{t("validation.reviewActionsTitle")}</h4><p>{t("validation.reviewActionsHint")}</p></div>
          <AuthorizationActionTable actions={reviewActions} label={t("validation.reviewActionsTitle")} />
          <Table.Footer note={catalog("completeActions", { count: profile.actions.length })}><TablePagination page={currentActionPage} pages={actionPages} pageSize={actionPageSize} onPageChange={setActionPage} onPageSizeChange={(size) => { setActionPageSize(size); setActionPage(1); }} labels={{ summary: catalog("page", { page: currentActionPage, pages: actionPages }), pageSize: catalog("pageSize"), previous: catalog("previous"), next: catalog("next") }} /></Table.Footer>
        </section>
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
