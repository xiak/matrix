"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TableSkeleton } from "@ui/xiak";
import type { ServiceRoleTemplateClient, ServiceRoleTemplateLoad } from "../application/AccountAccessProvider";
import type { ServiceRoleTemplate } from "../domain/accounts";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type State = { status: "loading" } | ServiceRoleTemplateLoad;

function durationLabel(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${seconds / 60} min`;
}

function TemplateDetail({ template, onBack }: { template: ServiceRoleTemplate; onBack(): void }) {
  const t = useTranslations("ServiceRoleTemplateDirectory");
  return <WorkspaceDetail title={`${t("detailTitle")} · ${template.id}`} onBack={onBack}>
    <div className={styles.sectionHeading}>
      <Badge status={template.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${template.status}`)}</Badge>
      <Badge>{t(`purposes.${template.spec.servicePurpose}`)}</Badge>
    </div>
    <Alert>{t("activeIsNotConsent")}</Alert>
    <dl className={styles.facts}>
      <div><dt>{t("fields.templateId")}</dt><dd><code>{template.id}</code></dd></div>
      <div><dt>{t("fields.templateVersion")}</dt><dd>v{template.version}</dd></div>
      <div><dt>{t("fields.product")}</dt><dd><code>{template.spec.product}</code></dd></div>
      <div><dt>{t("fields.servicePurpose")}</dt><dd>{t(`purposes.${template.spec.servicePurpose}`)} <small><code>{template.spec.servicePurpose}</code></small></dd></div>
      <div><dt>{t("fields.maxSession")}</dt><dd>{durationLabel(template.spec.maxSessionDurationSeconds)}</dd></div>
      <div><dt>{t("fields.workloadKinds")}</dt><dd><div className={styles.roleTags}>{template.spec.workloadResourceKinds.map((kind) => <Badge key={kind}>{kind}</Badge>)}</div></dd></div>
    </dl>
    <section className={styles.stack} aria-labelledby="service-role-policy-version">
      <div>
        <h3 className={styles.detailTitle} id="service-role-policy-version">{t("policySnapshotTitle")}</h3>
        <p className={styles.note}>{t("policySnapshotHint")}</p>
      </div>
      <dl className={styles.facts}>
        <div><dt>{t("fields.policyId")}</dt><dd><code>{template.spec.policyVersion.policyId}</code></dd></div>
        <div><dt>{t("fields.policyVersionId")}</dt><dd><code>{template.spec.policyVersion.versionId}</code></dd></div>
        <div><dt>{t("fields.policyDigest")}</dt><dd><code>{template.spec.policyVersion.contentDigest}</code></dd></div>
        <div><dt>{t("fields.templateDigest")}</dt><dd><code>{template.contentDigest}</code></dd></div>
      </dl>
    </section>
    <Alert status="warning">{t("noAccountObservation")}</Alert>
  </WorkspaceDetail>;
}

export function AccountServiceRoleTemplates({ client, onBack }: { client: ServiceRoleTemplateClient; onBack(): void }) {
  const t = useTranslations("ServiceRoleTemplateDirectory");
  const [state, setState] = useState<State>({ status: "loading" });
  const [selected, setSelected] = useState<ServiceRoleTemplate | null>(null);
  const request = useRef(0);

  const retry = useCallback(() => {
    const revision = ++request.current;
    setState({ status: "loading" });
    client.load().then((result) => {
      if (request.current === revision) setState(result);
    });
  }, [client]);

  useEffect(() => {
    const revision = ++request.current;
    client.load().then((result) => {
      if (request.current === revision) setState(result);
    });
    return () => { request.current += 1; };
  }, [client]);

  if (selected) return <TemplateDetail template={selected} onBack={() => setSelected(null)} />;

  return <Card aria-description={t("directoryHint")}>
    <ContentPage.Heading title={t("title")} scrollKey="service-role-template-directory" back={{ label: t("backToRoles"), onClick: onBack }} focus />
    <div className={styles.policyDirectoryIntro}>
      <p>{t("directoryHint")}</p>
      <p>{t("boundary")}</p>
    </div>
    {state.status === "loading" ? <TableSkeleton label={t("loading")} rows={4} /> : null}
    {state.status !== "loading" && state.status !== "ready" ? <EmptyState
      title={t(`errors.${state.status}.title`)}
      description={t(`errors.${state.status}.description`)}
      action={state.status === "expired" ? undefined : <Button variant="secondary" onClick={retry}>{t("retry")}</Button>}
    /> : null}
    {state.status === "ready" ? <>
      {state.directory.items.length ? <Table aria-label={t("tableLabel")} mobileLayout="stack">
        <thead><tr><th scope="col">{t("fields.template")}</th><th scope="col">{t("fields.product")}</th><th scope="col">{t("fields.workloadKinds")}</th><th scope="col">{t("fields.policySnapshot")}</th><th scope="col">{t("fields.templateState")}</th></tr></thead>
        <tbody>{state.directory.items.map((template) => <tr key={template.id}>
          <td data-label={t("fields.template")}><button className={styles.userLink} onClick={() => setSelected(template)}>{template.id}</button><small>v{template.version} · {durationLabel(template.spec.maxSessionDurationSeconds)}</small></td>
          <td data-label={t("fields.product")}><code>{template.spec.product}</code><small>{t(`purposes.${template.spec.servicePurpose}`)}</small></td>
          <td data-label={t("fields.workloadKinds")}><div className={styles.roleTags}>{template.spec.workloadResourceKinds.map((kind) => <Badge key={kind}>{kind}</Badge>)}</div></td>
          <td data-label={t("fields.policySnapshot")}><code>{template.spec.policyVersion.policyId}</code><small>{template.spec.policyVersion.versionId}</small></td>
          <td data-label={t("fields.templateState")}><Badge status={template.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${template.status}`)}</Badge><small>{t("notAccountState")}</small></td>
        </tr>)}</tbody>
      </Table> : <EmptyState title={t("emptyTitle")} description={t("emptyDescription")} />}
      <Table.Footer note={t("footerNote")} />
    </> : null}
  </Card>;
}
