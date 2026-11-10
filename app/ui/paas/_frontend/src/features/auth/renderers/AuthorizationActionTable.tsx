"use client";

import { Fragment, useId, useState } from "react";
import { ChevronRight } from "lucide-react";
import { useTranslations } from "next-intl";
import { Table } from "@ui/xiak";
import {
  admittedAuthorizationSubjects,
  admittedAuthorizationUserAuthenticationMethods,
  authorizationResourceShapeKind,
  type AuthorizationProfileAction
} from "../domain/accounts";
import styles from "./AuthorizationActionTable.module.css";

function ActionDetails({ action }: { action: AuthorizationProfileAction }) {
  const t = useTranslations("AuthorizationProfileCatalog");
  const subjects = admittedAuthorizationSubjects(action);
  const credentials = admittedAuthorizationUserAuthenticationMethods(action);
  const conditions = action.conditions ?? [];
  return <div className={styles.details}>
    <div className={styles.accessRules}>
      <h3>{t("accessRules")}</h3>
      <dl className={styles.properties}>
        <div><dt>{t("targets")}</dt><dd>
          <ul className={styles.targets}>{action.resourceShapes.map((shape) => {
            const kind = authorizationResourceShapeKind(shape);
            return <li key={kind}>{t(`shapes.${kind}`)}</li>;
          })}</ul>
        </dd></div>
        <div><dt>{t("subjectFilter")}</dt><dd>
          {subjects.map((subject) => t(`subjects.${subject}`)).join(" · ")}
          {action.subjectTypes === undefined && <> <span className={styles.defaultOrigin}>{t("historicalDefault")}</span></>}
        </dd></div>
        <div><dt>{t("userCredentials")}</dt><dd>
          {subjects.includes("USER") ? credentials.map((method) => t(`credentials.${method}`)).join(" · ") : t("notApplicable")}
          {subjects.includes("USER") && action.userAuthenticationMethods === undefined && <> <span className={styles.defaultOrigin}>{t("historicalDefault")}</span></>}
        </dd></div>
        {action.resultResourceKind && <div><dt>{t("resultResource")}</dt><dd><code>{action.resultResourceKind}</code></dd></div>}
        {action.instanceListBatch && <div><dt>{t("listChecks")}</dt><dd>{t("instanceListBatch")}</dd></div>}
        {!conditions.length && <div><dt>{t("conditions")}</dt><dd>{t("none")}</dd></div>}
      </dl>
    </div>
    {conditions.length > 0 && <div className={styles.conditions}>
      <h3>{t("conditions")}</h3>
      <Table aria-label={t("conditions")} className={styles.conditionTable}>
        <thead><tr>
          <th scope="col">{t("conditionKey")}</th><th scope="col">{t("conditionSource")}</th><th scope="col">{t("conditionType")}</th>
        </tr></thead>
        <tbody>{conditions.map((condition) => <tr key={condition.key}>
          <th scope="row"><code>{condition.key}</code></th>
          <td>{t(`conditionSources.${condition.source}`)}</td>
          <td>{t(`conditionValueTypes.${condition.valueType}`)}</td>
        </tr>)}</tbody>
      </Table>
    </div>}
  </div>;
}

export function AuthorizationActionTable({ actions, label, initialAction }: {
  actions: AuthorizationProfileAction[];
  label: string;
  initialAction?: string;
}) {
  const t = useTranslations("AuthorizationProfileCatalog");
  const id = useId();
  const [expanded, setExpanded] = useState<string | null>(initialAction ?? null);
  if (expanded !== null && !actions.some((item) => item.action === expanded)) setExpanded(null);

  return <Table aria-label={label} mobileLayout="grid" className={styles.table}>
    <thead><tr>
      <th scope="col" className={styles.actionColumn}>{t("action")}</th>
      <th scope="col" className={styles.resourceColumn}>{t("resource")}</th>
      <th scope="col">{t("scope")}</th>
      <th scope="col">{t("subjectFilter")}</th>
      <th scope="col" className={styles.count}>{t("conditions")}</th>
    </tr></thead>
    <tbody>{actions.map((action) => {
      const open = expanded === action.action;
      const triggerId = `${id}-${action.action}`;
      const detailId = `${triggerId}-detail`;
      return <Fragment key={action.action}>
        <tr className={styles.summary} data-expanded={open || undefined}>
          <td><Table.PrimaryAction id={triggerId} className={styles.disclose}
            aria-expanded={open} aria-controls={open ? detailId : undefined}
            onClick={() => setExpanded(open ? null : action.action)}>
            <ChevronRight aria-hidden="true" /><code>{action.action}</code>
          </Table.PrimaryAction></td>
          <td className={styles.resource} data-label={t("resource")}><code>{action.resourceKind}</code></td>
          <td className={styles.scope} data-label={t("scope")}>{t(`scopes.${action.scope}`)}</td>
          <td className={styles.subject}>{admittedAuthorizationSubjects(action).map((subject) => t(`subjects.${subject}`)).join(" · ")}</td>
          <td className={styles.count}>{action.conditions?.length || t("none")}</td>
        </tr>
        {open && <tr className={styles.inspection}><td colSpan={5}>
          <section id={detailId} aria-labelledby={triggerId}><ActionDetails action={action} /></section>
        </td></tr>}
      </Fragment>;
    })}</tbody>
  </Table>;
}
