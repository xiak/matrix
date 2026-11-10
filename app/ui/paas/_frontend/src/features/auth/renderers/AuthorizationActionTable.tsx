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
  return <dl className={styles.details}>
    <div>
      <dt>{t("resourceTarget")}</dt>
      <dd>
        <ul className={styles.items}>{action.resourceShapes.map((shape) =>
          <li key={authorizationResourceShapeKind(shape)}>{t(`shapes.${authorizationResourceShapeKind(shape)}`)}</li>
        )}</ul>
        {action.instanceListBatch && <small>{t("instanceListBatch")}</small>}
        {action.resultResourceKind && <small>{t("resultResource", { resource: action.resultResourceKind })}</small>}
      </dd>
    </div>
    <div>
      <dt>{t("subjectCredential")}</dt>
      <dd>
        <div>{subjects.map((subject) => t(`subjects.${subject}`)).join(" · ")}</div>
        {action.subjectTypes === undefined && <small>{t("legacySubjects")}</small>}
        <dl className={styles.credentials}>
          <dt>{t("userCredentials")}</dt>
          <dd>{subjects.includes("USER") ? credentials.map((method) => t(`credentials.${method}`)).join(" · ") : t("notApplicable")}</dd>
        </dl>
        {subjects.includes("USER") && action.userAuthenticationMethods === undefined && <small>{t("legacyCredentials")}</small>}
      </dd>
    </div>
    <div>
      <dt>{t("conditions")}</dt>
      <dd>{action.conditions?.length ? <ul className={styles.items}>{action.conditions.map((condition) =>
        <li key={condition.key}>
          <code>{condition.key}</code>
          <small>{t(`conditionSources.${condition.source}`)} · {t(`conditionValueTypes.${condition.valueType}`)}</small>
        </li>
      )}</ul> : t("none")}</dd>
    </div>
  </dl>;
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
