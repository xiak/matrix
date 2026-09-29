"use client";

import { useTranslations } from "next-intl";
import { Table } from "@ui/xiak";
import { admittedAuthorizationSubjects, authorizationResourceShapeKind, type AuthorizationProfileAction } from "../domain/accounts";
import styles from "./AuthorizationActionTable.module.css";

// The catalog and the product-onboarding review show the same declaration,
// never an evaluated grant. Search and paging remain owned by their screens.
export function AuthorizationActionTable({ actions, label }: { actions: AuthorizationProfileAction[]; label: string }) {
  const t = useTranslations("AuthorizationProfileCatalog");
  return <Table aria-label={label} mobileLayout="stack" className={styles.table}>
    <thead><tr><th scope="col">{t("action")}</th><th scope="col">{t("resourceTarget")}</th><th scope="col">{t("subjectCredential")}</th><th scope="col">{t("conditions")}</th></tr></thead>
    <tbody>{actions.map((action) => {
      const subjects = admittedAuthorizationSubjects(action);
      return <tr key={action.action}>
        <td data-label={t("action")}><code>{action.action}</code></td>
        <td data-label={t("resourceTarget")}><small>{t(`scopes.${action.scope}`)}</small><strong>{action.resourceKind}</strong>
          {action.resourceShapes.map((shape) => <small key={`${shape.mode}:${shape.collectionUsage ?? ""}`}>{t(`shapes.${authorizationResourceShapeKind(shape)}`)}</small>)}
          {action.resultResourceKind ? <small>{t("resultResource", { resource: action.resultResourceKind })}</small> : null}
        </td>
        <td data-label={t("subjectCredential")}>
          <strong>{subjects.map((subject) => t(`subjects.${subject}`)).join(" · ")}</strong>
          {action.subjectTypes === undefined ? <small>{t("legacySubjects")}</small> : null}
          <small>{t("userCredentials")}: {subjects.includes("USER")
            ? (action.userAuthenticationMethods ?? ["LOGIN_SESSION"]).map((method) => t(`credentials.${method}`)).join(" · ")
            : t("notApplicable")}</small>
          {subjects.includes("USER") && action.userAuthenticationMethods === undefined ? <small>{t("legacyCredentials")}</small> : null}
        </td>
        <td data-label={t("conditions")}>{action.conditions?.length ? <ul className={styles.conditionList}>{action.conditions.map((condition) => <li key={condition.key}>
          <code>{condition.key}</code>
          <small>{t(`conditionSources.${condition.source}`)} · {t(`conditionValueTypes.${condition.valueType}`)}</small>
        </li>)}</ul> : t("none")}</td>
      </tr>;
    })}</tbody>
  </Table>;
}
