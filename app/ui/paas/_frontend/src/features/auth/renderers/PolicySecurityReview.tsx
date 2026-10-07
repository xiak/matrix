"use client";

import { useTranslations } from "next-intl";
import { Alert } from "@ui/xiak";
import type { AccessPolicy } from "../domain/accessWorkspace";
import { policyDocumentDiagnostics, type PolicyDiagnostic } from "../domain/policyDocument";
import styles from "./PolicyWorkspace.module.css";

type SecurityDiagnostic = Extract<PolicyDiagnostic, { severity: "security-warning" }>;

/** Shared review projection for read and mutation surfaces. It keeps the same
 * local risk vocabulary without presenting those findings as effective access. */
export function PolicySecurityReview({ policies }: { policies: readonly AccessPolicy[] }) {
  const t = useTranslations("PolicyWorkspace");
  const reviews = policies.flatMap((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)?.document;
    if (!document) return [];
    const diagnostics = policyDocumentDiagnostics(document).filter((entry): entry is SecurityDiagnostic => entry.severity === "security-warning");
    return diagnostics.length ? [{ policy, diagnostics }] : [];
  });
  const count = reviews.reduce((total, review) => total + review.diagnostics.length, 0);
  if (!count) return null;
  return <Alert status="warning">
    <div className={styles.policySecurityReview}>
      <strong>{t("securityReviewTitle", { count })}</strong>
      <p>{t("securityReviewBoundary")}</p>
      <ul className={styles.policySecurityPolicies}>{reviews.map(({ policy, diagnostics }) => <li key={policy.id}>
        <strong>{policy.name}</strong>
        <ul className={styles.policySecurityFindings}>{[...new Set(diagnostics.map((entry) => entry.code))].map((code) => <li key={code}>{t(code)}</li>)}</ul>
      </li>)}</ul>
    </div>
  </Alert>;
}
