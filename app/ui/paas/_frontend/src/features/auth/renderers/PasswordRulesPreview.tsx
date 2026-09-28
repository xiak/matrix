"use client";

import { useTranslations } from "next-intl";
import { KeyRound } from "lucide-react";
import { Alert, Badge, Card, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

/** A read-only design preview. The live account policy must come from IAM's
 * fixed security-settings contract, never from these sample defaults. */
export function PasswordRulesPreview() {
  const t = useTranslations("PasswordRulesPreview");
  return <section aria-labelledby="password-rules-preview" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div><p>{t("eyebrow")}</p><h2 id="password-rules-preview">{t("title")}</h2><span>{t("hint")}</span></div>
      <Badge status="warning">{t("badge")}</Badge>
    </div>
    <Card>
      <Card.Header><div className={styles.cardTitle}><span><KeyRound aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("summaryTitle")}</Typography.Title><Typography.Text tone="muted">{t("summaryHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm}>
        <Alert>{t("previewBoundary")}</Alert>
        <dl className={styles.facts}>
          <div><dt>{t("minimumLength")}</dt><dd>{t("minimumLengthValue")}</dd></div>
          <div><dt>{t("characterClasses")}</dt><dd>{t("characterClassesValue")}</dd></div>
          <div><dt>{t("reuse")}</dt><dd>{t("reuseValue")}</dd></div>
          <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
          <div><dt>{t("protectedScope")}</dt><dd>{t("protectedScopeValue")}</dd></div>
        </dl>
        <Alert status="warning">{t("changeBoundary")}</Alert>
      </Card.Body>
    </Card>
  </section>;
}
