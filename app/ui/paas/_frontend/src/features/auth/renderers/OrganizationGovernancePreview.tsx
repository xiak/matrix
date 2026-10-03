"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Typography } from "@ui/xiak";
import styles from "./AccountAccessRenderer.module.css";

type GovernanceStage = "directory" | "attach" | "inherit" | "authorize" | "move" | "exceptions";

/**
 * Read-only IAM-EXT-08 concept projection. It models no organization node,
 * membership or guardrail resource until a fixed IAM contract exists.
 */
export function OrganizationGovernancePreview() {
  const t = useTranslations("AccountAccess.organizationGovernance");
  const titleId = useId();
  const stages: GovernanceStage[] = ["directory", "attach", "inherit", "authorize", "move", "exceptions"];

  return <section aria-labelledby={titleId}>
    <Card>
      <Card.Header className={styles.securityCheckHeading}>
        <div className={styles.stack}>
          <Typography.Title as="h2" id={titleId} level={3}>{t("title")}</Typography.Title>
          <Typography.Text tone="muted">{t("description")}</Typography.Text>
        </div>
        <Badge status="neutral">{t("deferred")}</Badge>
      </Card.Header>
      <Card.Body className={styles.stack}>
        <Alert status="info">{t("boundary")}</Alert>
        <dl className={styles.facts}>
          <div><dt>{t("directoryState")}</dt><dd><Badge status="warning">{t("notConnected")}</Badge></dd></div>
          <div><dt>{t("guardrailState")}</dt><dd>{t("noAuthoritativeSource")}</dd></div>
          <div><dt>{t("evaluationState")}</dt><dd>{t("notEvaluated")}</dd></div>
        </dl>
        <Alert status="warning">{t("upperBound")}</Alert>
        <ol className={styles.securityChecks}>
          {stages.map((stage, index) => <li key={stage}>
            <Badge status="neutral">{index + 1}</Badge>
            <div className={styles.securityCheckCopy}>
              <div className={styles.securityCheckHeading}>
                <strong>{t(`stages.${stage}.title`)}</strong>
                <Badge status="neutral">{t("mustDefine")}</Badge>
              </div>
              <p>{t(`stages.${stage}.detail`)}</p>
            </div>
          </li>)}
        </ol>
      </Card.Body>
    </Card>
  </section>;
}
