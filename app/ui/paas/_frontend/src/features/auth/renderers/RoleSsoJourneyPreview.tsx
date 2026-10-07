"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Typography } from "@ui/xiak";
import styles from "./AccountAccessRenderer.module.css";

const journey = ["provider", "assertion", "mapping", "trust", "permission", "session"] as const;
const readiness = ["protocol", "mapping", "trust", "recovery", "audit"] as const;

/**
 * Read-only Role SSO readiness model. It explains the gates a future IAM
 * implementation must satisfy without manufacturing providers, mappings,
 * trusted assertions or issued sessions in browser memory.
 */
export function RoleSsoJourneyPreview({ accountId }: { accountId: string }) {
  const t = useTranslations("IamWorkspace.roleSsoJourney");
  const titleId = useId();

  return <Card>
    <Card.Header>
      <div className={styles.cardHeadingCopy}>
        <Typography.Title as="h2" id={titleId} level={3}>{t("title")}</Typography.Title>
        <Typography.Text tone="muted">{t("subtitle")}</Typography.Text>
      </div>
      <div className={styles.headingBadges}><Badge status="warning">{t("state")}</Badge><Badge status="neutral">{accountId}</Badge></div>
    </Card.Header>
    <Card.Body className={styles.stack}>
      <Alert status="info">{t("boundary")}</Alert>
      <section aria-labelledby={`${titleId}-journey`} className={styles.stack}>
        <div className={styles.cardHeadingCopy}>
          <h3 className={styles.stepTitle} id={`${titleId}-journey`}>{t("journeyTitle")}</h3>
          <p className={styles.note}>{t("journeyHint")}</p>
        </div>
        <ol className={styles.securityChecks}>
          {journey.map((step, index) => <li key={step}>
            <Badge status="neutral">{index + 1}</Badge>
            <div className={styles.securityCheckCopy}>
              <div className={styles.securityCheckHeading}>
                <strong>{t(`steps.${step}.title`)}</strong>
                <Badge status="warning">{t(step === "session" ? "states.notIssued" : "states.notReady")}</Badge>
              </div>
              <p>{t(`steps.${step}.detail`)}</p>
            </div>
          </li>)}
        </ol>
      </section>
      <section aria-labelledby={`${titleId}-readiness`} className={styles.stack}>
        <div className={styles.cardHeadingCopy}>
          <h3 className={styles.stepTitle} id={`${titleId}-readiness`}>{t("readinessTitle")}</h3>
          <p className={styles.note}>{t("readinessHint")}</p>
        </div>
        <ol className={styles.securityChecks}>
          {readiness.map((item, index) => <li key={item}>
            <Badge status="neutral">{index + 1}</Badge>
            <div className={styles.securityCheckCopy}>
              <div className={styles.securityCheckHeading}><strong>{t(`readiness.${item}.title`)}</strong><Badge status="warning">{t("states.notReady")}</Badge></div>
              <p>{t(`readiness.${item}.detail`)}</p>
            </div>
          </li>)}
        </ol>
      </section>
    </Card.Body>
  </Card>;
}
