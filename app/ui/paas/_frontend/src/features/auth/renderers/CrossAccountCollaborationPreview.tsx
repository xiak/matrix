"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Typography } from "@ui/xiak";
import styles from "./AccountAccessRenderer.module.css";

type CollaborationStep = "invite" | "accept" | "trust" | "authorize" | "session" | "revoke";

/**
 * Read-only concept projection for IAM-EXT-06. It deliberately owns no
 * invitation, trust, session or revocation state until IAM publishes a fixed
 * cross-account contract.
 */
export function CrossAccountCollaborationPreview({ accountId }: { accountId: string }) {
  const t = useTranslations("IamWorkspace.crossAccountCollaboration");
  const titleId = useId();
  const steps: CollaborationStep[] = ["invite", "accept", "trust", "authorize", "session", "revoke"];

  return <section aria-labelledby={titleId}>
    <Card>
      <Card.Header className={styles.securityCheckHeading}>
        <div className={styles.stack}>
          <Typography.Title as="h2" id={titleId} level={3}>{t("title")}</Typography.Title>
          <Typography.Text tone="muted">{t("description")}</Typography.Text>
        </div>
        <Badge status="neutral">{t("concept")}</Badge>
      </Card.Header>
      <Card.Body className={styles.stack}>
        <Alert status="info">{t("boundary")}</Alert>
        <dl className={styles.facts}>
          <div><dt>{t("resourceOwner")}</dt><dd><code>{accountId}</code></dd></div>
          <div><dt>{t("state")}</dt><dd><Badge status="warning">{t("notConnected")}</Badge></dd></div>
          <div><dt>{t("prerequisite")}</dt><dd>{t("twoAccounts")}</dd></div>
        </dl>
        <section aria-labelledby={`${titleId}-modes`} className={styles.stack}>
          <div className={styles.securityEvidenceHeading}>
            <Typography.Title as="h3" id={`${titleId}-modes`} level={3}>{t("modes.title")}</Typography.Title>
            <Typography.Text tone="muted">{t("modes.description")}</Typography.Text>
          </div>
          <div className={styles.crossAccountModes}>
            <article className={styles.crossAccountMode}>
              <div className={styles.crossAccountModeHeading}>
                <strong>{t("modes.role.title")}</strong>
                <Badge status="neutral">{t("modes.role.status")}</Badge>
              </div>
              <p>{t("modes.role.description")}</p>
              <dl>
                <div><dt>{t("modes.surface")}</dt><dd>{t("modes.role.surface")}</dd></div>
                <div><dt>{t("modes.identity")}</dt><dd>{t("modes.role.identity")}</dd></div>
                <div><dt>{t("modes.authorization")}</dt><dd>{t("modes.role.authorization")}</dd></div>
              </dl>
            </article>
            <article className={styles.crossAccountMode}>
              <div className={styles.crossAccountModeHeading}>
                <strong>{t("modes.resource.title")}</strong>
                <Badge status="warning">{t("modes.resource.status")}</Badge>
              </div>
              <p>{t("modes.resource.description")}</p>
              <dl>
                <div><dt>{t("modes.surface")}</dt><dd>{t("modes.resource.surface")}</dd></div>
                <div><dt>{t("modes.identity")}</dt><dd>{t("modes.resource.identity")}</dd></div>
                <div><dt>{t("modes.authorization")}</dt><dd>{t("modes.resource.authorization")}</dd></div>
              </dl>
            </article>
          </div>
          <Alert status="warning">{t("modes.resourceBoundary")}</Alert>
        </section>
        <div className={styles.securityEvidenceHeading}>
          <Typography.Title as="h3" level={3}>{t("roleJourney")}</Typography.Title>
          <Typography.Text tone="muted">{t("roleJourneyHint")}</Typography.Text>
        </div>
        <ol className={styles.securityChecks}>
          {steps.map((step, index) => <li key={step}>
            <Badge status="neutral">{index + 1}</Badge>
            <div className={styles.securityCheckCopy}>
              <div className={styles.securityCheckHeading}>
                <strong>{t(`steps.${step}.title`)}</strong>
                <Badge status="neutral">{t("required")}</Badge>
              </div>
              <p>{t(`steps.${step}.detail`)}</p>
            </div>
          </li>)}
        </ol>
        <Alert status="warning">{t("revocationBoundary")}</Alert>
      </Card.Body>
    </Card>
  </section>;
}
