"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Typography } from "@ui/xiak";
import type { AccessRole, IdentityProvider, RoleSsoMappingPreview } from "../domain/accessWorkspace";
import styles from "./AccountAccessRenderer.module.css";

type JourneyMapping = Pick<RoleSsoMappingPreview, "name" | "assertionSubject" | "enabled">;
type JourneyStepKey = "provider" | "assertion" | "mapping" | "trust" | "session";
type JourneyStepState = "configuration" | "untrusted" | "candidate" | "disabled" | "notVerified" | "notIssued";

/**
 * Read-only concept projection for IAM-EXT-03. It explains the security
 * boundaries between provider verification, mapping, Role trust and STS
 * without defining a backend resource or issuing a session.
 */
export function RoleSsoJourneyPreview({ provider, mapping, role }: {
  provider?: IdentityProvider;
  mapping: JourneyMapping;
  role?: AccessRole;
}) {
  const t = useTranslations("IamWorkspace.roleSsoJourney");
  const titleId = useId();
  const trustConfigured = Boolean(provider && role?.principalType === "provider" && role.principal === provider.id);
  const steps: { key: JourneyStepKey; state: JourneyStepState; status: "neutral" | "warning" }[] = [
    {
      key: "provider",
      state: provider?.enabled ? "configuration" : "disabled",
      status: provider?.enabled ? "neutral" as const : "warning" as const
    },
    {
      key: "assertion",
      state: "untrusted",
      status: "warning" as const
    },
    {
      key: "mapping",
      state: mapping.enabled ? "candidate" : "disabled",
      status: mapping.enabled ? "neutral" as const : "warning" as const
    },
    {
      key: "trust",
      state: trustConfigured ? "configuration" : "notVerified",
      status: trustConfigured ? "neutral" as const : "warning" as const
    },
    {
      key: "session",
      state: "notIssued",
      status: "neutral" as const
    }
  ];

  return <section aria-labelledby={titleId} className={styles.stack}>
    <div className={styles.securityCheckHeading}>
      <Typography.Title as="h3" id={titleId} level={3}>{t("title")}</Typography.Title>
      <Badge status="neutral">{t("concept")}</Badge>
    </div>
    <Alert status="info">{t("boundary")}</Alert>
    <ol className={styles.securityChecks}>
      {steps.map((step, index) => <li key={step.key}>
        <Badge status="neutral">{index + 1}</Badge>
        <div className={styles.securityCheckCopy}>
          <div className={styles.securityCheckHeading}>
            <strong>{t(`steps.${step.key}.title`)}</strong>
            <Badge status={step.status}>{t(`states.${step.state}`)}</Badge>
          </div>
          <p>{t(`steps.${step.key}.detail`)}</p>
        </div>
      </li>)}
    </ol>
  </section>;
}
