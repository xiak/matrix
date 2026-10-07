"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Tabs } from "@ui/xiak";
import { CrossAccountCollaborationPreview } from "./CrossAccountCollaborationPreview";
import { OrganizationGovernancePreview } from "./OrganizationGovernancePreview";
import styles from "./AccountAccessRenderer.module.css";

type CollaborationSection = "cross-account" | "organization";

/**
 * Read-only catalog for IAM-EXT-06/08/09. These capabilities have no
 * customer-facing write contract yet, so this surface owns no draft,
 * invitation, organization, trust, policy, session, or adapter state.
 */
export function AccessCollaborationBoundaries({ accountId }: { accountId: string }) {
  const t = useTranslations("IamWorkspace.collaborationBoundaries");
  const crossAccount = useTranslations("IamWorkspace.crossAccountCollaboration");
  const organization = useTranslations("AccountAccess.organizationGovernance");
  const [section, setSection] = useState<CollaborationSection>("cross-account");

  return <div className={styles.stack}>
    <div className={styles.federationBoundaryHeading}>
      <div>
        <h2>{t("title")}</h2>
        <p>{t("description")}</p>
      </div>
      <Badge status="neutral">{t("deferred")}</Badge>
    </div>
    <Alert status="info">{t("boundary")}</Alert>
    <Tabs.Root value={section} onValueChange={(value) => setSection(value as CollaborationSection)}>
      <Tabs.List aria-label={t("sections")}>
        <Tabs.Trigger value="cross-account">{crossAccount("tab")}</Tabs.Trigger>
        <Tabs.Trigger value="organization">{organization("tab")}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value="cross-account"><CrossAccountCollaborationPreview accountId={accountId} /></Tabs.Content>
      <Tabs.Content value="organization"><OrganizationGovernancePreview /></Tabs.Content>
    </Tabs.Root>
  </div>;
}
