"use client";

import type { AccessWorkspace } from "../domain/accessWorkspace";
import { FederationBoundaryOverview } from "./FederationBoundaryOverview";
import { RoleSsoJourneyPreview } from "./RoleSsoJourneyPreview";
import styles from "./AccountAccessRenderer.module.css";

/**
 * Role SSO remains an information architecture surface until IAM publishes a
 * consumable provider, external trust and session contract. It deliberately
 * contains no local provider directory or writable configuration facsimile.
 */
export function AccessFederationWorkspace({ workspace }: { workspace: AccessWorkspace }) {
  return <div className={styles.stack}>
    <FederationBoundaryOverview current="role" />
    <RoleSsoJourneyPreview accountId={workspace.accountId} />
  </div>;
}
