"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge } from "@ui/xiak";
import type { AccessWorkspace, RoleSsoMappingPreview } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { RoleSsoJourneyPreview } from "./RoleSsoJourneyPreview";
import styles from "./AccountAccessRenderer.module.css";

export function AccessProviders({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = workspace.providers.find((provider) => provider.id === selectedId);

  return selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)}>
    <Alert status="info">{t("providerPreviewBoundary")}</Alert>
    <dl className={styles.facts}>
      <div><dt>{t("userSsoTarget")}</dt><dd><code>{selected.accountId}</code></dd></div>
      <div><dt>{t("protocol")}</dt><dd>{selected.protocol}</dd></div>
      <div><dt>{t("state")}</dt><dd><Badge status="warning">MOCK</Badge></dd></div>
      <div><dt>{t("providerIssuer")}</dt><dd>{selected.issuer}</dd></div>
      {selected.protocol === "OIDC"
        ? <div><dt>{t("providerRedirectUri")}</dt><dd>{selected.redirectUri}</dd></div>
        : <div><dt>{t("providerProtocolConfiguration")}</dt><dd>{t("providerSamlConfigurationState")}</dd></div>}
      <div><dt>{t("roles")}</dt><dd>{workspace.roles.filter((role) => role.principalType === "provider" && role.principal === selected.id).map((role) => role.name).join(" · ") || t("none")}</dd></div>
      <div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div>
    </dl>
  </WorkspaceDetail> : <WorkspaceCollection
    title={t("providers")}
    description={t("providerHint")}
    intro={<Alert status="info">{t("providerPreviewBoundary")}</Alert>}
    items={workspace.providers}
    keywords={(provider) => provider.issuer}
    filter={{ label: t("protocol"), options: ["SAML", "OIDC"].map((value) => ({ value, label: value })), matches: (provider, value) => provider.protocol === value }}
    columns={[t("name"), t("protocol"), t("state"), t("created")]}
    row={(provider) => <>
      <td><button className={styles.userLink} onClick={() => setSelectedId(provider.id)}>{provider.name}</button><small>{provider.issuer}</small></td>
      <td>{provider.protocol}</td>
      <td><Badge status="warning">MOCK</Badge></td>
      <td><WorkspaceTime value={provider.createdAt} /></td>
    </>}
  />;
}

export function AccessRoleSsoMappings({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = workspace.roleSsoMappings.find((entry) => entry.id === selectedId);
  const provider = (entry: RoleSsoMappingPreview) => workspace.providers.find((candidate) => candidate.id === entry.providerId);
  const role = (entry: RoleSsoMappingPreview) => workspace.roles.find((candidate) => candidate.id === entry.roleId);
  const providerName = (entry: RoleSsoMappingPreview) => provider(entry)?.name ?? entry.providerId;
  const roleName = (entry: RoleSsoMappingPreview) => role(entry)?.name ?? entry.roleId;

  return selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)}>
    <Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>
    <dl className={styles.facts}>
      <div><dt>{t("roleSsoSubjectSample")}</dt><dd>{selected.subjectSample}</dd></div>
      <div><dt>{t("provider")}</dt><dd>{providerName(selected)}</dd></div>
      <div><dt>{t("roleSsoTargetRole")}</dt><dd>{roleName(selected)}</dd></div>
      <div><dt>{t("state")}</dt><dd><Badge status="warning">MOCK</Badge></dd></div>
      <div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div>
    </dl>
    <RoleSsoJourneyPreview provider={provider(selected)} mapping={selected} role={role(selected)} />
  </WorkspaceDetail> : <WorkspaceCollection
    title={t("roleSsoMappings")}
    description={t("roleSsoMappingHint")}
    intro={<Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>}
    items={workspace.roleSsoMappings}
    keywords={(entry) => [entry.subjectSample, providerName(entry), roleName(entry)].join(" ")}
    columns={[t("name"), t("provider"), t("roleSsoTargetRole"), t("state")]}
    row={(entry) => <>
      <td><button className={styles.userLink} onClick={() => setSelectedId(entry.id)}>{entry.name}</button><small>{entry.subjectSample}</small></td>
      <td>{providerName(entry)}</td>
      <td>{roleName(entry)}</td>
      <td><Badge status="warning">MOCK</Badge></td>
    </>}
  />;
}
