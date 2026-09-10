"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, Checkbox, FormField, Input, Select, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, FederatedAccount, IdentityProvider } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function ProviderEditor({ provider, onClose }: { provider?: IdentityProvider; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(provider?.name ?? "");
  const [protocol, setProtocol] = useState<IdentityProvider["protocol"]>(provider?.protocol ?? "SAML");
  const [issuer, setIssuer] = useState(provider?.issuer ?? "");
  const [audience, setAudience] = useState(provider?.audience ?? "");
  const [metadata, setMetadata] = useState(provider?.metadata ?? "");
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  return <WorkspaceDialog title={provider ? t("edit") + " · " + provider.name : t("createProvider")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-provider", id: provider?.id, name, protocol, issuer, audience, metadata, enabled }))}>
    <FormField id={id + "-name"} label={t("name")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-protocol"} label={t("protocol")}><Select id={id + "-protocol"} value={protocol} options={["SAML", "OIDC"].map((value) => ({ value, label: value }))} onValueChange={(value) => setProtocol(value as IdentityProvider["protocol"])} /></FormField>
    <FormField id={id + "-issuer"} label={t("issuer")}><Input id={id + "-issuer"} type="url" required placeholder="https://identity.example.invalid" value={issuer} onChange={(event) => setIssuer(event.target.value)} /></FormField>
    <FormField id={id + "-audience"} label={t("audience")}><Input id={id + "-audience"} required maxLength={256} value={audience} onChange={(event) => setAudience(event.target.value)} /></FormField>
    <FormField id={id + "-metadata"} label={t("metadata")} hint={t("metadataHint")}><TextArea className={styles.codeEditor} id={id + "-metadata"} aria-describedby={id + "-metadata-hint"} required spellCheck={false} rows={6} maxLength={65536} value={metadata} onChange={(event) => setMetadata(event.target.value)} /></FormField>
    <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
  </WorkspaceDialog>;
}

export function AccessProviders({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<IdentityProvider | "new" | null>(null);
  const [deleting, setDeleting] = useState<IdentityProvider | null>(null);
  const selected = workspace.providers.find((provider) => provider.id === selectedId);
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actions={<><Button variant="secondary" onClick={() => setEditing(selected)}>{t("edit")}</Button><Button variant="ghost" onClick={() => setDeleting(selected)}>{t("delete")}</Button></>}>
      <dl className={styles.facts}><div><dt>{t("protocol")}</dt><dd>{selected.protocol}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("issuer")}</dt><dd>{selected.issuer}</dd></div><div><dt>{t("audience")}</dt><dd>{selected.audience}</dd></div><div><dt>{t("roles")}</dt><dd>{workspace.roles.filter((role) => role.principalType === "provider" && role.principal === selected.id).map((role) => role.name).join(" · ") || t("none")}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      <h3 className={styles.stepTitle}>{t("metadata")}</h3><pre className={styles.code} role="region" aria-label={t("metadata")} tabIndex={0}>{selected.metadata}</pre><p className={styles.note}>{t("metadataHint")}</p>
    </WorkspaceDetail> : <WorkspaceCollection title={t("providers")} description={t("providerHint")} items={workspace.providers} keywords={(provider) => provider.issuer} create={{ label: t("createProvider"), onClick: () => setEditing("new") }} filter={{ label: t("protocol"), options: ["SAML", "OIDC"].map((value) => ({ value, label: value })), matches: (provider, value) => provider.protocol === value }} columns={[t("name"), t("protocol"), t("state"), t("created"), t("actions")]} row={(provider) => <><td><button className={styles.userLink} onClick={() => setSelectedId(provider.id)}>{provider.name}</button><small>{provider.issuer}</small></td><td>{provider.protocol}</td><td><Badge status={provider.enabled ? "success" : "neutral"}>{t(provider.enabled ? "enabled" : "disabled")}</Badge></td><td><WorkspaceTime value={provider.createdAt} /></td><td><div className={styles.actions}><Button size="small" variant="ghost" onClick={() => setEditing(provider)}>{t("edit")}</Button><Button size="small" variant="ghost" onClick={() => setDeleting(provider)}>{t("delete")}</Button></div></td></>} />}
    {editing ? <ProviderEditor provider={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-provider", id: deleting.id })} /> : null}
  </>;
}

function FederationEditor({ federation, workspace, onClose }: { federation?: FederatedAccount; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(federation?.name ?? "");
  const [subject, setSubject] = useState(federation?.subject ?? "");
  const [providerId, setProviderId] = useState(federation?.providerId ?? "");
  const [roleId, setRoleId] = useState(federation?.roleId ?? "");
  const [enabled, setEnabled] = useState(federation?.enabled ?? true);
  return <WorkspaceDialog title={federation ? t("edit") + " · " + federation.name : t("createFederation")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-federation", id: federation?.id, name, subject, providerId, roleId, enabled }))}>
    <FormField id={id + "-name"} label={t("name")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-subject"} label={t("subject")}><Input id={id + "-subject"} required maxLength={256} value={subject} onChange={(event) => setSubject(event.target.value)} /></FormField>
    <FormField id={id + "-provider"} label={t("provider")}><Select id={id + "-provider"} required value={providerId} options={[{ value: "", label: t("ssoProvider") }, ...workspace.providers.map((provider) => ({ value: provider.id, label: provider.name }))]} onValueChange={(value) => { setProviderId(value); setRoleId(""); }} /></FormField>
    <FormField id={id + "-role"} label={t("targetRole")}><Select id={id + "-role"} required value={roleId} options={[{ value: "", label: t("targetRole") }, ...workspace.roles.filter((role) => role.principalType === "provider" && role.principal === providerId).map((role) => ({ value: role.id, label: role.name }))]} onValueChange={(value) => setRoleId(value)} /></FormField>
    <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
    <p className={styles.note}>{t("federationHint")}</p>
  </WorkspaceDialog>;
}

export function AccessFederations({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<FederatedAccount | "new" | null>(null);
  const [deleting, setDeleting] = useState<FederatedAccount | null>(null);
  const selected = workspace.federations.find((entry) => entry.id === selectedId);
  const providerName = (entry: FederatedAccount) => workspace.providers.find((provider) => provider.id === entry.providerId)?.name ?? entry.providerId;
  const roleName = (entry: FederatedAccount) => workspace.roles.find((role) => role.id === entry.roleId)?.name ?? entry.roleId;
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actions={<><Button variant="secondary" onClick={() => setEditing(selected)}>{t("edit")}</Button><Button variant="ghost" onClick={() => setDeleting(selected)}>{t("delete")}</Button></>}>
      <dl className={styles.facts}><div><dt>{t("subject")}</dt><dd>{selected.subject}</dd></div><div><dt>{t("provider")}</dt><dd>{providerName(selected)}</dd></div><div><dt>{t("targetRole")}</dt><dd>{roleName(selected)}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl><p className={styles.flow}>{providerName(selected)} → {selected.subject} → {roleName(selected)}</p>
    </WorkspaceDetail> : <WorkspaceCollection title={t("federatedIdentities")} description={t("federationHint")} items={workspace.federations} keywords={(entry) => [entry.subject, providerName(entry), roleName(entry)].join(" ")} create={{ label: t("createFederation"), onClick: () => setEditing("new") }} columns={[t("name"), t("provider"), t("targetRole"), t("state"), t("actions")]} row={(entry) => <><td><button className={styles.userLink} onClick={() => setSelectedId(entry.id)}>{entry.name}</button><small>{entry.subject}</small></td><td>{providerName(entry)}</td><td>{roleName(entry)}</td><td><Badge status={entry.enabled ? "success" : "neutral"}>{t(entry.enabled ? "enabled" : "disabled")}</Badge></td><td><div className={styles.actions}><Button size="small" variant="ghost" onClick={() => setEditing(entry)}>{t("edit")}</Button><Button size="small" variant="ghost" onClick={() => setDeleting(entry)}>{t("delete")}</Button></div></td></>} />}
    {editing ? <FederationEditor federation={editing === "new" ? undefined : editing} workspace={workspace} onClose={() => setEditing(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-federation", id: deleting.id })} /> : null}
  </>;
}
