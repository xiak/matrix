"use client";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Checkbox, FormField, Input, Select, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, IdentityProvider, RoleSsoMappingPreview } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function ProviderEditor({ provider, onClose }: { provider?: IdentityProvider; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(provider?.name ?? "");
  const [protocol, setProtocol] = useState<IdentityProvider["protocol"]>(provider?.protocol ?? "SAML");
  const [drafts, setDrafts] = useState<Record<IdentityProvider["protocol"], Pick<IdentityProvider, "issuer" | "audience" | "metadata">>>(() => ({
    SAML: provider?.protocol === "SAML" ? { issuer: provider.issuer, audience: provider.audience, metadata: provider.metadata } : { issuer: "", audience: "", metadata: "" },
    OIDC: provider?.protocol === "OIDC" ? { issuer: provider.issuer, audience: provider.audience, metadata: provider.metadata } : { issuer: "", audience: "", metadata: "" }
  }));
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  const draft = drafts[protocol];
  const updateDraft = (field: keyof typeof draft, value: string) => setDrafts((current) => ({ ...current, [protocol]: { ...current[protocol], [field]: value } }));
  const issuerLabel = t(protocol === "SAML" ? "providerSamlIssuer" : "providerOidcIssuer");
  const audienceLabel = t(protocol === "SAML" ? "providerSamlAudience" : "providerOidcClientId");
  const metadataLabel = t(protocol === "SAML" ? "providerSamlMetadata" : "providerOidcJwks");
  return <WorkspaceInlineForm title={provider ? t("edit") + " · " + provider.name : t("createProvider")} backLabel={t(provider ? "backToProviderDetails" : "backToProviderDirectory")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-provider", id: provider?.id, name, protocol, ...draft, enabled }))}>
    <Alert status="info">{t("providerPreviewBoundary")}</Alert>
    <FormField id={id + "-name"} label={t("name")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-protocol"} label={t("protocol")}><Select id={id + "-protocol"} value={protocol} options={["SAML", "OIDC"].map((value) => ({ value, label: value }))} onValueChange={(value) => setProtocol(value as IdentityProvider["protocol"])} /></FormField>
    <FormField id={id + "-issuer"} label={issuerLabel}><Input id={id + "-issuer"} type="url" required placeholder="https://identity.example.invalid" value={draft.issuer} onChange={(event) => updateDraft("issuer", event.target.value)} /></FormField>
    <FormField id={id + "-audience"} label={audienceLabel}><Input id={id + "-audience"} required maxLength={256} value={draft.audience} onChange={(event) => updateDraft("audience", event.target.value)} /></FormField>
    <FormField id={id + "-metadata"} label={metadataLabel} hint={t(protocol === "SAML" ? "providerSamlMetadataHint" : "providerOidcJwksHint")}><TextArea className={styles.codeEditor} id={id + "-metadata"} aria-describedby={id + "-metadata-hint"} required spellCheck={false} rows={6} maxLength={65536} value={draft.metadata} onChange={(event) => updateDraft("metadata", event.target.value)} /></FormField>
    <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
  </WorkspaceInlineForm>;
}

export function AccessProviders({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<IdentityProvider | "new" | null>(null);
  const [deleting, setDeleting] = useState<IdentityProvider | null>(null);
  const createTrigger = useRef<{ focus(): void }>(null);
  const editTrigger = useRef<{ focus(): void }>(null);
  const previousEditing = useRef<IdentityProvider | "new" | null>(null);
  const selected = workspace.providers.find((provider) => provider.id === selectedId);
  useLayoutEffect(() => {
    const previous = previousEditing.current;
    previousEditing.current = editing;
    if (!editing && previous) (previous === "new" ? createTrigger : editTrigger).current?.focus();
  }, [editing]);
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actionFocusRef={editTrigger} actions={editing ? undefined : { primary: { id: "edit", label: t("edit"), variant: "secondary", onSelect: () => setEditing(selected) }, secondary: [{ id: "delete", label: t("delete"), danger: true, onSelect: () => setDeleting(selected) }] }}>
      {editing && editing !== "new" ? <ProviderEditor provider={editing} onClose={() => setEditing(null)} /> : <>
        <Alert status="info">{t("providerPreviewBoundary")}</Alert>
        <dl className={styles.facts}><div><dt>{t("protocol")}</dt><dd>{selected.protocol}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t(selected.protocol === "SAML" ? "providerSamlIssuer" : "providerOidcIssuer")}</dt><dd>{selected.issuer}</dd></div><div><dt>{t(selected.protocol === "SAML" ? "providerSamlAudience" : "providerOidcClientId")}</dt><dd>{selected.audience}</dd></div><div><dt>{t("roles")}</dt><dd>{workspace.roles.filter((role) => role.principalType === "provider" && role.principal === selected.id).map((role) => role.name).join(" · ") || t("none")}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
        <h3 className={styles.stepTitle}>{t(selected.protocol === "SAML" ? "providerSamlMetadata" : "providerOidcJwks")}</h3><pre className={styles.code} role="region" aria-label={t(selected.protocol === "SAML" ? "providerSamlMetadata" : "providerOidcJwks")} tabIndex={0}>{selected.metadata}</pre><p className={styles.note}>{t(selected.protocol === "SAML" ? "providerSamlMetadataHint" : "providerOidcJwksHint")}</p>
      </>}
    </WorkspaceDetail> : <WorkspaceCollection title={t("providers")} description={t("providerHint")} intro={<Alert status="info">{t("providerPreviewBoundary")}</Alert>} items={workspace.providers} keywords={(provider) => provider.issuer} createFocusRef={createTrigger} create={{ label: t("createProvider"), onClick: () => setEditing("new") }} workflow={editing === "new" ? <ProviderEditor onClose={() => setEditing(null)} /> : undefined} filter={{ label: t("protocol"), options: ["SAML", "OIDC"].map((value) => ({ value, label: value })), matches: (provider, value) => provider.protocol === value }} columns={[t("name"), t("protocol"), t("state"), t("created")]} row={(provider) => <><td><button className={styles.userLink} onClick={() => setSelectedId(provider.id)}>{provider.name}</button><small>{provider.issuer}</small></td><td>{provider.protocol}</td><td><Badge status={provider.enabled ? "success" : "neutral"}>{t(provider.enabled ? "enabled" : "disabled")}</Badge></td><td><WorkspaceTime value={provider.createdAt} /></td></>} />}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-provider", id: deleting.id })} /> : null}
  </>;
}

function RoleSsoMappingPreviewEditor({ mapping, workspace, onClose }: { mapping?: RoleSsoMappingPreview; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(mapping?.name ?? "");
  const [assertionSubject, setAssertionSubject] = useState(mapping?.assertionSubject ?? "");
  const [providerId, setProviderId] = useState(mapping?.providerId ?? "");
  const [roleId, setRoleId] = useState(mapping?.roleId ?? "");
  const [enabled, setEnabled] = useState(mapping?.enabled ?? true);
  return <WorkspaceInlineForm title={mapping ? t("edit") + " · " + mapping.name : t("createRoleSsoMappingPreview")} backLabel={t(mapping ? "backToRoleSsoMappingDetails" : "backToRoleSsoMappingDirectory")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-role-sso-mapping-preview", id: mapping?.id, name, assertionSubject, providerId, roleId, enabled }))}>
    <Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>
    <FormField id={id + "-name"} label={t("name")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-subject"} label={t("roleSsoAssertionSubject")} hint={t("roleSsoAssertionSubjectHint")}><Input id={id + "-subject"} aria-describedby={id + "-subject-hint"} required maxLength={256} value={assertionSubject} onChange={(event) => setAssertionSubject(event.target.value)} /></FormField>
    <FormField id={id + "-provider"} label={t("provider")}><Select id={id + "-provider"} required value={providerId} options={[{ value: "", label: t("ssoProvider") }, ...workspace.providers.map((provider) => ({ value: provider.id, label: provider.name }))]} onValueChange={(value) => { setProviderId(value); setRoleId(""); }} /></FormField>
    <FormField id={id + "-role"} label={t("roleSsoTargetRole")}><Select id={id + "-role"} required value={roleId} options={[{ value: "", label: t("roleSsoTargetRole") }, ...workspace.roles.filter((role) => role.principalType === "provider" && role.principal === providerId).map((role) => ({ value: role.id, label: role.name }))]} onValueChange={(value) => setRoleId(value)} /></FormField>
    <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
  </WorkspaceInlineForm>;
}

export function AccessRoleSsoMappings({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState<RoleSsoMappingPreview | "new" | null>(null);
  const [deleting, setDeleting] = useState<RoleSsoMappingPreview | null>(null);
  const createTrigger = useRef<{ focus(): void }>(null);
  const editTrigger = useRef<{ focus(): void }>(null);
  const previousEditing = useRef<RoleSsoMappingPreview | "new" | null>(null);
  const selected = workspace.roleSsoMappings.find((entry) => entry.id === selectedId);
  const providerName = (entry: RoleSsoMappingPreview) => workspace.providers.find((provider) => provider.id === entry.providerId)?.name ?? entry.providerId;
  const roleName = (entry: RoleSsoMappingPreview) => workspace.roles.find((role) => role.id === entry.roleId)?.name ?? entry.roleId;
  useLayoutEffect(() => {
    const previous = previousEditing.current;
    previousEditing.current = editing;
    if (!editing && previous) (previous === "new" ? createTrigger : editTrigger).current?.focus();
  }, [editing]);
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actionFocusRef={editTrigger} actions={editing ? undefined : { primary: { id: "edit", label: t("edit"), variant: "secondary", onSelect: () => setEditing(selected) }, secondary: [{ id: "delete", label: t("delete"), danger: true, onSelect: () => setDeleting(selected) }] }}>
      {editing && editing !== "new" ? <RoleSsoMappingPreviewEditor mapping={editing} workspace={workspace} onClose={() => setEditing(null)} /> : <><Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert><dl className={styles.facts}><div><dt>{t("roleSsoAssertionSubject")}</dt><dd>{selected.assertionSubject}</dd></div><div><dt>{t("provider")}</dt><dd>{providerName(selected)}</dd></div><div><dt>{t("roleSsoTargetRole")}</dt><dd>{roleName(selected)}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl><p className={styles.flow}>{providerName(selected)} → {selected.assertionSubject} → {roleName(selected)}</p></>}
    </WorkspaceDetail> : <WorkspaceCollection title={t("roleSsoMappings")} description={t("roleSsoMappingHint")} intro={<Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>} items={workspace.roleSsoMappings} keywords={(entry) => [entry.assertionSubject, providerName(entry), roleName(entry)].join(" ")} createFocusRef={createTrigger} create={{ label: t("createRoleSsoMappingPreview"), onClick: () => setEditing("new") }} workflow={editing === "new" ? <RoleSsoMappingPreviewEditor workspace={workspace} onClose={() => setEditing(null)} /> : undefined} columns={[t("name"), t("provider"), t("roleSsoTargetRole"), t("state")]} row={(entry) => <><td><button className={styles.userLink} onClick={() => setSelectedId(entry.id)}>{entry.name}</button><small>{entry.assertionSubject}</small></td><td>{providerName(entry)}</td><td>{roleName(entry)}</td><td><Badge status={entry.enabled ? "success" : "neutral"}>{t(entry.enabled ? "enabled" : "disabled")}</Badge></td></>} />}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-role-sso-mapping-preview", id: deleting.id })} /> : null}
  </>;
}
