"use client";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Checkbox, FormField, Input, Select } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { identityProviderConfigurationIssue, roleSsoMappingPreviewIssue, type AccessWorkspace, type IdentityProvider, type IdentityProviderConfigurationIssue, type RoleSsoMappingPreview, type RoleSsoMappingPreviewIssue } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceTime } from "./AccessWorkspaceUi";
import { RoleSsoJourneyPreview } from "./RoleSsoJourneyPreview";
import styles from "./AccountAccessRenderer.module.css";

function ProviderEditor({ provider, workspace, onClose }: { provider?: IdentityProvider; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [phase, setPhase] = useState<"edit" | "review">("edit");
  const [issue, setIssue] = useState<IdentityProviderConfigurationIssue | null>(null);
  const [name, setName] = useState(provider?.name ?? "");
  const [protocol, setProtocol] = useState<IdentityProvider["protocol"]>(provider?.protocol ?? "SAML");
  const [drafts, setDrafts] = useState<Record<IdentityProvider["protocol"], Pick<IdentityProvider, "issuer" | "redirectUri">>>(() => ({
    SAML: provider?.protocol === "SAML" ? { issuer: provider.issuer, redirectUri: provider.redirectUri } : { issuer: "", redirectUri: "" },
    OIDC: provider?.protocol === "OIDC" ? { issuer: provider.issuer, redirectUri: provider.redirectUri } : { issuer: "", redirectUri: "" }
  }));
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  const draft = drafts[protocol];
  const updateDraft = (field: keyof typeof draft, value: string) => setDrafts((current) => ({ ...current, [protocol]: { ...current[protocol], [field]: value } }));
  const issuerLabel = t("providerIssuer");
  const redirectLabel = t("providerRedirectUri");
  const linkedRoles = provider ? workspace.roles.filter((role) => role.principalType === "provider" && role.principal === provider.id) : [];
  const linkedMappings = provider ? workspace.roleSsoMappings.filter((mapping) => mapping.providerId === provider.id) : [];
  const clearIssue = (field: IdentityProviderConfigurationIssue) => setIssue((current) => current === field || (field === "name" && current === "duplicate") ? null : current);
  const fieldId = issue === "duplicate" ? "name" : issue;
  const issueMessage = issue ? t(issue === "name" ? "providerIssues.name" : issue === "duplicate" ? "providerIssues.duplicate" : issue === "issuer" ? "providerIssues.issuer" : "providerIssues.redirectUri") : undefined;
  async function submit() {
    if (phase === "edit") {
      const next = identityProviderConfigurationIssue({ id: provider?.id, name, protocol, ...draft }, workspace.providers);
      if (next) {
        setIssue(next);
        document.getElementById(`${id}-${next === "duplicate" ? "name" : next}`)?.focus();
        return false;
      }
      setIssue(null);
      setPhase("review");
      return false;
    }
    return Boolean(await access.executeWorkspace({ kind: "save-provider", id: provider?.id, name, protocol, ...draft, enabled }));
  }
  const title = phase === "review" ? t("providerReviewTitle", { name }) : provider ? t("edit") + " · " + provider.name : t("createProvider");
  return <WorkspaceInlineForm title={title} backLabel={t(phase === "review" ? "userSsoBackToEdit" : provider ? "backToProviderDetails" : "backToProviderDirectory")} onClose={onClose} onBack={phase === "review" ? () => { access.clearWorkspaceError(); setPhase("edit"); } : undefined} onSubmit={submit} submitLabel={t(phase === "review" ? "ssoConfirmMockSave" : "userSsoReview")}>
    {phase === "edit" ? <>
      <Alert status="info">{t("providerPreviewBoundary")}</Alert>
      <FormField id={id + "-name"} label={t("name")} error={fieldId === "name" ? issueMessage : undefined}><Input id={id + "-name"} required maxLength={64} invalid={fieldId === "name"} value={name} onChange={(event) => { setName(event.target.value); clearIssue("name"); }} /></FormField>
      <FormField id={id + "-protocol"} label={t("protocol")}><Select id={id + "-protocol"} value={protocol} options={["SAML", "OIDC"].map((value) => ({ value, label: value }))} onValueChange={(value) => { setProtocol(value as IdentityProvider["protocol"]); setIssue(null); }} /></FormField>
      <FormField id={id + "-issuer"} label={issuerLabel} error={issue === "issuer" ? t("providerIssues.issuer") : undefined}><Input id={id + "-issuer"} type="url" required invalid={issue === "issuer"} placeholder="https://identity.example.invalid" value={draft.issuer} onChange={(event) => { updateDraft("issuer", event.target.value); clearIssue("issuer"); }} /></FormField>
      <FormField id={id + "-redirectUri"} label={redirectLabel} hint={t("providerRedirectUriHint")} error={issue === "redirectUri" ? t("providerIssues.redirectUri") : undefined}><Input id={id + "-redirectUri"} type="url" required invalid={issue === "redirectUri"} placeholder="https://console.example.invalid/auth/federation/callback" value={draft.redirectUri} onChange={(event) => { updateDraft("redirectUri", event.target.value); clearIssue("redirectUri"); }} /></FormField>
      <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
    </> : <>
      <Alert status="warning">{t(enabled ? "providerEnableReviewHint" : "providerDisableReviewHint", { count: linkedRoles.length + linkedMappings.length })}</Alert>
      <dl className={styles.facts}>
        <div><dt>{t("userSsoTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
        <div><dt>{t("name")}</dt><dd>{name}</dd></div>
        <div><dt>{t("protocol")}</dt><dd>{protocol}</dd></div>
        <div><dt>{issuerLabel}</dt><dd>{draft.issuer}</dd></div>
        <div><dt>{redirectLabel}</dt><dd>{draft.redirectUri}</dd></div>
        <div><dt>{t("userSsoPreviousState")}</dt><dd>{provider ? t(provider.enabled ? "enabled" : "disabled") : t("none")}</dd></div>
        <div><dt>{t("userSsoNewState")}</dt><dd>{t(enabled ? "enabled" : "disabled")}</dd></div>
        <div><dt>{t("providerLinkedRoles")}</dt><dd>{linkedRoles.map((role) => role.name).join(" · ") || t("none")}</dd></div>
        <div><dt>{t("providerLinkedMappings")}</dt><dd>{linkedMappings.map((mapping) => mapping.name).join(" · ") || t("none")}</dd></div>
      </dl>
      <p className={styles.note}>{t("providerReviewBoundary")}</p>
    </>}
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
      {editing && editing !== "new" ? <ProviderEditor provider={editing} workspace={workspace} onClose={() => setEditing(null)} /> : <>
        <Alert status="info">{t("providerPreviewBoundary")}</Alert>
        <dl className={styles.facts}><div><dt>{t("userSsoTarget")}</dt><dd><code>{selected.accountId}</code></dd></div><div><dt>{t("protocol")}</dt><dd>{selected.protocol}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("providerIssuer")}</dt><dd>{selected.issuer}</dd></div><div><dt>{t("providerRedirectUri")}</dt><dd>{selected.redirectUri}</dd></div><div><dt>{t("roles")}</dt><dd>{workspace.roles.filter((role) => role.principalType === "provider" && role.principal === selected.id).map((role) => role.name).join(" · ") || t("none")}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      </>}
    </WorkspaceDetail> : <WorkspaceCollection title={t("providers")} description={t("providerHint")} intro={<Alert status="info">{t("providerPreviewBoundary")}</Alert>} items={workspace.providers} keywords={(provider) => provider.issuer} createFocusRef={createTrigger} create={{ label: t("createProvider"), onClick: () => setEditing("new") }} workflow={editing === "new" ? <ProviderEditor workspace={workspace} onClose={() => setEditing(null)} /> : undefined} filter={{ label: t("protocol"), options: ["SAML", "OIDC"].map((value) => ({ value, label: value })), matches: (provider, value) => provider.protocol === value }} columns={[t("name"), t("protocol"), t("state"), t("created")]} row={(provider) => <><td><button className={styles.userLink} onClick={() => setSelectedId(provider.id)}>{provider.name}</button><small>{provider.issuer}</small></td><td>{provider.protocol}</td><td><Badge status={provider.enabled ? "success" : "neutral"}>{t(provider.enabled ? "enabled" : "disabled")}</Badge></td><td><WorkspaceTime value={provider.createdAt} /></td></>} />}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-provider", id: deleting.id })} /> : null}
  </>;
}

function RoleSsoMappingPreviewEditor({ mapping, workspace, onClose }: { mapping?: RoleSsoMappingPreview; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [phase, setPhase] = useState<"edit" | "review">("edit");
  const [issue, setIssue] = useState<RoleSsoMappingPreviewIssue | null>(null);
  const [name, setName] = useState(mapping?.name ?? "");
  const [assertionSubject, setAssertionSubject] = useState(mapping?.assertionSubject ?? "");
  const [providerId, setProviderId] = useState(mapping?.providerId ?? "");
  const [roleId, setRoleId] = useState(mapping?.roleId ?? "");
  const [enabled, setEnabled] = useState(mapping?.enabled ?? true);
  const provider = workspace.providers.find((entry) => entry.id === providerId);
  const role = workspace.roles.find((entry) => entry.id === roleId);
  const providerName = provider?.name ?? providerId;
  const roleName = role?.name ?? roleId;
  const clearIssue = (field: RoleSsoMappingPreviewIssue) => setIssue((current) => current === field || (field === "name" && current === "duplicate") ? null : current);
  const fieldId = issue === "duplicate" ? "name" : issue === "assertionSubject" ? "subject" : issue === "providerId" ? "provider" : issue === "roleId" ? "role" : issue;
  const issueMessage = issue ? t(issue === "name" ? "roleSsoMappingIssues.name" : issue === "duplicate" ? "roleSsoMappingIssues.duplicate" : issue === "assertionSubject" ? "roleSsoMappingIssues.assertionSubject" : issue === "providerId" ? "roleSsoMappingIssues.providerId" : "roleSsoMappingIssues.roleId") : undefined;
  async function submit() {
    if (phase === "edit") {
      const next = roleSsoMappingPreviewIssue({ id: mapping?.id, name, assertionSubject, providerId, roleId }, workspace);
      if (next) {
        setIssue(next);
        document.getElementById(`${id}-${next === "duplicate" ? "name" : next === "assertionSubject" ? "subject" : next === "providerId" ? "provider" : next === "roleId" ? "role" : next}`)?.focus();
        return false;
      }
      setIssue(null);
      setPhase("review");
      return false;
    }
    return Boolean(await access.executeWorkspace({ kind: "save-role-sso-mapping-preview", id: mapping?.id, name, assertionSubject, providerId, roleId, enabled }));
  }
  const title = phase === "review" ? t("roleSsoMappingReviewTitle", { name }) : mapping ? t("edit") + " · " + mapping.name : t("createRoleSsoMappingPreview");
  return <WorkspaceInlineForm title={title} backLabel={t(phase === "review" ? "userSsoBackToEdit" : mapping ? "backToRoleSsoMappingDetails" : "backToRoleSsoMappingDirectory")} onClose={onClose} onBack={phase === "review" ? () => { access.clearWorkspaceError(); setPhase("edit"); } : undefined} onSubmit={submit} submitLabel={t(phase === "review" ? "ssoConfirmMockSave" : "userSsoReview")}>
    {phase === "edit" ? <>
      <Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>
      <FormField id={id + "-name"} label={t("name")} error={fieldId === "name" ? issueMessage : undefined}><Input id={id + "-name"} required maxLength={64} invalid={fieldId === "name"} value={name} onChange={(event) => { setName(event.target.value); clearIssue("name"); }} /></FormField>
      <FormField id={id + "-subject"} label={t("roleSsoAssertionSubject")} hint={t("roleSsoAssertionSubjectHint")} error={issue === "assertionSubject" ? t("roleSsoMappingIssues.assertionSubject") : undefined}><Input id={id + "-subject"} aria-describedby={id + "-subject-hint"} required maxLength={256} invalid={issue === "assertionSubject"} value={assertionSubject} onChange={(event) => { setAssertionSubject(event.target.value); clearIssue("assertionSubject"); }} /></FormField>
      <FormField id={id + "-provider"} label={t("provider")} error={issue === "providerId" ? t("roleSsoMappingIssues.providerId") : undefined}><Select id={id + "-provider"} required invalid={issue === "providerId"} value={providerId} options={[{ value: "", label: t("ssoProvider") }, ...workspace.providers.map((provider) => ({ value: provider.id, label: provider.name }))]} onValueChange={(value) => { setProviderId(value); setRoleId(""); clearIssue("providerId"); clearIssue("roleId"); }} /></FormField>
      <FormField id={id + "-role"} label={t("roleSsoTargetRole")} error={issue === "roleId" ? t("roleSsoMappingIssues.roleId") : undefined}><Select id={id + "-role"} required invalid={issue === "roleId"} value={roleId} options={[{ value: "", label: t("roleSsoTargetRole") }, ...workspace.roles.filter((role) => role.principalType === "provider" && role.principal === providerId).map((role) => ({ value: role.id, label: role.name }))]} onValueChange={(value) => { setRoleId(value); clearIssue("roleId"); }} /></FormField>
      <Checkbox checked={enabled} onChange={(event) => setEnabled(event.target.checked)}>{t("enable")}</Checkbox>
    </> : <>
      <Alert status="warning">{t(enabled ? "roleSsoMappingEnableReviewHint" : "roleSsoMappingDisableReviewHint")}</Alert>
      <dl className={styles.facts}>
        <div><dt>{t("userSsoTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
        <div><dt>{t("name")}</dt><dd>{name}</dd></div>
        <div><dt>{t("provider")}</dt><dd>{providerName}</dd></div>
        <div><dt>{t("roleSsoAssertionSubject")}</dt><dd><code>{assertionSubject}</code></dd></div>
        <div><dt>{t("roleSsoTargetRole")}</dt><dd>{roleName}</dd></div>
        <div><dt>{t("userSsoPreviousState")}</dt><dd>{mapping ? t(mapping.enabled ? "enabled" : "disabled") : t("none")}</dd></div>
        <div><dt>{t("userSsoNewState")}</dt><dd>{t(enabled ? "enabled" : "disabled")}</dd></div>
      </dl>
      <RoleSsoJourneyPreview provider={provider} mapping={{ name, assertionSubject, enabled }} role={role} />
      <p className={styles.note}>{t("roleSsoMappingReviewBoundary")}</p>
    </>}
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
  const provider = (entry: RoleSsoMappingPreview) => workspace.providers.find((candidate) => candidate.id === entry.providerId);
  const role = (entry: RoleSsoMappingPreview) => workspace.roles.find((candidate) => candidate.id === entry.roleId);
  const providerName = (entry: RoleSsoMappingPreview) => workspace.providers.find((provider) => provider.id === entry.providerId)?.name ?? entry.providerId;
  const roleName = (entry: RoleSsoMappingPreview) => workspace.roles.find((role) => role.id === entry.roleId)?.name ?? entry.roleId;
  useLayoutEffect(() => {
    const previous = previousEditing.current;
    previousEditing.current = editing;
    if (!editing && previous) (previous === "new" ? createTrigger : editTrigger).current?.focus();
  }, [editing]);
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actionFocusRef={editTrigger} actions={editing ? undefined : { primary: { id: "edit", label: t("edit"), variant: "secondary", onSelect: () => setEditing(selected) }, secondary: [{ id: "delete", label: t("delete"), danger: true, onSelect: () => setDeleting(selected) }] }}>
      {editing && editing !== "new" ? <RoleSsoMappingPreviewEditor mapping={editing} workspace={workspace} onClose={() => setEditing(null)} /> : <><Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert><dl className={styles.facts}><div><dt>{t("roleSsoAssertionSubject")}</dt><dd>{selected.assertionSubject}</dd></div><div><dt>{t("provider")}</dt><dd>{providerName(selected)}</dd></div><div><dt>{t("roleSsoTargetRole")}</dt><dd>{roleName(selected)}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl><RoleSsoJourneyPreview provider={provider(selected)} mapping={selected} role={role(selected)} /></>}
    </WorkspaceDetail> : <WorkspaceCollection title={t("roleSsoMappings")} description={t("roleSsoMappingHint")} intro={<Alert status="info">{t("roleSsoMappingPreviewBoundary")}</Alert>} items={workspace.roleSsoMappings} keywords={(entry) => [entry.assertionSubject, providerName(entry), roleName(entry)].join(" ")} createFocusRef={createTrigger} create={{ label: t("createRoleSsoMappingPreview"), onClick: () => setEditing("new") }} workflow={editing === "new" ? <RoleSsoMappingPreviewEditor workspace={workspace} onClose={() => setEditing(null)} /> : undefined} columns={[t("name"), t("provider"), t("roleSsoTargetRole"), t("state")]} row={(entry) => <><td><button className={styles.userLink} onClick={() => setSelectedId(entry.id)}>{entry.name}</button><small>{entry.assertionSubject}</small></td><td>{providerName(entry)}</td><td>{roleName(entry)}</td><td><Badge status={entry.enabled ? "success" : "neutral"}>{t(entry.enabled ? "enabled" : "disabled")}</Badge></td></>} />}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-role-sso-mapping-preview", id: deleting.id })} /> : null}
  </>;
}
