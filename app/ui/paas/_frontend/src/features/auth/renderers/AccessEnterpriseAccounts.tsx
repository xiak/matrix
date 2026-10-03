"use client";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, EmptyState, FormField, Input, Table, Tabs, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, EnterpriseAccount } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceSelection } from "./AccessWorkspaceUi";
import { CrossAccountCollaborationPreview } from "./CrossAccountCollaborationPreview";
import styles from "./AccountAccessRenderer.module.css";

function EnterpriseEditor({ enterprise, workspace, onClose }: { enterprise?: EnterpriseAccount; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(enterprise?.name ?? "");
  const [corporationId, setCorporationId] = useState(enterprise?.corporationId ?? "MOCK_CORP");
  const [visible, setVisible] = useState(enterprise?.visibleMemberIds ?? []);
  return <WorkspaceInlineForm title={t(enterprise ? "edit" : "connectEnterprise")} backLabel={t(enterprise ? "backToEnterpriseDetails" : "backToEnterpriseDirectory")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-enterprise", id: enterprise?.id, name, corporationId, visibleMemberIds: visible }))}>
    <Alert>{t("enterpriseMock")}</Alert>
    <FormField id={id + "-name"} label={t("enterpriseName")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-corp"} label={t("corporationId")}><Input id={id + "-corp"} required maxLength={128} value={corporationId} onChange={(event) => setCorporationId(event.target.value)} /></FormField>
    <WorkspaceSelection label={t("visibleMembers")} options={workspace.enterpriseMembers.map((member) => ({ ...member, description: member.department }))} value={visible} onChange={setVisible} />
  </WorkspaceInlineForm>;
}

function EnterpriseImport({ enterprise, workspace, onClose }: { enterprise: EnterpriseAccount; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [members, setMembers] = useState<string[]>([]);
  return <WorkspaceInlineForm title={`${t("importMembers")} · ${enterprise.name}`} backLabel={t("backToEnterpriseDetails")} onClose={onClose} submitDisabled={!members.length} submitLabel={t("importMembers")} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "import-enterprise-members", id: enterprise.id, memberIds: members }))}>
    <Alert>{t("importHint")}</Alert><WorkspaceSelection label={t("selectMembers")} options={workspace.enterpriseMembers.filter((member) => enterprise.visibleMemberIds.includes(member.id) && !enterprise.importedMemberIds.includes(member.id)).map((member) => ({ ...member, description: member.department }))} value={members} onChange={setMembers} />
  </WorkspaceInlineForm>;
}

export function AccessEnterpriseAccounts({ workspace, onUsers }: { workspace: AccessWorkspace; onUsers(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [editing, setEditing] = useState<EnterpriseAccount | "new" | null>(null);
  const [deleting, setDeleting] = useState<EnterpriseAccount | null>(null);
  const [importing, setImporting] = useState<EnterpriseAccount | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [section, setSection] = useState<"enterprise" | "cross-account">("enterprise");
  const createAction = useRef<{ focus(): void }>(null);
  const emptyCreateAction = useRef<HTMLButtonElement>(null);
  const detailActions = useRef<{ focus(): void }>(null);
  const importAction = useRef<HTMLButtonElement>(null);
  const previousEditing = useRef<EnterpriseAccount | "new" | null>(null);
  const previousImporting = useRef<EnterpriseAccount | null>(null);
  const selected = workspace.enterprises.find((enterprise) => enterprise.id === selectedId);
  useLayoutEffect(() => {
    const previous = previousEditing.current;
    previousEditing.current = editing;
    if (!editing && previous) {
      if (previous === "new") (createAction.current ?? emptyCreateAction.current)?.focus();
      else detailActions.current?.focus();
    }
  }, [editing]);
  useLayoutEffect(() => {
    const previous = previousImporting.current;
    previousImporting.current = importing;
    if (!importing && previous) importAction.current?.focus();
  }, [importing]);
  const enterpriseView = selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} primaryActionRef={importAction} actionFocusRef={detailActions} actions={editing || importing ? undefined : { primary: { id: "import", label: t("importMembers"), onSelect: () => setImporting(selected) }, secondary: [{ id: "members", label: t("visibleMembers"), onSelect: () => setEditing(selected) }, { id: "disconnect", label: t("disconnectEnterprise"), danger: true, onSelect: () => setDeleting(selected) }] }}>
      {editing && editing !== "new" ? <EnterpriseEditor enterprise={editing} workspace={workspace} onClose={() => setEditing(null)} /> : importing ? <EnterpriseImport enterprise={importing} workspace={workspace} onClose={() => setImporting(null)} /> : <>
        <dl className={styles.facts}><div><dt>{t("corporationId")}</dt><dd>{selected.corporationId}</dd></div><div><dt>{t("type")}</dt><dd>{t("wecom")}</dd></div></dl><p className={styles.note}>{t("enterpriseMock")}</p>
        <Table aria-label={t("visibleMembers")} mobileLayout="stack"><thead><tr><th scope="col">{t("name")}</th><th scope="col">{t("department")}</th><th scope="col">{t("state")}</th></tr></thead><tbody>{workspace.enterpriseMembers.filter((member) => selected.visibleMemberIds.includes(member.id)).map((member) => <tr key={member.id}><td data-label={t("name")}>{member.name}</td><td data-label={t("department")}>{member.department}</td><td data-label={t("state")}><Badge status={selected.importedMemberIds.includes(member.id) ? "success" : "neutral"}>{t(selected.importedMemberIds.includes(member.id) ? "imported" : "notImported")}</Badge></td></tr>)}</tbody></Table><div><Button variant="secondary" onClick={onUsers}>{t("subusers")}</Button></div>
      </>}
    </WorkspaceDetail> : workspace.enterprises.length ? <WorkspaceCollection title={t("wecom")} description={t("enterpriseHint")} items={workspace.enterprises} keywords={(enterprise) => enterprise.corporationId} createFocusRef={createAction} create={{ label: t("connectEnterprise"), onClick: () => setEditing("new") }} workflow={editing === "new" ? <EnterpriseEditor workspace={workspace} onClose={() => setEditing(null)} /> : undefined} columns={[t("enterpriseName"), t("corporationId"), t("visibleMembers"), t("imported")]} row={(enterprise) => <><td><button className={styles.userLink} onClick={() => setSelectedId(enterprise.id)}>{enterprise.name}</button></td><td>{enterprise.corporationId}</td><td>{enterprise.visibleMemberIds.length}</td><td>{enterprise.importedMemberIds.length}</td></>} /> :
      <Card><Card.Header><Typography.Title as="h2" level={3}>{t("federations")} · {t("wecom")}</Typography.Title></Card.Header><Card.Body className={styles.stack}>{editing === "new" ? <EnterpriseEditor workspace={workspace} onClose={() => setEditing(null)} /> : <><p className={styles.note}>{t("enterpriseHint")}</p><p className={styles.flow}>{t("enterpriseFlow")}</p><EmptyState title={t("enterpriseStart")} description={t("enterpriseMock")} action={<Button ref={emptyCreateAction} onClick={() => setEditing("new")}>{t("connectEnterprise")}</Button>} /></>}</Card.Body></Card>;
  return <>
    {selected || editing || importing ? enterpriseView : <Tabs.Root value={section} onValueChange={(value) => setSection(value as typeof section)}>
      <Tabs.List aria-label={t("externalCollaborationSections")}>
        <Tabs.Trigger value="enterprise">{t("enterpriseMemberAccess")}</Tabs.Trigger>
        <Tabs.Trigger value="cross-account">{t("crossAccountCollaboration.tab")}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value="enterprise">{enterpriseView}</Tabs.Content>
      <Tabs.Content value="cross-account"><CrossAccountCollaborationPreview accountId={workspace.accountId} /></Tabs.Content>
    </Tabs.Root>}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-enterprise", id: deleting.id })} /> : null}
  </>;
}
