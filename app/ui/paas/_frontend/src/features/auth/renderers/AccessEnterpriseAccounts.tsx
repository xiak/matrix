"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, EmptyState, FormField, Input, Table, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, EnterpriseAccount } from "../domain/accessWorkspace";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceSelection } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function EnterpriseEditor({ enterprise, workspace, onClose }: { enterprise?: EnterpriseAccount; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(enterprise?.name ?? "");
  const [corporationId, setCorporationId] = useState(enterprise?.corporationId ?? "MOCK_CORP");
  const [visible, setVisible] = useState(enterprise?.visibleMemberIds ?? []);
  return <WorkspaceDialog title={t(enterprise ? "edit" : "connectEnterprise")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "save-enterprise", id: enterprise?.id, name, corporationId, visibleMemberIds: visible }))}>
    <Alert>{t("enterpriseMock")}</Alert>
    <FormField id={id + "-name"} label={t("enterpriseName")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-corp"} label={t("corporationId")}><Input id={id + "-corp"} required maxLength={128} value={corporationId} onChange={(event) => setCorporationId(event.target.value)} /></FormField>
    <WorkspaceSelection label={t("visibleMembers")} options={workspace.enterpriseMembers.map((member) => ({ ...member, description: member.department }))} value={visible} onChange={setVisible} />
  </WorkspaceDialog>;
}

function EnterpriseImport({ enterprise, workspace, onClose }: { enterprise: EnterpriseAccount; workspace: AccessWorkspace; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [members, setMembers] = useState<string[]>([]);
  return <WorkspaceDialog title={t("importMembers")} onClose={onClose} submitLabel={t("importMembers")} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "import-enterprise-members", id: enterprise.id, memberIds: members }))}>
    <Alert>{t("importHint")}</Alert><WorkspaceSelection label={t("selectMembers")} options={workspace.enterpriseMembers.filter((member) => enterprise.visibleMemberIds.includes(member.id) && !enterprise.importedMemberIds.includes(member.id)).map((member) => ({ ...member, description: member.department }))} value={members} onChange={setMembers} />
  </WorkspaceDialog>;
}

export function AccessEnterpriseAccounts({ workspace, onUsers }: { workspace: AccessWorkspace; onUsers(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [editing, setEditing] = useState<EnterpriseAccount | "new" | null>(null);
  const [deleting, setDeleting] = useState<EnterpriseAccount | null>(null);
  const [importing, setImporting] = useState<EnterpriseAccount | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = workspace.enterprises.find((enterprise) => enterprise.id === selectedId);
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => setSelectedId(null)} actions={<><Button onClick={() => setImporting(selected)}>{t("importMembers")}</Button><Button variant="secondary" onClick={() => setEditing(selected)}>{t("visibleMembers")}</Button><Button variant="ghost" onClick={() => setDeleting(selected)}>{t("disconnectEnterprise")}</Button></>}>
      <dl className={styles.facts}><div><dt>{t("corporationId")}</dt><dd>{selected.corporationId}</dd></div><div><dt>{t("type")}</dt><dd>{t("wecom")}</dd></div></dl><p className={styles.note}>{t("enterpriseMock")}</p>
      <Table aria-label={t("visibleMembers")}><thead><tr><th>{t("name")}</th><th>{t("department")}</th><th>{t("state")}</th></tr></thead><tbody>{workspace.enterpriseMembers.filter((member) => selected.visibleMemberIds.includes(member.id)).map((member) => <tr key={member.id}><td>{member.name}</td><td>{member.department}</td><td><Badge status={selected.importedMemberIds.includes(member.id) ? "success" : "neutral"}>{t(selected.importedMemberIds.includes(member.id) ? "imported" : "notImported")}</Badge></td></tr>)}</tbody></Table><div><Button variant="secondary" onClick={onUsers}>{t("subusers")}</Button></div>
    </WorkspaceDetail> : workspace.enterprises.length ? <WorkspaceCollection title={t("wecom")} description={t("enterpriseHint")} items={workspace.enterprises} keywords={(enterprise) => enterprise.corporationId} create={{ label: t("connectEnterprise"), onClick: () => setEditing("new") }} columns={[t("enterpriseName"), t("corporationId"), t("visibleMembers"), t("imported"), t("actions")]} row={(enterprise) => <><td><button className={styles.userLink} onClick={() => setSelectedId(enterprise.id)}>{enterprise.name}</button></td><td>{enterprise.corporationId}</td><td>{enterprise.visibleMemberIds.length}</td><td>{enterprise.importedMemberIds.length}</td><td><Button variant="ghost" size="small" onClick={() => setImporting(enterprise)}>{t("importMembers")}</Button></td></>} /> :
      <Card><Card.Header><Typography.Title as="h2" level={3}>{t("federations")} · {t("wecom")}</Typography.Title></Card.Header><Card.Body className={styles.stack}><p className={styles.note}>{t("enterpriseHint")}</p><p className={styles.flow}>{t("enterpriseFlow")}</p><EmptyState title={t("enterpriseStart")} description={t("enterpriseMock")} action={<Button onClick={() => setEditing("new")}>{t("connectEnterprise")}</Button>} /></Card.Body></Card>}
    {editing ? <EnterpriseEditor enterprise={editing === "new" ? undefined : editing} workspace={workspace} onClose={() => setEditing(null)} /> : null}
    {importing ? <EnterpriseImport enterprise={importing} workspace={workspace} onClose={() => setImporting(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-enterprise", id: deleting.id })} /> : null}
  </>;
}
