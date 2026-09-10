"use client";
import { useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Dialog, EmptyState, FormField, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { policyAssociationCount, policyVersionLimit, type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceTime } from "./AccessWorkspaceUi";
import { PolicyDocumentViewer } from "./PolicyDocumentViewer";
import { PolicyAuthoringWizard } from "./PolicyAuthoringWizard";
import { PolicyDirectory, usePolicyDescription } from "./PolicyDirectory";
import { PolicyAssociationEditor, PolicyAffectedIdentities } from "./PolicyAssociationReview";
import { PolicyDocumentChanges } from "./PolicyDocumentChanges";
import policyStyles from "./PolicyWorkspace.module.css";
import styles from "./AccountAccessRenderer.module.css";

const currentDocument = (policy: AccessPolicy) => policy.versions.find((version) => version.id === policy.defaultVersion)!.document;

function PolicyDescriptionEditor({ policy, onClose }: { policy: AccessPolicy; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [description, setDescription] = useState(policy.description);
  return <WorkspaceDialog title={t("editDescription")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-policy-description", id: policy.id, description }))}>
    <p className={styles.note}>{t("descriptionOnly")}</p>
    <FormField id={id} label={t("description")}><TextArea id={id} rows={3} maxLength={256} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField>
  </WorkspaceDialog>;
}

function PolicyVersionHistory({ policy, associationCount, workspace, scene }: { policy: AccessPolicy; associationCount: number; workspace: AccessWorkspace; scene: AccountAccessScene }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const p = useTranslations("PolicyWorkspace");
  const history = useRef<HTMLDivElement>(null);
  const [intent, setIntent] = useState<{ action: "inspect" | "activate" | "delete"; version: number } | null>(null);
  const revision = policy.versions.find((entry) => entry.id === intent?.version);
  const close = () => setIntent(null);
  return <div className={styles.stack} ref={history}>
    <p className={styles.note}>{t("versionHistoryHint", { count: policy.versions.length, limit: policyVersionLimit })}</p>
    {policy.kind === "custom" && policy.versions.length >= policyVersionLimit ? <Alert status="warning">{t("errors.versionLimit")}</Alert> : null}
    <Table aria-label={t("versions")}>
      <thead><tr><th scope="col">{t("version")}</th><th scope="col">{t("created")}</th><th scope="col">{t("actions")}</th></tr></thead>
      <tbody>{[...policy.versions].reverse().map((item) => <tr key={item.id}>
        <td>v{item.id} {item.id === policy.defaultVersion ? <Badge status="success">{t("defaultVersion")}</Badge> : null}</td>
        <td><WorkspaceTime value={item.createdAt} /></td>
        <td><div className={styles.actions}>
          <Button variant="ghost" size="small" aria-label={t("inspectVersion", { version: item.id })} onClick={() => setIntent({ action: "inspect", version: item.id })}>{t("viewContent")}</Button>
          {policy.kind === "custom" && item.id !== policy.defaultVersion ? <>
            <Button variant="ghost" size="small" aria-label={t("activateVersion", { version: item.id })} onClick={() => setIntent({ action: "activate", version: item.id })}>{t("setDefault")}</Button>
            <Button variant="ghost" size="small" aria-label={t("deleteVersion", { version: item.id })} onClick={() => setIntent({ action: "delete", version: item.id })}>{t("delete")}</Button>
          </> : null}
        </div></td>
      </tr>)}</tbody>
    </Table>
    {revision && intent?.action === "inspect" ? <Dialog open size="wide" title={t("inspectVersion", { version: revision.id })} closeLabel={t("close")} onClose={close} footer={<Button onClick={close} variant="secondary">{t("close")}</Button>}>
      <p className={styles.note}>{t("inspectVersionHint")}</p><PolicyDocumentViewer document={revision.document} />
    </Dialog> : null}
    {revision && intent?.action === "activate" ? <WorkspaceDialog fallbackFocusRef={history} size="wide" title={t("activateVersion", { version: revision.id })} onClose={close} submitLabel={t("setDefault")} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "set-policy-version", id: policy.id, version: revision.id }))}>
      <Alert status="warning">{t("rollbackImpact", { count: associationCount })}</Alert>
      <PolicyDocumentChanges before={currentDocument(policy)} after={revision.document} />
      <PolicyAffectedIdentities policyId={policy.id} workspace={workspace} scene={scene} />
      <details className={policyStyles.details}><summary>{p("compareJson")}</summary><div className={styles.policyComparison}>
        <section className={styles.stack}><h3 className={styles.stepTitle}>{t("currentRevision", { version: policy.defaultVersion })}</h3>
          <pre className={styles.code} role="region" aria-label={t("currentRevision", { version: policy.defaultVersion })} tabIndex={0}>{JSON.stringify(currentDocument(policy), null, 2)}</pre>
        </section>
        <section className={styles.stack}><h3 className={styles.stepTitle}>{t("targetRevision", { version: revision.id })}</h3>
          <pre className={styles.code} role="region" aria-label={t("targetRevision", { version: revision.id })} tabIndex={0}>{JSON.stringify(revision.document, null, 2)}</pre>
        </section>
      </div></details>
    </WorkspaceDialog> : null}
    {revision && intent?.action === "delete" ? <WorkspaceDialog fallbackFocusRef={history} size="wide" title={t("deleteVersion", { version: revision.id })} onClose={close} submitLabel={t("deleteConfirm")} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "delete-policy-version", id: policy.id, version: revision.id }))}>
      <Alert status="warning">{t("deleteVersionHint", { version: revision.id })}</Alert>
      <PolicyDocumentViewer document={revision.document} />
    </WorkspaceDialog> : null}
  </div>;
}

function PolicyBoundaryUses({ policyId, workspace, scene, onOpen }: { policyId: string; workspace: AccessWorkspace; scene: AccountAccessScene; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const users = Object.entries(workspace.userBoundaries).filter(([, id]) => id === policyId).map(([id]) => ({ id, name: scene.users.find((user) => user.id === id)?.loginName ?? id, view: "users" as const }));
  const roles = workspace.roles.filter((role) => role.boundaryPolicyId === policyId).map((role) => ({ id: role.id, name: role.name, view: "roles" as const }));
  if (!users.length && !roles.length) return null;
  return <section className={styles.stack}><h3>{t("boundaryUses")}</h3><p className={styles.note}>{t("boundaryHint")}</p><Table aria-label={t("boundaryUses")}><thead><tr><th>{w("name")}</th><th>{w("type")}</th></tr></thead><tbody>{[...users, ...roles].map((subject) => <tr key={subject.view + subject.id}><td><button className={styles.userLink} onClick={() => onOpen(subject.view, subject.id)}>{subject.name}</button></td><td>{w(subject.view === "users" ? "subusers" : "roles")}</td></tr>)}</tbody></Table></section>;
}

export function AccessPolicies({ workspace, scene, entityId, onCreate, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onCreate(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyWizard");
  const summary = useTranslations("PolicyWorkspace");
  const describe = usePolicyDescription();
  const access = useAccountAccess();
  const [editing, setEditing] = useState<{ policy?: AccessPolicy; copy?: boolean } | null>(null);
  const [deleting, setDeleting] = useState<AccessPolicy | null>(null);
  const [associating, setAssociating] = useState<{ policies: AccessPolicy[]; additive?: boolean } | null>(null);
  const [editingDescription, setEditingDescription] = useState(false);
  const selected = workspace.policies.find((policy) => policy.id === entityId);
  if (entityId && !selected) return <EmptyState title={t("entityUnavailable")} description={t("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("policies")}>{t("back")}</Button>} />;
  if (editing) return <PolicyAuthoringWizard {...editing} workspace={workspace} scene={scene} onBack={() => setEditing(null)} onDone={(id) => { setEditing(null); onOpen("policies", id); }} />;
  return <>
    {access.workspaceError && !associating && !deleting && !editingDescription ? <Alert status="danger">{t(`errors.${access.workspaceError}`)}</Alert> : null}
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => onOpen("policies")} actions={<>
      <Button onClick={() => setAssociating({ policies: [selected] })}>{t("associateTargets")}</Button>
      {selected.kind === "custom" ? <Button onClick={() => setEditing({ policy: selected })} variant="secondary">{t("edit")}</Button> : null}
      <Button onClick={() => setEditing({ policy: selected, copy: true })} variant="secondary">{t("copyPolicy")}</Button>
      {selected.kind === "custom" ? <Button onClick={() => setDeleting(selected)} variant="ghost">{t("delete")}</Button> : null}
    </>}>
      <div className={styles.actions}><Badge>{t(selected.kind)}</Badge><p className={styles.note}>{describe(selected)}</p>{selected.kind === "custom" ? <Button variant="ghost" size="small" onClick={() => setEditingDescription(true)}>{t("editDescription")}</Button> : null}</div>
      <dl className={policyStyles.facts}><div><dt>{summary("policyId")}</dt><dd>{selected.id}</dd></div><div><dt>{summary("defaultVersion")}</dt><dd>v{selected.defaultVersion}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      {selected.tags.length ? <section aria-label={p("metadataTags")} className={styles.actions}><span className={styles.note}>{p("metadataTags")}</span>{selected.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}</section> : null}
      {selected.kind === "system" ? <p className={styles.note}>{t("systemReadOnly")}</p> : null}
      {includesPermissionManagement(currentDocument(selected)) ? <Alert status="warning">{t("highPrivilege")}</Alert> : null}
      <Tabs.Root defaultValue="document"><Tabs.List aria-label={selected.name}><Tabs.Trigger value="document">{t("document")}</Tabs.Trigger><Tabs.Trigger value="versions">{t("versions")}</Tabs.Trigger><Tabs.Trigger value="associations">{t("associations")} ({policyAssociationCount(workspace, selected.id)})</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="document"><PolicyDocumentViewer document={currentDocument(selected)} /></Tabs.Content>
        <Tabs.Content value="versions"><PolicyVersionHistory policy={selected} associationCount={policyAssociationCount(workspace, selected.id)} workspace={workspace} scene={scene} /></Tabs.Content>
        <Tabs.Content value="associations"><Table aria-label={t("associations")}><thead><tr><th>{t("name")}</th><th>{t("type")}</th></tr></thead><tbody>{scene.users.filter((user) => workspace.userPolicies[user.id]?.includes(selected.id)).map((user) => <tr key={user.id}><td><button className={styles.userLink} onClick={() => onOpen("users", user.id)}>{user.loginName}</button></td><td>{t("subusers")}</td></tr>)}{workspace.groups.filter((group) => group.policyIds.includes(selected.id)).map((group) => <tr key={group.id}><td><button className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{group.name}</button></td><td>{t("groups")}</td></tr>)}{workspace.roles.filter((role) => role.policyIds.includes(selected.id)).map((role) => <tr key={role.id}><td><button className={styles.userLink} onClick={() => onOpen("roles", role.id)}>{role.name}</button></td><td>{t("roles")}</td></tr>)}</tbody></Table>{!policyAssociationCount(workspace, selected.id) ? <p className={styles.note}>{t("empty")}</p> : null}<PolicyBoundaryUses policyId={selected.id} workspace={workspace} scene={scene} onOpen={onOpen} /></Tabs.Content>
      </Tabs.Root>
    </WorkspaceDetail> : <PolicyDirectory workspace={workspace} onCreate={onCreate} onOpen={(id) => onOpen("policies", id)} onAssociate={(policies, additive) => setAssociating({ policies, additive })} />}
    {associating ? <PolicyAssociationEditor {...associating} workspace={workspace} scene={scene} onClose={() => setAssociating(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-policy", id: deleting.id }); if (result && entityId === deleting.id) onOpen("policies"); return result; }} /> : null}
    {selected && editingDescription ? <PolicyDescriptionEditor policy={selected} onClose={() => setEditingDescription(false)} /> : null}
  </>;
}
