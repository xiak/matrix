"use client";
import { useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Dialog, EmptyState, FormField, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { policyUsageCounts, policyVersionLimit, type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceTime } from "./AccessWorkspaceUi";
import { PolicyDocumentViewer } from "./PolicyDocumentViewer";
import { PolicyAuthoringWizard } from "./PolicyAuthoringWizard";
import { PolicyDirectory, usePolicyDescription } from "./PolicyDirectory";
import { PolicyCreationMethods, type PolicyCreationMethod } from "./PolicyCreationMethods";
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

function PolicyVersionHistory({ policy, usageCount, workspace, scene }: { policy: AccessPolicy; usageCount: number; workspace: AccessWorkspace; scene: AccountAccessScene }) {
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
      <Alert status="warning">{t("rollbackImpact", { count: usageCount })}</Alert>
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

type PolicyUseSubject = { id: string; name: string; view: "users" | "groups" | "roles" };

function PolicyUseSection({ title, hint, empty, subjects, onOpen }: { title: string; hint: string; empty: string; subjects: PolicyUseSubject[]; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace");
  return <section className={styles.stack}>
    <h3>{title} ({subjects.length})</h3>
    <p className={styles.note}>{hint}</p>
    {subjects.length ? <Table aria-label={title}><thead><tr><th>{t("name")}</th><th>{t("type")}</th></tr></thead><tbody>{subjects.map((subject) => <tr key={subject.view + subject.id}><td><button className={styles.userLink} onClick={() => onOpen(subject.view, subject.id)}>{subject.name}</button></td><td>{t(subject.view === "users" ? "subusers" : subject.view)}</td></tr>)}</tbody></Table> : <p className={styles.note}>{empty}</p>}
  </section>;
}

function PolicyUses({ policyId, workspace, scene, onOpen }: { policyId: string; workspace: AccessWorkspace; scene: AccountAccessScene; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace"), role = useTranslations("RoleWorkspace");
  const permissionSubjects: PolicyUseSubject[] = [
    ...scene.users.filter((user) => workspace.userPolicies[user.id]?.includes(policyId)).map((user) => ({ id: user.id, name: user.loginName, view: "users" as const })),
    ...workspace.groups.filter((group) => group.policyIds.includes(policyId)).map((group) => ({ id: group.id, name: group.name, view: "groups" as const })),
    ...workspace.roles.filter((entry) => entry.policyIds.includes(policyId)).map((entry) => ({ id: entry.id, name: entry.name, view: "roles" as const }))
  ];
  const boundarySubjects: PolicyUseSubject[] = [
    ...Object.entries(workspace.userBoundaries).filter(([, id]) => id === policyId).map(([id]) => ({ id, name: scene.users.find((user) => user.id === id)?.loginName ?? id, view: "users" as const })),
    ...workspace.roles.filter((entry) => entry.boundaryPolicyId === policyId).map((entry) => ({ id: entry.id, name: entry.name, view: "roles" as const }))
  ];
  return <div className={styles.stack}>
    <PolicyUseSection title={t("permissionUses")} hint={t("permissionUsesHint")} empty={t("noPermissionUses")} subjects={permissionSubjects} onOpen={onOpen} />
    <PolicyUseSection title={role("boundaryUses")} hint={role("boundaryHint")} empty={t("noBoundaryUses")} subjects={boundarySubjects} onOpen={onOpen} />
  </div>;
}

export function AccessPolicies({ workspace, scene, entityId, onCreate, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onCreate(method: PolicyCreationMethod): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyWizard");
  const summary = useTranslations("PolicyWorkspace");
  const describe = usePolicyDescription();
  const access = useAccountAccess();
  const [editing, setEditing] = useState<{ policy?: AccessPolicy; copy?: boolean } | null>(null);
  const [deleting, setDeleting] = useState<AccessPolicy | null>(null);
  const [associating, setAssociating] = useState<{ policies: AccessPolicy[]; additive?: boolean } | null>(null);
  const [editingDescription, setEditingDescription] = useState(false);
  const [choosingMethod, setChoosingMethod] = useState(false);
  const selected = workspace.policies.find((policy) => policy.id === entityId);
  const usage = selected ? policyUsageCounts(workspace, selected.id) : null;
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
      <Tabs.Root defaultValue="document"><Tabs.List aria-label={selected.name}><Tabs.Trigger value="document">{t("document")}</Tabs.Trigger><Tabs.Trigger value="versions">{t("versions")}</Tabs.Trigger><Tabs.Trigger value="usage">{t("usage")} ({usage!.total})</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="document"><PolicyDocumentViewer document={currentDocument(selected)} /></Tabs.Content>
        <Tabs.Content value="versions"><PolicyVersionHistory policy={selected} usageCount={usage!.total} workspace={workspace} scene={scene} /></Tabs.Content>
        <Tabs.Content value="usage"><PolicyUses policyId={selected.id} workspace={workspace} scene={scene} onOpen={onOpen} /></Tabs.Content>
      </Tabs.Root>
    </WorkspaceDetail> : <PolicyDirectory workspace={workspace} onCreate={() => setChoosingMethod(true)} onOpen={(id) => onOpen("policies", id)} onAssociate={(policies, additive) => setAssociating({ policies, additive })} />}
    {choosingMethod ? <PolicyCreationMethods onClose={() => setChoosingMethod(false)} onSelect={(method) => { setChoosingMethod(false); onCreate(method); }} /> : null}
    {associating ? <PolicyAssociationEditor {...associating} workspace={workspace} scene={scene} onClose={() => setAssociating(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} onClose={() => setDeleting(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-policy", id: deleting.id }); if (result && entityId === deleting.id) onOpen("policies"); return result; }} /> : null}
    {selected && editingDescription ? <PolicyDescriptionEditor policy={selected} onClose={() => setEditingDescription(false)} /> : null}
  </>;
}
