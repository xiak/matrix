"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Checkbox, Dialog, FormField, Input, Select, Table } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessKey, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function KeyCreation({ scene, workspace, onCreated, onClose }: { scene: AccountAccessScene; workspace: AccessWorkspace; onCreated(key: { id: string; secret: string }): void; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [ownerId, setOwnerId] = useState(scene.users.length === 1 ? scene.users[0]!.id : "");
  const [description, setDescription] = useState("");
  return <WorkspaceDialog title={t("createKey")} onClose={onClose} submitLabel={t("createKey")} onSubmit={async () => {
    const result = await access.executeWorkspace({ kind: "create-key", ownerId, description });
    if (result?.issuedKey) { onCreated(result.issuedKey); return true; }
    return false;
  }}>
    <Alert status="warning">{t("keyHint")}</Alert>
    <FormField id={id + "-owner"} label={t("owner")}><Select id={id + "-owner"} required value={ownerId} options={[{ value: "", label: t("owner") }, ...scene.users.filter((user) => user.enabled).map((user) => ({ value: user.id, label: user.loginName + " · " + workspace.keys.filter((key) => key.ownerId === user.id).length + "/2", disabled: workspace.keys.filter((key) => key.ownerId === user.id).length >= 2 }))]} onValueChange={(value) => setOwnerId(value)} /></FormField>
    <FormField id={id + "-description"} label={t("description")}><Input id={id + "-description"} maxLength={256} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField>
    {!scene.users.length ? <p className={styles.note}>{t("keyPrimary")}</p> : null}
  </WorkspaceDialog>;
}

function IssuedKey({ value, onClose }: { value: { id: string; secret: string }; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const [acknowledged, setAcknowledged] = useState(false);
  return <Dialog open title={t("keyCreated")} closeLabel={t("close")} onClose={onClose} footer={<Button disabled={!acknowledged} onClick={onClose}>{t("done")}</Button>}>
    <div className={styles.stack}><Alert status="warning">{t("keyWarning")}</Alert><div><p className={styles.fieldCaption}>{t("keyId")}</p><AccountIdentifier label={t("keyId")} value={value.id} /></div><div><p className={styles.fieldCaption}>{t("keySecret")}</p><code className={styles.keySecret}>{value.secret}</code></div><Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("keyAcknowledge")}</Checkbox></div>
  </Dialog>;
}

export function AccessCredentials({ workspace, scene, embedded = false }: { workspace: AccessWorkspace; scene: AccountAccessScene; embedded?: boolean }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<{ id: string; secret: string } | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [changing, setChanging] = useState<AccessKey | null>(null);
  const [deleting, setDeleting] = useState<AccessKey | null>(null);
  const selected = workspace.keys.find((key) => key.id === selectedId);
  const owner = (key: AccessKey) => scene.users.find((user) => user.id === key.ownerId)?.loginName ?? key.ownerId;
  const rowActions = (key: AccessKey) => <div className={styles.actions}><Button size="small" variant="ghost" onClick={() => setChanging(key)}>{t(key.enabled ? "disable" : "enable")}</Button><Button disabled={key.enabled} title={key.enabled ? t("errors.disableFirst") : undefined} size="small" variant="ghost" onClick={() => setDeleting(key)}>{t("delete")}</Button></div>;
  return <>
    {selected ? <WorkspaceDetail embedded={embedded} title={selected.id} onBack={() => setSelectedId(null)} actions={rowActions(selected)}>
      <dl className={styles.facts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.id} /></dd></div><div><dt>{t("owner")}</dt><dd>{owner(selected)}</dd></div><div><dt>{t("description")}</dt><dd>{selected.description || t("none")}</dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.enabled ? "success" : "neutral"}>{t(selected.enabled ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div><div><dt>{t("lastUsed")}</dt><dd><WorkspaceTime value={selected.lastUsedAt} /></dd></div></dl>
      <h3 className={styles.stepTitle}>{t("keyLogs")}</h3>{selected.lastUsedAt ? <Table aria-label={t("keyLogs")}><thead><tr><th>{t("time")}</th><th>{t("event")}</th><th>{t("state")}</th></tr></thead><tbody><tr><td><WorkspaceTime value={selected.lastUsedAt} /></td><td>MOCK · ListResources</td><td><Badge status="success">200 · MOCK</Badge></td></tr></tbody></Table> : <p className={styles.note}>{t("noKeyLogs")}</p>}
    </WorkspaceDetail> : <WorkspaceCollection embedded={embedded} title={t("keys")} description={t("keyHint")} items={workspace.keys.map((key) => ({ ...key, name: key.id }))} keywords={(key) => owner(key) + " " + key.description} filter={{ label: t("state"), options: [{ value: "enabled", label: t("enabled") }, { value: "disabled", label: t("disabled") }], matches: (key, value) => key.enabled === (value === "enabled") }} create={{ label: t("createKey"), onClick: () => setCreating(true) }} columns={[t("keyId"), t("owner"), t("state"), t("lastUsed"), t("actions")]} row={(key) => <><td><button className={styles.userLink} onClick={() => setSelectedId(key.id)}>{key.id}</button><small>{key.description}</small></td><td>{owner(key)}</td><td><Badge status={key.enabled ? "success" : "neutral"}>{t(key.enabled ? "enabled" : "disabled")}</Badge></td><td><WorkspaceTime value={key.lastUsedAt} /></td><td>{rowActions(key)}</td></>} />}
    {creating ? <KeyCreation scene={scene} workspace={workspace} onCreated={setIssued} onClose={() => setCreating(false)} /> : null}
    {issued ? <IssuedKey value={issued} onClose={() => setIssued(null)} /> : null}
    {changing ? <WorkspaceDialog title={t("changeStateTitle", { action: t(changing.enabled ? "disable" : "enable"), name: changing.id })} onClose={() => setChanging(null)} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "set-key-status", id: changing.id, enabled: !changing.enabled }))}><Alert status="warning">{t("changeStateHint")}</Alert><strong>{owner(changing)}</strong></WorkspaceDialog> : null}
    {deleting ? <WorkspaceDelete name={deleting.id} onClose={() => setDeleting(null)} onConfirm={() => access.executeWorkspace({ kind: "delete-key", id: deleting.id })} /> : null}
  </>;
}
