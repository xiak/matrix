"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Play } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Input, Select, Table } from "@ui/xiak";
import { evaluateUserAccess, evaluateRoleSessionAccess, type AccessTestRequest, type AccessTestResult } from "../domain/policyEvaluation";
import { parsePolicyResource, policyActions, policyServices, type PolicyService } from "../domain/policyLanguage";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import styles from "./PolicyAuthoringWizard.module.css";

export function AccessSimulator({ workspace, scene, entityId }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string }) {
  const t = useTranslations("AccessSimulator");
  const r = useTranslations("PolicyRules");
  const w = useTranslations("IamWorkspace");
  const id = useId();
  const [service, setService] = useState<PolicyService>("logs");
  const [subject, setSubject] = useState<"user" | "session">(() => workspace.roleSessions.some((session) => session.id === entityId) ? "session" : "user");
  const [request, setRequest] = useState<AccessTestRequest>(() => ({ principalId: entityId ?? scene.users[0]?.id ?? "", action: "logs:search", resourceId: "logs-production/payment", sourceIp: "192.0.2.42", at: new Date().toISOString() }));
  const [tested, setTested] = useState<{ result: AccessTestResult; workspace: AccessWorkspace } | null>(null);
  const [page, setPage] = useState(1);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const resources = workspace.testResources.map((entry) => ({ ...entry, parsed: parsePolicyResource(entry.reference, false) })).filter((entry) => entry.parsed?.service === service);
  const selected = resources.find((entry) => entry.id === request.resourceId);
  const actions = policyActions.filter((action) => action.service === service && action.resourceType === selected?.parsed?.type);
  const result = tested?.workspace === workspace ? tested.result : null;
  useEffect(() => {
    if (!tested || tested.workspace !== workspace || subject !== "session") return;
    const session = workspace.roleSessions.find((entry) => entry.id === request.principalId);
    const remaining = session ? Date.parse(session.expiresAt) - Date.now() : 0;
    if (remaining <= 0) return;
    const timer = window.setTimeout(() => setTested({ workspace, result: evaluateRoleSessionAccess(workspace, scene.users.map((user) => user.id), request.principalId, request, new Date().toISOString()) }), remaining + 1);
    return () => window.clearTimeout(timer);
  }, [tested, workspace, subject, request, scene.users]);
  useEffect(() => {
    if (!result) return;
    resultHeading.current?.focus({ preventScroll: true });
    resultHeading.current?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [result]);
  const pages = Math.max(1, Math.ceil((result?.evidence.length ?? 0) / 20));
  function change(patch: Partial<AccessTestRequest>) { setRequest((current) => ({ ...current, ...patch })); setTested(null); setPage(1); }
  if (!scene.users.length && !workspace.roleSessions.length) return <EmptyState title={t("noUsers")} description={t("noUsersHint")} />;
  return <div className={styles.root}><div className={styles.stack}>
    <Alert>{t("scope")}</Alert>
    {subject === "user" && request.principalId && !scene.users.some((user) => user.id === request.principalId) ? <Alert status="warning">{t("errors.unknownIdentity")}</Alert> : null}
    <Card><Card.Header><h2>{t("request")}</h2></Card.Header><Card.Body>
      <form className={styles.stack} onSubmit={(event) => { event.preventDefault(); setPage(1); const users = scene.users.map((user) => user.id); setTested({ workspace, result: subject === "user" ? evaluateUserAccess(workspace, users, request) : evaluateRoleSessionAccess(workspace, users, request.principalId, request, new Date().toISOString()) }); }}>
        <div className={styles.fields}>
          <FormField id={id + "-subject"} label={t("identityType")}><Select id={id + "-subject"} value={subject} options={[{ value: "user", label: t("user") }, { value: "session", label: t("roleSession") }]} onValueChange={(value) => { setSubject(value as "user" | "session"); change({ principalId: "" }); }} /></FormField>
          <FormField id={id + "-user"} label={t(subject === "user" ? "user" : "roleSession")}><Select id={id + "-user"} value={request.principalId} onValueChange={(principalId) => change({ principalId })} options={subject === "user" ? scene.users.map((user) => ({ value: user.id, label: user.loginName })) : workspace.roleSessions.map((session) => ({ value: session.id, label: (workspace.roles.find((role) => role.id === session.roleId)?.name ?? session.roleId) + " · " + session.id }))} /></FormField>
          <FormField id={id + "-service"} label={r("service")}><Select id={id + "-service"} value={service} options={policyServices.map((value) => ({ value, label: r(`services.${value}`) }))} onValueChange={(value) => { setService(value as PolicyService); change({ action: "", resourceId: "" }); }} /></FormField>
          <FormField id={id + "-resource"} label={t("resource")}><Select id={id + "-resource"} value={request.resourceId} placeholder={t("chooseResource")} options={resources.map((entry) => ({ value: entry.id, label: entry.parsed!.id + " · " + entry.parsed!.region }))} onValueChange={(resourceId) => change({ resourceId, action: "" })} /></FormField>
          <FormField id={id + "-action"} label={t("action")}><Select id={id + "-action"} value={request.action} placeholder={t("chooseAction")} options={actions.map((action) => ({ value: action.id, label: r(`actionNames.${action.id}`) + " · " + action.id }))} onValueChange={(action) => change({ action })} /></FormField>
          <FormField id={id + "-ip"} label={t("sourceIp")} hint={t("contextHint")}><Input id={id + "-ip"} maxLength={64} value={request.sourceIp ?? ""} placeholder="192.0.2.42" aria-describedby={id + "-ip-hint"} onChange={(event) => change({ sourceIp: event.target.value })} /></FormField>
          <FormField id={id + "-time"} label={t("time")}><Input id={id + "-time"} type="datetime-local" step="0.001" value={request.at?.replace(/Z$/, "") ?? ""} onChange={(event) => { const text = event.target.value; const date = new Date(text + "Z"); change({ at: text && Number.isFinite(date.getTime()) ? date.toISOString() : text }); }} /></FormField>
        </div>
        {selected ? <div className={styles.section}><code className={styles.resourcePreview}>{selected.reference}</code><div className={styles.actions}>{Object.entries(selected.tags ?? {}).map(([key, value]) => <Badge key={key}>{key} : {value}</Badge>)}</div></div> : null}
        <div><Button type="submit" disabled={!request.principalId || !request.action || !selected}><Play aria-hidden="true" />{t("run")}</Button></div>
      </form>
    </Card.Body></Card>
    {result ? <Card><Card.Header><h2 ref={resultHeading} tabIndex={-1}>{t("result")}</h2></Card.Header><Card.Body className={styles.stack}>
      <Alert status={result.decision === "allow" ? "success" : result.decision === "explicitDeny" || result.decision === "invalidRequest" ? "danger" : "warning"}><strong>{t(`decisions.${result.decision}`)}</strong><p>{result.error ? t(`errors.${result.error}`) : t(`explanations.${result.decision}`)}</p></Alert>
      {result.boundary ? <Alert>{t("boundaryResult", { name: workspace.policies.find((policy) => policy.id === result.boundary!.policyId)?.name ?? result.boundary.policyId, decision: t(`decisions.${result.boundary.decision}`) })}</Alert> : null}
      {result.evidence.length ? <><p className={styles.note}>{t("evidenceCount", { count: result.evidence.length })}</p><Table aria-label={t("evidence")}>
        <thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("source")}</th><th scope="col">{t("matching")}</th><th scope="col">{t("statementEffect")}</th></tr></thead>
        <tbody>{result.evidence.slice((page - 1) * 20, page * 20).map((entry, index) => <tr key={index}>
          <td><strong>{entry.policyName}</strong><small>{entry.version ? "v" + entry.version : "—"}{entry.statement ? " · " + w("statementNumber", { number: entry.statement }) : ""}</small></td>
          <td>{t(`sources.${entry.source}`)}{entry.groupId ? <small>{workspace.groups.find((group) => group.id === entry.groupId)?.name ?? entry.groupId}</small> : null}</td>
          <td>{t(`reasons.${entry.reason}`)}{entry.reason === "missingContext" ? <small>{entry.missing?.map((key) => t(`missing.${key}`)).join(" · ")}</small> : null}</td>
          <td>{entry.effect ? <Badge status={entry.reason === "matched" ? entry.effect === "deny" ? "danger" : "success" : undefined}>{w(entry.effect)}</Badge> : "—"}</td>
        </tr>)}</tbody>
      </Table>{pages > 1 ? <div className={styles.row}><span>{w("page", { page, pages })}</span><div className={styles.actions}><Button variant="secondary" disabled={page <= 1} onClick={() => setPage((current) => current - 1)}>{w("previous")}</Button><Button variant="secondary" disabled={page >= pages} onClick={() => setPage((current) => current + 1)}>{w("next")}</Button></div></div> : null}</> : result.decision === "implicitDeny" ? <EmptyState title={t("noGrants")} description={t("noGrantsHint")} /> : null}
    </Card.Body></Card> : <p className={styles.note}>{t("beforeRun")}</p>}
  </div></div>;
}
