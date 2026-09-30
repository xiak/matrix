"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ClipboardList } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Input, Select, Table, TablePagination } from "@ui/xiak";
import { parsePolicyResource } from "../domain/policyLanguage";
import { policyActions, policyServices, previewAuthorizationCatalogVersion, type PolicyConditionKey, type PolicyService } from "../domain/previewAuthorizationCatalog";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessView } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import styles from "./PolicyAuthoringWizard.module.css";

type ConfigurationSource = { policyId: string; source: "direct" | "group" | "role" | "boundary"; groupId?: string };
type WorksheetRequest = { principalId: string; action: string; resourceId: string; sourceIp?: string; at?: string };
type WorksheetError = "unknownIdentity" | "unknownResource" | "crossTenant" | "unknownAction" | "actionResourceMismatch" | "unavailableSession";
type ConfigurationRow = ConfigurationSource & {
  policyName: string;
  version?: number;
  statement?: number;
  effect?: "allow" | "deny";
  conditionKeys: string[];
  state: "loaded" | "unavailable";
};
type ConfigurationWorksheet = { error?: WorksheetError; rows: ConfigurationRow[]; boundaryId?: string };

function configurationSources(workspace: AccessWorkspace, scene: AccountAccessScene, subject: "user" | "session", principalId: string) {
  if (subject === "user") {
    if (!scene.users.some((user) => user.id === principalId)) return { error: "unknownIdentity" as const, sources: [] as ConfigurationSource[] };
    const sources: ConfigurationSource[] = [
      ...(workspace.userPolicies[principalId] ?? []).map((policyId) => ({ policyId, source: "direct" as const })),
      ...workspace.groups.filter((group) => group.memberIds.includes(principalId)).flatMap((group) => group.policyIds.map((policyId) => ({ policyId, source: "group" as const, groupId: group.id })))
    ];
    return { sources, boundaryId: workspace.userBoundaries[principalId] };
  }
  const session = workspace.roleSessions.find((entry) => entry.id === principalId);
  const role = session && workspace.roles.find((entry) => entry.id === session.roleId);
  if (!session || !role) return { error: "unavailableSession" as const, sources: [] as ConfigurationSource[] };
  return { sources: role.policyIds.map((policyId) => ({ policyId, source: "role" as const })), boundaryId: role.boundaryPolicyId };
}

function buildConfigurationWorksheet(workspace: AccessWorkspace, scene: AccountAccessScene, subject: "user" | "session", request: WorksheetRequest): ConfigurationWorksheet {
  const configuration = configurationSources(workspace, scene, subject, request.principalId);
  if (configuration.error) return { error: configuration.error, rows: [] };
  const fixture = workspace.testResources.find((entry) => entry.id === request.resourceId);
  const resource = fixture && parsePolicyResource(fixture.reference, false);
  if (!fixture || !resource) return { error: "unknownResource", rows: [] };
  if (resource.tenant !== workspace.accountId) return { error: "crossTenant", rows: [] };
  const action = policyActions.find((entry) => entry.id === request.action);
  if (!action) return { error: "unknownAction", rows: [] };
  if (action.service !== resource.service || action.resourceType !== resource.type) return { error: "actionResourceMismatch", rows: [] };

  const allSources = configuration.boundaryId
    ? [...configuration.sources, { policyId: configuration.boundaryId, source: "boundary" as const }]
    : configuration.sources;
  const rows = allSources.flatMap<ConfigurationRow>((source) => {
    const policy = workspace.policies.find((entry) => entry.id === source.policyId);
    const version = policy?.versions.find((entry) => entry.id === policy.defaultVersion);
    if (!policy || !version) return [{ ...source, policyName: policy?.name ?? source.policyId, conditionKeys: [], state: "unavailable" }];
    return version.document.statement.map((statement, index) => ({
      ...source,
      policyName: policy.name,
      version: version.id,
      statement: index + 1,
      effect: statement.effect,
      conditionKeys: Object.keys(statement.condition ?? {}),
      state: "loaded" as const
    }));
  });
  return { rows, boundaryId: configuration.boundaryId };
}

export function PolicyCoveragePreview({ workspace, scene, entityId, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("PolicyCoveragePreview");
  const r = useTranslations("PolicyRules");
  const w = useTranslations("IamWorkspace");
  const id = useId();
  const [subject, setSubject] = useState<"user" | "session">(() => workspace.roleSessions.some((session) => session.id === entityId) ? "session" : "user");
  const [request, setRequest] = useState<WorksheetRequest>(() => {
    const example = workspace.testRequests.find((entry) => scene.users.some((user) => user.id === entry.request.principalId))?.request;
    const resource = workspace.testResources.find((entry) => parsePolicyResource(entry.reference, false));
    const parsed = resource && parsePolicyResource(resource.reference, false);
    const action = policyActions.find((entry) => entry.service === parsed?.service && entry.resourceType === parsed?.type);
    return { principalId: entityId ?? example?.principalId ?? scene.users[0]?.id ?? "", action: example?.action ?? action?.id ?? "", resourceId: example?.resourceId ?? resource?.id ?? "", sourceIp: "192.0.2.42", at: new Date().toISOString() };
  });
  const [service, setService] = useState<PolicyService>(() => parsePolicyResource(workspace.testResources.find((entry) => entry.id === request.resourceId)?.reference ?? "", false)?.service ?? policyServices[0]);
  const [exampleId, setExampleId] = useState<AccessWorkspace["testRequests"][number]["id"] | "">("");
  const [checked, setChecked] = useState<{ worksheet: ConfigurationWorksheet; workspace: AccessWorkspace } | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const inventory = useMemo(() => workspace.testResources.map((entry) => ({ ...entry, parsed: parsePolicyResource(entry.reference, false) })), [workspace.testResources]);
  const resources = inventory.filter((entry) => entry.parsed?.service === service);
  const selected = resources.find((entry) => entry.id === request.resourceId);
  const actions = policyActions.filter((action) => action.service === service && action.resourceType === selected?.parsed?.type);
  const worksheet = checked?.workspace === workspace ? checked.worksheet : null;
  const selectedUser = subject === "user" ? scene.users.find((user) => user.id === request.principalId) : undefined;
  const selectedRole = subject === "session" ? workspace.roles.find((role) => role.id === workspace.roleSessions.find((session) => session.id === request.principalId)?.roleId) : undefined;
  const policyCount = worksheet ? new Set(worksheet.rows.map((entry) => entry.policyId)).size : 0;
  const coverageStages = worksheet ? [
    { id: "input", title: t("coverage.input"), state: worksheet.error ? t("coverage.states.needsAttention") : t("coverage.states.recorded"), hint: worksheet.error ? t(`errors.${worksheet.error}`) : t("coverage.inputHint") },
    { id: "documents", title: t("coverage.documents"), state: worksheet.error ? t("coverage.states.skipped") : worksheet.rows.length ? t("coverage.states.referenced") : t("coverage.states.none"), hint: worksheet.error ? t("coverage.skippedHint") : worksheet.rows.length ? t("coverage.documentsHint", { policies: policyCount, statements: worksheet.rows.length }) : t("coverage.noDocumentsHint") },
    { id: "boundary", title: t("coverage.boundary"), state: worksheet.error ? t("coverage.states.skipped") : worksheet.boundaryId ? t("coverage.states.configured") : t("coverage.states.notConfigured"), hint: worksheet.error ? t("coverage.skippedHint") : worksheet.boundaryId ? t("coverage.boundaryConfiguredHint") : t("coverage.boundaryNotConfiguredHint") },
    { id: "runtime", title: t("coverage.runtime"), state: "NOT_EVALUATED", hint: t("coverage.runtimeHint") }
  ] : [];
  useEffect(() => {
    if (!worksheet) return;
    resultHeading.current?.focus({ preventScroll: true });
    resultHeading.current?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [worksheet]);
  const pages = Math.max(1, Math.ceil((worksheet?.rows.length ?? 0) / pageSize));
  const currentPage = Math.min(page, pages);
  function change(patch: Partial<WorksheetRequest>) { setRequest((current) => ({ ...current, ...patch })); setChecked(null); setPage(1); setExampleId(""); }
  if (!scene.users.length && !workspace.roleSessions.length) return <EmptyState title={t("noUsers")} description={t("noUsersHint")} />;
  return <div className={styles.root}><div className={styles.stack}>
    <p className={styles.note}>{t("scope")}</p>
    {subject === "user" && request.principalId && !scene.users.some((user) => user.id === request.principalId) ? <Alert status="warning">{t("errors.unknownIdentity")}</Alert> : null}
    <Card><Card.Header><h2>{t("request")}</h2></Card.Header><Card.Body>
      <form className={styles.stack} onSubmit={(event) => { event.preventDefault(); setPage(1); setChecked({ workspace, worksheet: buildConfigurationWorksheet(workspace, scene, subject, request) }); }}>
        <p className={styles.note}>{t("profileFixture", { version: previewAuthorizationCatalogVersion })}</p>
        <p className={styles.note}>{t("contextProvenance")}</p>
        {subject === "user" && workspace.testRequests.length ? <FormField id={id + "-example"} label={t("example")} hint={exampleId ? t(`examples.${exampleId}.hint`) : t("exampleHint")}><Select id={id + "-example"} aria-describedby={id + "-example-hint"} value={exampleId} placeholder={t("chooseExample")} options={workspace.testRequests.map((entry) => ({ value: entry.id, label: t(`examples.${entry.id}.label`), disabled: !scene.users.some((user) => user.id === entry.request.principalId) || !inventory.some((resource) => resource.id === entry.request.resourceId && resource.parsed) }))} onValueChange={(value) => {
          const example = workspace.testRequests.find((entry) => entry.id === value);
          const resource = inventory.find((entry) => entry.id === example?.request.resourceId);
          if (!example || !resource?.parsed) return;
          setService(resource.parsed.service); change(example.request); setExampleId(example.id);
        }} /></FormField> : null}
        <div className={styles.fields}>
          <FormField id={id + "-subject"} label={t("identityType")}><Select id={id + "-subject"} value={subject} options={[{ value: "user", label: t("user") }, { value: "session", label: t("roleSession") }]} onValueChange={(value) => { setSubject(value as "user" | "session"); change({ principalId: "" }); }} /></FormField>
          <FormField id={id + "-user"} label={t(subject === "user" ? "user" : "roleSession")}><Select id={id + "-user"} value={request.principalId} onValueChange={(principalId) => change({ principalId })} options={subject === "user" ? scene.users.map((user) => ({ value: user.id, label: user.loginName })) : workspace.roleSessions.map((session) => ({ value: session.id, label: (workspace.roles.find((role) => role.id === session.roleId)?.name ?? session.roleId) + " · " + session.id }))} /></FormField>
          <FormField id={id + "-service"} label={r("service")}><Select id={id + "-service"} value={service} options={policyServices.map((value) => ({ value, label: r(`services.${value}`) }))} onValueChange={(value) => { setService(value as PolicyService); change({ action: "", resourceId: "" }); }} /></FormField>
          <FormField id={id + "-resource"} label={t("resource")}><Select id={id + "-resource"} value={request.resourceId} placeholder={t("chooseResource")} options={resources.map((entry) => ({ value: entry.id, label: entry.parsed!.id + " · " + entry.parsed!.region }))} onValueChange={(resourceId) => {
            const target = inventory.find((entry) => entry.id === resourceId)?.parsed;
            const compatible = policyActions.some((action) => action.id === request.action && action.service === target?.service && action.resourceType === target?.type);
            change({ resourceId, action: compatible ? request.action : "" });
          }} /></FormField>
          <FormField id={id + "-action"} label={t("action")}><Select id={id + "-action"} value={request.action} placeholder={t("chooseAction")} options={actions.map((action) => ({ value: action.id, label: r(`actionNames.${action.id}`) + " · " + action.id }))} onValueChange={(action) => change({ action })} /></FormField>
          <FormField id={id + "-ip"} label={t("sourceIp")} hint={t("contextHint")}><Input id={id + "-ip"} maxLength={64} value={request.sourceIp ?? ""} placeholder="192.0.2.42" aria-describedby={id + "-ip-hint"} onChange={(event) => change({ sourceIp: event.target.value })} /></FormField>
          <FormField id={id + "-time"} label={t("time")}><Input id={id + "-time"} type="datetime-local" step="0.001" value={request.at?.replace(/Z$/, "") ?? ""} onChange={(event) => { const text = event.target.value; const date = new Date(text + "Z"); change({ at: text && Number.isFinite(date.getTime()) ? date.toISOString() : text }); }} /></FormField>
        </div>
        {selectedUser && !selectedUser.enabled ? <Alert status="warning">{t("disabledUser")}</Alert> : null}
        {selected ? <div className={styles.section}><code className={styles.resourcePreview}>{selected.reference}</code><div className={styles.actions}>{Object.entries(selected.tags ?? {}).map(([key, value]) => <Badge key={key}>{key} : {value}</Badge>)}</div></div> : null}
        <div><Button type="submit" disabled={!request.principalId || !request.action || !selected}><ClipboardList aria-hidden="true" />{t("run")}</Button></div>
      </form>
    </Card.Body></Card>
    {worksheet ? <Card><Card.Header><h2 ref={resultHeading} tabIndex={-1}>{t("result")}</h2></Card.Header><Card.Body className={styles.stack}>
      <Alert status={worksheet.error ? "warning" : "info"}><strong>{t(worksheet.error ? "worksheetNeedsAttention" : "worksheetReady")}</strong><p>{t(worksheet.error ? "worksheetNeedsAttentionHint" : "worksheetReadyHint")}</p></Alert>
      <section className={styles.coverage} aria-labelledby={id + "-coverage"}>
        <div className={styles.coverageHeading}><h3 id={id + "-coverage"}>{t("coverage.title")}</h3><p>{t("coverage.hint")}</p></div>
        <ol className={styles.coverageStages}>{coverageStages.map((stage, index) => <li key={stage.id} className={styles.coverageStage}>
          <span className={styles.coverageNumber} aria-hidden="true">{index + 1}</span>
          <div><div className={styles.coverageStageHeading}><strong>{stage.title}</strong><Badge>{stage.state}</Badge></div><p>{stage.hint}</p></div>
        </li>)}</ol>
      </section>
      <div className={styles.evaluationScope}>
        <p>{t("notEvaluated")}</p>
        {subject === "session" ? <p>{t("sessionScope")}</p> : null}
        {selectedUser ? <Button variant="ghost" size="small" onClick={() => onOpen("users", selectedUser.id)}>{t("inspectUser", { name: selectedUser.loginName })}</Button> : selectedRole ? <Button variant="ghost" size="small" onClick={() => onOpen("roles", selectedRole.id)}>{t("inspectRole")}</Button> : null}
      </div>
      {!worksheet.error && worksheet.rows.length ? <p className={styles.note}>{t("evidenceCount", { count: worksheet.rows.length })}</p> : !worksheet.error ? <EmptyState title={t("noStatements")} description={t("noStatementsHint")} /> : null}
    </Card.Body>{!worksheet.error && worksheet.rows.length ? <><Table aria-label={t("evidence")} mobileLayout="stack">
        <thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("source")}</th><th scope="col">{t("configurationState")}</th><th scope="col">{t("statement")}</th></tr></thead>
        <tbody>{worksheet.rows.slice((currentPage - 1) * pageSize, currentPage * pageSize).map((entry, index) => <tr key={`${entry.policyId}:${entry.source}:${entry.groupId ?? ""}:${entry.statement ?? index}`}>
          <td data-label={t("policy")}>{workspace.policies.some((policy) => policy.id === entry.policyId) ? <button className={styles.evidenceLink} onClick={() => onOpen("policies", entry.policyId)}>{entry.policyName}</button> : entry.policyName}<small>{entry.version ? "v" + entry.version : "—"}{entry.statement ? " · " + w("statementNumber", { number: entry.statement }) : ""}</small></td>
          <td data-label={t("source")}>{t(`sources.${entry.source}`)}{entry.groupId ? <small><button className={styles.evidenceLink} onClick={() => onOpen("groups", entry.groupId)}>{workspace.groups.find((group) => group.id === entry.groupId)?.name ?? entry.groupId}</button></small> : null}</td>
          <td data-label={t("configurationState")}><Badge>{t(`configurationStates.${entry.state}`)}</Badge></td>
          <td data-label={t("statement")}>{entry.effect ? <Badge>{t(`effects.${entry.effect}`)}</Badge> : "—"}<small>{entry.conditionKeys.length ? t("conditionFields", { conditions: entry.conditionKeys.map((key) => t(`conditionNames.${key as PolicyConditionKey}`)).join(" · ") }) : t("noConditionFields")}</small></td>
        </tr>)}</tbody>
      </Table><Table.Footer><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: w("page", { page: currentPage, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : null}</Card> : <p className={styles.note}>{t("beforeRun")}</p>}
  </div></div>;
}
