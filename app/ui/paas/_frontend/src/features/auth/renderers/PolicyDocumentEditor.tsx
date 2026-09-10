"use client";

import { useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, Button, Dialog, FormField, Select, Tabs, TextArea } from "@ui/xiak";
import { type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { analyzePolicyDocument, includesPermissionManagement, type PolicyDocument } from "../domain/policyDocument";
import { PolicyStatementEditor, statementService, type StatementDraft } from "./PolicyStatementEditor";
import { PolicyDiagnostics } from "./PolicyDiagnostics";
import styles from "./PolicyAuthoringWizard.module.css";

const visualStatements = (document: PolicyDocument): StatementDraft[] => document.statement.map((entry, index) => ({ id: index, effect: entry.effect, service: statementService(entry.action), condition: entry.condition ? structuredClone(entry.condition) : undefined, actions: entry.action.join("\n"), resources: entry.resource.join("\n") }));
const canRepresent = (document: PolicyDocument) => document.statement.every((statement) => [...statement.action, ...statement.resource].every((value) => !/[\r\n]/.test(value) && value === value.trim()));

/** JSON remains the authoritative draft. Visual rows never discard other statements. */
export function PolicyDocumentEditor({ text, onChange, policies, accountId, resources, hasDocumentChanges, error }: {
  resources: AccessWorkspace["testResources"];
  text: string; onChange(text: string): void; policies: readonly AccessPolicy[]; hasDocumentChanges: boolean; accountId: string; error?: string;
}) {
  const t = useTranslations("PolicyWizard");
  const w = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyWorkspace");
  const root = useRef<HTMLDivElement>(null);
  const id = useId();
  const analysis = useMemo(() => analyzePolicyDocument(text, accountId), [text, accountId]);
  const parsed = analysis.document;
  const [mode, setMode] = useState(parsed && !canRepresent(parsed) ? "json" : "visual");
  const [statements, setStatements] = useState<StatementDraft[]>(() => parsed ? visualStatements(parsed) : [{ id: 0, effect: "allow", service: "", actions: "", resources: "*" }]);
  const nextId = useRef(statements.length);
  const [templateId, setTemplateId] = useState("");
  const [replaceTemplate, setReplaceTemplate] = useState<AccessPolicy | null>(null);
  const template = policies.find((policy) => policy.id === templateId);
  function update(next: StatementDraft[]) {
    setStatements(next);
    onChange(JSON.stringify({ version: "1", statement: next.map((entry) => ({ effect: entry.effect, action: entry.actions.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), resource: entry.resources.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), ...(entry.condition ? { condition: entry.condition } : {}) })) }, null, 2));
  }
  function applyTemplate(policy: AccessPolicy) {
    const document = policy.versions.find((entry) => entry.id === policy.defaultVersion)!.document;
    onChange(JSON.stringify(document, null, 2));
    setStatements(visualStatements(document).map((entry) => ({ ...entry, id: nextId.current++ })));
    setMode(canRepresent(document) ? "visual" : "json");
    setReplaceTemplate(null);
  }
  return <div className={styles.stack} ref={root}>
    <div className={styles.template}>
      <FormField id={id + "-template"} label={t("template")}><Select id={id + "-template"} value={templateId} onValueChange={setTemplateId} placeholder={t("chooseTemplate")} options={policies.map((policy) => ({ value: policy.id, label: policy.name }))} /></FormField>
      <Button variant="secondary" disabled={!template} onClick={() => { if (!template) return; if (hasDocumentChanges) setReplaceTemplate(template); else applyTemplate(template); }}>{t("applyTemplate")}</Button>
    </div>
    <Tabs.Root value={mode} onValueChange={(next) => {
      if (next !== "json" && mode === "json" && parsed && canRepresent(parsed)) { setStatements(visualStatements(parsed)); nextId.current = parsed.statement.length; }
      setMode(next);
    }}><Tabs.List aria-label={w("document")}><Tabs.Trigger value="visual" disabled={mode === "json" && (!parsed || !canRepresent(parsed))}>{w("visual")}</Tabs.Trigger><Tabs.Trigger value="json">{w("json")}</Tabs.Trigger><Tabs.Trigger value="tags" disabled={mode === "json" && (!parsed || !canRepresent(parsed))}>{p("tagMethod")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content value={mode === "tags" ? "tags" : "visual"}><div className={styles.stack}>
        {mode === "tags" ? <Alert>{p("tagMethodHint")}</Alert> : null}
        {statements.map((statement, index) => <PolicyStatementEditor accountId={accountId} resources={resources} tagMode={mode === "tags"} key={statement.id} value={statement} index={index} total={statements.length} onChange={(value) => update(statements.map((entry, at) => at === index ? value : entry))} onRemove={() => update(statements.filter((entry) => entry.id !== statement.id))} onMove={(direction) => {
          const next = [...statements];
          [next[index], next[index + direction]] = [next[index + direction]!, next[index]!];
          update(next);
        }} />)}
        <div><Button variant="secondary" disabled={statements.length >= 50} onClick={() => update([...statements, { id: nextId.current++, effect: "allow", service: "", actions: "", resources: "*" }])}><Plus aria-hidden="true" />{t("addStatement")}</Button></div>
      </div></Tabs.Content>
      <Tabs.Content value="json"><FormField id={id + "-json"} label={w("document")} hint={w("policyFormat")}><TextArea id={id + "-json"} className={styles.codeEditor} aria-describedby={id + "-json-hint"} invalid={Boolean(error)} rows={18} maxLength={65536} value={text} spellCheck={false} onChange={(event) => onChange(event.target.value)} /></FormField>
        {!parsed || (parsed && !canRepresent(parsed)) ? <p className={styles.note}>{t("visualUnavailable")}</p> : null}
      </Tabs.Content>
    </Tabs.Root>
    {error ? <Alert status="danger" tabIndex={-1} data-policy-validation>{error}</Alert> : null}
    {parsed && includesPermissionManagement(parsed) ? <Alert status="warning">{w("highPrivilege")}</Alert> : null}
    <PolicyDiagnostics diagnostics={analysis.diagnostics} pristine={!hasDocumentChanges && !parsed && !error} onLocate={(path) => {
      const index = path.match(/^\$\.statement\[(\d+)\]/)?.[1];
      const target = mode !== "json" && index !== undefined ? root.current?.querySelector<HTMLElement>(`[data-policy-statement="${index}"]`) : root.current?.querySelector<HTMLTextAreaElement>("textarea");
      target?.focus({ preventScroll: true }); target?.scrollIntoView?.({ block: "center", inline: "nearest" });
    }} />
    {replaceTemplate ? <Dialog open title={t("replaceTemplate")} closeLabel={w("cancel")} onClose={() => setReplaceTemplate(null)} footer={<><Button variant="secondary" onClick={() => setReplaceTemplate(null)}>{t("keepDraft")}</Button><Button onClick={() => applyTemplate(replaceTemplate)}>{t("confirmReplace")}</Button></>}><p>{t("replaceTemplateHint", { name: replaceTemplate.name })}</p></Dialog> : null}
  </div>;
}
