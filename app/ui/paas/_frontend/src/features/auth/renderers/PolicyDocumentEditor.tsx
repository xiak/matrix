"use client";

import { useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, Button, Dialog, FormField, Select, Tabs, TextArea } from "@ui/xiak";
import { type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { analyzePolicyDocument, includesPermissionManagement, type PolicyDocument } from "../domain/policyDocument";
import { actionPatternValid, parsePolicyResource, utcTimeValid } from "../domain/policyLanguage";
import { PolicyStatementEditor, statementService, type StatementDraft } from "./PolicyStatementEditor";
import { PolicyDiagnostics } from "./PolicyDiagnostics";
import { policyCreationMethod, type PolicyCreationMethod } from "./PolicyCreationMethods";
import { canEditPolicyFeatures, PolicyFeatureEditor } from "./PolicyFeatureEditor";
import styles from "./PolicyAuthoringWizard.module.css";

const visualStatements = (document: PolicyDocument): StatementDraft[] => document.statement.map((entry, index) => ({ id: index, effect: entry.effect, service: statementService(entry.action), condition: entry.condition ? structuredClone(entry.condition) : undefined, actions: entry.action.join("\n"), resources: entry.resource.join("\n") }));

const objectFields = (value: unknown, keys: readonly string[]): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every((key) => keys.includes(key)));
const formLines = (value: unknown, limit: number): value is string[] => Array.isArray(value) && value.length <= limit &&
  value.every((line) => typeof line === "string" && !/[\r\n]/.test(line) && line === line.trim());

/** Projection capability, not authorization validity. Empty/incomplete form values
 * can be edited; unknown fields and values the controls would lose stay in JSON.
 * Saving and diagnostics continue to use the strict domain parser independently. */
function readEditorDraft(text: string): PolicyDocument | null {
  if (text.length > 65536) return null;
  let draft: unknown;
  try { draft = JSON.parse(text); } catch { return null; }
  if (!objectFields(draft, ["version", "statement"]) || draft.version !== "1" || !Array.isArray(draft.statement) || draft.statement.length > 50) return null;
  for (const statement of draft.statement) {
    if (!objectFields(statement, ["effect", "action", "resource", "condition"]) ||
      (statement.effect !== "allow" && statement.effect !== "deny") ||
      !formLines(statement.action, 100) || !statement.action.every(actionPatternValid) ||
      !formLines(statement.resource, 50) || statement.resource.some((value) => value !== "*" && !parsePolicyResource(value)) ||
      (statement.resource.includes("*") && statement.resource.length !== 1)) return null;
    const condition = statement.condition;
    if (condition === undefined) continue;
    if (!objectFields(condition, ["sourceIp", "resourceTag", "notBefore", "notAfter"])) return null;
    if (condition.sourceIp !== undefined && !formLines(condition.sourceIp, 10)) return null;
    if (condition.resourceTag !== undefined && (!Array.isArray(condition.resourceTag) || condition.resourceTag.length > 10 ||
      condition.resourceTag.some((tag) => !objectFields(tag, ["key", "value"]) || typeof tag.key !== "string" || typeof tag.value !== "string" ||
        /[\r\n]/.test(tag.key + tag.value)))) return null;
    for (const key of ["notBefore", "notAfter"] as const) {
      const value = condition[key];
      if (value !== undefined && (typeof value !== "string" || (value !== "" && !utcTimeValid(value)))) return null;
    }
  }
  return draft as PolicyDocument;
}

/** JSON remains the authoritative draft. Visual rows never discard other statements. */
export function PolicyDocumentEditor({ text, onChange, policies, accountId, resources, hasDocumentChanges, error, initialMode = "visual", onModeChange }: {
  resources: AccessWorkspace["testResources"];
  text: string; onChange(text: string): void; policies: readonly AccessPolicy[]; hasDocumentChanges: boolean; accountId: string; error?: string;
  initialMode?: PolicyCreationMethod; onModeChange?(mode: PolicyCreationMethod): void;
}) {
  const t = useTranslations("PolicyWizard");
  const w = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyWorkspace");
  const root = useRef<HTMLDivElement>(null);
  const id = useId();
  const analysis = useMemo(() => analyzePolicyDocument(text, accountId), [text, accountId]);
  const parsed = analysis.document;
  const editorDraft = useMemo(() => readEditorDraft(text), [text]);
  const [mode, setMode] = useState<PolicyCreationMethod>(editorDraft ? initialMode : "json");
  const [statements, setStatements] = useState<StatementDraft[]>(() => editorDraft ? visualStatements(editorDraft) : []);
  const nextId = useRef(statements.length);
  const [templateId, setTemplateId] = useState("");
  const [replaceTemplate, setReplaceTemplate] = useState<AccessPolicy | null>(null);
  const template = policies.find((policy) => policy.id === templateId);
  function changeMode(next: PolicyCreationMethod) { setMode(next); onModeChange?.(next); }
  const draftDocument = (next: StatementDraft[]): PolicyDocument => ({ version: "1", statement: next.map((entry) => ({ effect: entry.effect, action: entry.actions.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), resource: entry.resources.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), ...(entry.condition ? { condition: entry.condition } : {}) })) });
  const featureDocument = mode === "json" ? editorDraft : draftDocument(statements);
  const featuresAvailable = Boolean(featureDocument && canEditPolicyFeatures(featureDocument));
  function update(next: StatementDraft[]) {
    setStatements(next);
    onChange(JSON.stringify(draftDocument(next), null, 2));
  }
  function applyTemplate(policy: AccessPolicy) {
    const document = policy.versions.find((entry) => entry.id === policy.defaultVersion)!.document;
    const nextText = JSON.stringify(document, null, 2);
    onChange(nextText);
    setStatements(visualStatements(document).map((entry) => ({ ...entry, id: nextId.current++ })));
    changeMode(readEditorDraft(nextText) ? "visual" : "json");
    setReplaceTemplate(null);
  }
  return <div className={styles.stack} ref={root}>
    <div className={styles.template}>
      <FormField id={id + "-template"} label={t("template")}><Select id={id + "-template"} value={templateId} onValueChange={setTemplateId} placeholder={t("chooseTemplate")} options={policies.map((policy) => ({ value: policy.id, label: policy.name }))} /></FormField>
      <Button variant="secondary" disabled={!template} onClick={() => { if (!template) return; if (hasDocumentChanges) setReplaceTemplate(template); else applyTemplate(template); }}>{t("applyTemplate")}</Button>
    </div>
    <Tabs.Root value={mode} onValueChange={(next) => {
      if (next !== "json" && mode === "json" && editorDraft) { setStatements(visualStatements(editorDraft)); nextId.current = editorDraft.statement.length; }
      changeMode(policyCreationMethod(next));
    }}><Tabs.List aria-label={w("document")}><Tabs.Trigger value="visual" disabled={mode === "json" && !editorDraft}>{w("visual")}</Tabs.Trigger><Tabs.Trigger value="json">{w("json")}</Tabs.Trigger><Tabs.Trigger value="tags" disabled={mode === "json" && !editorDraft}>{p("tagMethod")}</Tabs.Trigger><Tabs.Trigger value="features" disabled={!featuresAvailable}>{t("featureMethod")}</Tabs.Trigger></Tabs.List>
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
        {!editorDraft ? <p className={styles.note}>{t("visualUnavailable")}</p> : null}
      </Tabs.Content>
      <Tabs.Content value="features">{featureDocument && featuresAvailable ? <PolicyFeatureEditor document={featureDocument} onChange={(document) => {
        setStatements(visualStatements(document).map((entry) => ({ ...entry, id: nextId.current++ })));
        onChange(JSON.stringify(document, null, 2));
      }} /> : null}</Tabs.Content>
    </Tabs.Root>
    {featureDocument && !featuresAvailable ? <p className={styles.note}>{t("featureUnavailable")}</p> : null}
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
