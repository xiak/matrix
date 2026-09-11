"use client";

import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { Alert, Badge, Button, Checkbox, Dialog, FormField, Input, SearchInput, Select, TagEditor, TextArea } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { PolicyCondition } from "../domain/policyDocument";
import { expandPolicyActions, formatPolicyResource, parsePolicyResource, policyActions, policyConditionsForActions, policyServices, type PolicyAction, type PolicyConditionKey, type PolicyResource, type PolicyService } from "../domain/policyLanguage";
import styles from "./PolicyAuthoringWizard.module.css";

export type StatementDraft = { id: number; effect: "allow" | "deny"; service: string; actions: string; resources: string; condition?: PolicyCondition };
export function statementService(actions: readonly string[]): string {
  const services = [...new Set(actions.map((action) => action.split(":")[0]))];
  return services.length === 1 && policyServices.includes(services[0] as PolicyService) ? services[0]! : actions.length ? "custom" : "";
}
const lines = (text: string) => text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);

function ResourceScopeEditor({ text, actions, service, accountId, resources, onChange }: {
  resources: AccessWorkspace["testResources"];
  text: string; actions: readonly string[]; service: string; accountId: string; onChange(text: string): void;
}) {
  const t = useTranslations("PolicyRules");
  const id = useId();
  const p = useTranslations("PolicyWorkspace");
  const [resourceId, setResourceId] = useState("");
  const expandedActions = expandPolicyActions(actions);
  const inventory = resources.flatMap((entry) => { const resource = parsePolicyResource(entry.reference, false); return resource && resource.tenant === accountId && expandedActions.some((action) => action.service === resource.service && action.resourceType === resource.type && action.granularity === "resource") ? [{ ...entry, resource }] : []; });
  const resourceActions = expandedActions.filter((action) => action.granularity === "resource");
  const availableServices = [...new Set(resourceActions.map((action) => action.service))];
  const typesFor = (value: string) => [...new Set(resourceActions.filter((action) => action.service === value).map((action) => action.resourceType))];
  const defaultService = availableServices.find((value) => value === service) ?? availableServices[0];
  const blank = (): PolicyResource | null => defaultService ? ({ service: defaultService, tenant: accountId, region: "*", type: typesFor(defaultService)[0]!, id: "" }) : null;
  const [rows, setRows] = useState<PolicyResource[]>(() => lines(text).map((line) => parsePolicyResource(line)).filter((value): value is PolicyResource => Boolean(value)));
  const all = text === "*";
  const accountLevel = expandedActions.some((action) => action.granularity === "operation");
  function update(next: PolicyResource[]) { setRows(next); onChange(next.map(formatPolicyResource).join("\n")); }
  return <section className={styles.section}>
    <FormField id={id + "-scope"} label={t("scope")}><Select id={id + "-scope"} value={all ? "all" : "specific"} options={[{ value: "all", label: t("allResources") }, { value: "specific", label: t("specificResources"), disabled: accountLevel || !resourceActions.length }]} onValueChange={(value) => {
      if (value === "all") onChange("*");
      else { const next = blank(); if (rows.length) update(rows); else if (next) update([next]); }
    }} /></FormField>
    {accountLevel ? <Alert>{t("accountLevel")}</Alert> : !expandedActions.length ? <p className={styles.note}>{p("selectActionsFirst")}</p> : null}
    {!all ? <>
      <div className={styles.template}><FormField id={id + "-inventory"} label={p("resourceInventory")}><Select id={id + "-inventory"} value={resourceId} onValueChange={setResourceId} placeholder={p("chooseResource")} options={inventory.map((entry) => ({ value: entry.id, label: entry.resource.id + " · " + entry.resource.region }))} /></FormField><Button variant="secondary" disabled={rows.filter((row) => row.id.trim()).length >= 50 || !inventory.some((entry) => entry.id === resourceId)} onClick={() => { const selected = inventory.find((entry) => entry.id === resourceId); if (!selected) return; const reference = selected.reference; update([...rows.filter((row) => row.id.trim() && formatPolicyResource(row) !== reference), selected.resource]); setResourceId(""); }}>{p("addInventory")}</Button></div>
      <p className={styles.note}>{p("inventoryHint")}</p>
      <p className={styles.note}>{t("resourceHint")}</p>
      <p className={styles.note}>{t("resourceTenant")} · <code>{accountId}</code></p>
      {rows.map((row, index) => <div className={styles.resourceRow} key={index}>
        <FormField id={id + "-service-" + index} label={t("resourceService", { number: index + 1 })}><Select id={id + "-service-" + index} value={row.service} options={[...new Set([...availableServices, row.service])].map((value) => ({ value, label: t(`services.${value}`), disabled: !availableServices.includes(value) }))} onValueChange={(value) => update(rows.map((entry, at) => at === index ? { ...entry, service: value as PolicyService, type: typesFor(value)[0]! } : entry))} /></FormField>
        <FormField id={id + "-type-" + index} label={t("resourceType", { number: index + 1 })}><Select id={id + "-type-" + index} value={row.type} options={[...new Set([...typesFor(row.service), row.type])].map((value) => ({ value, label: t(`types.${value as PolicyAction["resourceType"]}`), disabled: !typesFor(row.service).some((type) => type === value) }))} onValueChange={(value) => update(rows.map((entry, at) => at === index ? { ...entry, type: value } : entry))} /></FormField>
        <FormField id={id + "-region-" + index} label={t("resourceRegion", { number: index + 1 })}><Input id={id + "-region-" + index} value={row.region} maxLength={64} onChange={(event) => update(rows.map((entry, at) => at === index ? { ...entry, region: event.target.value } : entry))} /></FormField>
        <FormField id={id + "-resource-" + index} label={t("resourceId", { number: index + 1 })}><Input id={id + "-resource-" + index} value={row.id} maxLength={128} onChange={(event) => update(rows.map((entry, at) => at === index ? { ...entry, id: event.target.value } : entry))} /></FormField>
        <Button iconOnly variant="ghost" aria-label={t("removeResource", { number: index + 1 })} disabled={rows.length === 1} onClick={() => update(rows.filter((_, at) => at !== index))}><Trash2 aria-hidden="true" /></Button>
        <code className={styles.resourcePreview}>{formatPolicyResource(row)}</code>
      </div>)}
      <div><Button variant="secondary" disabled={rows.length >= 50 || !defaultService} onClick={() => { const next = blank(); if (next) update([...rows, next]); }}><Plus aria-hidden="true" />{t("addResource")}</Button></div>
    </> : null}
  </section>;
}

function ConditionsEditor({ value, actions, tagMode, onChange }: { value?: PolicyCondition; actions: readonly PolicyAction[]; tagMode: boolean; onChange(value: PolicyCondition | undefined): void }) {
  const t = useTranslations("PolicyRules");
  const u = useTranslations("UserWizard");
  const p = useTranslations("PolicyWorkspace");
  const id = useId();
  const supported = policyConditionsForActions(actions);
  const available = (key: PolicyConditionKey) => supported.includes(key);
  const incompatible = value && Object.keys(value).some((key) => !supported.includes(key as PolicyConditionKey));
  function update(key: keyof PolicyCondition, next: PolicyCondition[keyof PolicyCondition] | undefined) {
    const result = { ...value, [key]: next };
    if (next === undefined) delete result[key];
    onChange(Object.keys(result).length ? result : undefined);
  }
  return <section className={styles.section}>
    <h3>{t(tagMode ? "tagConditions" : "conditions")}</h3><p className={styles.note}>{t("conditionsHint")}</p>
    <p className={styles.note}>{actions.length ? p("supportedConditions", { conditions: supported.map((key) => t(`conditionNames.${key}`)).join(" · ") || t("noConditions") }) : p("selectActionsFirst")}</p>
    {incompatible ? <Alert status="warning">{p("incompatibleConditions")}</Alert> : null}
    <Checkbox disabled={!available("sourceIp") && !value?.sourceIp} checked={value?.sourceIp !== undefined} onChange={(event) => update("sourceIp", event.target.checked ? [""] : undefined)}>{t("useIp")}</Checkbox>
    {value?.sourceIp ? <FormField id={id + "-ip"} label={t("sourceIp")} hint={t("ipHint")}><TextArea id={id + "-ip"} value={value.sourceIp.join("\n")} maxLength={900} rows={2} aria-describedby={id + "-ip-hint"} onChange={(event) => update("sourceIp", event.target.value.split(/\r?\n/))} /></FormField> : null}
    <Checkbox disabled={!available("resourceTag") && !value?.resourceTag} checked={value?.resourceTag !== undefined} onChange={(event) => update("resourceTag", event.target.checked ? [{ key: "", value: "" }] : undefined)}>{t("useTags")}</Checkbox>
    {tagMode && !value?.resourceTag ? <p className={styles.note}>{p("tagMethodHint")}</p> : null}
    {value?.resourceTag ? <div><p className={styles.note}>{t("resourceTags")}</p><TagEditor value={value.resourceTag} onChange={(next) => update("resourceTag", next)} labels={{ key: (index) => u("tagKey", { index }), value: (index) => u("tagValue", { index }), remove: (index) => u("removeTag", { index }), add: u("addTag"), empty: t("emptyTags"), count: u("tagCount", { count: value.resourceTag.length }) }} /></div> : null}
    <div className={styles.fields}>{(["notBefore", "notAfter"] as const).map((key) => <div className={styles.conditionTime} key={key}>
      <Checkbox disabled={!available(key) && value?.[key] === undefined} checked={value?.[key] !== undefined} onChange={(event) => update(key, event.target.checked ? "" : undefined)}>{t(key === "notBefore" ? "useStart" : "useEnd")}</Checkbox>
      {value?.[key] !== undefined ? <FormField id={id + key} label={t(key)}><Input id={id + key} type="datetime-local" step="0.001" value={value[key].replace(/Z$/, "")} onChange={(event) => { const text = event.target.value; const date = new Date(text + "Z"); update(key, text && Number.isFinite(date.getTime()) ? date.toISOString() : text); }} /></FormField> : null}
    </div>)}</div>
  </section>;
}

export function PolicyStatementEditor({ value, index, total, accountId, resources, tagMode, onChange, onMove, onRemove }: {
  resources: AccessWorkspace["testResources"]; tagMode: boolean;
  value: StatementDraft; index: number; total: number; accountId: string; onChange(value: StatementDraft): void; onMove(direction: -1 | 1): void; onRemove(): void;
}) {
  const t = useTranslations("PolicyRules");
  const w = useTranslations("IamWorkspace");
  const wizard = useTranslations("PolicyWizard");
  const p = useTranslations("PolicyWorkspace");
  const id = useId();
  const [query, setQuery] = useState("");
  const [level, setLevel] = useState("all");
  const [changingService, setChangingService] = useState<string | null>(null);
  const selected = expandPolicyActions(lines(value.actions)).map((action) => action.id);
  const available = policyActions.filter((action) => action.service === value.service && (!tagMode || (action.conditions as readonly PolicyConditionKey[]).includes("resourceTag") || selected.includes(action.id)) && (level === "all" || action.level === level) && (action.id + " " + t(`actionNames.${action.id}`)).toLowerCase().includes(query.toLowerCase().trim()));
  function service(next: string) { onChange({ ...value, service: next, actions: "", resources: "*" }); setQuery(""); setLevel("all"); setChangingService(null); }
  return <section className={styles.statement} tabIndex={-1} data-policy-statement={index} aria-label={w("statementNumber", { number: index + 1 })}>
    <header className={styles.row}><h3>{w("statementNumber", { number: index + 1 })}</h3><div className={styles.actions}>
      <Button iconOnly size="small" variant="ghost" disabled={index === 0} aria-label={wizard("moveUp", { number: index + 1 })} onClick={() => onMove(-1)}><ArrowUp aria-hidden="true" /></Button>
      <Button iconOnly size="small" variant="ghost" disabled={index === total - 1} aria-label={wizard("moveDown", { number: index + 1 })} onClick={() => onMove(1)}><ArrowDown aria-hidden="true" /></Button>
      <Button iconOnly size="small" variant="ghost" disabled={total === 1} aria-label={wizard("removeStatement", { number: index + 1 })} onClick={onRemove}><Trash2 aria-hidden="true" /></Button>
    </div></header>
    <div className={styles.fields}>
      <FormField id={id + "-service"} label={t("service")}><Select id={id + "-service"} value={value.service} placeholder={t("chooseService")} options={[...policyServices.map((service) => ({ value: service, label: t(`services.${service}`) })), { value: "custom", label: t("custom") }]} onValueChange={(next) => {
        if (next === "custom") onChange({ ...value, service: next });
        else if (value.actions.trim() || value.resources !== "*") setChangingService(next);
        else service(next);
      }} /></FormField>
      <FormField id={id + "-effect"} label={w("effect")}><Select id={id + "-effect"} value={value.effect} options={(["allow", "deny"] as const).map((effect) => ({ value: effect, label: w(effect) }))} onValueChange={(effect) => onChange({ ...value, effect: effect as StatementDraft["effect"] })} /></FormField>
    </div>
    {value.service === "custom" ? <FormField id={id + "-actions"} label={w("action")} hint={wizard("actionsHint")}><TextArea id={id + "-actions"} aria-describedby={id + "-actions-hint"} rows={4} maxLength={16000} value={value.actions} spellCheck={false} onChange={(event) => onChange({ ...value, actions: event.target.value })} /></FormField> : value.service ? <section className={styles.actionPicker} aria-label={t("actions")}>
      <div className={styles.actionToolbar}><SearchInput aria-label={t("actionSearch")} placeholder={t("actionSearch")} value={query} onChange={(event) => setQuery(event.target.value)} /><Select aria-label={w("type")} value={level} onValueChange={setLevel} options={[{ value: "all", label: w("all") }, ...(["read", "list", "write", "permissions"] as const).map((value) => ({ value, label: t(`levels.${value}`) }))]} /></div>
      <div className={styles.row}><span className={styles.note}>{t("selectedActions", { count: selected.length })}</span><div className={styles.actions}><Button variant="ghost" size="small" disabled={!available.length} onClick={() => onChange({ ...value, actions: [...new Set([...selected, ...available.map((action) => action.id)])].join("\n") })}>{t("allActions")}</Button><Button variant="ghost" size="small" disabled={!selected.length} onClick={() => onChange({ ...value, actions: "" })}>{t("clearActions")}</Button></div></div>
      <div className={styles.actionOptions}>{available.map((action) => <Checkbox key={action.id} aria-label={action.id} checked={selected.includes(action.id)} onChange={(event) => onChange({ ...value, actions: (event.target.checked ? [...selected, action.id] : selected.filter((entry) => entry !== action.id)).join("\n") })}><span className={styles.actionCopy}><strong>{t(`actionNames.${action.id}`)}</strong><code>{action.id}</code><span className={styles.note}>{t(`actionDescriptions.${action.id}`)}</span><small className={styles.note}>{action.granularity === "operation" ? p("operationGranularity") : p("resourceGranularity", { type: t(`types.${action.resourceType}`) })}</small></span><Badge>{t(`levels.${action.level}`)}</Badge></Checkbox>)}{!available.length ? <p className={styles.note}>{t("noActions")}</p> : null}</div>
    </section> : null}
    <ResourceScopeEditor resources={resources} key={value.service} text={value.resources} actions={lines(value.actions)} service={value.service} accountId={accountId} onChange={(resources) => onChange({ ...value, resources })} />
    <ConditionsEditor tagMode={tagMode} actions={expandPolicyActions(lines(value.actions))} value={value.condition} onChange={(condition) => onChange({ ...value, condition })} />
    {changingService ? <Dialog open title={t("switchService")} closeLabel={w("close")} onClose={() => setChangingService(null)} footer={<><Button variant="secondary" onClick={() => setChangingService(null)}>{w("cancel")}</Button><Button onClick={() => service(changingService)}>{t("switchConfirm")}</Button></>}><p>{t("switchHint")}</p></Dialog> : null}
  </section>;
}
