"use client";

import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { ArrowLeft, ChevronLeft, ChevronRight } from "lucide-react";
import { useTranslations } from "next-intl";
import { Badge, Button, SearchInput, Table, Tabs } from "@ui/xiak";
import { resourcesForPolicyActions, summarizePolicyServices, type PolicyCondition, type PolicyDocument, type PolicyServiceSummary } from "../domain/policyDocument";
import { expandPolicyActions, parsePolicyResource, policyActions } from "../domain/policyLanguage";
import styles from "./AccountAccessRenderer.module.css";
import policyStyles from "./PolicyWorkspace.module.css";

export function ConditionSummary({ value }: { value?: PolicyCondition }) {
  const t = useTranslations("PolicyRules");
  if (!value) return <span>{t("noConditions")}</span>;
  return <div className={styles.stack}>
    {value.sourceIp ? <div><small>{t("sourceIpSummary")}</small>{value.sourceIp.map((range) => <div key={range}><code>{range}</code></div>)}</div> : null}
    {value.resourceTag ? <div><small>{t("tagSummary")}</small>{value.resourceTag.map((tag) => <div key={tag.key}><code>{tag.key} = {JSON.stringify(tag.value)}</code></div>)}</div> : null}
    {(["notBefore", "notAfter"] as const).map((key) => value[key] ? <div key={key}><small>{t(key)}</small><code>{value[key]}</code></div> : null)}
  </div>;
}

export function PolicyActionsSummary({ actions }: { actions: readonly string[] }) {
  const t = useTranslations("PolicyWorkspace"), r = useTranslations("PolicyRules");
  const expanded = expandPolicyActions(actions);
  const services = [...new Set(expanded.map((action) => action.service))];
  return <div>{services.map((service) => {
    const entries = expanded.filter((action) => action.service === service);
    return <div key={service} className={policyStyles.serviceBlock}><strong>{r(`services.${service}`)}</strong>
      {entries.length <= 2 ? entries.map((action) => <span key={action.id}>{r(`actionNames.${action.id}`)}</span>) : <details className={policyStyles.details}><summary>{t("actionCount", { count: entries.length })} · {[...new Set(entries.map((action) => action.level))].map((level) => r(`levels.${level}`)).join(" / ")}</summary>{entries.map((action) => <div key={action.id}>{r(`actionNames.${action.id}`)} <code>{action.id}</code></div>)}</details>}
    </div>;
  })}<details className={policyStyles.details}><summary>{t("exactActions")}</summary>{actions.map((action, index) => <div key={index}><code>{action}</code></div>)}</details></div>;
}

export function PolicyResourcesSummary({ resources }: { resources: readonly string[] }) {
  const t = useTranslations("PolicyWorkspace"), r = useTranslations("PolicyRules"), w = useTranslations("IamWorkspace");
  const typeLabels: Record<string, string> = Object.fromEntries((["account", "region", "node", "application", "instance", "topic", "pipeline", "monitor", "user", "role", "auditEvent"] as const).map((type) => [type, r(`types.${type}`)]));
  return <div>{resources.map((value, index) => {
    if (value === "*") return <span key={index}>{w("allAccountResources")}</span>;
    const resource = parsePolicyResource(value);
    return <div className={policyStyles.serviceBlock} key={index}>
      {resource ? <><strong>{resource.id}</strong><span className={policyStyles.note}>{t("resourceParts", { type: typeLabels[resource.type] ?? resource.type, region: resource.region })}</span></> : null}
      <code>{value}</code>
    </div>;
  })}</div>;
}

const pageSize = 10;
const normalized = (value: string) => value.normalize("NFKC").trim().toLowerCase();
const searchWords = (value: string) => normalized(value).split(/\s+/).filter(Boolean);

function SummaryPagination({ count, page, onPage }: { count: number; page: number; onPage(page: number): void }) {
  const t = useTranslations("IamWorkspace");
  const pages = Math.max(1, Math.ceil(count / pageSize));
  if (pages === 1) return null;
  return <div className={policyStyles.summaryPagination}>
    <span className={policyStyles.note} role="status">{t("page", { page, pages })}</span>
    <div className={policyStyles.actions}>
      <Button variant="ghost" size="small" iconOnly aria-label={t("previous")} disabled={page === 1} onClick={() => onPage(page - 1)}><ChevronLeft aria-hidden="true" /></Button>
      <Button variant="ghost" size="small" iconOnly aria-label={t("next")} disabled={page === pages} onClick={() => onPage(page + 1)}><ChevronRight aria-hidden="true" /></Button>
    </div>
  </div>;
}

function PolicyServiceTable({ services, page, onOpen, buttonRef }: {
  services: readonly PolicyServiceSummary[];
  page: number;
  onOpen(key: string): void;
  buttonRef(key: string, button: HTMLButtonElement | null): void;
}) {
  const t = useTranslations("IamWorkspace"), p = useTranslations("PolicyWorkspace"), r = useTranslations("PolicyRules");
  const visible = services.slice((page - 1) * pageSize, page * pageSize);
  return <Table aria-label={t("policySummary")} className={policyStyles.serviceTable}>
    <thead><tr><th scope="col">{p("serviceColumn")}</th><th scope="col">{t("action")}</th><th scope="col">{t("resource")}</th><th scope="col">{p("conditionColumn")}</th></tr></thead>
    {(["allow", "deny"] as const).map((effect) => {
      const group = visible.filter((service) => service.effect === effect);
      if (!group.length) return null;
      return <tbody key={effect}>
        <tr className={policyStyles.effectGroup}><th scope="rowgroup" colSpan={4}><Badge status={effect === "deny" ? "danger" : "success"}>{t(effect)}</Badge><span>{p("serviceCount", { count: services.filter((service) => service.effect === effect).length })}</span></th></tr>
        {group.map((entry) => {
          const only = entry.rules.length === 1 ? entry.rules[0]! : null;
          return <tr key={entry.key}>
            <td><button type="button" ref={(node) => buttonRef(entry.key, node)} className={policyStyles.serviceLink} onClick={() => onOpen(entry.key)} aria-label={p("openService", { service: r(`services.${entry.service}`), effect: t(effect) })}>{r(`services.${entry.service}`)}</button><code>{entry.service}</code></td>
            <td data-label={t("action")}><span>{p("actionCoverage", { count: entry.actions.length, total: policyActions.filter((action) => action.service === entry.service).length })}</span></td>
            <td data-label={t("resource")}>{only ? <PolicyResourcesSummary resources={only.resources} /> : <span>{p("separateRules", { count: entry.rules.length })}</span>}</td>
            <td data-label={p("conditionColumn")}>{only ? <ConditionSummary value={only.condition} /> : <span>{p("separateRules", { count: entry.rules.length })}</span>}</td>
          </tr>;
        })}
      </tbody>;
    })}
  </Table>;
}

function PolicyOperationDetails({ service, headingRef, onBack }: {
  service: PolicyServiceSummary;
  headingRef: RefObject<HTMLHeadingElement | null>;
  onBack(): void;
}) {
  const t = useTranslations("IamWorkspace"), p = useTranslations("PolicyWorkspace"), r = useTranslations("PolicyRules");
  const [query, setQuery] = useState("");
  const [requestedPage, setPage] = useState(1);
  // Only the selected service expands to operation rows. Each row retains its
  // source statement; identical actions in different branches stay distinct.
  const rows = useMemo(() => service.rules.flatMap((rule) => rule.actions.map((action) => ({
    rule, action, resources: resourcesForPolicyActions(rule.resources, [action]),
    keywords: normalized([action.id, r(`actionNames.${action.id}`), r(`actionDescriptions.${action.id}`)].join(" "))
  }))), [service, r]);
  const matches = useMemo(() => {
    const words = searchWords(query);
    return rows.filter((row) => words.every((word) => row.keywords.includes(word)));
  }, [rows, query]);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(matches.length / pageSize)));
  const visible = matches.slice((page - 1) * pageSize, page * pageSize);
  return <section className={policyStyles.summaryStack} aria-label={p("operationDetails")}>
    <div className={policyStyles.serviceHeading}>
      <Button variant="ghost" size="small" onClick={onBack}><ArrowLeft aria-hidden="true" />{p("backServices")}</Button>
      <h3 ref={headingRef} tabIndex={-1}>{r(`services.${service.service}`)} <code>{service.service}</code></h3>
      <Badge status={service.effect === "deny" ? "danger" : "success"}>{t(service.effect)}</Badge>
    </div>
    <div className={policyStyles.summaryToolbar}>
      <p className={policyStyles.note}>{p("operationRuleCount", { actions: service.actions.length, rules: service.rules.length })}</p>
      <SearchInput aria-label={r("actionSearch")} placeholder={r("actionSearch")} value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} clearAction={query ? { label: t("clear"), onClear: () => { setQuery(""); setPage(1); } } : undefined} />
    </div>
    <Table aria-label={p("operationDetails")} className={policyStyles.operationTable}>
      <thead><tr><th scope="col">{t("action")}</th><th scope="col">{p("actionDescription")}</th><th scope="col">{t("resource")}</th><th scope="col">{p("conditionColumn")}</th></tr></thead>
      <tbody>{visible.map(({ action, rule, resources }) => <tr key={rule.statement + ":" + action.id}>
        <td><code>{action.id}</code><small>{t("statementNumber", { number: rule.statement })}</small></td>
        <td data-label={p("actionDescription")}><strong>{r(`actionNames.${action.id}`)}</strong><span>{r(`actionDescriptions.${action.id}`)}</span><small>{r(`levels.${action.level}`)} · {action.granularity === "operation" ? p("operationGranularity") : p("resourceGranularity", { type: r(`types.${action.resourceType}`) })}</small></td>
        <td data-label={t("resource")}><PolicyResourcesSummary resources={resources} /></td>
        <td data-label={p("conditionColumn")}><ConditionSummary value={rule.condition} /></td>
      </tr>)}</tbody>
    </Table>
    {!visible.length ? <p className={policyStyles.note} role="status">{r("noActions")}</p> : null}
    <SummaryPagination count={matches.length} page={page} onPage={setPage} />
    <details className={policyStyles.details}><summary>{p("sourceRules")}</summary>
      {service.rules.map((rule) => <div className={policyStyles.sourceRule} key={rule.statement}>
        <strong>{t("statementNumber", { number: rule.statement })}</strong>
        <span className={policyStyles.note}>{p("exactActions")}</span>
        {rule.patterns.map((pattern, index) => <code key={index}>{pattern}</code>)}
      </div>)}
    </details>
    <p className={policyStyles.note}>{p("branchHint")}</p>
  </section>;
}

// The same document/capability projection is used in policy details, creation
// review and historical inspection. It never changes the effective revision.
export function PolicyDocumentViewer({ document }: { document: PolicyDocument }) {
  const t = useTranslations("IamWorkspace"), r = useTranslations("PolicyRules"), p = useTranslations("PolicyWorkspace");
  const [query, setQuery] = useState("");
  const [requestedPage, setPage] = useState(1);
  const [selection, setSelection] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const serviceButtons = useRef(new Map<string, HTMLButtonElement>());
  const focusIntent = useRef<{ key: string; detail: boolean } | null>(null);
  const services = useMemo(() => summarizePolicyServices(document), [document]);
  const selected = services.find((entry) => entry.key === selection);
  const matches = useMemo(() => {
    const words = searchWords(query);
    return services.filter((entry) => {
      const text = normalized([entry.service, r(`services.${entry.service}`), ...entry.actions.flatMap((action) => [action.id, r(`actionNames.${action.id}`)])].join(" "));
      return words.every((word) => text.includes(word));
    });
  }, [services, query, r]);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(matches.length / pageSize)));
  useEffect(() => {
    const intent = focusIntent.current;
    if (!intent) return;
    // A service can be opened far down the summary. Reveal the destination
    // heading (or originating service on return), not the old scroll position.
    (intent.detail ? heading.current : serviceButtons.current.get(intent.key))?.focus();
    focusIntent.current = null;
  }, [selected]);
  const hasWildcard = document.statement.some((statement) => statement.action.some((action) => action.includes("*")));
  return <Tabs.Root defaultValue="summary">
    <Tabs.List aria-label={t("policyPreview")}><Tabs.Trigger value="summary">{t("policySummary")}</Tabs.Trigger><Tabs.Trigger value="json">JSON</Tabs.Trigger></Tabs.List>
    <Tabs.Content value="summary">
      <div className={policyStyles.summaryBrowser}>
        {selected ? <PolicyOperationDetails key={selected.key} service={selected} headingRef={heading} onBack={() => { focusIntent.current = { key: selected.key, detail: false }; setSelection(null); }} /> : <div className={policyStyles.summaryStack}>
          <div className={policyStyles.summaryToolbar}>
            <p className={policyStyles.note} role="status">{p("summaryCount", { services: new Set(matches.map((entry) => entry.service)).size, statements: document.statement.length })}</p>
            <SearchInput aria-label={p("serviceSearch")} placeholder={p("serviceSearch")} value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} clearAction={query ? { label: t("clear"), onClear: () => { setQuery(""); setPage(1); } } : undefined} />
          </div>
          <PolicyServiceTable services={matches} page={page} onOpen={(key) => { focusIntent.current = { key, detail: true }; setSelection(key); }} buttonRef={(key, button) => { if (button) serviceButtons.current.set(key, button); else serviceButtons.current.delete(key); }} />
          {!matches.length ? <p className={policyStyles.note} role="status">{p("noService")}</p> : null}
          <SummaryPagination count={matches.length} page={page} onPage={setPage} />
        </div>}
        {hasWildcard ? <p className={policyStyles.note}>{p("catalogExpansion")}</p> : null}
        <p className={policyStyles.note}>{t("policyInterpretation")}</p>
      </div>
    </Tabs.Content>
    <Tabs.Content value="json"><pre className={styles.code} role="region" aria-label={t("document")} tabIndex={0}>{JSON.stringify(document, null, 2)}</pre></Tabs.Content>
  </Tabs.Root>;
}
