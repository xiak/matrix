"use client";

import { useId, useRef, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { useTranslations } from "next-intl";
import { Badge, SearchInput, Tabs } from "@ui/xiak";
import type { AccountPolicyDocument, AccountPolicyVersion } from "../domain/accounts";
import styles from "./AccountAccessRenderer.module.css";

type Statement = AccountPolicyDocument["statements"][number];
type Field = "actions" | "resourceScope" | "conditions";
type Entry = { value: string; detail?: string; values?: string[]; keywords?: string; key?: string };
const fieldOrder: readonly Field[] = ["actions", "resourceScope", "conditions"];

function ValueRows({ entries, commonScope }: { entries: Entry[]; commonScope?: string }) {
  if (commonScope) return <div className={styles.statementKinds}>
    <p>{commonScope}</p>
    <ul>{entries.map((entry) => <li key={entry.key}><code>{entry.value}</code></li>)}</ul>
  </div>;
  return <ul className={styles.statementValues}>
    {entries.map((entry) => <li key={entry.key ?? entry.value}>
      <code>{entry.value}</code>
      {entry.detail && <span className={styles.statementValueDetail}>{entry.detail}
        {entry.values?.map((value, index) => <code key={index}>{value}</code>)}
      </span>}
    </li>)}
  </ul>;
}

function ScopeDisclosure({ initiallyOpen, className, summaryClassName, summary, children }: {
  initiallyOpen: boolean; className?: string; summaryClassName?: string; summary: ReactNode; children: ReactNode;
}) {
  const [visited, setVisited] = useState(initiallyOpen);
  return <details className={className} open={initiallyOpen} onToggle={(event) => {
    if (event.currentTarget.open) setVisited(true);
  }}>
    <summary className={summaryClassName}><ChevronRight aria-hidden="true" />{summary}</summary>
    {visited && children}
  </details>;
}

function ProductActions({ actions, names }: { actions: Entry[]; names: Map<string, string> }) {
  const t = useTranslations("AccountPolicyDirectory");
  const groups = new Map<string, Entry[]>();
  for (const action of actions) {
    const product = action.value.split(".")[0]!;
    const entries = groups.get(product);
    if (entries) entries.push(action);
    else groups.set(product, [action]);
  }
  return <div className={styles.statementProducts}>
    {Array.from(groups, ([product, entries], index) => {
      const name = names.get(product);
      return <ScopeDisclosure key={product} initiallyOpen={groups.size === 1 || (index === 0 && entries.length <= 3)} summary={<>
        <strong>{name ?? product}</strong>
        {name && !name.toLowerCase().includes(product) && <code>{product}</code>}
        <span>{t("actionCount", { count: entries.length })}</span>
      </>}>
        <ValueRows entries={entries} />
      </ScopeDisclosure>;
    })}
  </div>;
}

function StatementScope({ statement, actions, names }: { statement: Statement; actions: string[]; names: Map<string, string> }) {
  const t = useTranslations("AccountPolicyDirectory");
  const collection = useTranslations("Collection");
  const viewportId = useId();
  const viewport = useRef<HTMLDivElement>(null);
  const [field, setField] = useState<Field>("actions");
  const [queries, setQueries] = useState({ actions: "", resourceScope: "", conditions: "" });
  const entries: Record<Field, Entry[]> = {
    actions: actions.map((value) => ({ value, keywords: names.get(value.split(".")[0]!) })),
    resourceScope: statement.resources.map((resource) => ({
      key: JSON.stringify(resource), value: resource.kind, keywords: resource.match,
      detail: [t(`matches.${resource.match}`), resource.id].filter(Boolean).join(" · ")
    })),
    conditions: (statement.conditions ?? []).map((condition) => ({
      key: JSON.stringify(condition), value: condition.key, detail: condition.operator, values: condition.values
    }))
  };
  const commonScope = statement.resources.length > 0 && statement.resources.every((resource) => resource.match === "ANY_IN_AUTHORITY")
    ? t("allResourcesOfKinds") : undefined;
  const fields = fieldOrder.filter((key) => entries[key].length > 0);
  const values = entries[field];
  const query = queries[field];
  const normalized = (text: string) => text.normalize("NFKC").toLowerCase();
  const words = normalized(query).trim().split(/\s+/).filter(Boolean);
  const matches = words.length ? values.filter((entry) => {
    const text = normalized([entry.value, entry.detail, entry.keywords, ...(entry.values ?? []), field === "resourceScope" ? commonScope : ""].join(" "));
    return words.every((word) => text.includes(word));
  }) : values;
  const label = t("statementValues", { label: t(field), sid: statement.sid });
  function changeQuery(value: string) {
    setQueries((current) => ({ ...current, [field]: value }));
    if (viewport.current) viewport.current.scrollTop = 0;
  }
  return <Tabs.Root value={field} onValueChange={(value) => setField(value as Field)}>
    <div className={styles.statementTools}>
      <Tabs.List aria-label={t("statementFields", { sid: statement.sid })} className={styles.statementSwitch}>
        {fields.map((key) => <Tabs.Trigger key={key} value={key} aria-label={`${t(key)} (${entries[key].length})`}>
          {t(key)}<span aria-hidden="true">{entries[key].length}</span>
        </Tabs.Trigger>)}
      </Tabs.List>
      <div className={styles.statementSearch}>
        <SearchInput aria-label={t("searchStatementValues", { label: t(field), sid: statement.sid })} aria-controls={viewportId}
          placeholder={t(`valueSearch.${field}`)} controlSize="small" value={query} onChange={(event) => changeQuery(event.target.value)}
          clearAction={query ? { label: collection("clearSearch"), onClear: () => changeQuery("") } : undefined} />
      </div>
    </div>
    {fields.map((key) => <Tabs.Content key={key} value={key} inset="none">
      {field === key && <>
        {words.length > 0 && <p className={styles.statementMatchCount} role="status">{t("valueMatches", { shown: matches.length, total: values.length })}</p>}
        <div id={viewportId} ref={viewport} role="region" aria-label={label} className={styles.statementViewport} tabIndex={0}>
          {matches.length === 0 ? <p className={styles.statementNoMatches}>{t("noValueMatches")}</p>
            : field === "actions" && !words.length ? <ProductActions actions={values} names={names} />
            : <ValueRows entries={matches} commonScope={field === "resourceScope" ? commonScope : undefined} />}
        </div>
      </>}
    </Tabs.Content>)}
  </Tabs.Root>;
}

export function PolicyStatements({ version, title }: { version: AccountPolicyVersion; title: string }) {
  const t = useTranslations("AccountPolicyDirectory");
  const message = useTranslations();
  const names = new Map([
    ["audit", message("ServiceDirectory.services.audit.name")], ["devops", message("ServiceDirectory.services.devops.name")],
    ["iam", message("ServiceDirectory.services.iam.name")], ["managedservice", message("Console.managedServices")],
    ["paas", message("ServiceDirectory.services.applications.name")], ["platform", t("platformService")]
  ]);
  const statements = version.document.statements;
  const multiple = statements.length > 1;
  return <section aria-label={t("statementList")} className={styles.statementDocument}>
    {multiple && <header className={styles.statementSetHeading}><h2>{title}</h2><span>{t("statementTotal", { count: statements.length })}</span></header>}
    {statements.map((statement, index) => {
      const actions = version.compilation?.resolvedStatements.find((item) => item.sid === statement.sid)?.actions ?? statement.actions;
      const effect = <Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(statement.effect === "DENY" ? "deny" : "allow")}</Badge>;
      const scope = <StatementScope statement={statement} actions={actions} names={names} />;
      if (multiple) return <ScopeDisclosure key={statement.sid} initiallyOpen={index === 0} className={styles.statementRule} summaryClassName={styles.statementHeading} summary={<>
        {effect}<strong>{statement.sid}</strong>
        <span className={styles.statementMeta}>{t("ruleScopeCounts", { actions: actions.length, resourceCount: statement.resources.length, conditionCount: statement.conditions?.length ?? 0 })}</span>
      </>}>{scope}</ScopeDisclosure>;
      return <article key={statement.sid} aria-label={statement.sid} className={styles.statementRule}>
        <header className={styles.statementHeading}>{effect}<h2>{statement.sid}</h2>
          {!statement.conditions?.length && <span className={styles.statementCondition}>{t("noConditions")}</span>}
          <span className={styles.statementMeta}>{title}</span>
        </header>
        {scope}
      </article>;
    })}
  </section>;
}
