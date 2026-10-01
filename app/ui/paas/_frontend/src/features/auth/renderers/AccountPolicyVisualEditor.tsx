"use client";

import { useId, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Checkbox, FormField, Input, Radio, SearchInput, Select, Table, TablePagination, TextArea } from "@ui/xiak";
import type { AccountPolicyDocument, AuthorizationProfileAction, AuthorizationProfileCondition, AuthorizationProfileDirectory } from "../domain/accounts";
import { visualActionGroups, visualActionShapeKey, type VisualActionGroup } from "../domain/accountPolicyVisualAuthoring";
import { AuthorizationActionTable } from "./AuthorizationActionTable";
import styles from "./AccountPolicyVisualEditor.module.css";

type Statement = AccountPolicyDocument["statements"][number];
type Resource = Statement["resources"][number];
type Condition = NonNullable<Statement["conditions"]>[number];
const conditionLabelKey = {
  "iam.account-id": "accountId",
  "iam.principal-id": "principalId",
  "iam.current-time": "currentTime",
  "request.source-ip": "sourceIp",
  "request.tag/environment": "environmentRequestTag",
  "resource.tag/environment": "environmentResourceTag"
} as const;
const stringOperators = ["STRING_EQUALS", "STRING_NOT_EQUALS"] as const;
const timeOperators = ["DATE_GREATER_THAN_EQUALS", "DATE_LESS_THAN"] as const;
const ipOperators = ["IP_ADDRESS", "NOT_IP_ADDRESS"] as const;
const maxStatementActions = 128;
const emptySelectedActions: string[] = [];
const collectionOnly = (action: AuthorizationProfileAction) => visualActionShapeKey(action) === "COLLECTION";
const operatorLabelKey = { STRING_EQUALS: "operators.STRING_EQUALS", STRING_NOT_EQUALS: "operators.STRING_NOT_EQUALS",
  DATE_GREATER_THAN_EQUALS: "operators.DATE_GREATER_THAN_EQUALS", DATE_LESS_THAN: "operators.DATE_LESS_THAN",
  IP_ADDRESS: "operators.IP_ADDRESS", NOT_IP_ADDRESS: "operators.NOT_IP_ADDRESS" } as const;

function operatorsFor(condition: AuthorizationProfileCondition) {
  if (condition.valueType === "TIME") return timeOperators;
  if (condition.valueType === "IP") return ipOperators;
  return stringOperators;
}

function CatalogSnapshot({ document, directory, review = false }: {
  document: AccountPolicyDocument; directory: AuthorizationProfileDirectory; review?: boolean;
}) {
  const t = useTranslations("PolicyVisualAuthoring");
  const actions = new Set(document.statements.flatMap((statement) => statement.actions));
  const profiles = directory.items.filter((entry) => entry.profile.actions.some((action) => actions.has(action.action)));
  if (!profiles.length) return null;
  const title = t(review ? "reviewCatalogSnapshotTitle" : "catalogSnapshotTitle");
  return <section className={styles.catalogSnapshot} aria-label={title}>
    <strong>{title}</strong>
    <div>{profiles.map((entry) => <code key={`${entry.profile.product}\0${entry.profile.revision}`}>{t("catalogSnapshotItem", {
      product: entry.profile.product, revision: entry.profile.revision
    })}</code>)}</div>
    <p>{t(review ? "reviewCatalogSnapshotHint" : "catalogSnapshotHint")}</p>
  </section>;
}

function ActionDeclarationDisclosure({ actions }: { actions: AuthorizationProfileAction[] }) {
  const t = useTranslations("PolicyVisualAuthoring");
  const id = useId();
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const pages = Math.max(1, Math.ceil(actions.length / pageSize));
  const currentPage = Math.min(page, pages);
  const title = t("selectedActionDeclarationsTitle", { count: actions.length });
  return <section className={styles.actionDeclaration} aria-label={title}>
    <div className={styles.actionDeclarationHeading}>
      <div><strong>{title}</strong><p>{t("selectedActionDeclarationsHint")}</p></div>
      <Button variant="ghost" aria-controls={id} aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        {t(open ? "hideSelectedActionDeclarations" : "showSelectedActionDeclarations")}
      </Button>
    </div>
    {open ? <div className={styles.actionDeclarationBody} id={id}>
      <AuthorizationActionTable actions={actions.slice((currentPage - 1) * pageSize, currentPage * pageSize)}
        label={t("selectedActionDeclarationsTable")} />
      <Table.Footer><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage}
        onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }),
          pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>
    </div> : null}
  </section>;
}

export function PolicyVisualReview({ document, directory, headingLevel = 3 }: {
  document: AccountPolicyDocument; directory: AuthorizationProfileDirectory; headingLevel?: 3 | 4;
}) {
  const t = useTranslations("PolicyVisualAuthoring");
  const id = useId();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const statement = document.statements[selectedIndex];
  if (!statement) return null;
  const actionNames = new Set(statement.actions);
  const actionDeclarations = directory.items.flatMap((entry) => entry.profile.actions).filter((action) => actionNames.has(action.action));
  const SummaryHeading = headingLevel === 3 ? "h3" : "h4";
  const StatementHeading = headingLevel === 3 ? "h4" : "h5";
  return <section className={styles.reviewSummary} aria-label={t("reviewSummary")}>
    <div className={styles.reviewHeading}>
      <SummaryHeading>{t("reviewSummary")}</SummaryHeading>
      <span>{t("reviewStatementCount", { count: document.statements.length })}</span>
    </div>
    <CatalogSnapshot document={document} directory={directory} review />
    {document.statements.length > 1 ? <FormField id={id + "-statement"} label={t("reviewChooseStatement")}>
      <Select id={id + "-statement"} value={String(selectedIndex)} onValueChange={(value) => setSelectedIndex(Number(value))}
        options={document.statements.map((item, at) => ({ value: String(at), label: t("statementOption", { number: at + 1, sid: item.sid }) }))} />
    </FormField> : null}
    <StatementHeading>{t("statementOption", { number: selectedIndex + 1, sid: statement.sid })}</StatementHeading>
    <dl className={styles.reviewFields}>
      <div><dt>{t("effect")}</dt><dd>{t(statement.effect === "DENY" ? "deny" : "allow")}</dd></div>
      <div><dt>{t("actions")}</dt><dd><ul>{statement.actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul></dd></div>
      <div><dt>{t("resources")}</dt><dd><ul>{statement.resources.map((resource, at) => <li key={at}>
        {t(`matches.${resource.match}`)} · <code>{resource.kind}</code>{resource.id ? <> · <code>{resource.id}</code></> : null}
      </li>)}</ul></dd></div>
      <div><dt>{t("conditions")}</dt><dd>{statement.conditions?.length ? <ul>{statement.conditions.map((condition, at) => <li key={at}>
        {Object.hasOwn(conditionLabelKey, condition.key) ? t(`keys.${conditionLabelKey[condition.key as keyof typeof conditionLabelKey]}`) : <code>{condition.key}</code>}
        {" · "}{Object.hasOwn(operatorLabelKey, condition.operator) ? t(operatorLabelKey[condition.operator as keyof typeof operatorLabelKey]) : <code>{condition.operator}</code>}
        {" · "}<code>{condition.values.join(", ")}</code>
      </li>)}</ul> : t("reviewNoConditions")}</dd></div>
    </dl>
    {actionDeclarations.length ? <ActionDeclarationDisclosure actions={actionDeclarations} /> : null}
    <p>{t("reviewSummaryHint")}</p>
  </section>;
}

type ActionIncompatibility = "shape" | "prefix" | "collection" | "condition";

function actionIncompatibility(action: AuthorizationProfileAction, statement: Statement,
  selected: AuthorizationProfileAction[]): ActionIncompatibility | null {
  if (selected.length && visualActionShapeKey(action) !== visualActionShapeKey(selected[0]!)) return "shape";
  if (statement.resources.some((resource) => resource.match === "PREFIX_IN_AUTHORITY") &&
      !action.resourceShapes.some((shape) => shape.mode === "INSTANCE" && shape.prefixAllowed)) return "prefix";
  if (collectionOnly(action) &&
      statement.resources.some((resource) => resource.match === "EXACT" && resource.id !== "collection")) return "collection";
  if ((statement.conditions ?? []).some((condition) => !(action.conditions ?? []).some((item) => item.key === condition.key))) return "condition";
  return null;
}

function ActionChoices({ group, selectedActions = emptySelectedActions, multiple = false, compatible, onSelect }: {
  group: VisualActionGroup; selectedActions?: string[]; multiple?: boolean;
  compatible?: (action: AuthorizationProfileAction) => ActionIncompatibility | null;
  onSelect(action: AuthorizationProfileAction, selected: boolean): void;
}) {
  const t = useTranslations("PolicyVisualAuthoring");
  const id = useId();
  const [query, setQuery] = useState("");
  const [selectedOnly, setSelectedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const selectedSet = useMemo(() => new Set(selectedActions), [selectedActions]);
  const compatibilityState = useMemo(() => {
    const reasons = new Map(group.actions.map((action) => [action.action, compatible?.(action) ?? null] as const));
    return { reasons, incompatible: [...reasons.values()].filter(Boolean).length };
  }, [compatible, group.actions]);
  const normalizedQuery = query.normalize("NFKC").trim().toLowerCase();
  const filtered = useMemo(() => group.actions.filter((action) =>
    (!multiple || !selectedOnly || selectedSet.has(action.action)) &&
    action.action.toLowerCase().includes(normalizedQuery)),
  [group.actions, multiple, normalizedQuery, selectedOnly, selectedSet]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  return <>
    <div className={styles.actionFilters}>
      <SearchInput aria-label={t("searchActions")} placeholder={t("searchActions")} value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }}
        clearAction={query ? { label: t("clearSearch"), onClear: () => { setQuery(""); setPage(1); } } : undefined} />
      {multiple ? <Button variant="ghost" aria-pressed={selectedOnly} onClick={() => { setSelectedOnly(!selectedOnly); setPage(1); }}>
        {t(selectedOnly ? "showAllActions" : "showSelectedActions")}
      </Button> : null}
    </div>
    {multiple && compatibilityState.incompatible ? <p className={styles.compatibilitySummary}>{t("actionCompatibilitySummary", {
      compatible: group.actions.length - compatibilityState.incompatible, incompatible: compatibilityState.incompatible
    })}</p> : null}
    <div className={styles.actionList}>{filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize).map((action) => {
      const incompatibility = compatibilityState.reasons.get(action.action) ?? null;
      const enabled = incompatibility === null;
      const checked = selectedSet.has(action.action);
      const maxed = multiple && !checked && selectedActions.length >= maxStatementActions;
      const last = multiple && checked && selectedActions.length === 1;
      const target = action.resourceShapes.map((shape) => t(`targets.${shape.mode === "INSTANCE" ? "INSTANCE" : shape.collectionUsage ?? "COLLECTION"}`)).join(" · ");
      const incompatibilityLabel = incompatibility ? t(`incompatibleActions.${incompatibility}`) : null;
      const title = incompatibilityLabel ?? (maxed ? t("maxActions") : last ? t("lastAction") : undefined);
      const label = <span className={styles.actionChoice}><code>{action.action}</code><small>{target}</small>
        {incompatibilityLabel ? <small className={styles.actionIncompatibility}>{incompatibilityLabel}</small> : null}</span>;
      return multiple ? <Checkbox key={action.action} checked={checked} disabled={!enabled || maxed || last} title={title}
        onChange={(event) => onSelect(action, event.target.checked)}>{label}</Checkbox> :
        <Radio key={action.action} name={id + "-action"} checked={checked} disabled={!enabled} title={title}
          onChange={() => onSelect(action, true)}>{label}</Radio>;
    })}{!filtered.length ? <p className={styles.note}>{t("noActions")}</p> : null}</div>
    <TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage}
      onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} />
  </>;
}

function StatementFields({ statement, group, onChange }: {
  statement: Statement; group: VisualActionGroup; onChange(next: Statement): void;
}) {
  const t = useTranslations("PolicyVisualAuthoring");
  const id = useId();
  const selected = group.actions.filter((action) => statement.actions.includes(action.action));
  const allCollectionOnly = selected.length > 0 && selected.every(collectionOnly);
  const prefixAllowed = selected.every((action) => action.resourceShapes.some((shape) => shape.mode === "INSTANCE" && shape.prefixAllowed));
  const availableConditions = (selected[0]?.conditions ?? []).filter((definition) => selected.every((action) =>
    (action.conditions ?? []).some((condition) => condition.key === definition.key && condition.valueType === definition.valueType && condition.source === definition.source)));
  const trustedNetwork = availableConditions.some((condition) => condition.source === "CALLING_SERVICE_NETWORK");
  const trustedRequestTags = availableConditions.filter((condition) => condition.source === "CALLING_SERVICE_REQUEST_TAG");
  const trustedResourceTags = availableConditions.filter((condition) => condition.source === "CALLING_SERVICE_RESOURCE_TAG");
  const nextCondition = availableConditions.flatMap((definition) => operatorsFor(definition)
    .map((operator) => ({ key: definition.key, operator }))).find((candidate) => !(statement.conditions ?? []).some((condition) => condition.key === candidate.key && condition.operator === candidate.operator));
  const updateResource = (index: number, next: Resource) => onChange({ ...statement, resources: statement.resources.map((resource, at) => at === index ? next : resource) });
  const updateCondition = (index: number, next: Condition) => onChange({ ...statement, conditions: statement.conditions?.map((condition, at) => at === index ? next : condition) });
  return <div className={styles.statementFields}>
    <div className={styles.identityFields}>
      <FormField id={id + "-sid"} label={t("sid")} hint={t("sidHint")}>
        <Input id={id + "-sid"} maxLength={128} value={statement.sid} onChange={(event) => onChange({ ...statement, sid: event.target.value })} />
      </FormField>
      <FormField id={id + "-effect"} label={t("effect")}>
        <Select id={id + "-effect"} value={statement.effect} options={[{ value: "ALLOW", label: t("allow") }, { value: "DENY", label: t("deny") }]}
          onValueChange={(value) => onChange({ ...statement, effect: value as Statement["effect"] })} />
      </FormField>
    </div>
    <section className={styles.groupSection} aria-label={t("actions")}>
      <div className={styles.sectionHeading}><div><h4>{t("actions")}</h4><p>{t("actionGroup", { product: group.product, kind: group.resourceKind })}</p></div></div>
      <p className={styles.selectedAction}>{t("selectedActions", { count: selected.length, max: maxStatementActions })} · {t("compatibleActionsHint")}</p>
      <ActionChoices group={group} selectedActions={statement.actions} multiple compatible={(action) => actionIncompatibility(action, statement, selected)}
        onSelect={(action, checked) => {
          if (checked && selected.length >= maxStatementActions || !checked && selected.length <= 1) return;
          const next = new Set(statement.actions);
          if (checked) next.add(action.action); else next.delete(action.action);
          onChange({ ...statement, actions: group.actions.filter((candidate) => next.has(candidate.action)).map((candidate) => candidate.action) });
        }} />
      <ActionDeclarationDisclosure actions={selected} />
    </section>
    <section className={styles.groupSection} aria-label={t("resources")}>
      <div className={styles.sectionHeading}><div><h4>{t("resources")}</h4><p>{t("resourceHint", { kind: group.resourceKind })}</p></div></div>
      {statement.resources.map((resource, index) => <div className={styles.row} key={index}>
        <FormField id={id + "-match-" + index} label={t("resourceMatch", { number: index + 1 })}>
          <Select id={id + "-match-" + index} value={resource.match} options={[
            { value: "ANY_IN_AUTHORITY", label: t("matches.ANY_IN_AUTHORITY") },
            { value: "EXACT", label: t("matches.EXACT") },
            { value: "PREFIX_IN_AUTHORITY", label: t("matches.PREFIX_IN_AUTHORITY"), disabled: !prefixAllowed }
          ]} onValueChange={(value) => updateResource(index, value === "ANY_IN_AUTHORITY" ? { kind: group.resourceKind, match: value } :
            { kind: group.resourceKind, match: value as Resource["match"], id: resource.id ?? (allCollectionOnly ? "collection" : "") })} />
        </FormField>
        {resource.match !== "ANY_IN_AUTHORITY" ? <FormField id={id + "-resource-id-" + index} label={t("resourceId")} hint={t(allCollectionOnly ? "collectionIdHint" : "resourceIdHint")}>
          <Input id={id + "-resource-id-" + index} maxLength={128} value={resource.id ?? ""} disabled={allCollectionOnly && resource.match === "EXACT"}
            onChange={(event) => updateResource(index, { ...resource, id: event.target.value })} />
        </FormField> : null}
        <Button variant="ghost" disabled={statement.resources.length === 1} onClick={() => onChange({ ...statement, resources: statement.resources.filter((_, at) => at !== index) })}>{t("removeResource")}</Button>
      </div>)}
      <Button variant="secondary" disabled={allCollectionOnly || statement.resources.length >= 64 || statement.resources.some((resource) => resource.match === "ANY_IN_AUTHORITY")}
        onClick={() => onChange({ ...statement, resources: [...statement.resources, { kind: group.resourceKind, match: "EXACT", id: "" }] })}>{t("addResource")}</Button>
      {statement.resources.some((resource) => resource.match === "ANY_IN_AUTHORITY") ? <p className={styles.note}>{t("anyResourceHint")}</p> : null}
    </section>
    <section className={styles.groupSection} aria-label={t("conditions")}>
      <div className={styles.sectionHeading}><div><h4>{t("conditions")}</h4><p>{t("conditionsHint")}</p></div></div>
      {trustedNetwork || trustedRequestTags.length || trustedResourceTags.length ? <div className={styles.conditionCapability}>
        <strong>{t("trustedRequestContextTitle")}</strong>
        {trustedNetwork ? <p>{t("trustedNetworkCapability")}</p> : null}
        {trustedRequestTags.length ? <p>{t("trustedRequestTagCapability", { keys: trustedRequestTags.map((condition) => condition.key.replace("request.tag/", "")).join(" · ") })}</p> : null}
        {trustedResourceTags.length ? <p>{t("trustedResourceTagCapability", { keys: trustedResourceTags.map((condition) => condition.key.replace("resource.tag/", "")).join(" · ") })}</p> : null}
        <p>{t("trustedConditionCombination")}</p>
        {trustedRequestTags.length ? <p>{t("trustedRequestTagMissing")}</p> : null}
        {trustedResourceTags.length ? <p>{t("trustedResourceTagMissing")}</p> : null}
      </div> : null}
      {(statement.conditions ?? []).map((condition, index) => <div className={styles.row} key={index}>
        <FormField id={id + "-condition-key-" + index} label={t("conditionKey", { number: index + 1 })}>
          <Select id={id + "-condition-key-" + index} value={condition.key} options={availableConditions.map((definition) => ({ value: definition.key, label: t(`keys.${conditionLabelKey[definition.key]}`),
            disabled: operatorsFor(definition).every((operator) =>
              (statement.conditions ?? []).some((other, at) => at !== index && other.key === definition.key && other.operator === operator)) }))}
            onValueChange={(value) => { const definition = availableConditions.find((candidate) => candidate.key === value);
              const operator = definition && operatorsFor(definition).find((candidate) =>
                !(statement.conditions ?? []).some((other, at) => at !== index && other.key === value && other.operator === candidate));
              if (operator) updateCondition(index, { key: value, operator, values: [""] }); }} />
        </FormField>
        <FormField id={id + "-condition-operator-" + index} label={t("operator")}>
          <Select id={id + "-condition-operator-" + index} value={condition.operator}
            options={(availableConditions.find((definition) => definition.key === condition.key) ?
              operatorsFor(availableConditions.find((definition) => definition.key === condition.key)!) : stringOperators).map((operator) => ({ value: operator, label: t(`operators.${operator}`),
              disabled: (statement.conditions ?? []).some((other, at) => at !== index && other.key === condition.key && other.operator === operator) }))}
            onValueChange={(value) => updateCondition(index, { ...condition, operator: value })} />
        </FormField>
        <FormField id={id + "-condition-values-" + index} label={t("values")} hint={t(condition.key === "iam.current-time" ? "timeHint" :
          condition.key === "request.source-ip" ? "ipHint" : condition.key.startsWith("request.tag/") ? "requestTagValuesHint" :
            condition.key.startsWith("resource.tag/") ? "resourceTagValuesHint" : "valuesHint")}>
          <TextArea id={id + "-condition-values-" + index} rows={2} maxLength={2048} value={condition.values.join("\n")}
            onChange={(event) => updateCondition(index, { ...condition, values: event.target.value.split(/\r?\n/) })} />
        </FormField>
        <Button variant="ghost" onClick={() => { const remaining = statement.conditions?.filter((_, at) => at !== index); onChange({ ...statement, conditions: remaining?.length ? remaining : undefined }); }}>{t("removeCondition")}</Button>
      </div>)}
      <Button variant="secondary" disabled={!nextCondition || (statement.conditions?.length ?? 0) >= 16}
        onClick={() => { if (!nextCondition) return; onChange({ ...statement, conditions: [...statement.conditions ?? [], { ...nextCondition, values: [""] }] }); }}>{t("addCondition")}</Button>
      {!availableConditions.length ? <p className={styles.note}>{t("noConditions")}</p> : null}
    </section>
  </div>;
}

export function AccountPolicyVisualEditor({ document, directory, onChange }: {
  document: AccountPolicyDocument; directory: AuthorizationProfileDirectory; onChange(document: AccountPolicyDocument): void;
}) {
  const t = useTranslations("PolicyVisualAuthoring");
  const id = useId();
  const groups = useMemo(() => visualActionGroups(directory), [directory]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [newGroup, setNewGroup] = useState("0");
  const [adding, setAdding] = useState(false);
  const [removePending, setRemovePending] = useState(false);
  const index = Math.max(0, Math.min(selectedIndex, document.statements.length - 1));
  const statement = document.statements[index];
  const group = statement ? groups.find((candidate) => candidate.actions.some((action) => action.action === statement.actions[0])) : undefined;
  const replace = (next: Statement) => onChange({ ...document, statements: document.statements.map((item, at) => at === index ? next : item) });
  const add = (action: AuthorizationProfileAction) => {
    const selected = groups[Number(newGroup)];
    if (!selected?.actions.some((candidate) => candidate.action === action.action) || document.statements.length >= 64) return;
    let number = document.statements.length + 1;
    while (document.statements.some((item) => item.sid === `statement-${number}`)) number++;
    const collectionOnly = action.resourceShapes.every((shape) => shape.mode === "COLLECTION");
    onChange({ ...document, statements: [...document.statements, { sid: `statement-${number}`, effect: "ALLOW", actions: [action.action],
      resources: [{ kind: selected.resourceKind, match: "EXACT", id: collectionOnly ? "collection" : "" }] }] });
    setSelectedIndex(document.statements.length);
    setAdding(false);
    setRemovePending(false);
  };
  const remove = () => {
    if (document.statements.length <= 1) return;
    onChange({ ...document, statements: document.statements.filter((_, at) => at !== index) });
    setSelectedIndex(Math.max(0, index - 1));
    setRemovePending(false);
  };
  return <div className={styles.editor}>
    <Alert status="info">{t("catalogNotice")}</Alert>
    <CatalogSnapshot document={document} directory={directory} />
    {statement ? <div className={styles.statementToolbar}>
      <FormField id={id + "-statement"} label={t("statement")}>
        <Select id={id + "-statement"} value={String(index)} onValueChange={(value) => { setSelectedIndex(Number(value)); setRemovePending(false); setAdding(false); }}
          options={document.statements.map((item, at) => ({ value: String(at), label: t("statementOption", { number: at + 1, sid: item.sid }) }))} />
      </FormField>
      <Button variant="secondary" disabled={document.statements.length >= 64 || !groups.length} onClick={() => setAdding(true)}>{t("addStatement")}</Button>
      <Button variant="ghost" disabled={document.statements.length <= 1} onClick={() => setRemovePending(true)}>{t("removeStatement")}</Button>
    </div> : null}
    {removePending && statement ? <Alert status="warning"><div className={styles.removal}><p>{t("removeStatementConfirm", { sid: statement.sid })}</p><div>
      <Button variant="danger" onClick={remove}>{t("confirmRemove")}</Button><Button variant="ghost" onClick={() => setRemovePending(false)}>{t("cancelRemove")}</Button>
    </div></div></Alert> : null}
    {(!statement || adding) && groups.length ? <section className={styles.groupSection} aria-label={t("chooseActionForNewStatement")}>
      <div className={styles.sectionHeading}><div><h4>{t("chooseActionForNewStatement")}</h4><p>{t("newStatementHint")}</p></div></div>
      <FormField id={id + "-group"} label={t("newStatementProduct")}>
        <Select id={id + "-group"} value={newGroup} onValueChange={setNewGroup}
          options={groups.map((item, at) => ({ value: String(at), label: `${item.product} · ${item.resourceKind}` }))} />
      </FormField>
      <ActionChoices key={newGroup} group={groups[Number(newGroup)]!} onSelect={add} />
      {statement ? <div><Button variant="ghost" onClick={() => setAdding(false)}>{t("cancelAdd")}</Button></div> : null}
    </section> : !statement ? <Alert status="warning">{t("noActions")}</Alert> : null}
    {statement && group && !adding ? <StatementFields key={index} statement={statement} group={group} onChange={replace} /> : null}
  </div>;
}
