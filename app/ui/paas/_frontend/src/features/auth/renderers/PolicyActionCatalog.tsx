"use client";

import { Fragment, useId, useLayoutEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Info, X } from "lucide-react";
import { Badge, Button, Table, TableSelectionCell } from "@ui/xiak";
import type { PolicyAction, PolicyConditionKey, PolicyService } from "../domain/previewAuthorizationCatalog";
import styles from "./PolicyActionCatalog.module.css";

const levelStatus = {
  read: "info",
  list: "neutral",
  write: "warning",
  permissions: "danger"
} as const;
const actionDefinitionId = (base: string, action: string) => `${base}-${action.replace(/[^a-zA-Z0-9_-]/g, "-")}`;

export function PolicyActionCatalog({ actions, selected, service, onChange }: {
  actions: readonly PolicyAction[];
  selected: readonly string[];
  service: PolicyService;
  onChange(actions: string[]): void;
}) {
  const t = useTranslations("PolicyRules");
  const p = useTranslations("PolicyWorkspace");
  const id = useId();
  const [inspected, setInspected] = useState<string | null>(null);
  const visibleIds = actions.map((action) => action.id);
  const selectedVisible = visibleIds.filter((action) => selected.includes(action));
  const selectionState = selectedVisible.length === 0 ? false : selectedVisible.length === visibleIds.length ? true : "mixed";
  const tableLabel = t("catalogTable", { service: t(`services.${service}`) });

  useLayoutEffect(() => {
    if (!inspected) return;
    const definition = document.getElementById(actionDefinitionId(id, inspected));
    if (typeof definition?.scrollIntoView === "function") definition.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [id, inspected]);

  function selectVisible(checked: boolean) {
    const visible = new Set<string>(visibleIds);
    onChange(checked
      ? [...new Set([...selected, ...visibleIds])]
      : selected.filter((action) => !visible.has(action)));
  }

  return <section className={styles.root} aria-label={t("catalogTitle")}>
    <header className={styles.header}>
      <div>
        <strong>{t("catalogTitle")}</strong>
        <span>{t("catalogHint")}</span>
      </div>
      <Badge status="info">{t("catalogCount", { count: actions.length })}</Badge>
    </header>
    <div className={styles.frame}>
      <Table aria-label={tableLabel} className={styles.table}>
        <thead><tr>
          <TableSelectionCell
            header
            label={selectionState === true ? t("unselectResults") : t("selectResults")}
            checked={selectionState}
            disabled={!actions.length}
            onChange={selectVisible}
          />
          <th scope="col">{t("actionColumn")}</th>
          <th scope="col" data-catalog-secondary>{t("levelColumn")}</th>
          <th scope="col" data-catalog-secondary>{t("resourceCapabilityColumn")}</th>
          <th scope="col" data-catalog-secondary>{t("conditionsColumn")}</th>
          <th scope="col" data-catalog-control>{t("definitionColumn")}</th>
        </tr></thead>
        <tbody>
          {actions.map((action) => {
            const isSelected = selected.includes(action.id);
            const isOpen = inspected === action.id;
            const panelId = actionDefinitionId(id, action.id);
            return <Fragment key={action.id}>
              <tr data-selected={isSelected || undefined}>
                <TableSelectionCell
                  label={action.id}
                  checked={isSelected}
                  onChange={(checked) => onChange(checked
                    ? [...new Set([...selected, action.id])]
                    : selected.filter((entry) => entry !== action.id))}
                />
                <td>
                  <strong>{t(`actionNames.${action.id}`)}</strong>
                  <code>{action.id}</code>
                  <small>{t(`actionDescriptions.${action.id}`)}</small>
                  <span className={styles.mobileFacts}>
                    <Badge status={levelStatus[action.level]}>{t(`levels.${action.level}`)}</Badge>
                    <span>{action.granularity === "operation" ? t("operationScopeShort") : t("resourceScopeShort", { type: t(`types.${action.resourceType}`) })}</span>
                  </span>
                </td>
                <td data-catalog-secondary><Badge status={levelStatus[action.level]}>{t(`levels.${action.level}`)}</Badge></td>
                <td data-catalog-secondary>{action.granularity === "operation" ? p("operationGranularity") : p("resourceGranularity", { type: t(`types.${action.resourceType}`) })}</td>
                <td data-catalog-secondary>{t("conditionCount", { count: action.conditions.length })}</td>
                <td data-catalog-control>
                  <Button
                    aria-controls={panelId}
                    aria-expanded={isOpen}
                    aria-label={isOpen ? t("closeActionDefinition") : t("inspectAction", { action: action.id })}
                    iconOnly
                    size="small"
                    variant="ghost"
                    onClick={() => setInspected(isOpen ? null : action.id)}
                  >{isOpen ? <X aria-hidden="true" /> : <Info aria-hidden="true" />}</Button>
                </td>
              </tr>
              {isOpen ? <tr className={styles.definitionRow}>
                <td colSpan={6}>
                  <section className={styles.definition} id={panelId} aria-label={t("actionDefinition", { action: action.id })}>
                    <header>
                      <div><strong>{t("actionDefinition", { action: t(`actionNames.${action.id}`) })}</strong><code>{action.id}</code></div>
                      <Button iconOnly size="small" variant="ghost" aria-label={t("closeActionDefinition")} onClick={() => setInspected(null)}><X aria-hidden="true" /></Button>
                    </header>
                    <p>{t(`actionDescriptions.${action.id}`)}</p>
                    <dl>
                      <div><dt>{t("catalogService")}</dt><dd>{t(`services.${action.service}`)}</dd></div>
                      <div><dt>{t("levelColumn")}</dt><dd>{t(`levels.${action.level}`)}</dd></div>
                      <div><dt>{t("catalogScope")}</dt><dd>{action.granularity === "operation" ? p("operationGranularity") : p("resourceGranularity", { type: t(`types.${action.resourceType}`) })}</dd></div>
                      <div><dt>{t("catalogResult")}</dt><dd>{action.resultResourceType ? t(`types.${action.resultResourceType as PolicyAction["resourceType"]}`) : t("noResultResource")}</dd></div>
                      <div><dt>{t("catalogConditions")}</dt><dd>{action.conditions.length ? action.conditions.map((condition) => t(`conditionNames.${condition as PolicyConditionKey}`)).join(" · ") : t("noCatalogConditions")}</dd></div>
                      <div><dt>{t("catalogSource")}</dt><dd>{t("catalogPreviewSource")}</dd></div>
                    </dl>
                    <p className={styles.notice}>{t("catalogPreviewNotice")}</p>
                  </section>
                </td>
              </tr> : null}
            </Fragment>;
          })}
          {!actions.length ? <tr><td colSpan={6} className={styles.empty}>{t("noActions")}</td></tr> : null}
        </tbody>
      </Table>
    </div>
  </section>;
}
