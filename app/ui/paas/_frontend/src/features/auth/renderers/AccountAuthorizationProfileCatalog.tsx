"use client";

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, Table, TablePagination, TableSkeleton, TableToolbar } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess, type AuthorizationProfileClient, type AuthorizationProfileLoad } from "../application/AccountAccessProvider";
import type { AuthorizationProfileAction, AuthorizationProfileEntry, AuthorizationResourceShape } from "../domain/accounts";
import { AuthorizationProfilePublishingPreview } from "./AuthorizationProfilePublishingPreview";
import styles from "./AccountAccessRenderer.module.css";

type CatalogState = { status: "loading" } | AuthorizationProfileLoad;

function scopeStatus(scope: AuthorizationProfileAction["scope"]): "success" | "warning" | "neutral" {
  if (scope === "TENANT") return "success";
  if (scope === "INSTALLATION") return "warning";
  return "neutral";
}

export function AccountAuthorizationProfileCatalog() {
  const t = useTranslations("AuthorizationProfileCatalog");
  const client = useAccountAccess().authorizationProfiles;
  if (!client) return <EmptyState title={t("notConnected")} description={t("notConnectedHint")} />;
  return <AuthorizationProfileCatalog key={`${client.accountId}:${client.preview ? "preview" : "live"}`} client={client} />;
}

function AuthorizationProfileCatalog({ client }: { client: AuthorizationProfileClient }) {
  const t = useTranslations("AuthorizationProfileCatalog");
  const toolbarLabels = useTableToolbarLabels();
  const [state, setState] = useState<CatalogState>({ status: "loading" });
  const [query, setQuery] = useState("");
  const [actionQuery, setActionQuery] = useState("");
  const [productPage, setProductPage] = useState(1);
  const [productPageSize, setProductPageSize] = useState(10);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [selectedProduct, setSelectedProduct] = useState<string | null>(null);
  const [publishingPreview, setPublishingPreview] = useState(false);
  const selectedHeading = useRef<HTMLHeadingElement>(null);
  const publishingTrigger = useRef<HTMLButtonElement>(null);
  const restorePublishingFocus = useRef(false);
  const returnProduct = useRef<string | null>(null);
  const productButtons = useRef(new Map<string, HTMLButtonElement>());
  const request = useRef(0);

  const load = useCallback(() => {
    if (!client) return;
    const current = ++request.current;
    setState({ status: "loading" });
    void client.load().then((result) => { if (current === request.current) setState(result); });
  }, [client]);

  useEffect(() => {
    if (!client) return;
    const current = ++request.current;
    void client.load().then((result) => { if (current === request.current) setState(result); });
    return () => { request.current += 1; };
  }, [client]);
  useLayoutEffect(() => {
    if (publishingPreview || !restorePublishingFocus.current) return;
    restorePublishingFocus.current = false;
    publishingTrigger.current?.focus();
  }, [publishingPreview]);
  const entries = useMemo(() => state.status === "ready" ? state.directory.items : [], [state]);
  const selected = useMemo(() => entries.find((entry) => entry.profile.product === selectedProduct) ?? null, [entries, selectedProduct]);
  useEffect(() => { if (selected) selectedHeading.current?.focus(); }, [selected]);
  useLayoutEffect(() => {
    if (state.status !== "ready" || selected || !returnProduct.current) return;
    const product = returnProduct.current;
    returnProduct.current = null;
    productButtons.current.get(product)?.focus();
  }, [selected, state.status]);
  const filteredEntries = useMemo(() => {
    const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return entries.filter((entry) => {
      const value = [entry.profile.product, entry.profile.callingService, ...entry.profile.actions.map((action) => action.action)].join(" ").toLowerCase();
      return words.every((word) => value.includes(word));
    });
  }, [entries, query]);

  const filteredActions = useMemo(() => {
    if (!selected) return [];
    const words = actionQuery.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return selected.profile.actions.filter((action) => {
      const value = [action.action, action.resourceKind, action.scope, action.resultResourceKind ?? "", ...(action.conditions ?? []).map((condition) => condition.key)].join(" ").toLowerCase();
      return words.every((word) => value.includes(word));
    });
  }, [actionQuery, selected]);

  const productPages = Math.max(1, Math.ceil(filteredEntries.length / productPageSize));
  const currentProductPage = Math.min(productPage, productPages);
  const visibleProducts = filteredEntries.slice((currentProductPage - 1) * productPageSize, currentProductPage * productPageSize);
  const pages = Math.max(1, Math.ceil(filteredActions.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visibleActions = filteredActions.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const resetActions = () => { setActionQuery(""); setPage(1); };
  const open = (entry: AuthorizationProfileEntry) => {
    returnProduct.current = entry.profile.product;
    setActionQuery(""); setPage(1); setSelectedProduct(entry.profile.product);
  };
  const back = () => setSelectedProduct(null);
  const closePublishingPreview = () => { restorePublishingFocus.current = true; setPublishingPreview(false); };

  if (selected && publishingPreview) return <AuthorizationProfilePublishingPreview entry={selected} onClose={closePublishingPreview} />;

  if (selected) return <section aria-label={t("productDetail", { product: selected.profile.product })} className={styles.catalogSection}>
    <div className={styles.catalogDetailHeading}>
      <Button variant="ghost" size="small" onClick={back}><ArrowLeft aria-hidden="true" />{t("back")}</Button>
      <h2 ref={selectedHeading} tabIndex={-1}>{selected.profile.product}</h2>
      {client.preview ? <Badge status="warning">{t("mock")}</Badge> : null}
      {client.preview ? <Button ref={publishingTrigger} variant="secondary" size="small" onClick={() => setPublishingPreview(true)}>{t("previewPublishing")}</Button> : null}
    </div>
    <p className={styles.note}>{t("detailHint")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("revision")}</dt><dd>{selected.profile.revision}</dd></div>
      <div><dt>{t("callingService")}</dt><dd>{selected.profile.callingService}</dd></div>
      <div><dt>{t("actions")}</dt><dd>{selected.profile.actions.length}</dd></div>
      <div className={styles.catalogDigest}><dt>{t("digest")}</dt><dd><code>{selected.contentDigest}</code></dd></div>
    </dl>
    {selected.profile.actions.some((action) => action.scope !== "TENANT") ? <Alert status="warning">{t("platformScopeHint")}</Alert> : null}
    <TableToolbar labels={toolbarLabels}
      search={{ label: t("searchActions"), placeholder: t("searchActionsPlaceholder"), value: actionQuery, onChange: (value) => { setActionQuery(value); setPage(1); } }}
      status={t("actionCount", { count: filteredActions.length })} />
    {visibleActions.length ? <Table aria-label={t("actionTable", { product: selected.profile.product })} mobileLayout="stack" className={styles.catalogActionTable}>
      <thead><tr><th scope="col">{t("action")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("resource")}</th><th scope="col">{t("targets")}</th><th scope="col">{t("conditions")}</th></tr></thead>
      <tbody>{visibleActions.map((action) => <tr key={action.action}>
        <td data-label={t("action")}><code>{action.action}</code></td>
        <td data-label={t("scope")}><Badge status={scopeStatus(action.scope)}>{t(`scopes.${action.scope}`)}</Badge></td>
        <td data-label={t("resource")}><strong>{action.resourceKind}</strong>{action.resultResourceKind ? <small>{t("resultResource", { resource: action.resultResourceKind })}</small> : null}</td>
        <td data-label={t("targets")}>{action.resourceShapes.map((shape) => <span className={styles.catalogShape} key={`${shape.mode}:${shape.collectionUsage ?? ""}`}>{t(shapeKey(shape))}</span>)}</td>
        <td data-label={t("conditions")}>{action.conditions?.length ? action.conditions.map((condition) => <span className={styles.catalogCondition} key={condition.key} title={`${condition.valueType} · ${condition.source}`}>{condition.key}</span>) : t("none")}</td>
      </tr>)}</tbody>
    </Table> : <EmptyState title={t("noActions")} description={t("noActionsHint")} action={<Button variant="secondary" onClick={resetActions}>{toolbarLabels.resetQuery}</Button>} />}
    <Table.Footer note={t("completeActions", { count: selected.profile.actions.length })}><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>
  </section>;

  return <section aria-label={t("title")} className={styles.catalogSection}>
    <CatalogNotice preview={client.preview} />
    <TableToolbar labels={toolbarLabels}
      search={{ label: t("searchProducts"), placeholder: t("searchProductsPlaceholder"), value: query, onChange: (value) => { setQuery(value); setProductPage(1); } }}
      status={state.status === "ready" ? t("productCount", { count: filteredEntries.length }) : state.status === "loading" ? t("loading") : undefined} />
    {state.status === "loading" ? <TableSkeleton label={t("loading")} rows={4} /> : null}
    {state.status !== "ready" && state.status !== "loading" ? <>
      <Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`errors.${state.status}`)}</Alert>
      {state.status !== "expired" ? <div><Button variant="secondary" onClick={() => load()}>{t("retry")}</Button></div> : null}
    </> : null}
    {state.status === "ready" ? <>{visibleProducts.length ? <Table aria-label={t("table")} mobileLayout="stack" className={styles.catalogProductTable}>
      <thead><tr><th scope="col">{t("product")}</th><th scope="col">{t("callingService")}</th><th scope="col">{t("revision")}</th><th scope="col">{t("actions")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("digest")}</th></tr></thead>
      <tbody>{visibleProducts.map((entry) => {
        const scopes = [...new Set(entry.profile.actions.map((action) => action.scope))];
        return <tr key={entry.profile.product}>
          <td data-label={t("product")}><button
            ref={(node) => {
              if (node) productButtons.current.set(entry.profile.product, node);
              else productButtons.current.delete(entry.profile.product);
            }}
            className={styles.userLink}
            onClick={() => open(entry)}
          >{entry.profile.product}</button></td>
          <td data-label={t("callingService")}>{entry.profile.callingService}</td>
          <td data-label={t("revision")}>{entry.profile.revision}</td>
          <td data-label={t("actions")}>{entry.profile.actions.length}</td>
          <td data-label={t("scope")}><div className={styles.catalogBadges}>{scopes.map((scope) => <Badge status={scopeStatus(scope)} key={scope}>{t(`scopes.${scope}`)}</Badge>)}</div></td>
          <td data-label={t("digest")}><code className={styles.catalogDigestShort} title={entry.contentDigest}>{entry.contentDigest.slice(0, 18)}…</code></td>
        </tr>;
      })}</tbody>
    </Table> : <EmptyState title={t("noProducts")} description={t("noProductsHint")} action={<Button variant="secondary" onClick={() => { setQuery(""); setProductPage(1); }}>{toolbarLabels.resetQuery}</Button>} />}
    <Table.Footer note={t("completeProducts", { count: entries.length })}><TablePagination page={currentProductPage} pages={productPages} pageSize={productPageSize} onPageChange={setProductPage} onPageSizeChange={(size) => { setProductPageSize(size); setProductPage(1); }} labels={{ summary: t("page", { page: currentProductPage, pages: productPages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer></> : null}
  </section>;
}

function CatalogNotice({ preview }: { preview: boolean }) {
  const t = useTranslations("AuthorizationProfileCatalog");
  return <div className={styles.catalogNotice}>
    <Alert status={preview ? "warning" : "info"}>{t(preview ? "mockNotice" : "notice")}</Alert>
    <p className={styles.note}>{t("ownershipHint")}</p>
  </div>;
}

function shapeKey(shape: AuthorizationResourceShape): "shapes.INSTANCE" | "shapes.INSTANCE_PREFIX" | "shapes.COLLECTION_LIST" | "shapes.COLLECTION_CREATE" {
  if (shape.mode === "COLLECTION") return shape.collectionUsage === "COLLECTION_CREATE" ? "shapes.COLLECTION_CREATE" : "shapes.COLLECTION_LIST";
  return shape.prefixAllowed ? "shapes.INSTANCE_PREFIX" : "shapes.INSTANCE";
}
