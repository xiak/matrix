"use client";
import { useEffect, useRef, useState, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { Grid2X2, Search, UserRound, LogOut, ShieldCheck, Layers3, GitBranch, ChevronRight } from "lucide-react";
import { Badge, Brand, Button, EmptyState, PageSkeleton, SearchInput, useLeaveConfirmation } from "@ui/xiak";
import { HeaderMenu, HeaderMenuTrigger } from "@ui/xiak/header-menu/HeaderMenu";
import { AppearanceControls } from "@/preferences/AppearanceControls";
import { useApi, useSession } from "../auth/SessionProvider";
import { useProducts } from "./ProductProvider";
import { productPresentation } from "./products";
import { PlatformLink } from "./Navigation";
import styles from "./PlatformShell.module.css";

export function PlatformHeader({ backgroundRef }: { backgroundRef: RefObject<HTMLElement | null> }) {
  const t = useTranslations("Platform");
  const api = useApi();
  const session = useSession()!;
  const inventory = useProducts();
  const leave = useLeaveConfirmation();
  const [surface, setSurface] = useState<"products" | "search" | "account" | null>(null);
  const [query, setQuery] = useState("");
  const productTrigger = useRef<HTMLButtonElement>(null);
  const searchTrigger = useRef<HTMLButtonElement>(null);
  const accountTrigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const key = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setSurface(current => current === "search" ? null : "search"); setQuery(""); } };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  const close = () => setSurface(null);
  const keyword = query.trim().toLowerCase();
  const matches = (terms: string[]) => terms.join(" ").toLowerCase().includes(keyword);
  const visible = inventory.value?.products.filter(product => matches([t(`productNames.${product.id}`), t(`productDescriptions.${product.id}`), t(`categories.${product.id}`), product.id, ...productPresentation[product.id].pages.map(page => t(`pages.${page}`))])) ?? [];
  const accountMatches = matches([t("account"), t("identity")]);
  return <header className={styles.header} data-surface="shell" aria-label={t("navigation")}>
    <PlatformLink href="/" aria-label={t("home")} className={styles.brand}><Brand responsive decorative /></PlatformLink>
    <HeaderMenuTrigger triggerRef={productTrigger} label={t("products")} icon={<Grid2X2 aria-hidden="true" />} open={surface === "products"} controls="matrix-product-menu" onClick={() => { setSurface(value => value === "products" ? null : "products"); setQuery(""); }} />
    <Button ref={searchTrigger} className={styles.searchTrigger} variant="ghost" aria-label={t("search")} aria-expanded={surface === "search"} aria-haspopup="dialog" onClick={() => { setSurface(value => value === "search" ? null : "search"); setQuery(""); }}><Search aria-hidden="true" /><span>{t("search")}</span><kbd>⌘ K</kbd></Button>
    <span className={styles.installation}>{t("privateCloud")}</span>
    <Button ref={accountTrigger} className={styles.accountTrigger} variant="ghost" iconOnly aria-label={`${t("account")} · ${session.loginName}`} aria-expanded={surface === "account"} aria-haspopup="dialog" onClick={() => setSurface(value => value === "account" ? null : "account")}><UserRound aria-hidden="true" /></Button>
    {surface === "products" || surface === "search" ? <HeaderMenu wide persistent={surface === "products"} label={t(surface === "products" ? "products" : "search")} id="matrix-product-menu" closeLabel={t("close")} onClose={close} triggerRef={surface === "products" ? productTrigger : searchTrigger} backgroundRef={backgroundRef}>
      <SearchInput aria-label={t("productSearch")} placeholder={t("productSearch")} value={query} onChange={event => setQuery(event.target.value)} clearAction={query ? { label: t("clearSearch"), onClear: () => setQuery("") } : undefined} className={styles.catalogSearch} />
      <p className={styles.catalogHint}>{t("signedInventory")}</p>
      {inventory.status === "loading" ? <PageSkeleton label={t("loadingProducts")} /> : <div className={styles.catalogGrid}>
        {visible.map(product => { const Icon = product.id === "APPLICATION_PAAS" ? Layers3 : GitBranch; return <section className={styles.catalogProduct} key={product.id}>
          <div className={styles.catalogCategory}><Icon aria-hidden="true" />{t(`categories.${product.id}`)}</div>
          <PlatformLink href={productPresentation[product.id].path} onNavigate={close} className={styles.catalogTitle}>{t(`productNames.${product.id}`)}<ChevronRight aria-hidden="true" /></PlatformLink>
          <p>{t(`productDescriptions.${product.id}`)}</p><Badge status={product.state === "READY" ? "success" : "warning"}>{t(`states.${product.state}`)}</Badge>
          <nav aria-label={t(`productNames.${product.id}`)}>{productPresentation[product.id].pages.map(page => <PlatformLink key={page} href={`/${product.routeKey}/${page}/`} onNavigate={close}>{t(`pages.${page}`)}</PlatformLink>)}</nav>
        </section>; })}
        {accountMatches ? <section className={styles.catalogProduct}><div className={styles.catalogCategory}><ShieldCheck aria-hidden="true" />{t("identity")}</div><PlatformLink href="/account/" onNavigate={close} className={styles.catalogTitle}>{t("account")}<ChevronRight aria-hidden="true" /></PlatformLink><p>{session.organizationId}</p></section> : null}
      </div>}
      {inventory.status !== "loading" && visible.length === 0 && !accountMatches ? <EmptyState title={t("noMatches")} /> : null}
    </HeaderMenu> : null}
    {surface === "account" ? <HeaderMenu label={t("account")} id="matrix-account-menu" closeLabel={t("close")} onClose={close} triggerRef={accountTrigger} backgroundRef={backgroundRef}>
      <section className={styles.accountIdentity}><small>{t("signedIn")}</small><strong>{session.loginName}</strong><small>{session.principalId}</small></section>
      <section className={styles.accountSection}><small>{t("organization")}</small><strong>{session.organizationId}</strong></section>
      <section className={styles.accountSection}><AppearanceControls variant="panel" /></section>
      <nav className={styles.accountSection} aria-label={t("account")}><PlatformLink href="/account/" onNavigate={close} className={styles.accountLink}><ShieldCheck aria-hidden="true" />{t("account")}<ChevronRight aria-hidden="true" /></PlatformLink><Button variant="ghost" onClick={() => { close(); leave(() => api.logout().catch(() => undefined)); }} className={styles.logout}><LogOut aria-hidden="true" />{t("logout")}</Button></nav>
    </HeaderMenu> : null}
  </header>;
}
