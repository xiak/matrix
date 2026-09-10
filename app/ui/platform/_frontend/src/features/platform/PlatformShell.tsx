"use client";
import { useRef, useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { GitBranch, Grid2X2, Layers3, Menu, RefreshCw, ShieldCheck } from "lucide-react";
import { Button, ContentPage, Dialog, PageSkeleton, useLeaveConfirmation } from "@ui/xiak";
import { PlatformHeader } from "./PlatformHeader";
import { PlatformLink, usePendingNavigation } from "./Navigation";
import { useProducts } from "./ProductProvider";
import { productPresentation } from "./products";
import styles from "./PlatformShell.module.css";

export function PlatformShell({ children }: { children: ReactNode }) {
  const t = useTranslations("Platform");
  const pathname = usePathname();
  const pending = usePendingNavigation();
  const inventory = useProducts();
  const background = useRef<HTMLDivElement>(null);
  const [navOpen, setNavOpen] = useState(false);
  const leave = useLeaveConfirmation();
  const route = pathname.split("/").filter(Boolean);
  const product = inventory.value?.products.find(item => item.routeKey === route[0]);
  const Icon = product?.id === "DEVOPS" ? GitBranch : product ? Layers3 : ShieldCheck;
  const label = product ? t(`productNames.${product.id}`) : route[0] === "account" ? t("account") : t("home");
  const page = product && productPresentation[product.id].pages.find(item => item === route[1]);
  const title = page ? t(`pages.${page}`) : label;
  const navigation = <nav aria-label={t("navigation")} className={styles.navigation}>
    <PlatformLink href="/" onNavigate={() => setNavOpen(false)} aria-current={pathname === "/" ? "page" : undefined}><Grid2X2 aria-hidden="true" />{t("home")}</PlatformLink>
    {product ? productPresentation[product.id].pages.map(item => <PlatformLink key={item} href={`/${product.routeKey}/${item}/`} onNavigate={() => setNavOpen(false)} aria-current={page === item ? "page" : undefined}>{t(`pages.${item}`)}</PlatformLink>) : <PlatformLink href="/account/" onNavigate={() => setNavOpen(false)} aria-current={route[0] === "account" ? "page" : undefined}><ShieldCheck aria-hidden="true" />{t("account")}</PlatformLink>}
  </nav>;
  return <div className={styles.shell}>
    <a className={styles.skip} href="#matrix-main">{t("skip")}</a>
    <PlatformHeader backgroundRef={background} />
    <div className={styles.body} ref={background}>
      <aside className={styles.sider} aria-label={label}><div className={styles.serviceTitle}><Icon aria-hidden="true" /><strong>{label}</strong></div>{navigation}<div className={styles.siderFoot}><ShieldCheck aria-hidden="true" /><span>{t("privateCloud")}<small>{inventory.value?.releaseVersion ?? "—"}</small></span></div></aside>
      <main id="matrix-main" className={styles.main} tabIndex={-1}>
        <ContentPage parentLabel={label} pending={Boolean(pending)}>
          <ContentPage.Header leading={<Button className={styles.mobileMenu} variant="ghost" iconOnly aria-label={t("menu")} aria-expanded={navOpen} onClick={() => setNavOpen(true)}><Menu aria-hidden="true" /></Button>} trailing={<Button variant="ghost" className={styles.refresh} aria-label={t("refresh")} disabled={inventory.status === "loading"} onClick={() => leave(inventory.refresh)}><RefreshCw aria-hidden="true" /><span>{t("refresh")}</span></Button>}><h1 className={styles.pageTitle}>{pending ? t("loading") : title}</h1></ContentPage.Header>
          <ContentPage.Body transitionKey={pathname} pending={Boolean(pending)} loading={<PageSkeleton label={t("loading")} />}><div className={styles.content}>{children}</div></ContentPage.Body>
        </ContentPage>
      </main>
      <Dialog open={navOpen} title={label} closeLabel={t("close")} onClose={() => setNavOpen(false)}>{navigation}</Dialog>
    </div>
  </div>;
}
