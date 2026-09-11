"use client";

import { ConsoleLink as Link, useConsoleNavigation } from "../routes/ConsoleNavigation";
import { memo, useMemo } from "react";
import { useTranslations } from "next-intl";
import { consoleRouteHref } from "../domain/selection";
import { ChevronRight } from "lucide-react";
import { Brand, Layout, Progress } from "@ui/xiak";
import type { ConsoleScene } from "../scenes/consoleScene";
import { AccountMenu, type AccountIdentity } from "./AccountMenu";
import { GlobalSearch } from "./GlobalSearch";
import { NotificationCenter } from "./NotificationCenter";
import { ProductLauncher } from "./ProductLauncher";
import { RegionSwitcher } from "./ScopeSwitcher";
import { useServiceDirectory } from "./ServiceDirectory";
import { useConsoleUiStore, type HeaderPanel } from "../application/consoleUiStore";
import styles from "./ConsoleHeader.module.css";

type ConsoleHeaderProps = Readonly<{
  scene: Pick<ConsoleScene, "preview" | "search" | "scope" | "activeOperationCount" | "messages">;
  scope: Readonly<{
    regionId: string;
    onRegionChange(value: string): void;
  }>;
  productName: string;
  identity: AccountIdentity;
  onLogout(): void;
  revoking: boolean;
}>;

export function ConsoleBrand({ inactive = false }: { inactive?: boolean }) {
  const t = useTranslations("Console");
  return (
    <Link aria-label={t("brandHome")} className={styles.brand} inert={inactive} href="/console/">
      <Brand decorative responsive />
    </Link>
  );
}

function RouteProgress() {
  const { pendingSelection } = useConsoleNavigation();
  const t = useTranslations("Console");
  const navigation = useTranslations("ServiceNavigation");
  if (!pendingSelection) return null;
  return <Progress className={styles.routeProgress} aria-label={t("openingPage", { name: navigation(`items.${pendingSelection.view ?? pendingSelection.section}.label`) })} />;
}

export const ConsoleHeader = memo(function ConsoleHeader({ scene, productName, scope, identity, onLogout, revoking }: ConsoleHeaderProps) {
  const t = useTranslations("Console");
  const navigation = useTranslations("ServiceNavigation");
  const resourceKinds = useTranslations("GlobalSearch.resourceKinds");
  const services = useServiceDirectory();
  const activePanel = useConsoleUiStore((state) => state.headerPanel);
  const onPanelChange = useConsoleUiStore((state) => state.setHeaderPanel);
  const visitService = useConsoleUiStore((state) => state.visitService);
  const searchResults = useMemo(() => [
    ...services.map((service) => ({ ...service, id: `service-${service.id}`, category: "product" as const })),
    ...(["messages", "resources", "operations"] as const).map((section) => ({ id: `page-${section}`, label: navigation(`items.${section}.label`), description: navigation(`items.${section}.hint`), href: consoleRouteHref({ section }), category: "page" as const, icon: "foundation" as const })),
    ...scene.search.map((item) => ({ ...item, description: `${resourceKinds(item.resourceKind)} · ${item.description}`, keywords: [...(item.keywords ?? []), resourceKinds(item.resourceKind)] }))
  ], [services, navigation, resourceKinds, scene.search]);
  const catalogOpen = activePanel === "products";
  const openPanel = (panel: HeaderPanel) => (open: boolean) => {
    if (catalogOpen && panel !== "products") return;
    onPanelChange(open ? panel : null);
  };

  return (
    <Layout.Header data-surface="shell" aria-label={t("globalNavigation")} className={styles.header}>
      <div className={styles.navigation}>
        <ConsoleBrand inactive={catalogOpen} />
        <span aria-hidden="true" className={styles.divider} />
        {scene.preview ? (
          <ProductLauncher onOpenChange={openPanel("products")} open={activePanel === "products"} />
        ) : <div className={styles.productContext}><span>{t("console")}</span><ChevronRight aria-hidden="true" /><strong>{productName}</strong></div>}
      </div>

      {scene.preview ? <GlobalSearch inactive={catalogOpen} onChoose={(id) => { const service = services.find((item) => `service-${item.id}` === id); if (service) visitService(service.id); }} onOpenChange={openPanel("search")} open={activePanel === "search"} results={searchResults} /> : null}

      <div className={styles.utilities} inert={catalogOpen}>
        {scene.preview && scene.scope ? <RegionSwitcher {...scope} onOpenChange={openPanel("region")} open={activePanel === "region"} scope={scene.scope} /> : null}
        {scene.preview ? <span className={styles.previewChip} title={t("previewHint")}><span aria-hidden="true" />MOCK<span className={styles.previewLabel}>{t("preview")}</span></span> : null}
        <div aria-label={t("globalTools")} className={styles.tools}>
          {scene.preview ? <NotificationCenter activeOperationCount={scene.activeOperationCount} messages={scene.messages} onOpenChange={openPanel("notifications")} open={activePanel === "notifications"} /> : null}
          <AccountMenu identity={identity} onLogout={onLogout} onOpenChange={openPanel("account")} open={activePanel === "account"} revoking={revoking} />
        </div>
      </div>
      <RouteProgress />
    </Layout.Header>
  );
});
