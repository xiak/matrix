"use client";

import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowUpRight, Boxes, ChartNoAxesCombined, Clock3, Database, Grid2X2, Layers3, MapPin, PackageSearch, Settings2, ShieldCheck, Star, Workflow, X } from "lucide-react";
import { Alert, Button, EmptyState, Progress, SearchInput } from "@ui/xiak";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { useLiveServiceDefinitionDirectory } from "../application/liveServiceActivation";
import type { ServiceDefinitionDirectory } from "../domain/serviceActivation";
import { matchesService, serviceCategories, serviceDirectory, type ServiceCategory, type ServiceDirectoryItem } from "../scenes/serviceDirectory";
import styles from "./ServiceDirectory.module.css";

const categoryIcons = {
  infrastructure: MapPin,
  applications: Layers3,
  databases: Database,
  analytics: ChartNoAxesCombined,
  middleware: Boxes,
  delivery: Workflow,
  security: ShieldCheck,
  management: Settings2
};
type DirectoryView = "all" | "favorites" | "recent" | ServiceCategory;

export function useServiceDirectory(): ServiceDirectoryItem[] {
  const t = useTranslations("ServiceDirectory");
  return useMemo(() => serviceDirectory.map((service) => ({
    ...service,
    label: t(`services.${service.id}.name`),
    description: t(`services.${service.id}.description`),
    categoryLabel: t(`categories.${service.category}`),
    groupLabel: t(`groups.${service.group}`),
    keywords: t(`services.${service.id}.keywords`).split(" ")
  })), [t]);
}

function MatchText({ text, query }: { text: string; query: string }) {
  const term = query.trim();
  const index = term ? text.toLowerCase().indexOf(term.toLowerCase()) : -1;
  return index < 0 ? text : <>{text.slice(0, index)}<mark>{text.slice(index, index + term.length)}</mark>{text.slice(index + term.length)}</>;
}

function ServiceEntry({ service, query = "", onNavigate, onRemoveFavorite }: { service: ServiceDirectoryItem; query?: string; onNavigate?(): void; onRemoveFavorite?(): void }) {
  const t = useTranslations("ServiceDirectory");
  const favorite = useConsoleUiStore((state) => state.favoriteServices.includes(service.id));
  const toggleFavorite = useConsoleUiStore((state) => state.toggleFavoriteService);
  const visitService = useConsoleUiStore((state) => state.visitService);
  return <li className={styles.service}>
    <Link className={styles.serviceLink} data-service-link="true" href={service.href} onAccepted={() => { onNavigate?.(); visitService(service.id); }}>
      <span className={styles.serviceName}><span><MatchText query={query} text={service.label} /></span><ArrowUpRight aria-hidden="true" /></span>
      <span className={styles.serviceDescription}><MatchText query={query} text={service.description} /></span>
    </Link>
    <button aria-label={t(favorite ? "removeFavorite" : "addFavorite", { name: service.label })} aria-pressed={favorite} className={styles.favorite} onClick={() => { if (favorite) onRemoveFavorite?.(); toggleFavorite(service.id); }} title={t(favorite ? "removeFavorite" : "addFavorite", { name: service.label })} type="button"><Star aria-hidden="true" /></button>
  </li>;
}

export function CommonServiceLinks() {
  const services = useServiceDirectory();
  return <ul className={styles.commonServices}>
    {services.filter((service) => ["applications", "postgresql", "devops", "monitoring"].includes(service.id)).map((service) => <ServiceEntry key={service.id} service={service} />)}
  </ul>;
}

export function ServiceDirectory({ onClose, onNavigate, preview = true, readServiceDefinitions }: {
  onClose(): void;
  onNavigate(): void;
  preview?: boolean;
  readServiceDefinitions?(): Promise<ServiceDefinitionDirectory>;
}) {
  const t = useTranslations("ServiceDirectory");
  const presentation = useServiceDirectory();
  const live = useLiveServiceDefinitionDirectory(!preview, readServiceDefinitions);
  const services = useMemo(() => preview ? presentation : [
    ...presentation.filter((service) => service.discovery === "platform"),
    ...(live.directory?.services.flatMap((definition) => {
      const destination = presentation.find((item) => item.id === definition.id);
      return destination?.discovery === "managed" ? [{ ...destination, label: definition.displayName, description: definition.description,
        keywords: [definition.id, definition.displayName, ...destination.keywords] }] : [];
    }) ?? [])
  ], [live.directory, presentation, preview]);
  const unsupported = preview ? [] : live.directory?.services.filter((definition) => {
    const destination = presentation.find((item) => item.id === definition.id);
    return !destination || destination.discovery === "preview";
  }) ?? [];
  const managedDirectoryPending = !preview && live.status === "checking";
  const managedDirectoryFailed = !preview && live.status !== "checking" && live.status !== "ready";
  const liveFailure = live.status === "forbidden" || live.status === "expired" ? live.status : "unavailable";
  const favorites = useConsoleUiStore((state) => state.favoriteServices);
  const recent = useConsoleUiStore((state) => state.recentServices);
  const [view, setView] = useState<DirectoryView>("all");
  const [query, setQuery] = useState("");
  const search = useRef<HTMLInputElement>(null);
  const navigation = useRef<HTMLElement>(null);
  const results = useRef<HTMLDivElement>(null);
  const resultId = useId();
  const searching = Boolean(query.trim());
  const visible = searching ? services.filter((service) => matchesService(service, query))
    : view === "favorites" ? services.filter((service) => favorites.includes(service.id))
      : view === "recent" ? recent.flatMap((id) => services.filter((service) => service.id === id))
        : services.filter((service) => view === "all" || service.category === view);
  const unsupportedVisible = unsupported.filter((definition) => searching
    ? query.normalize("NFKC").toLowerCase().trim().split(/\s+/).every((word) =>
      `${definition.id} ${definition.displayName} ${definition.description}`.normalize("NFKC").toLowerCase().includes(word))
    : view === "all");
  const views = [
    { id: "all", label: t("all"), icon: Grid2X2, count: services.length + unsupported.length },
    { id: "favorites", label: t("favorites"), icon: Star, count: services.filter((service) => favorites.includes(service.id)).length },
    { id: "recent", label: t("recent"), icon: Clock3, count: services.filter((service) => recent.includes(service.id)).length },
    ...serviceCategories.map((id) => ({ id, label: t(`categories.${id}`), icon: categoryIcons[id], count: services.filter((service) => service.category === id).length }))
  ];
  const selectedView = searching ? "all" : view;

  useEffect(() => { search.current?.focus(); }, []);

  function changeView(id: DirectoryView) {
    setView(id);
    setQuery("");
    if (results.current) results.current.scrollTop = 0;
  }

  function navigateCategories(event: KeyboardEvent<HTMLElement>) {
    const direction = ["ArrowDown", "ArrowRight"].includes(event.key) ? 1 : ["ArrowUp", "ArrowLeft"].includes(event.key) ? -1 : 0;
    if (!direction && event.key !== "Home" && event.key !== "End") return;
    const buttons = Array.from(navigation.current?.querySelectorAll<HTMLButtonElement>("button") ?? []);
    const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (index < 0) return;
    event.preventDefault();
    const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (index + direction + buttons.length) % buttons.length;
    const nextView = views[next];
    if (!nextView) return;
    changeView(nextView.id as DirectoryView);
    buttons[next]?.focus();
  }

  function navigateResults(event: KeyboardEvent<HTMLDivElement>) {
    if (!(event.target instanceof HTMLAnchorElement) || !event.target.hasAttribute("data-service-link")) return;
    const links = Array.from(results.current?.querySelectorAll<HTMLAnchorElement>("[data-service-link]") ?? []);
    const index = links.indexOf(event.target);
    if (event.key === "ArrowUp" && index === 0) { event.preventDefault(); search.current?.focus(); return; }
    const next = event.key === "ArrowDown" ? Math.min(index + 1, links.length - 1) : event.key === "ArrowUp" ? index - 1 : event.key === "Home" ? 0 : event.key === "End" ? links.length - 1 : -1;
    if (next < 0) return;
    event.preventDefault();
    links[next]?.focus();
  }

  const emptyTitle = searching ? "noResults" : view === "favorites" ? "noFavorites" : "noRecent";
  const emptyHint = searching ? "noResultsHint" : view === "favorites" ? "noFavoritesHint" : "noRecentHint";
  return <div className={styles.directory}>
    <header className={styles.toolbar}>
      <div className={styles.identity}><Grid2X2 aria-hidden="true" /><strong>{t("title")}</strong></div>
      <div className={styles.searchField}>
        <SearchInput clearAction={query ? { label: t("clear"), onClear: () => setQuery("") } : undefined} controlSize="large" aria-controls={resultId} aria-label={t("search")} autoComplete="off" onChange={(event) => { setQuery(event.target.value); if (results.current) results.current.scrollTop = 0; }} onKeyDown={(event) => {
          if (event.nativeEvent.isComposing) return;
          const first = results.current?.querySelector<HTMLAnchorElement>("[data-service-link]");
          if (event.key === "ArrowDown") { event.preventDefault(); first?.focus(); }
          if (event.key === "Enter" && searching) { event.preventDefault(); first?.click(); }
        }} placeholder={t("placeholder")} ref={search} type="search" value={query} />
      </div>
      <Button aria-label={t("close")} className={styles.close} iconOnly onClick={onClose} size="large" variant="ghost"><X aria-hidden="true" /></Button>
    </header>
    <div className={styles.workspace}>
      <nav aria-label={t("categoriesLabel")} className={styles.navigation} onKeyDown={navigateCategories} ref={navigation}>
        {views.map(({ id, label, icon: Icon, count }, index) => <div key={id}>
          {index === 3 ? <p className={styles.navigationLabel}>{t("categoriesLabel")}</p> : null}
          <button aria-controls={resultId} aria-pressed={selectedView === id} className={styles.categoryButton} onClick={() => changeView(id as DirectoryView)} tabIndex={selectedView === id ? 0 : -1} type="button"><Icon aria-hidden="true" /><span>{label}</span><small>{count}</small></button>
        </div>)}
      </nav>
      <div className={styles.results} id={resultId} onKeyDown={navigateResults} ref={results}>
        {managedDirectoryPending ? <Progress aria-label={t("live.loading")} className={styles.liveProgress} /> : null}
        <div className={styles.resultHeading}><div><h2>{searching ? t("searchTitle") : views.find((item) => item.id === view)?.label}</h2><p>{searching ? t("searchScope") : t(preview ? "browseHint" : "live.browseHint")}</p></div><span aria-live="polite" role="status">{t("count", { count: visible.length + unsupportedVisible.length })}</span></div>
        {managedDirectoryFailed ? <Alert className={styles.liveFailure} status="warning"><div><strong>{t(`live.${liveFailure}Title`)}</strong><span>{t(`live.${liveFailure}Hint`)}</span></div><Button onClick={live.retry} size="small" variant="secondary">{t("live.retry")}</Button></Alert> : null}
        {!visible.length && !unsupportedVisible.length ? managedDirectoryPending ? <p className={styles.loadingHint} role="status">{t("live.loading")}</p>
          : <EmptyState title={t(!preview && !searching && view === "all" ? "live.emptyTitle" : emptyTitle)} description={t(!preview && !searching && view === "all" ? "live.emptyHint" : emptyHint)} icon={<PackageSearch />} action={<Button onClick={() => { changeView("all"); search.current?.focus(); }} variant="secondary">{t("reset")}</Button>} />
          : !searching && (view === "favorites" || view === "recent") ? <ul className={styles.savedServices}>{visible.map((service) => <ServiceEntry key={service.id} onNavigate={onNavigate} onRemoveFavorite={view === "favorites" ? () => search.current?.focus() : undefined} service={service} />)}</ul>
            : <div className={styles.groups}>{serviceCategories.map((category) => {
              const entries = visible.filter((service) => service.category === category);
              const Icon = categoryIcons[category];
              return entries.length ? <section className={styles.group} key={category}><h3><Icon aria-hidden="true" />{t(`categories.${category}`)}<span>{entries.length}</span></h3>{[...new Set(entries.map((service) => service.group))].map((group) => <div key={group}><h4 className={styles.groupLabel}>{t(`groups.${group}`)}</h4><ul>{entries.filter((service) => service.group === group).map((service) => <ServiceEntry key={service.id} onNavigate={onNavigate} query={query} service={service} />)}</ul></div>)}</section> : null;
            })}{unsupportedVisible.length ? <section className={styles.group}><h3>{t("live.unsupportedTitle")}<span>{unsupportedVisible.length}</span></h3><ul>{unsupportedVisible.map((definition) => <li className={styles.service} key={definition.id}><div className={styles.serviceLink}><span className={styles.serviceName}>{definition.displayName}</span><span className={styles.serviceDescription}>{definition.description}</span><span className={styles.serviceDescription}>{t("live.unsupportedHint")}</span></div></li>)}</ul></section> : null}</div>}
      </div>
    </div>
    <footer className={styles.footer}><div><span className={styles.previewHint}>{t(preview ? "previewHint" : "live.visibilityHint")}</span><span className={styles.sessionHint}>{t(preview ? "sessionHint" : "live.sessionHint")}</span></div></footer>
  </div>;
}
