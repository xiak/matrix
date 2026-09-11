"use client";

import {
  Fragment,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentProps,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent
} from "react";
import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import {
  Activity,
  Bell,
  Boxes,
  Building2,
  ChartNoAxesCombined,
  ChevronRight,
  CircleGauge,
  Database,
  FileText,
  Star,
  Gauge,
  GitBranch,
  KeyRound,
  Network,
  LayoutDashboard,
  LogOut,
  MapPin,
  Menu,
  PackageSearch,
  PackagePlus,
  PanelRightClose,
  RefreshCcw,
  ServerCog,
  Settings2,
  ShieldCheck,
  Users,
  Workflow,
  X
} from "lucide-react";
import { useSession } from "@/features/auth/application/SessionProvider";
import { AccountAccessProvider, useAccountAccess, useAccountCapabilities } from "@/features/auth/application/AccountAccessProvider";
import { LoginRenderer } from "@/features/auth/renderers/LoginRenderer";
import type { AccountRepository } from "@/features/auth/repositories/iamRepository";
import {
  App,
  Alert,
  EmptyState,
  Button,
  ContentPage,
  Layout,
  Sider,
  Skeleton,
  PageSkeleton,
  Progress,
  useLeaveConfirmation,
  type PageSkeletonLayout
} from "@ui/xiak";
import { ControlPlaneProvider, useControlPlane } from "../application/ControlPlaneProvider";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ExperienceSnapshot } from "../domain/experience";
import { consoleRouteHref, type ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type {
  ConsoleWorkspaceScene,
  NavigationIconKind,
  RailIconKind
} from "../scenes/consoleScene";
import { ConsoleBrand, ConsoleHeader } from "./ConsoleHeader";
import headerStyles from "./ConsoleHeader.module.css";
import { ConsoleContentRenderer } from "./ConsoleContentRenderer";
import { ConsoleWorkspaceRenderer } from "./ConsoleWorkspaceRenderer";
import styles from "./ConsoleShellRenderer.module.css";
import { useServiceDirectory } from "./ServiceDirectory";
import { serviceForSection, type ServiceId } from "../scenes/serviceDirectory";
import { ConsoleNavigationProvider, useConsoleNavigation } from "../routes/ConsoleNavigation";

function pageSkeletonLayout({ section, view }: ControlPlaneRouteSelection): PageSkeletonLayout {
  if (section === "overview" || (!view && ["devops", "observability", "logs"].includes(section))) return "dashboard";
  if (section === "access") return !view ? "dashboard" : view === "settings" || view === "user-sso" ? "access" : "table";
  if (["regions", "quotas", "catalog"].includes(section) || view === "environments") return "cards";
  if (section === "operations" || section === "messages" || view === "alerts" || view === "health") return "list";
  return "table";
}

const railIcons = {
  overview: LayoutDashboard,
  database: Database,
  devops: GitBranch,
  observability: ChartNoAxesCombined,
  access: ShieldCheck
} satisfies Record<RailIconKind, typeof Database>;

const favoriteIcons = { regions: MapPin, applications: Boxes, postgresql: Database, devops: GitBranch, monitoring: ChartNoAxesCombined, logs: FileText, iam: ShieldCheck } satisfies Record<ServiceId, typeof Database>;

const navigationIcons = {
  policy: FileText,
  sso: Network,
  key: KeyRound,
  users: Users,
  settings: Settings2,
  tenants: Building2,
  overview: LayoutDashboard,
  messages: Bell,
  resources: Boxes,
  operations: Activity,
  catalog: PackageSearch,
  quota: Gauge,
  installation: ServerCog,
  region: MapPin,
  pipeline: Workflow,
  observability: ChartNoAxesCombined,
  access: ShieldCheck
} satisfies Record<NavigationIconKind, typeof Database>;

function ShellFrame({ children }: { children: React.ReactNode }) {
  return (
    <App.Frame className={styles.shellContainer}>
      <App.Background />
      <App.Layers><App.Layer>{children}</App.Layer></App.Layers>
    </App.Frame>
  );
}

// Header state must not invalidate the service page, its forms or sidebars.
// Only these overlay boundaries subscribe to the header's open/closed state.
function HeaderBackdrop() {
  const t = useTranslations("Console");
  const panel = useConsoleUiStore((state) => state.headerPanel);
  const setPanel = useConsoleUiStore((state) => state.setHeaderPanel);
  if (!panel || panel === "products") return null;
  return <button tabIndex={-1} aria-label={t("closeOverlay")} className={styles.globalBackdrop} onClick={() => setPanel(null)} type="button" />;
}

function ServiceLayout({ children }: { children: React.ReactNode }) {
  const catalogOpen = useConsoleUiStore((state) => state.headerPanel === "products");
  return <Layout inert={catalogOpen}>{children}</Layout>;
}

function ConsoleRefresh({ account, pending }: { account: boolean; pending: boolean }) {
  const t = useTranslations("Console");
  const access = useAccountAccess();
  const controlPlane = useControlPlane();
  const loading = account ? access.loading : controlPlane.loading;
  return <Button aria-label={t("refresh")} aria-busy={loading} disabled={pending || loading || (account && access.busy)} onClick={() => account ? access.reload() : void controlPlane.reload()} size="small" variant="ghost"><RefreshCcw className={loading ? styles.refreshing : undefined} aria-hidden="true" /><span>{t("refresh")}</span></Button>;
}

function LoadingShell({ error, logout, retry, revoking, sessionError, selection }: {
  error: string | null;
  logout(): void;
  retry(): void;
  revoking: boolean;
  sessionError: string | null;
  selection: ControlPlaneRouteSelection;
}) {
  const t = useTranslations("Console");
  return (
    <ShellFrame>
      <App>
        <App.Base>
          <Layout.Header data-surface="shell" className={headerStyles.header}>
            <ConsoleBrand />
            <div className={styles.loadingPath}><span>{t("unifiedConsole")}</span><ChevronRight aria-hidden="true" /><span>{t("loading")}</span></div>
            <Button aria-label={t("logoutLabel")} className={styles.loadingLogout} disabled={revoking} onClick={logout} size="small" variant="ghost">
              <LogOut aria-hidden="true" />{revoking ? t("loggingOut") : t("logout")}
            </Button>
          </Layout.Header>
          <Layout>
            <Sider className={styles.sider}>
              <Sider.RailMenu data-surface="shell" className={styles.railLoading}><Skeleton /><Skeleton /><Skeleton /></Sider.RailMenu>
              <Sider.ContextMenu className={`${styles.contextMenu} ${styles.contextLoading}`}><Skeleton /><Skeleton /><Skeleton /><Skeleton /></Sider.ContextMenu>
            </Sider>
            <Layout.Content>
              <ContentPage>
                <ContentPage.Header title={<Skeleton className={styles.headerSkeleton} />} />
                <ContentPage.Body>
                  {sessionError ? <Alert className={styles.feedback} status="danger">{sessionError}</Alert> : null}
                  {error ? (
                    <div role="alert"><EmptyState title={t("loadFailed")} description={error} icon={<ServerCog />} action={<div className={styles.recoveryActions}>
                      <Button onClick={retry} variant="secondary"><RefreshCcw aria-hidden="true" />{t("retry")}</Button>
                      <Button asChild variant="ghost"><Link href="/console/access/">{t("openAccess")}</Link></Button>
                    </div>} /></div>
                  ) : <PageSkeleton label={t("loadingConsole")} layout={pageSkeletonLayout(selection)} />}
                </ContentPage.Body>
              </ContentPage>
            </Layout.Content>
          </Layout>
        </App.Base>
      </App>
    </ShellFrame>
  );
}

type WorkspaceSize = "compact" | "medium" | "wide";

// Route-level identity is known before feature data or heading contributions
// arrive. Keep query subscriptions here rather than rerendering the shell.
function ConsolePageHeader({ selection, pendingHref, title, ...props }: Omit<ComponentProps<typeof ContentPage.Header>, "back"> & { selection: ControlPlaneRouteSelection; pendingHref: string | null }) {
  const query = useSearchParams();
  const { navigate } = useConsoleNavigation();
  const navigationText = useTranslations("ServiceNavigation");
  const w = useTranslations("IamWorkspace");
  const workflowParents = { "create-user": "users", "create-group": "groups", "create-policy": "policies", "create-role": "roles" } as const;
  const view = selection.view;
  const id = pendingHref ? new URL(pendingHref, "https://matrix.invalid").searchParams.get("id") : query.get("id");
  const parent = selection.section !== "access" || !view ? null : view in workflowParents ? workflowParents[view as keyof typeof workflowParents] : id && ["users", "groups", "policies", "roles"].includes(view) ? view : null;
  return <ContentPage.Header {...props} title={title} back={parent ? { label: w("back"), parentLabel: navigationText(`items.${parent}.label`), disabled: Boolean(pendingHref), onClick: () => navigate(`/console/access/${parent}/`) } : undefined} />;
}

const workspaceActions = {
  "quota-order": { icon: PackagePlus, primary: true },
  "installation-order": { icon: ServerCog, primary: true },
  "platform-status": { icon: Activity, primary: false }
} satisfies Record<NonNullable<ConsoleWorkspaceScene>["kind"], {
  icon: typeof Activity;
  primary: boolean;
}>;

const focusableControlSelector = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex="0"]:not([role="separator"])'
].join(",");

function loopOverlayFocus(
  event: ReactKeyboardEvent<HTMLElement>,
  container: HTMLElement | null
) {
  if (event.key !== "Tab" || !container) return;
  const controls = Array.from(
    container.querySelectorAll<HTMLElement>(focusableControlSelector)
  ).filter((control) => control.getAttribute("aria-hidden") !== "true");
  const first = controls[0];
  const last = controls[controls.length - 1];
  if (!first || !last) return;
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function ConsoleShell() {
  const t = useTranslations("Console");
  const authErrors = useTranslations("Auth.errors");
  const accountMessages = useTranslations("AccountMenu");
  const accountText = useTranslations("AccountAccess");
  const dashboard = useTranslations("Dashboard");
  const directory = useTranslations("ServiceDirectory");
  const navigationText = useTranslations("ServiceNavigation");
  const iamWorkspaceText = useTranslations("IamWorkspace");
  const services = useServiceDirectory();
  const navigation = useConsoleNavigation();
  const favorites = useConsoleUiStore((state) => state.favoriteServices);
  const router = useRouter();
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const controlPlane = useControlPlane();
  const accountCapabilities = useAccountCapabilities();
  const scene = controlPlane.scene;
  const sidebarPanel = useRef<HTMLDivElement>(null);
  const sidebarTrigger = useRef<HTMLButtonElement>(null);
  const sidebarCloseButton = useRef<HTMLButtonElement>(null);
  const workspacePanel = useRef<HTMLElement>(null);
  const workspaceTrigger = useRef<HTMLButtonElement>(null);
  const workspaceCloseButton = useRef<HTMLButtonElement>(null);
  const workspaceFocusRequested = useRef(false);
  const sidebarOverlayOpen = useConsoleUiStore((state) => state.sidebarOverlayOpen);
  const workspaceOpen = useConsoleUiStore((state) => state.workspaceOpen);
  const openSidebar = useConsoleUiStore((state) => state.openSidebar);
  const closeSidebar = useConsoleUiStore((state) => state.closeSidebar);
  const toggleWorkspace = useConsoleUiStore((state) => state.toggleWorkspace);
  const closeWorkspace = useConsoleUiStore((state) => state.closeWorkspace);
  const [workspaceSize, setWorkspaceSize] = useState<WorkspaceSize>("medium");
  const [regionId, setRegionId] = useState("all");
  const setHeaderPanel = useConsoleUiStore((state) => state.setHeaderPanel);
  const principal = session.current;
  const organizationId = scene?.scope?.organization.id;
  const organizationName = scene?.scope?.organization.name;
  const headerIdentity = useMemo(() => ({
    accountType: accountMessages(principal?.loginName.includes("@") ? "child" : "primary"),
    loginName: principal?.loginName ?? t("user"),
    principalId: principal?.session.principalId ?? "IAM session",
    tenant: { id: organizationId, name: organizationName ?? principal?.session.organizationId ?? t("unspecifiedTenant") }
  }), [principal, organizationId, organizationName, accountMessages, t]);
  const headerScope = useMemo(() => ({ regionId, onRegionChange: setRegionId }), [regionId]);
  useEffect(() => () => useConsoleUiStore.getState().resetSessionUi(), []);

  const closeSidebarAndRestoreFocus = useCallback(() => {
    const shouldRestore = sidebarOverlayOpen;
    closeSidebar();
    if (shouldRestore) window.setTimeout(() => sidebarTrigger.current?.focus(), 0);
  }, [closeSidebar, sidebarOverlayOpen]);

  const closeWorkspaceAndRestoreFocus = useCallback(() => {
    closeWorkspace();
    window.setTimeout(() => workspaceTrigger.current?.focus(), 0);
  }, [closeWorkspace]);

  useEffect(() => { closeWorkspace(); }, [scene?.section, closeWorkspace]);

  useEffect(() => {
    if (!navigation.pendingHref) return;
    closeSidebar();
    closeWorkspace();
  }, [navigation.pendingHref, closeSidebar, closeWorkspace]);

  useEffect(() => {
    if (sidebarOverlayOpen) sidebarCloseButton.current?.focus();
  }, [sidebarOverlayOpen]);

  useEffect(() => {
    if (!workspaceOpen || !workspaceFocusRequested.current) return;
    workspaceFocusRequested.current = false;
    workspaceCloseButton.current?.focus();
  }, [workspaceOpen]);

  useEffect(() => {
    const dismiss = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      const headerPanel = useConsoleUiStore.getState().headerPanel;
      if (headerPanel === "products") return;
      if (headerPanel) {
        setHeaderPanel(null);
        return;
      }
      if (sidebarOverlayOpen) {
        closeSidebarAndRestoreFocus();
        return;
      }
      if (workspaceOpen) closeWorkspaceAndRestoreFocus();
    };
    window.addEventListener("keydown", dismiss);
    return () => window.removeEventListener("keydown", dismiss);
  }, [setHeaderPanel, closeSidebarAndRestoreFocus, closeWorkspaceAndRestoreFocus, sidebarOverlayOpen, workspaceOpen]);

  const sessionLogout = session.logout;
  const logout = useCallback(async () => {
    if (await sessionLogout()) {
      router.replace("/");
      return;
    }
    setHeaderPanel(null);
  }, [sessionLogout, router, setHeaderPanel]);
  const headerLogout = useCallback(() => { setHeaderPanel(null); requestLeave(logout); }, [setHeaderPanel, requestLeave, logout]);

  if (!scene) {
    return (
      <LoadingShell
        error={controlPlane.error ? t(`errors.${controlPlane.error}`) : null}
        logout={() => requestLeave(logout)}
        retry={() => void controlPlane.reload()}
        revoking={session.phase === "revoking"}
        sessionError={session.error ? authErrors(session.error) : null}
        selection={navigation.pendingSelection ?? navigation.selection}
      />
    );
  }

  const workspaceVisible = Boolean(scene.workspace && workspaceOpen && !navigation.pendingHref);
  const workspaceAction = scene.workspace && !navigation.pendingHref ? workspaceActions[scene.workspace.kind] : null;
  const WorkspaceActionIcon = workspaceAction?.icon;
  const activeService = scene.preview ? serviceForSection(scene.section) : undefined;
  const ProductContextIcon = activeService ? favoriteIcons[activeService.id] : railIcons[scene.productIcon];
  const productName = activeService ? directory(`services.${activeService.id}.name`) : scene.productId === "console" ? t("consoleName") : directory(`services.${scene.productId}.name`);
  const selectedPage = scene.navigation.find((item) => item.selected);
  const localNavigation = scene.navigation.filter((item) => scene.section !== "access" ||
    (["access", "settings", "roles", "tenants"].includes(item.id) || accountCapabilities.canManage) &&
    (item.id !== "tenants" || accountCapabilities.canCreateOrganizations));
  const accessTitles = { "create-user": accountText("createUserTitle"), "create-group": iamWorkspaceText("createGroup"), "create-policy": iamWorkspaceText("createPolicy"), "create-role": iamWorkspaceText("createRole"), tenants: accountText("tenantAccounts") };
  const accessView = scene.content.kind === "access" ? scene.content.view : undefined;
  const pageTitle = accessView && accessView in accessTitles ? accessTitles[accessView as keyof typeof accessTitles] : selectedPage ? navigationText(`items.${selectedPage.messageKey}.label`) : scene.section === "overview" ? dashboard("title") : t(`pages.${scene.section}.title`);
  const pendingSelection = navigation.pendingSelection;
  const pendingView = pendingSelection?.section === "access" ? pendingSelection.view : undefined;
  const visiblePageTitle = pendingSelection ? pendingView && pendingView in accessTitles ? accessTitles[pendingView as keyof typeof accessTitles] : navigationText(`items.${pendingSelection.view ?? pendingSelection.section}.label`) : pageTitle;
  const loadingLabel = pendingSelection ? t("openingPage", { name: visiblePageTitle }) : t("refreshingPage");

  function resizeWorkspace(event: ReactPointerEvent<HTMLDivElement>) {
    event.preventDefault();
    const update = (pointer: PointerEvent) => {
      const width = window.innerWidth - pointer.clientX;
      setWorkspaceSize(width < 330 ? "compact" : width > 450 ? "wide" : "medium");
    };
    const finish = () => {
      window.removeEventListener("pointermove", update);
      window.removeEventListener("pointerup", finish);
    };
    window.addEventListener("pointermove", update);
    window.addEventListener("pointerup", finish);
  }

  function toggleWorkspaceWithFocus() {
    if (workspaceVisible) {
      closeWorkspaceAndRestoreFocus();
      return;
    }
    workspaceFocusRequested.current = true;
    toggleWorkspace();
  }

  function handleSidebarKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (!sidebarOverlayOpen) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeSidebarAndRestoreFocus();
      return;
    }
    loopOverlayFocus(event, sidebarPanel.current);
  }

  function handleWorkspaceKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeWorkspaceAndRestoreFocus();
      return;
    }
    if (typeof window.matchMedia === "function" && window.matchMedia("(max-width: 920px)").matches) {
      loopOverlayFocus(event, workspacePanel.current);
    }
  }

  return (
    <ShellFrame>
      <App>
        <App.Base className={styles.shellBase} data-sidebar-overlay-open={sidebarOverlayOpen ? "true" : "false"} data-workspace-overlay-open={workspaceVisible ? "true" : "false"}>
          <ConsoleHeader
            identity={headerIdentity}
            onLogout={headerLogout}
            revoking={session.phase === "revoking"}
            scene={scene}
            productName={productName}
            scope={headerScope}
          />

          <HeaderBackdrop />

          <ServiceLayout>
            <Sider className={styles.sider}>
              <Sider.RailMenu data-surface="shell" aria-label={scene.preview ? navigationText("favorites") : t("productNavigation")} className={styles.rail}>
                <Link aria-label={t("dashboardHome")} className={styles.railHome} href="/console/" onClick={closeSidebarAndRestoreFocus}><LayoutDashboard aria-hidden="true" /></Link>
                <span className={styles.railDivider} />
                {scene.preview ? favorites.flatMap((id) => services.filter((service) => service.id === id)).map((service) => {
                  const Icon = favoriteIcons[service.id];
                  const selected = service.id === activeService?.id;
                  return <Link aria-current={selected ? "page" : undefined} aria-label={service.label} className={styles.railItem} data-selected={selected ? "true" : undefined} href={service.href} key={service.id} onNavigate={closeSidebarAndRestoreFocus} onAccepted={() => useConsoleUiStore.getState().visitService(service.id)} title={service.label}><span className={styles.railIndicator} /><Icon aria-hidden="true" /><span className={styles.railTooltip}>{service.label}</span></Link>;
                }) : scene.rail.slice(1).map((item) => {
                  const Icon = railIcons[item.icon];
                  const label = directory(`services.${item.id === "access" ? "iam" : "postgresql"}.name`);
                  return (
                    <Link aria-current={item.selected ? "page" : undefined} aria-label={label} className={styles.railItem} data-selected={item.selected ? "true" : undefined} href={item.href} key={item.id} onClick={closeSidebarAndRestoreFocus}>
                      <span className={styles.railIndicator} /><Icon aria-hidden="true" /><span className={styles.railTooltip}>{label}</span>
                    </Link>
                  );
                })}
                {scene.preview ? <button aria-label={navigationText("addFavorite")} className={styles.railItem} onClick={() => setHeaderPanel("products")} title={navigationText("addFavorite")} type="button"><Star aria-hidden="true" /><span className={styles.railTooltip}>{navigationText("addFavorite")}</span></button> : null}
              </Sider.RailMenu>

              <Sider.ContextMenu
                aria-label={sidebarOverlayOpen ? t("productNavigation") : undefined}
                aria-modal={sidebarOverlayOpen ? true : undefined}
                className={styles.contextMenu}
                id="console-product-navigation"
                onKeyDown={handleSidebarKeyDown}
                ref={sidebarPanel}
                role={sidebarOverlayOpen ? "dialog" : undefined}
              >
                <div className={styles.contextHeader}>
                  <span className={styles.contextProductIcon}><ProductContextIcon aria-hidden="true" /></span>
                  <strong title={productName}>{productName}</strong>
                  <Button aria-label={t("closeNavigation")} className={styles.contextCloseButton} onClick={closeSidebarAndRestoreFocus} ref={sidebarCloseButton} iconOnly size="small" variant="ghost"><X aria-hidden="true" /></Button>
                </div>
                <nav aria-label={t("navigation")} className={styles.contextNavigation} data-compact={scene.section === "access" ? "true" : undefined}>
                  {localNavigation.map((item, index) => {
                    const Icon = navigationIcons[item.icon];
                    return (
                      <Fragment key={item.id}>
                      {item.group && item.group !== localNavigation[index - 1]?.group ? <p>{iamWorkspaceText(item.group)}</p> : null}
                      <Link aria-current={item.selected ? "page" : undefined} className={styles.contextItem} data-selected={item.selected ? "true" : undefined} href={item.href} onClick={closeSidebarAndRestoreFocus}>
                        <Icon aria-hidden="true" /><span><strong>{navigationText(`items.${item.messageKey}.label`)}</strong>{scene.section !== "access" ? <small title={navigationText(`items.${item.messageKey}.hint`)}>{navigationText(`items.${item.messageKey}.hint`)}</small> : null}</span>{typeof item.count === "number" ? <em>{item.count}</em> : null}
                      </Link>
                      </Fragment>
                    );
                  })}
                </nav>
                <div className={styles.contextCallout}>
                  <CircleGauge aria-hidden="true" />
                  <div><strong>{scene.preview ? t("previewEnvironment") : t("localDeployment")}</strong><span>{scene.preview ? t("previewDescription") : t("deploymentDescription")}</span></div>
                </div>
              </Sider.ContextMenu>
              <Sider.ResizeHandle />
            </Sider>

            <button aria-hidden="true" aria-label={t("closeNavigation")} className={styles.overlayBackdrop} onClick={closeSidebarAndRestoreFocus} tabIndex={-1} type="button" />

            <Layout.Content>
              <ContentPage parentLabel={pageTitle} pending={Boolean(pendingSelection)} data-navigating={pendingSelection ? "true" : undefined}>
                <Suspense fallback={<ContentPage.Header title={visiblePageTitle} />}><ConsolePageHeader title={visiblePageTitle} selection={pendingSelection ?? navigation.selection} pendingHref={navigation.pendingHref} className={styles.pageHeader} data-workflow={workspaceAction ? "true" : undefined}
                  leading={<Button aria-controls="console-product-navigation" aria-expanded={sidebarOverlayOpen} aria-label={t("openNavigation")} className={styles.mobileMenuButton} onClick={openSidebar} ref={sidebarTrigger} iconOnly size="small" variant="ghost"><Menu aria-hidden="true" /></Button>}
                  trailing={<div className={styles.pageActions}>
                    <ConsoleRefresh account={scene.section === "access"} pending={Boolean(pendingSelection)} />
                    {workspaceAction && WorkspaceActionIcon ? <Button disabled={Boolean(pendingSelection)} data-workflow-action="" aria-controls="console-workspace" aria-expanded={workspaceVisible} aria-label={t(`workspaceActions.${scene.workspace!.kind}.${workspaceVisible ? "expanded" : "collapsed"}`)} onClick={toggleWorkspaceWithFocus} ref={workspaceTrigger} size="small" variant={workspaceVisible || !workspaceAction.primary ? "secondary" : "primary"}>{workspaceVisible ? <PanelRightClose aria-hidden="true" /> : <WorkspaceActionIcon aria-hidden="true" />}<span>{t(`workspaceActions.${scene.workspace!.kind}.${workspaceVisible ? "expanded" : "collapsed"}`)}</span></Button> : null}
                  </div>}
                  progress={!pendingSelection && controlPlane.loading && scene.section !== "access" ? <Progress aria-label={loadingLabel} className={styles.navigationProgress} /> : null} /></Suspense>
                <ContentPage.Body transitionKey={navigation.currentHref} pending={Boolean(pendingSelection)} loading={pendingSelection ? <div className={styles.pageCanvas}><PageSkeleton label={loadingLabel} layout={pageSkeletonLayout(pendingSelection)} /></div> : undefined}>
                  <div aria-busy={controlPlane.loading && scene.section !== "access"} className={styles.pageCanvas}>
                    {session.error ? <Alert className={styles.feedback} status="danger">{authErrors(session.error)}</Alert> : null}
                    {controlPlane.error ? <Alert className={styles.feedback} status="danger">{t(`errors.${controlPlane.error}`)}</Alert> : null}
                    <ConsoleContentRenderer scene={scene.content} scope={{ regionId }} />
                  </div>
                </ContentPage.Body>
              </ContentPage>
            </Layout.Content>

            <button aria-hidden="true" aria-label={t("closeWorkspace")} className={styles.workspaceBackdrop} onClick={closeWorkspaceAndRestoreFocus} tabIndex={-1} type="button" />
            <Layout.Workspace inert={!workspaceVisible} aria-hidden={!workspaceVisible} className={styles.workspacePane} data-size={workspaceSize} data-visible={workspaceVisible ? "true" : "false"} id="console-workspace" onKeyDown={handleWorkspaceKeyDown} ref={workspacePanel}>
              <div
                aria-label={t("resizeWorkspace")}
                aria-orientation="vertical"
                aria-valuemax={3}
                aria-valuemin={1}
                aria-valuenow={workspaceSize === "compact" ? 1 : workspaceSize === "wide" ? 3 : 2}
                className={styles.workspaceResizeHandle}
                onKeyDown={(event) => {
                  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
                  event.preventDefault();
                  if (event.key === "ArrowLeft") setWorkspaceSize(workspaceSize === "compact" ? "medium" : "wide");
                  if (event.key === "ArrowRight") setWorkspaceSize(workspaceSize === "wide" ? "medium" : "compact");
                  if (event.key === "Home") setWorkspaceSize("compact");
                  if (event.key === "End") setWorkspaceSize("wide");
                }}
                onPointerDown={resizeWorkspace}
                role="separator"
                tabIndex={0}
              />
              <Button aria-label={t("closeWorkspace")} className={styles.workspaceCloseButton} onClick={closeWorkspaceAndRestoreFocus} ref={workspaceCloseButton} iconOnly size="small" variant="ghost"><X aria-hidden="true" /></Button>
              {scene.workspace ? <ConsoleWorkspaceRenderer scene={scene.workspace} /> : null}
            </Layout.Workspace>
          </ServiceLayout>
        </App.Base>
      </App>
    </ShellFrame>
  );
}

function ConsoleSignIn({ returnTo }: { returnTo: string }) {
  const query = useSearchParams().toString();
  return <LoginRenderer returnTo={returnTo + (query ? "?" + query : "")} />;
}

export function ConsoleShellRenderer({ accountRepository, experience, repository, selection }: {
  accountRepository?: AccountRepository;
  experience?: ExperienceSnapshot;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const session = useSession();
  const t = useTranslations("Auth");
  const returnTo = consoleRouteHref(selection);
  if (!session.current || (session.phase !== "authenticated" && session.phase !== "revoking")) return <Suspense fallback={<ShellFrame><PageSkeleton label={t("welcome")} layout="access" /></ShellFrame>}><ConsoleSignIn returnTo={returnTo} /></Suspense>;
  return (
    <ConsoleNavigationProvider selection={selection}>
      <AccountAccessProvider active={selection.section === "access"} repository={accountRepository}>
        <ControlPlaneProvider experience={experience} repository={repository} selection={selection}>
          <ConsoleShell />
        </ControlPlaneProvider>
      </AccountAccessProvider>
    </ConsoleNavigationProvider>
  );
}
