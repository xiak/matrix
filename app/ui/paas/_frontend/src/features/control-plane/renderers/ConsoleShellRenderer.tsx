"use client";

import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent
} from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Activity,
  Boxes,
  ChartNoAxesCombined,
  ChevronRight,
  CircleGauge,
  Database,
  Gauge,
  GitBranch,
  Grid2X2,
  LayoutDashboard,
  LogOut,
  MapPin,
  Menu,
  PackageSearch,
  PackagePlus,
  PanelRightClose,
  RefreshCcw,
  Search,
  ServerCog,
  ShieldCheck,
  Workflow,
  X
} from "lucide-react";
import { useSession } from "@/features/auth/application/SessionProvider";
import { LoginRenderer } from "@/features/auth/renderers/LoginRenderer";
import type { AccountRepository } from "@/features/auth/repositories/iamRepository";
import {
  App,
  Button,
  ContentPage,
  Layout,
  Sider,
  Skeleton,
  Typography
} from "@ui/xiak";
import { ControlPlaneProvider, useControlPlane } from "../application/ControlPlaneProvider";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ExperienceSnapshot } from "../domain/experience";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type {
  ConsoleWorkspaceScene,
  GlobalSearchResultScene,
  NavigationIconKind,
  RailIconKind
} from "../scenes/consoleScene";
import { AccountMenu } from "./AccountMenu";
import { ConsoleContentRenderer } from "./ConsoleContentRenderer";
import { ConsoleWorkspaceRenderer } from "./ConsoleWorkspaceRenderer";
import { ExperienceIconTile } from "./ExperienceIconTile";
import headerToolStyles from "./HeaderTool.module.css";
import { NotificationCenter } from "./NotificationCenter";
import { ProductLauncher } from "./ProductLauncher";
import { CompactScopeSwitcher, HeaderScopeControls } from "./ScopeSwitcher";
import styles from "./ConsoleShellRenderer.module.css";

const railIcons = {
  overview: LayoutDashboard,
  database: Database,
  devops: GitBranch,
  observability: ChartNoAxesCombined,
  access: ShieldCheck
} satisfies Record<RailIconKind, typeof Database>;

const navigationIcons = {
  overview: LayoutDashboard,
  products: Grid2X2,
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

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link aria-label="Matrix Cloud 控制台首页" className={styles.brand} href="/console/">
      <span className={styles.brandMark}><Boxes aria-hidden="true" /></span>
      {compact ? null : <span><strong>Matrix</strong><small>Cloud</small></span>}
    </Link>
  );
}

function LoadingShell({ error, logout, retry, revoking, sessionError }: {
  error: string | null;
  logout(): void;
  retry(): void;
  revoking: boolean;
  sessionError: string | null;
}) {
  return (
    <ShellFrame>
      <App>
        <App.Base>
          <Layout.Header className={styles.topbar}>
            <Brand />
            <div className={styles.loadingPath}><span>统一云控制台</span><ChevronRight aria-hidden="true" /><span>正在加载</span></div>
            <Button aria-label="注销并撤销 IAM 会话" className={styles.loadingLogout} disabled={revoking} onClick={logout} size="small" variant="ghost">
              <LogOut aria-hidden="true" />{revoking ? "正在注销…" : "注销"}
            </Button>
          </Layout.Header>
          <Layout>
            <Sider className={styles.sider}>
              <Sider.RailMenu className={styles.railLoading}><Skeleton /><Skeleton /><Skeleton /></Sider.RailMenu>
              <Sider.ContextMenu className={`${styles.contextMenu} ${styles.contextLoading}`}><Skeleton /><Skeleton /><Skeleton /><Skeleton /></Sider.ContextMenu>
            </Sider>
            <Layout.Content>
              <ContentPage>
                <ContentPage.Header><Skeleton className={styles.headerSkeleton} /></ContentPage.Header>
                <ContentPage.Body>
                  {sessionError ? <div className={styles.errorBanner} role="alert"><ShieldCheck aria-hidden="true" /><span>{sessionError}</span></div> : null}
                  {error ? (
                    <div className={styles.unavailable} role="alert">
                      <ServerCog aria-hidden="true" />
                      <Typography.Title as="h2" level={2}>控制面未能加载</Typography.Title>
                      <p>{error}</p>
                      <Button onClick={retry} variant="secondary"><RefreshCcw aria-hidden="true" />重试</Button>
                      <Link href="/console/access/">进入访问管理</Link>
                    </div>
                  ) : <div className={styles.loadingGrid} aria-label="正在加载控制面"><Skeleton /><Skeleton /><Skeleton /><Skeleton /></div>}
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

const workspaceActions = {
  "quota-order": { collapsed: "激活配额", expanded: "收起配额配置", icon: PackagePlus, primary: true },
  "installation-order": { collapsed: "安装服务", expanded: "收起安装配置", icon: ServerCog, primary: true },
  "platform-status": { collapsed: "查看平台状态", expanded: "收起平台状态", icon: Activity, primary: false }
} satisfies Record<NonNullable<ConsoleWorkspaceScene>["kind"], {
  collapsed: string;
  expanded: string;
  icon: typeof Activity;
  primary: boolean;
}>;

function SearchResult({ active, index, item, onChoose, onHover }: {
  active: boolean;
  index: number;
  item: GlobalSearchResultScene;
  onChoose(): void;
  onHover(index: number): void;
}) {
  return (
    <Link
      aria-selected={active}
      className={styles.searchResult}
      data-active={active ? "true" : undefined}
      href={item.href}
      onClick={onChoose}
      onMouseEnter={() => onHover(index)}
      role="option"
    >
      <ExperienceIconTile kind={item.icon} />
      <span><strong>{item.label}</strong><small>{item.description}</small></span>
      <em>{item.category}</em>
    </Link>
  );
}

function ConsoleShell({ accountRepository }: { accountRepository?: AccountRepository }) {
  const router = useRouter();
  const session = useSession();
  const controlPlane = useControlPlane();
  const scene = controlPlane.scene;
  const searchInput = useRef<HTMLInputElement>(null);
  const sidebarOverlayOpen = useConsoleUiStore((state) => state.sidebarOverlayOpen);
  const workspaceOpen = useConsoleUiStore((state) => state.workspaceOpen);
  const openSidebar = useConsoleUiStore((state) => state.openSidebar);
  const closeSidebar = useConsoleUiStore((state) => state.closeSidebar);
  const toggleWorkspace = useConsoleUiStore((state) => state.toggleWorkspace);
  const closeWorkspace = useConsoleUiStore((state) => state.closeWorkspace);
  const [workspaceSize, setWorkspaceSize] = useState<WorkspaceSize>("medium");
  const [projectId, setProjectId] = useState("all");
  const [regionId, setRegionId] = useState("all");
  const [productMenuOpen, setProductMenuOpen] = useState(false);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [noticesOpen, setNoticesOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSearchIndex, setActiveSearchIndex] = useState(0);

  const searchResults = useMemo(() => {
    if (!scene) return [];
    const normalized = searchQuery.trim().toLocaleLowerCase("zh-CN");
    const results = normalized
      ? scene.search.filter((item) => [item.label, item.description, item.category]
        .some((value) => value.toLocaleLowerCase("zh-CN").includes(normalized)))
      : scene.search;
    return results.slice(0, 8);
  }, [scene, searchQuery]);

  useEffect(() => {
    const shortcuts = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === "k") {
        event.preventDefault();
        setProductMenuOpen(false);
        setScopeOpen(false);
        setNoticesOpen(false);
        setAccountMenuOpen(false);
        setSearchOpen(true);
        searchInput.current?.focus();
      }
      if (event.key === "Escape") {
        closeSidebar();
        closeWorkspace();
        setProductMenuOpen(false);
        setScopeOpen(false);
        setNoticesOpen(false);
        setAccountMenuOpen(false);
        setSearchOpen(false);
      }
    };
    window.addEventListener("keydown", shortcuts);
    return () => window.removeEventListener("keydown", shortcuts);
  }, [closeSidebar, closeWorkspace]);

  async function logout() {
    if (await session.logout()) {
      router.replace("/");
      return;
    }
    setAccountMenuOpen(false);
  }

  if (!scene) {
    return (
      <LoadingShell
        error={controlPlane.error}
        logout={() => void logout()}
        retry={() => void controlPlane.reload()}
        revoking={session.phase === "revoking"}
        sessionError={session.error}
      />
    );
  }

  const workspaceVisible = Boolean(scene.workspace && workspaceOpen);
  const workspaceAction = scene.workspace ? workspaceActions[scene.workspace.kind] : null;
  const WorkspaceActionIcon = workspaceAction?.icon;
  const principal = session.current;
  const productResults = scene.search.filter((item) => item.category === "产品");
  const globalOverlayOpen = productMenuOpen || scopeOpen || noticesOpen || accountMenuOpen || searchOpen;
  const ProductContextIcon = railIcons[scene.productIcon];
  const principalName = principal?.loginName ?? "用户";
  const principalId = principal?.session.principalId ?? "IAM session";
  const tenantName = scene.scope?.organization.name ?? principal?.session.organizationId ?? "未指定租户";
  const tenantId = scene.scope?.organization.id;
  const accountType = principal?.loginName.includes("@") ? "IAM 子账号" : "主账号";

  function closeGlobalOverlays() {
    setProductMenuOpen(false);
    setScopeOpen(false);
    setNoticesOpen(false);
    setAccountMenuOpen(false);
    setSearchOpen(false);
  }

  function chooseSearchResult(href: string) {
    closeGlobalOverlays();
    setSearchQuery("");
    router.push(href);
  }

  function handleSearchKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveSearchIndex((index) => Math.min(index + 1, Math.max(0, searchResults.length - 1)));
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveSearchIndex((index) => Math.max(0, index - 1));
    }
    if (event.key === "Enter" && searchResults[activeSearchIndex]) {
      event.preventDefault();
      chooseSearchResult(searchResults[activeSearchIndex].href);
    }
  }

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

  return (
    <ShellFrame>
      <App>
        <App.Base className={styles.shellBase} data-sidebar-overlay-open={sidebarOverlayOpen ? "true" : "false"} data-workspace-overlay-open={workspaceVisible ? "true" : "false"}>
          <Layout.Header className={styles.topbar}>
            <div className={styles.topbarStart}>
              <Brand />
              {scene.preview ? (
                <ProductLauncher
                  onOpenChange={(open) => {
                    setProductMenuOpen(open);
                    if (!open) return;
                    setScopeOpen(false);
                    setNoticesOpen(false);
                    setAccountMenuOpen(false);
                    setSearchOpen(false);
                  }}
                  open={productMenuOpen}
                  products={productResults}
                />
              ) : <div className={styles.legacyPath}><span>Control Plane</span><ChevronRight aria-hidden="true" /><strong>{scene.productName}</strong></div>}
            </div>

            {scene.preview ? (
              <div className={styles.globalSearch} data-open={searchOpen ? "true" : undefined}>
                <Search aria-hidden="true" />
                <input
                  aria-autocomplete="list"
                  aria-controls="global-search-results"
                  aria-expanded={searchOpen}
                  aria-label="搜索产品、资源和页面"
                  onChange={(event) => {
                    setSearchQuery(event.target.value);
                    setActiveSearchIndex(0);
                  }}
                  onFocus={() => {
                    setSearchOpen(true);
                    setProductMenuOpen(false);
                    setScopeOpen(false);
                    setNoticesOpen(false);
                    setAccountMenuOpen(false);
                  }}
                  onKeyDown={handleSearchKeyDown}
                  placeholder="搜索产品、资源和页面"
                  ref={searchInput}
                  role="combobox"
                  value={searchQuery}
                />
                <kbd>Ctrl K</kbd>
                {searchOpen ? (
                  <div aria-label="搜索结果" className={styles.searchPanel} id="global-search-results" role="listbox">
                    <div className={styles.searchPanelHeader}><span>{searchQuery ? `“${searchQuery}” 的结果` : "快速访问"}</span><small>↑↓ 选择 · Enter 打开</small></div>
                    {searchResults.length ? searchResults.map((item, index) => (
                      <SearchResult active={index === activeSearchIndex} index={index} item={item} key={item.id} onChoose={() => chooseSearchResult(item.href)} onHover={setActiveSearchIndex} />
                    )) : <div className={styles.searchEmpty}><PackageSearch aria-hidden="true" /><span>没有匹配的产品或资源</span></div>}
                  </div>
                ) : null}
              </div>
            ) : null}

            <div className={styles.topbarTools}>
              {scene.preview && scene.scope ? (
                <HeaderScopeControls onProjectChange={setProjectId} onRegionChange={setRegionId} projectId={projectId} regionId={regionId} scope={scene.scope} />
              ) : null}
              {scene.preview ? <span className={styles.previewChip}>MOCK 体验</span> : null}
              {scene.preview ? <Link aria-label={`操作与任务，${scene.activeOperationCount} 个执行中`} className={`${headerToolStyles.iconButton} ${styles.operationShortcut}`} href="/console/operations/"><Activity aria-hidden="true" />{scene.activeOperationCount ? <span>{scene.activeOperationCount}</span> : null}</Link> : null}
              {scene.preview ? (
                <NotificationCenter
                  count={scene.noticeCount}
                  notices={scene.notices}
                  onOpenChange={(open) => {
                    setNoticesOpen(open);
                    if (!open) return;
                    setProductMenuOpen(false);
                    setScopeOpen(false);
                    setAccountMenuOpen(false);
                    setSearchOpen(false);
                  }}
                  open={noticesOpen}
                />
              ) : null}
              <AccountMenu
                identity={{
                  accountType,
                  loginName: principalName,
                  principalId,
                  tenant: { id: tenantId, name: tenantName }
                }}
                onLogout={() => void logout()}
                onOpenChange={(open) => {
                  setAccountMenuOpen(open);
                  if (!open) return;
                  setProductMenuOpen(false);
                  setScopeOpen(false);
                  setNoticesOpen(false);
                  setSearchOpen(false);
                }}
                open={accountMenuOpen}
                revoking={session.phase === "revoking"}
              />
            </div>
          </Layout.Header>

          {globalOverlayOpen ? <button aria-label="关闭全局浮层" className={styles.globalBackdrop} onClick={closeGlobalOverlays} type="button" /> : null}

          <Layout>
            <Sider className={styles.sider}>
              <Sider.RailMenu aria-label="产品导航" className={styles.rail}>
                <Link aria-label="控制台首页" className={styles.railHome} href="/console/" onClick={closeSidebar}><LayoutDashboard aria-hidden="true" /></Link>
                <span className={styles.railDivider} />
                {scene.rail.slice(1).map((item) => {
                  const Icon = railIcons[item.icon];
                  return (
                    <Link aria-current={item.selected ? "page" : undefined} aria-label={item.label} className={styles.railItem} data-selected={item.selected ? "true" : undefined} href={item.href} key={item.id} onClick={closeSidebar}>
                      <span className={styles.railIndicator} /><Icon aria-hidden="true" /><span className={styles.railTooltip}>{item.label}</span>
                    </Link>
                  );
                })}
              </Sider.RailMenu>

              <Sider.ContextMenu className={styles.contextMenu}>
                <div className={styles.contextHeader}>
                  <span className={styles.contextProductIcon}><ProductContextIcon aria-hidden="true" /></span>
                  <div><Typography.Eyebrow>{scene.productEyebrow}</Typography.Eyebrow><strong>{scene.productName}</strong></div>
                  <button aria-label="关闭导航" className={styles.contextCloseButton} onClick={closeSidebar} type="button"><X aria-hidden="true" /></button>
                </div>
                <nav aria-label="控制台导航" className={styles.contextNavigation}>
                  <p>功能导航</p>
                  {scene.navigation.map((item) => {
                    const Icon = navigationIcons[item.icon];
                    return (
                      <Link aria-current={item.selected ? "page" : undefined} className={styles.contextItem} data-selected={item.selected ? "true" : undefined} href={item.href} key={item.id} onClick={closeSidebar}>
                        <Icon aria-hidden="true" /><span><strong>{item.label}</strong><small>{item.description}</small></span>{typeof item.count === "number" ? <em>{item.count}</em> : null}
                      </Link>
                    );
                  })}
                </nav>
                <div className={styles.contextCallout}>
                  <CircleGauge aria-hidden="true" />
                  <div><strong>{scene.preview ? "体验环境" : "本机部署"}</strong><span>{scene.preview ? "前端 MOCK · 不写入后端" : "PostgreSQL · 托管服务"}</span></div>
                </div>
              </Sider.ContextMenu>
              <Sider.ResizeHandle />
            </Sider>

            <button aria-label="关闭导航" className={styles.overlayBackdrop} onClick={closeSidebar} type="button" />

            <Layout.Content>
              <ContentPage>
                <ContentPage.Header>
                  <div className={styles.pageHeading}>
                    <button aria-label="打开产品导航" className={styles.mobileMenuButton} onClick={openSidebar} type="button"><Menu aria-hidden="true" /></button>
                    <div><span className={styles.breadcrumb}>{scene.productName}<ChevronRight aria-hidden="true" />{scene.title}</span><Typography.Title as="h1" level={2}>{scene.title}</Typography.Title></div>
                  </div>
                  <div className={styles.pageActions}>
                    {scene.section !== "access" ? <Button aria-label="刷新" disabled={controlPlane.loading} onClick={() => void controlPlane.reload()} size="small" variant="ghost"><RefreshCcw aria-hidden="true" /><span>刷新</span></Button> : null}
                    {workspaceAction && WorkspaceActionIcon ? <Button aria-controls="console-workspace" aria-expanded={workspaceVisible} aria-label={workspaceVisible ? workspaceAction.expanded : workspaceAction.collapsed} onClick={toggleWorkspace} size="small" variant={workspaceVisible || !workspaceAction.primary ? "secondary" : "primary"}>{workspaceVisible ? <PanelRightClose aria-hidden="true" /> : <WorkspaceActionIcon aria-hidden="true" />}<span>{workspaceVisible ? workspaceAction.expanded : workspaceAction.collapsed}</span></Button> : null}
                  </div>
                </ContentPage.Header>
                <ContentPage.Body>
                  <div className={styles.pageCanvas}>
                    {scene.preview && scene.scope ? (
                      <CompactScopeSwitcher
                        onOpenChange={(open) => {
                          setScopeOpen(open);
                          if (!open) return;
                          setProductMenuOpen(false);
                          setNoticesOpen(false);
                          setAccountMenuOpen(false);
                          setSearchOpen(false);
                        }}
                        onProjectChange={setProjectId}
                        onRegionChange={setRegionId}
                        open={scopeOpen}
                        projectId={projectId}
                        regionId={regionId}
                        scope={scene.scope}
                      />
                    ) : null}
                    <div className={styles.pageIntro}>{scene.description}</div>
                    {session.error ? <div className={styles.errorBanner} role="alert"><ShieldCheck aria-hidden="true" /><span>{session.error}</span></div> : null}
                    {controlPlane.error ? <div className={styles.errorBanner} role="alert"><ServerCog aria-hidden="true" /><span>{controlPlane.error}</span></div> : null}
                    <ConsoleContentRenderer accountRepository={accountRepository} scene={scene.content} scope={{ projectId, regionId }} />
                  </div>
                </ContentPage.Body>
              </ContentPage>
            </Layout.Content>

            <button aria-label="关闭上下文面板" className={styles.workspaceBackdrop} onClick={closeWorkspace} type="button" />
            <Layout.Workspace className={styles.workspacePane} data-size={workspaceSize} data-visible={workspaceVisible ? "true" : "false"} id="console-workspace">
              <div
                aria-label="调整上下文面板宽度"
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
              <button aria-label="关闭上下文面板" className={styles.workspaceCloseButton} onClick={closeWorkspace} type="button"><X aria-hidden="true" /></button>
              {scene.workspace ? <ConsoleWorkspaceRenderer scene={scene.workspace} /> : null}
            </Layout.Workspace>
          </Layout>
        </App.Base>
      </App>
    </ShellFrame>
  );
}

export function ConsoleShellRenderer({ accountRepository, experience, repository, selection }: {
  accountRepository?: AccountRepository;
  experience?: ExperienceSnapshot;
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const session = useSession();
  const returnTo = selection.section === "overview" ? "/console/" : `/console/${selection.section}/`;
  if (!session.current || (session.phase !== "authenticated" && session.phase !== "revoking")) return <LoginRenderer returnTo={returnTo} />;
  return (
    <ControlPlaneProvider experience={experience} repository={repository} selection={selection}>
      <ConsoleShell accountRepository={accountRepository} />
    </ControlPlaneProvider>
  );
}
