"use client";

import { useEffect, useState, type PointerEvent as ReactPointerEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Boxes,
  ChevronRight,
  CircleGauge,
  Database,
  Gauge,
  LayoutDashboard,
  LogOut,
  MapPin,
  Menu,
  PackageSearch,
  PanelRightClose,
  PanelRightOpen,
  RefreshCcw,
  ServerCog,
  ShieldCheck,
  X
} from "lucide-react";
import { LoginRenderer } from "@/features/auth/renderers/LoginRenderer";
import { useSession } from "@/features/auth/application/SessionProvider";
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
import type { ControlPlaneRouteSelection } from "../domain/selection";
import type { ControlPlaneRepository } from "../repositories/controlPlaneRepository";
import type {
  NavigationIconKind,
  RailIconKind
} from "../scenes/consoleScene";
import { ConsoleContentRenderer } from "./ConsoleContentRenderer";
import { ConsoleWorkspaceRenderer } from "./ConsoleWorkspaceRenderer";
import styles from "./ConsoleShellRenderer.module.css";

const railIcons = {
  overview: LayoutDashboard,
  database: Database
} satisfies Record<RailIconKind, typeof Database>;

const navigationIcons = {
  catalog: PackageSearch,
  quota: Gauge,
  installation: ServerCog,
  region: MapPin
} satisfies Record<NavigationIconKind, typeof Database>;

function ShellFrame({ children }: { children: React.ReactNode }) {
  return (
    <App.Frame className={styles.shellContainer}>
      <App.Background />
      <App.Layers>
        <App.Layer>{children}</App.Layer>
      </App.Layers>
    </App.Frame>
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
            <div className={styles.topbarBrand}><Boxes aria-hidden="true" /><strong>Matrix</strong></div>
            <div className={styles.topbarPath}><span>Control Plane</span><ChevronRight aria-hidden="true" /><span>Managed Services</span></div>
            <Button
              aria-label="注销并撤销 IAM 会话"
              className={styles.loadingLogout}
              disabled={revoking}
              onClick={logout}
              size="small"
              variant="ghost"
            >
              <LogOut aria-hidden="true" />{revoking ? "正在注销…" : "注销"}
            </Button>
          </Layout.Header>
          <Layout>
            <Sider className={styles.sider}>
              <Sider.RailMenu className={styles.railLoading}>
                <div className={styles.railLogo}><Boxes aria-hidden="true" /></div>
                <Skeleton /><Skeleton />
              </Sider.RailMenu>
              <Sider.ContextMenu className={`${styles.contextMenu} ${styles.contextLoading}`}>
                <Skeleton />
                <Skeleton />
                <Skeleton />
                <Skeleton />
              </Sider.ContextMenu>
            </Sider>
            <Layout.Content>
              <ContentPage>
                <ContentPage.Header><Skeleton className={styles.headerSkeleton} /></ContentPage.Header>
                <ContentPage.Body>
                  {sessionError ? (
                    <div className={styles.errorBanner} role="alert">
                      <ShieldCheck aria-hidden="true" /><span>{sessionError}</span>
                    </div>
                  ) : null}
                  {error ? (
                    <div className={styles.unavailable} role="alert">
                      <ServerCog aria-hidden="true" />
                      <Typography.Title as="h2" level={2}>控制面未能加载</Typography.Title>
                      <p>{error}</p>
                      <Button onClick={retry} variant="secondary"><RefreshCcw aria-hidden="true" />重试</Button>
                    </div>
                  ) : (
                    <div className={styles.loadingGrid} aria-label="正在加载控制面">
                      <Skeleton /><Skeleton /><Skeleton /><Skeleton />
                    </div>
                  )}
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

function ConsoleShell() {
  const router = useRouter();
  const session = useSession();
  const controlPlane = useControlPlane();
  const scene = controlPlane.scene;
  const sidebarOverlayOpen = useConsoleUiStore((state) => state.sidebarOverlayOpen);
  const workspaceOpen = useConsoleUiStore((state) => state.workspaceOpen);
  const openSidebar = useConsoleUiStore((state) => state.openSidebar);
  const closeSidebar = useConsoleUiStore((state) => state.closeSidebar);
  const toggleWorkspace = useConsoleUiStore((state) => state.toggleWorkspace);
  const closeWorkspace = useConsoleUiStore((state) => state.closeWorkspace);
  const [workspaceSize, setWorkspaceSize] = useState<WorkspaceSize>("medium");

  useEffect(() => {
    if (!sidebarOverlayOpen && !workspaceOpen) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeSidebar();
        closeWorkspace();
      }
    };
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, [closeSidebar, closeWorkspace, sidebarOverlayOpen, workspaceOpen]);

  async function logout() {
    if (await session.logout()) router.replace("/");
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
  const principal = session.current;

  function resizeWorkspace(event: ReactPointerEvent<HTMLDivElement>) {
    event.preventDefault();
    const update = (pointer: PointerEvent) => {
      const width = window.innerWidth - pointer.clientX;
      setWorkspaceSize(width < 320 ? "compact" : width > 430 ? "wide" : "medium");
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
        <App.Base
          className={styles.shellBase}
          data-sidebar-overlay-open={sidebarOverlayOpen ? "true" : "false"}
          data-workspace-overlay-open={workspaceVisible ? "true" : "false"}
        >
          <Layout.Header className={styles.topbar}>
            <div className={styles.topbarBrand}><Boxes aria-hidden="true" /><strong>Matrix</strong></div>
            <div className={styles.topbarPath}>
              <span>Control Plane</span><ChevronRight aria-hidden="true" /><strong>{scene.title}</strong>
            </div>
            <div className={styles.topbarStatus}>
              <ShieldCheck aria-hidden="true" />
              <span>{principal?.session.organizationId ?? "organization"}</span>
            </div>
          </Layout.Header>

          <Layout>
            <Sider className={styles.sider}>
              <Sider.RailMenu aria-label="产品导航" className={styles.rail}>
                <Link aria-label="Matrix 控制面" className={styles.railLogo} href="/console/">
                  <Boxes aria-hidden="true" />
                </Link>
                <span className={styles.railDivider} />
                {scene.rail.map((item) => {
                  const Icon = railIcons[item.icon];
                  return (
                    <Link
                      aria-current={item.selected ? "page" : undefined}
                      aria-label={item.label}
                      className={styles.railItem}
                      data-selected={item.selected ? "true" : undefined}
                      href={item.href}
                      key={item.id}
                      onClick={closeSidebar}
                    >
                      <span className={styles.railIndicator} />
                      <Icon aria-hidden="true" />
                      <span className={styles.railTooltip}>{item.label}</span>
                    </Link>
                  );
                })}
              </Sider.RailMenu>

              <Sider.ContextMenu className={styles.contextMenu}>
                <div className={styles.contextHeader}>
                  <div><Typography.Eyebrow>Managed services</Typography.Eyebrow><strong>托管数据库</strong></div>
                  <Database aria-hidden="true" />
                </div>
                <nav aria-label="托管服务导航" className={styles.contextNavigation}>
                  <p>控制面</p>
                  {scene.navigation.map((item) => {
                    const Icon = navigationIcons[item.icon];
                    return (
                      <Link
                        aria-current={item.selected ? "page" : undefined}
                        className={styles.contextItem}
                        data-selected={item.selected ? "true" : undefined}
                        href={item.href}
                        key={item.id}
                        onClick={closeSidebar}
                      >
                        <Icon aria-hidden="true" />
                        <span><strong>{item.label}</strong><small>{item.description}</small></span>
                        {typeof item.count === "number" ? <em>{item.count}</em> : null}
                      </Link>
                    );
                  })}
                </nav>
                <div className={styles.contextCallout}>
                  <CircleGauge aria-hidden="true" />
                  <div><strong>本机部署</strong><span>PostgreSQL · 托管服务</span></div>
                </div>
                <div className={styles.userDock}>
                  <div className={styles.avatar} aria-hidden="true">
                    {principal?.loginName.slice(0, 1).toUpperCase() ?? "U"}
                  </div>
                  <div className={styles.userIdentity}>
                    <strong>{principal?.loginName ?? "用户"}</strong>
                    <span>{principal?.session.principalId ?? "IAM session"}</span>
                  </div>
                  <button
                    aria-label="注销并撤销 IAM 会话"
                    className={styles.logoutButton}
                    disabled={session.phase === "revoking"}
                    onClick={() => void logout()}
                    type="button"
                  >
                    <LogOut aria-hidden="true" />
                  </button>
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
                    <div><Typography.Eyebrow>{scene.eyebrow}</Typography.Eyebrow><Typography.Title as="h1" level={2}>{scene.title}</Typography.Title></div>
                  </div>
                  <div className={styles.pageActions}>
                    <Button aria-label="刷新" disabled={controlPlane.loading} onClick={() => void controlPlane.reload()} size="small" variant="ghost">
                      <RefreshCcw aria-hidden="true" /><span>刷新</span>
                    </Button>
                    {scene.workspace ? (
                      <Button
                        aria-controls="console-workspace"
                        aria-expanded={workspaceVisible}
                        aria-label={workspaceVisible ? "收起面板" : "打开面板"}
                        onClick={toggleWorkspace}
                        size="small"
                        variant={workspaceVisible ? "secondary" : "ghost"}
                      >
                        {workspaceVisible ? <PanelRightClose aria-hidden="true" /> : <PanelRightOpen aria-hidden="true" />}
                        <span>{workspaceVisible ? "收起面板" : "打开面板"}</span>
                      </Button>
                    ) : null}
                  </div>
                </ContentPage.Header>
                <ContentPage.Body>
                  <div className={styles.pageIntro}>{scene.description}</div>
                  {session.error ? (
                    <div className={styles.errorBanner} role="alert">
                      <ShieldCheck aria-hidden="true" /><span>{session.error}</span>
                    </div>
                  ) : null}
                  {controlPlane.error ? (
                    <div className={styles.errorBanner} role="alert">
                      <ServerCog aria-hidden="true" /><span>{controlPlane.error}</span>
                    </div>
                  ) : null}
                  <ConsoleContentRenderer scene={scene.content} />
                </ContentPage.Body>
              </ContentPage>
            </Layout.Content>

            <button aria-label="关闭上下文面板" className={styles.workspaceBackdrop} onClick={closeWorkspace} type="button" />
            <Layout.Workspace
              className={styles.workspacePane}
              data-size={workspaceSize}
              data-visible={workspaceVisible ? "true" : "false"}
              id="console-workspace"
            >
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

export function ConsoleShellRenderer({
  repository,
  selection
}: {
  repository?: ControlPlaneRepository;
  selection: ControlPlaneRouteSelection;
}) {
  const session = useSession();
  if (
    !session.current ||
    (session.phase !== "authenticated" && session.phase !== "revoking")
  ) {
    return <LoginRenderer />;
  }
  return (
    <ControlPlaneProvider repository={repository} selection={selection}>
      <ConsoleShell />
    </ControlPlaneProvider>
  );
}
