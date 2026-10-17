import { Suspense, useEffect, useRef, useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleLink, ConsoleNavigationProvider, useConsoleNavigation } from "./ConsoleNavigation";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";
import { useUnsavedChanges } from "@ui/xiak";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { ConsoleHeader } from "../renderers/ConsoleHeader";
import { AccountLiveGroups } from "@/features/auth/renderers/AccountLiveGroups";
import type { GroupAccessClient } from "@/features/auth/application/AccountAccessProvider";
import type { AccountIdentity, GroupAccess, GroupDeletion } from "@/features/auth/domain/accounts";
import { buildAccountAccessScene } from "@/features/auth/scenes/accountAccessScene";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import messages from "@/i18n/messages/zh-CN.json";

const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
const staticHeaderRender = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ useRouter: () => router }));
vi.mock("../renderers/AccountMenu", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../renderers/AccountMenu")>();
  return { ...actual, AccountMenu: (props: React.ComponentProps<typeof actual.AccountMenu>) => { staticHeaderRender(); return <actual.AccountMenu {...props} />; } };
});
vi.mock("next/link", () => ({
  default: ({ onNavigate, onClick, href, children, replace, scroll, ...props }: React.ComponentProps<"a"> & { replace?: boolean; scroll?: boolean; onNavigate?(event: { preventDefault(): void }): void }) => <a {...props} href={href} data-replace={replace} data-scroll={scroll} onClick={(event) => {
    onClick?.(event);
    if (event.defaultPrevented) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || props.target === "_blank" || props.download !== undefined) {
      event.preventDefault(); // jsdom has no second-tab/download navigation; do not invoke onNavigate.
      return;
    }
    event.preventDefault();
    onNavigate?.({ preventDefault() {} });
  }}>{children}</a>
}));

const requests = new Map<string, { promise: Promise<void>; release(): void; ready: boolean }>();
function hold(href: string) {
  let resolve!: () => void;
  const request = { promise: new Promise<void>((done) => { resolve = done; }), ready: false, release() { request.ready = true; resolve(); } };
  requests.set(href, request);
  return request;
}

function RouteContent({ href }: { href: string }) {
  useEffect(() => { window.history.replaceState(null, "", href); }, [href]);
  const request = requests.get(href);
  if (request && !request.ready) throw request.promise;
  return <output aria-label="Current content">{href}</output>;
}

function NavigationControls({ onAccepted }: { onAccepted?(): void }) {
  const navigation = useConsoleNavigation();
  return <>
    <output aria-label="Pending destination">{navigation.pendingHref ?? "idle"}</output>
    <output aria-label="Pending section">{navigation.pendingSelection?.section ?? "idle"}</output>
    <ConsoleLink href="/console/">Home</ConsoleLink>
    <ConsoleLink href="/console/resources/">Resources</ConsoleLink>
    <ConsoleLink href="/console/logs/" onAccepted={onAccepted}>Logs</ConsoleLink>
    <ConsoleLink href="/console/access/groups/?id=group%2Fexample">Group detail</ConsoleLink>
    <ConsoleLink href="/console/access/groups/">Group directory</ConsoleLink>
    <ConsoleLink href="/console/access/roles/">Roles</ConsoleLink>
    <ConsoleLink href="/console/quotas/" onNavigate={(event) => event.preventDefault()}>Blocked</ConsoleLink>
    <button onClick={() => navigation.navigate("/console/operations/")} type="button">Search result</button>
  </>;
}

const draftCopy = { title: "Leave workflow?", description: "The draft is not saved.", stay: "Keep editing", leave: "Leave", close: "Close", busyTitle: "Saving", busyDescription: "Wait", failure: "Navigation failed", retry: "Retry" };

const deletionGroup: GroupAccess = {
  group: { id: "group-delete-proof", accountId: "account-proof", name: "Disposable review group", description: "Owned test fixture",
    resourceVersion: 1, createdAt: "2026-10-16T08:00:00Z", updatedAt: "2026-10-16T08:00:00Z" }, policyAttachments: [],
  capabilities: ["iam.group.read", "iam.group.delete", "iam.group-membership.list"].map((action) => ({ action: action as GroupAccess["capabilities"][number]["action"], resource: { kind: "GROUP", id: "group-delete-proof" }, available: true, restrictionReason: null }))
};
const deletionReceipt: GroupDeletion = { id: deletionGroup.group.id, accountId: deletionGroup.group.accountId, name: deletionGroup.group.name,
  resourceVersion: 2, removedMemberships: 3, revokedPolicyAttachments: 2, deletedAt: "2026-10-16T09:00:00Z" };
function deletionFixture() {
  let active = true;
  const identity: AccountIdentity = {
    account: { id: deletionGroup.group.accountId, displayName: "Test account", status: "ACTIVE", rootIdentity: { principalId: "root-proof", loginName: "admin" }, loginAlias: null, resourceVersion: 1 },
    user: { id: "root-proof", accountId: deletionGroup.group.accountId, loginName: "admin", displayName: "Test owner", status: "ACTIVE", resourceVersion: 1, mustChangePassword: false },
    identityKind: "ROOT_IDENTITY", policySources: [], permissionBoundary: { accountId: deletionGroup.group.accountId, userId: "root-proof", resourceVersion: 1, policy: null }, capabilities: []
  };
  const scene = buildAccountAccessScene(identity, { items: [], nextAfter: null }, null,
    { accountId: identity.account.id, scope: "TENANT", installationId: null, items: [] },
    { accountId: identity.account.id, scope: "INSTALLATION", installationId: "test-installation", items: [] });
  const client: GroupAccessClient = { identity: "group-navigation-view", expire: vi.fn(), accountId: identity.account.id, actorPrincipalId: identity.user.id, canList: true, listRestrictionReason: null, canCreate: false, createRestrictionReason: "AUTHORITY_REQUIRED",
    list: vi.fn(async () => ({ items: active ? [deletionGroup] : [], nextAfter: null })), get: vi.fn(async () => deletionGroup),
    delete: vi.fn(async () => { active = false; return structuredClone(deletionReceipt); }),
    create: vi.fn(), update: vi.fn(), listMemberships: vi.fn(async () => ({ accountId: identity.account.id, groupId: deletionGroup.group.id, items: [], nextAfter: null })),
    createMembership: vi.fn(), removeMembership: vi.fn(), createPolicyAttachment: vi.fn(), revokePolicyAttachment: vi.fn(), inspectPolicyAttachmentChange: vi.fn()
  };
  return { client, scene };
}
function GroupDeletionRoute({ client, scene, onAccepted }: ReturnType<typeof deletionFixture> & { onAccepted(): void }) {
  const [entityId, setEntityId] = useState<string | undefined>(deletionGroup.group.id);
  const navigation = useConsoleNavigation();
  return <AccountLiveGroups client={client} scene={scene} entityId={entityId} onCreate={() => {}} onOpen={(view, id) => {
    navigation.navigate(`/console/access/${view}/${id ? `?id=${encodeURIComponent(id)}` : ""}`, { onAccepted: () => { onAccepted(); setEntityId(id); } });
  }} />;
}
function GroupDeletionHarness({ fixture, owner = "session-one", onAccepted }: { fixture: ReturnType<typeof deletionFixture>; owner?: string; onAccepted(): void }) {
  return <LocaleProvider><ConsoleNavigationProvider selection={{ section: "access", view: "groups" }}>
    <GroupDeletionRoute key={owner} {...fixture} onAccepted={onAccepted} />
  </ConsoleNavigationProvider></LocaleProvider>;
}
async function confirmGroupDeletion(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "更多操作" }));
  await user.click(within(await screen.findByRole("menu", { name: "更多操作" })).getByRole("menuitem", { name: "删除" }));
  const dialog = await screen.findByRole("dialog");
  await user.click(within(dialog).getByRole("textbox")); await user.paste(deletionGroup.group.name);
  await user.click(within(dialog).getByRole("button", { name: "确认删除" }));
}
function DraftProbe() {
  const [value, setValue] = useState("");
  const form = useRef<HTMLFormElement>(null);
  useUnsavedChanges({ dirty: Boolean(value), busy: false, copy: draftCopy, focusRef: form });
  return <form ref={form}><input aria-label="Workflow draft" value={value} onChange={(event) => setValue(event.target.value)} /></form>;
}

const headerProps: React.ComponentProps<typeof ConsoleHeader> = {
  scene: { preview: true, search: [], scope: null, activeOperationCount: 0, messages: [] },
  scope: { regionId: "all", onRegionChange() {} }, identity: { accountType: "Primary", loginName: "preview", principalId: "preview", tenant: { name: "Preview" } }, onLogout() {}, revoking: false
};

function Harness({ initialHref = "/console/", onAccepted, withDraft = false, withHeader = false }: { initialHref?: string; onAccepted?(): void; withDraft?: boolean; withHeader?: boolean }) {
  const [href, setHref] = useState(initialHref);
  router.push.mockImplementation((target: string) => setHref(target));
  return <ConsoleNavigationProvider selection={parseControlPlanePathname(href.split(/[?#]/)[0] ?? "")}>
    {withHeader ? <ConsoleHeader {...headerProps} /> : null}
    <NavigationControls onAccepted={onAccepted} />
    <Suspense fallback={<span>Route fallback</span>}><RouteContent href={href} />{withDraft && href === initialHref ? <DraftProbe /> : null}</Suspense>
  </ConsoleNavigationProvider>;
}

afterEach(() => { cleanup(); requests.clear(); vi.clearAllMocks(); window.history.replaceState(null, "", "/"); });

describe("Console navigation", () => {
  it("accepts successful LIVE Group deletion navigation after the busy guard unmounts and retains the exact receipt counts", async () => {
    const fixture = deletionFixture(); const accepted = vi.fn(); const user = userEvent.setup({ delay: null });
    window.history.replaceState(null, "", `/console/access/groups/?id=${deletionGroup.group.id}`);
    const history = vi.spyOn(window.history, "pushState");
    render(<GroupDeletionHarness fixture={fixture} onAccepted={accepted} />);
    await confirmGroupDeletion(user);
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe("/console/access/groups/"));
    expect(accepted).toHaveBeenCalledOnce(); expect(history).toHaveBeenCalledExactlyOnceWith(null, "", "/console/access/groups/");
    const receipt = screen.getByRole("status", { name: "用户组删除回执" });
    expect(receipt.textContent).toContain("解除 3 个成员关系"); expect(receipt.textContent).toContain("撤销 2 条直接策略关联");
    expect(receipt.textContent).toContain(deletionGroup.group.id); expect(receipt.textContent).toContain("v2");
    expect(receipt.querySelector("time")?.dateTime).toBe(deletionReceipt.deletedAt);
    await waitFor(() => expect(fixture.client.list).toHaveBeenCalledOnce());
    expect(screen.queryByRole("heading", { name: deletionGroup.group.name })).toBeNull(); expect(screen.queryByRole("dialog")).toBeNull();
    expect(fixture.client.get).toHaveBeenCalledTimes(1); expect(router.push).not.toHaveBeenCalled();
  });

  it.each([403, 409, 503, "mismatched-receipt"] as const)("does not navigate or report success for a %s Group deletion result", async (failure) => {
    const fixture = deletionFixture(); const accepted = vi.fn(); const user = userEvent.setup({ delay: null });
    if (typeof failure === "number") vi.mocked(fixture.client.delete).mockRejectedValueOnce(new HttpProblem(failure, "REJECTED"));
    else vi.mocked(fixture.client.delete).mockResolvedValueOnce({ ...deletionReceipt, id: "wrong-group" });
    window.history.replaceState(null, "", `/console/access/groups/?id=${deletionGroup.group.id}`);
    const history = vi.spyOn(window.history, "pushState"); render(<GroupDeletionHarness fixture={fixture} onAccepted={accepted} />);
    await confirmGroupDeletion(user);
    const dialog = screen.getByRole("dialog");
    expect(await within(dialog).findByText(typeof failure !== "number" || failure === 503 ? messages.GroupWorkspace.liveDeleteUnconfirmed : messages.IamWorkspace.errors[failure === 403 ? "forbidden" : "conflict"])).toBeTruthy();
    expect(accepted).not.toHaveBeenCalled(); expect(history).not.toHaveBeenCalled(); expect(fixture.client.list).not.toHaveBeenCalled();
    expect(window.location.search).toBe(`?id=${deletionGroup.group.id}`); expect(screen.queryByRole("status", { name: "用户组删除回执" })).toBeNull();
  });

  it.each(["Session", "repository"])("drops a late successful Group deletion reply after the originating %s view is replaced", async (change) => {
    const fixture = deletionFixture(); let release!: (value: GroupDeletion) => void;
    vi.mocked(fixture.client.delete).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
    const accepted = vi.fn(); const user = userEvent.setup({ delay: null }); window.history.replaceState(null, "", `/console/access/groups/?id=${deletionGroup.group.id}`);
    const view = render(<GroupDeletionHarness fixture={fixture} onAccepted={accepted} />); await confirmGroupDeletion(user);
    view.rerender(<GroupDeletionHarness fixture={deletionFixture()} owner={change === "Session" ? "session-two" : "session-one"} onAccepted={accepted} />);
    await act(async () => { release(structuredClone(deletionReceipt)); });
    expect(accepted).not.toHaveBeenCalled(); expect(window.location.search).toBe(`?id=${deletionGroup.group.id}`);
    expect(screen.queryByRole("status", { name: "用户组删除回执" })).toBeNull();
  });

  it("updates only the header's route-progress subscriber while a destination is pending", async () => {
    const user = userEvent.setup(), request = hold("/console/resources/");
    render(<LocaleProvider><Harness withHeader /></LocaleProvider>);
    const header = screen.getByLabelText("全局导航");
    expect(within(header).queryByRole("progressbar")).toBeNull();
    staticHeaderRender.mockClear();
    await user.click(screen.getByRole("link", { name: "Resources" }));
    expect(within(header).getByRole("progressbar", { name: "正在打开资源中心…" })).toBeTruthy();
    expect(staticHeaderRender).not.toHaveBeenCalled();
    await act(async () => request.release());
    expect(within(header).queryByRole("progressbar")).toBeNull();
    expect(staticHeaderRender).not.toHaveBeenCalled();
  });

  it("waits for leave consent before starting a real route transition or changing the destination", async () => {
    const user = userEvent.setup(), request = hold("/console/resources/");
    render(<Harness withDraft />);
    await user.type(screen.getByLabelText("Workflow draft"), "keep this policy");
    await user.click(screen.getByRole("link", { name: "Resources" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(router.push).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    await user.click(screen.getByRole("button", { name: "Keep editing" }));
    expect((screen.getByLabelText("Workflow draft") as HTMLInputElement).value).toBe("keep this policy");
    await user.click(screen.getByRole("link", { name: "Resources" }));
    await user.click(screen.getByRole("button", { name: "Leave" }));
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/resources/", { scroll: false });
    expect(screen.getByLabelText("Pending destination").textContent).toBe("/console/resources/");
    await act(async () => request.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/resources/");
    expect(screen.queryByLabelText("Workflow draft")).toBeNull();
  });

  it("guards imperative search visits but not same-page, modified or cancelled anchor navigation", async () => {
    const user = userEvent.setup();
    render(<Harness withDraft />);
    await user.type(screen.getByLabelText("Workflow draft"), "draft");
    await user.click(screen.getByRole("link", { name: "Home" }));
    fireEvent.click(screen.getByRole("link", { name: "Resources" }), { ctrlKey: true });
    await user.click(screen.getByRole("link", { name: "Blocked" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Search result" }));
    expect(router.push).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Leave" }));
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/operations/", { scroll: false });
  });

  it("preserves replace and scroll options and records a service visit only after acceptance", async () => {
    const accepted = vi.fn(), user = userEvent.setup();
    render(<ConsoleNavigationProvider selection={{ section: "overview" }}><DraftProbe /><ConsoleLink href="/console/logs/" replace scroll={false} onAccepted={accepted}>Service</ConsoleLink></ConsoleNavigationProvider>);
    await user.type(screen.getByLabelText("Workflow draft"), "draft");
    await user.click(screen.getByRole("link", { name: "Service" }));
    expect(accepted).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Keep editing" }));
    await user.click(screen.getByRole("link", { name: "Service" }));
    await user.click(screen.getByRole("button", { name: "Leave" }));
    expect(router.replace).toHaveBeenCalledExactlyOnceWith("/console/logs/", { scroll: false });
    expect(router.push).not.toHaveBeenCalled();
    expect(accepted).toHaveBeenCalledTimes(1);
  });

  it("changes encoded entity queries and returns to the directory without fetching a page tree", async () => {
    const href = "/console/access/groups/?id=group%2Fexample";
    const user = userEvent.setup();
    render(<Harness initialHref="/console/access/groups/" />);
    await user.click(screen.getByRole("link", { name: "Group detail" }));
    expect(window.location.pathname + window.location.search).toBe(href);
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    await user.click(screen.getByRole("link", { name: "Group detail" }));
    await user.click(screen.getByRole("link", { name: "Group directory" }));
    expect(window.location.pathname + window.location.search).toBe("/console/access/groups/");
    expect(router.push).not.toHaveBeenCalled();
  });

  it("keeps client query navigation behind the draft guard", async () => {
    const user = userEvent.setup();
    render(<Harness initialHref="/console/access/groups/" withDraft />);
    await user.type(screen.getByLabelText("Workflow draft"), "keep membership changes");
    await user.click(screen.getByRole("link", { name: "Group detail" }));
    expect(window.location.search).toBe("");
    expect(router.push).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Leave" }));
    expect(window.location.search).toBe("?id=group%2Fexample");
    expect(router.push).not.toHaveBeenCalled();
  });

  it("honors query replacement without a page request or another history entry", async () => {
    const user = userEvent.setup();
    window.history.replaceState(null, "", "/console/access/groups/?id=group%2Fexample");
    const replace = vi.spyOn(window.history, "replaceState");
    function ReplaceQuery() {
      const navigation = useConsoleNavigation();
      return <button onClick={() => navigation.navigate("/console/access/groups/?id=another", { replace: true })}>Replace query</button>;
    }
    render(<ConsoleNavigationProvider selection={parseControlPlanePathname("/console/access/groups/")}><ReplaceQuery /></ConsoleNavigationProvider>);
    await user.click(screen.getByRole("button", { name: "Replace query" }));
    expect(replace).toHaveBeenCalledExactlyOnceWith(null, "", "/console/access/groups/?id=another");
    expect(router.replace).not.toHaveBeenCalled();
    replace.mockRestore();
  });
  it("exposes a real pending destination while a route suspends and clears it on commit", async () => {
    const request = hold("/console/resources/");
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("link", { name: "Resources" }));
    expect(screen.getByLabelText("Pending destination").textContent).toBe("/console/resources/");
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/");
    expect(screen.getByRole("link", { name: "Resources" }).getAttribute("aria-busy")).toBe("true");
    await act(async () => request.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/resources/");
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
  });

  it("exposes the destination frame immediately, independently of regional loading feedback", async () => {
    const request = hold("/console/resources/");
    render(<Harness />);
    fireEvent.click(screen.getByRole("link", { name: "Resources" }));
    expect(screen.getByLabelText("Pending section").textContent).toBe("resources");
    await act(async () => request.release());
    expect(screen.getByLabelText("Pending section").textContent).toBe("idle");
  });

  it("runs accepted-navigation effects only after the destination frame is in the DOM", async () => {
    const request = hold("/console/logs/");
    const observed: string[] = [];
    render(<Harness onAccepted={() => observed.push(screen.getByLabelText("Pending section").textContent ?? "missing")} />);

    fireEvent.click(screen.getByRole("link", { name: "Logs" }));

    expect(observed).toEqual(["logs"]);
    expect(screen.getByLabelText("Pending destination").textContent).toBe("/console/logs/");
    await act(async () => request.release());
  });

  it("keeps the latest destination when navigation interrupts a slower visit", async () => {
    const first = hold("/console/resources/");
    const latest = hold("/console/logs/");
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("link", { name: "Resources" }));
    await user.click(screen.getByRole("link", { name: "Logs" }));
    expect(screen.getByLabelText("Pending destination").textContent).toBe("/console/logs/");
    await act(async () => latest.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/logs/");
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    await act(async () => first.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/logs/");
  });

  it("remains interactive after 200 rapid interrupted IAM menu visits", async () => {
    const groups = hold("/console/access/groups/");
    const roles = hold("/console/access/roles/");
    render(<Harness />);

    const groupsLink = screen.getByRole("link", { name: "Group directory" });
    const rolesLink = screen.getByRole("link", { name: "Roles" });
    for (let index = 0; index < 200; index += 1) {
      fireEvent.click(index % 2 === 0 ? groupsLink : rolesLink);
    }

    expect(router.push).toHaveBeenCalledTimes(200);
    expect(screen.getByLabelText("Pending destination").textContent).toBe("/console/access/roles/");
    expect(rolesLink.getAttribute("aria-busy")).toBe("true");
    expect(groupsLink.getAttribute("aria-busy")).toBeNull();

    await act(async () => roles.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/access/roles/");
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    expect(rolesLink.getAttribute("aria-busy")).toBeNull();

    await act(async () => groups.release());
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/access/roles/");
    fireEvent.click(groupsLink);
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/access/groups/");
  });

  it("does not fabricate waits for cached/same-page visits or intercept modified/cancelled links", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("link", { name: "Home" }));
    fireEvent.click(screen.getByRole("link", { name: "Resources" }), { ctrlKey: true });
    await user.click(screen.getByRole("link", { name: "Blocked" }));
    expect(router.push).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    await user.click(screen.getByRole("button", { name: "Search result" }));
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/operations/", { scroll: false });
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/operations/");
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
  });
});
