import { Suspense, useEffect, useRef, useState } from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsoleLink, ConsoleNavigationProvider, useConsoleNavigation } from "./ConsoleNavigation";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";
import { useUnsavedChanges } from "@ui/xiak";

const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => router }));
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

function NavigationControls() {
  const navigation = useConsoleNavigation();
  return <>
    <output aria-label="Pending destination">{navigation.pendingHref ?? "idle"}</output>
    <ConsoleLink href="/console/">Home</ConsoleLink>
    <ConsoleLink href="/console/resources/">Resources</ConsoleLink>
    <ConsoleLink href="/console/logs/">Logs</ConsoleLink>
    <ConsoleLink href="/console/access/groups/?id=group%2Fexample">Group detail</ConsoleLink>
    <ConsoleLink href="/console/access/groups/">Group directory</ConsoleLink>
    <ConsoleLink href="/console/quotas/" onNavigate={(event) => event.preventDefault()}>Blocked</ConsoleLink>
    <button onClick={() => navigation.navigate("/console/operations/")} type="button">Search result</button>
  </>;
}

const draftCopy = { title: "Leave workflow?", description: "The draft is not saved.", stay: "Keep editing", leave: "Leave", close: "Close", busyTitle: "Saving", busyDescription: "Wait", failure: "Navigation failed", retry: "Retry" };
function DraftProbe() {
  const [value, setValue] = useState("");
  const form = useRef<HTMLFormElement>(null);
  useUnsavedChanges({ dirty: Boolean(value), busy: false, copy: draftCopy, focusRef: form });
  return <form ref={form}><input aria-label="Workflow draft" value={value} onChange={(event) => setValue(event.target.value)} /></form>;
}

function Harness({ initialHref = "/console/", withDraft = false }: { initialHref?: string; withDraft?: boolean }) {
  const [href, setHref] = useState(initialHref);
  router.push.mockImplementation((target: string) => setHref(target));
  return <ConsoleNavigationProvider selection={parseControlPlanePathname(href.split(/[?#]/)[0] ?? "")}>
    <NavigationControls />
    <Suspense fallback={<span>Route fallback</span>}><RouteContent href={href} />{withDraft && href === initialHref ? <DraftProbe /> : null}</Suspense>
  </ConsoleNavigationProvider>;
}

afterEach(() => { cleanup(); requests.clear(); vi.clearAllMocks(); window.history.replaceState(null, "", "/"); });

describe("Console navigation", () => {
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
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/resources/");
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
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/operations/");
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

  it("preserves encoded entity queries and navigates back to the same-path directory", async () => {
    const href = "/console/access/groups/?id=group%2Fexample";
    const request = hold(href);
    const user = userEvent.setup();
    render(<Harness initialHref="/console/access/groups/" />);
    await user.click(screen.getByRole("link", { name: "Group detail" }));
    expect(screen.getByLabelText("Pending destination").textContent).toBe(href);
    expect(screen.getByRole("link", { name: "Group detail" }).getAttribute("aria-busy")).toBe("true");
    await act(async () => request.release());
    expect(screen.getByLabelText("Current content").textContent).toBe(href);
    await user.click(screen.getByRole("link", { name: "Group detail" }));
    expect(router.push).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("link", { name: "Group directory" }));
    expect(router.push).toHaveBeenLastCalledWith("/console/access/groups/");
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/access/groups/");
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

  it("does not fabricate waits for cached/same-page visits or intercept modified/cancelled links", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("link", { name: "Home" }));
    fireEvent.click(screen.getByRole("link", { name: "Resources" }), { ctrlKey: true });
    await user.click(screen.getByRole("link", { name: "Blocked" }));
    expect(router.push).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
    await user.click(screen.getByRole("button", { name: "Search result" }));
    expect(router.push).toHaveBeenCalledExactlyOnceWith("/console/operations/");
    expect(screen.getByLabelText("Current content").textContent).toBe("/console/operations/");
    expect(screen.getByLabelText("Pending destination").textContent).toBe("idle");
  });
});
