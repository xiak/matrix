import { Profiler, useRef, useState } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UnsavedChangesProvider, useLeaveConfirmation, useUnsavedChanges, type UnsavedChangesCopy } from "./UnsavedChanges";

const copy: UnsavedChangesCopy = { title: "Discard this draft?", description: "Unsaved fields will be cleared.", stay: "Continue editing", leave: "Discard and leave", close: "Close confirmation", busyTitle: "Saving", busyDescription: "Wait for this submission to finish.", failure: "Navigation failed; the draft is retained.", retry: "Retry leaving" };
const headerCommit = vi.fn();
function Controls({ navigate }: { navigate(): void | Promise<unknown> }) {
  const request = useLeaveConfirmation();
  return <Profiler id="header" onRender={headerCommit}><button onClick={() => request(navigate)}>Menu destination</button></Profiler>;
}
function Draft({ busy = false, completed = false, labels = copy }: { busy?: boolean; completed?: boolean; labels?: UnsavedChangesCopy }) {
  const [text, setText] = useState("");
  const form = useRef<HTMLFormElement>(null);
  useUnsavedChanges({ dirty: Boolean(text) && !completed, busy, copy: labels, focusRef: form });
  return <form ref={form}><h2 tabIndex={-1}>Workflow step</h2><input aria-label="Draft field" value={text} onChange={(event) => setText(event.target.value)} /></form>;
}
function Fixture({ navigate = vi.fn(), busy, completed, mounted = true, labels }: { navigate?: () => void | Promise<unknown>; busy?: boolean; completed?: boolean; mounted?: boolean; labels?: UnsavedChangesCopy }) {
  return <UnsavedChangesProvider><Controls navigate={navigate} />{mounted ? <Draft busy={busy} completed={completed} labels={labels} /> : null}</UnsavedChangesProvider>;
}
function unload() { const event = new Event("beforeunload", { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented; }
function traversal(navigation: EventTarget, key: string, { cancelable = true, sameDocument = true, path = "/console/roles/" } = {}) {
  const event = new Event("navigate", { cancelable });
  Object.assign(event, { navigationType: "traverse", destination: { key, url: new URL(path, window.location.href).href, sameDocument } });
  navigation.dispatchEvent(event);
  return event;
}
function browserNavigation() {
  const navigation = Object.assign(new EventTarget(), { traverseTo: vi.fn((key: string) => {
    expect(traversal(navigation, key).defaultPrevented).toBe(false);
    return { committed: Promise.resolve(), finished: Promise.resolve() };
  }) });
  vi.stubGlobal("navigation", navigation);
  return navigation;
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); headerCommit.mockClear(); window.history.replaceState(null, "", "/"); });

describe("unsaved workflow boundary", () => {
  it("defers navigation, retains fields and focus on stay, and never rerenders unrelated header content", async () => {
    const navigate = vi.fn(), user = userEvent.setup();
    render(<Fixture navigate={navigate} />);
    const commits = headerCommit.mock.calls.length;
    expect(unload()).toBe(false);
    await user.type(screen.getByLabelText("Draft field"), "retain all my input");
    expect(unload()).toBe(true);
    await user.click(screen.getByRole("button", { name: "Menu destination" }));
    const dialog = screen.getByRole("dialog");
    expect(document.activeElement).toBe(within(dialog).getByRole("heading"));
    expect(navigate).not.toHaveBeenCalled();
    fireEvent(dialog, new Event("cancel", { cancelable: true }));
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Menu destination" }));
    expect((screen.getByLabelText("Draft field") as HTMLInputElement).value).toBe("retain all my input");
    expect(headerCommit).toHaveBeenCalledTimes(commits);
    await user.clear(screen.getByLabelText("Draft field"));
    expect(unload()).toBe(false);
    await user.click(screen.getByRole("button", { name: "Menu destination" }));
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("authorizes one exact action including nested guarded routing, without storing the draft", async () => {
    const user = userEvent.setup(), first = vi.fn(), second = vi.fn();
    const storage = vi.spyOn(Storage.prototype, "setItem");
    function Destinations() {
      const request = useLeaveConfirmation();
      return <><button onClick={() => request(() => request(first))}>First</button><button onClick={() => request(second)}>Second</button></>;
    }
    render(<UnsavedChangesProvider><Destinations /><Draft /></UnsavedChangesProvider>);
    await user.type(screen.getByLabelText("Draft field"), "private draft");
    await user.click(screen.getByRole("button", { name: "First" }));
    // jsdom does not implement inertness; a background attempt still must not replace the target.
    fireEvent.click(screen.getByRole("button", { name: "Second" }));
    await user.click(screen.getByRole("button", { name: "Discard and leave" }));
    expect(first).toHaveBeenCalledTimes(1);
    expect(second).not.toHaveBeenCalled();
    expect(storage).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does not discard or queue navigation during submission and clears protection only after successful completion", async () => {
    const user = userEvent.setup(), navigate = vi.fn();
    const view = render(<Fixture navigate={navigate} />);
    await user.type(screen.getByLabelText("Draft field"), "pending save");
    view.rerender(<Fixture navigate={navigate} busy />);
    await user.click(screen.getByRole("button", { name: "Menu destination" }));
    expect(screen.getByRole("heading", { name: "Saving" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Discard and leave" })).toBeNull();
    view.rerender(<Fixture navigate={navigate} />); // A failed save retains protection, but no deferred visit.
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(navigate).not.toHaveBeenCalled();
    expect(unload()).toBe(true);
    view.rerender(<Fixture navigate={navigate} completed />);
    expect(unload()).toBe(false);
    await user.click(screen.getByRole("button", { name: "Menu destination" }));
    expect(navigate).toHaveBeenCalledTimes(1);
  });

  it("updates confirmation language without resetting fields and invalidates a pending action on forced unmount", async () => {
    const user = userEvent.setup(), navigate = vi.fn();
    const view = render(<Fixture navigate={navigate} />);
    await user.type(screen.getByLabelText("Draft field"), "preserved");
    await user.click(screen.getByRole("button", { name: "Menu destination" }));
    view.rerender(<Fixture navigate={navigate} labels={{ ...copy, title: "放弃草稿？", stay: "继续编辑", leave: "放弃并离开" }} />);
    expect(screen.getByRole("heading", { name: "放弃草稿？" })).toBeTruthy();
    expect((screen.getByLabelText("Draft field") as HTMLInputElement).value).toBe("preserved");
    view.rerender(<Fixture navigate={navigate} mounted={false} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(unload()).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
  });

  it("returns focus to the workflow when a product popup trigger has unmounted", async () => {
    const user = userEvent.setup();
    function Popup() {
      const [open, setOpen] = useState(true), request = useLeaveConfirmation();
      return open ? <button onClick={() => { setOpen(false); request(() => {}); }}>Product result</button> : null;
    }
    render(<UnsavedChangesProvider><Draft /><Popup /></UnsavedChangesProvider>);
    await user.type(screen.getByLabelText("Draft field"), "draft");
    await user.click(screen.getByRole("button", { name: "Product result" }));
    await user.click(screen.getByRole("button", { name: "Continue editing" }));
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Workflow step" }));
  });

  it("cancels browser traversal before commit and resumes the exact entry only after confirmation", async () => {
    window.history.replaceState(null, "", "/console/access/create-role/");
    const navigation = browserNavigation(), user = userEvent.setup();
    const push = vi.spyOn(window.history, "pushState"), replace = vi.spyOn(window.history, "replaceState");
    render(<Fixture />);
    await user.type(screen.getByLabelText("Draft field"), "role trust draft");
    let event!: Event;
    await act(async () => { event = traversal(navigation, "prior-entry"); });
    expect(event.defaultPrevented).toBe(true);
    expect(window.location.pathname).toBe("/console/access/create-role/");
    await user.click(screen.getByRole("button", { name: "Continue editing" }));
    expect(navigation.traverseTo).not.toHaveBeenCalled();
    await act(async () => { traversal(navigation, "exact-query-entry"); });
    await user.click(screen.getByRole("button", { name: "Discard and leave" }));
    expect(navigation.traverseTo).toHaveBeenCalledExactlyOnceWith("exact-query-entry");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(push).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  });

  it("does not trap forced/cross-document traversal or hash-only visits, and removes browser bindings on unmount", async () => {
    window.history.replaceState(null, "", "/console/access/create-role/");
    const navigation = browserNavigation(), user = userEvent.setup();
    const view = render(<Fixture />);
    await user.type(screen.getByLabelText("Draft field"), "draft");
    for (const options of [{ cancelable: false }, { sameDocument: false }, { path: "/console/access/create-role/#review" }]) {
      expect(traversal(navigation, "destination", options).defaultPrevented).toBe(false);
    }
    expect(screen.queryByRole("dialog")).toBeNull();
    view.unmount();
    expect(traversal(navigation, "destination").defaultPrevented).toBe(false);
    expect(unload()).toBe(false);
  });

  it("retains a draft after interrupted traversal and offers a single retry without unhandled rejections", async () => {
    const navigation = browserNavigation(), user = userEvent.setup();
    navigation.traverseTo.mockImplementationOnce(() => ({ committed: Promise.reject(new Error("interrupted")), finished: Promise.reject(new Error("interrupted")) }));
    render(<Fixture />);
    await user.type(screen.getByLabelText("Draft field"), "not lost");
    await act(async () => { traversal(navigation, "previous"); });
    await user.click(screen.getByRole("button", { name: "Discard and leave" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("alert").textContent).toBe(copy.failure);
    expect((screen.getByLabelText("Draft field") as HTMLInputElement).value).toBe("not lost");
    await user.click(screen.getByRole("button", { name: "Retry leaving" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(navigation.traverseTo).toHaveBeenCalledTimes(2);
  });
});
