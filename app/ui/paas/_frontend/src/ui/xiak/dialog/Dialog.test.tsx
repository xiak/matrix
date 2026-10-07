import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dialog, Button, Input } from "../index";

afterEach(cleanup);
function Harness({ busy = false }: { busy?: boolean }) {
  const [open, setOpen] = useState(false);
  return <><Button onClick={() => setOpen(true)}>Open</Button><Input aria-label="Behind" />
    <Dialog busy={busy} closeLabel="Close" onClose={() => setOpen(false)} open={open} title="Create resource" footer={<Button disabled={busy} onClick={() => setOpen(false)}>Cancel</Button>}>
      <Input aria-label="Name" />
    </Dialog></>;
}
describe("shared dialog", () => {
  it("does not mount closed or not-yet-loaded content", async () => {
    const content = vi.fn();
    function ExpensiveContent() { content(); return <Input aria-label="Loaded name" />; }
    const onClose = vi.fn();
    const props = { title: "Edit resource", closeLabel: "Close", onClose };
    const { rerender } = render(<Dialog {...props} open={false}><ExpensiveContent /></Dialog>);
    expect(content).not.toHaveBeenCalled();
    rerender(<Dialog {...props} open loading="Loading resource"><ExpensiveContent /></Dialog>);
    const panel = screen.getByRole("dialog", { name: "Edit resource" });
    expect(screen.getByRole("status").textContent).toBe("Loading resource");
    expect(content).not.toHaveBeenCalled();
    // A read is cancellable; only a mutation locks dismissal.
    fireEvent(panel, new Event("cancel", { cancelable: true }));
    expect(onClose).toHaveBeenCalledOnce();
    await userEvent.setup().click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(2);
    rerender(<Dialog {...props} open><ExpensiveContent /></Dialog>);
    expect(screen.getByRole("dialog")).toBe(panel);
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByLabelText("Loaded name")).toBeTruthy();
  });

  it("opens before a pending read settles and recovers in the same shell", async () => {
    let resolveRead!: () => void;
    const read = new Promise<void>((resolve) => { resolveRead = resolve; });
    function Example() {
      const [open, setOpen] = useState(false);
      const [phase, setPhase] = useState("loading");
      return <><Button onClick={() => { setOpen(true); void read.then(() => setPhase("failed")); }}>Read resource</Button>
        <Dialog open={open} title="Resource" closeLabel="Close" onClose={() => setOpen(false)} loading={phase === "loading" ? "Loading resource" : undefined}>
          {phase === "failed" ? <><p role="alert">Unable to load</p><Button onClick={() => setPhase("ready")}>Retry</Button></> : <Input aria-label="Resource name" />}
        </Dialog></>;
    }
    const user = userEvent.setup();
    render(<Example />);
    await user.click(screen.getByRole("button", { name: "Read resource" }));
    const panel = screen.getByRole("dialog", { name: "Resource" });
    expect(screen.getByRole("status").textContent).toBe("Loading resource");
    await act(async () => { resolveRead(); });
    expect(screen.getByRole("alert").textContent).toBe("Unable to load");
    expect(screen.getByRole("dialog")).toBe(panel);
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(screen.getByLabelText("Resource name")).toBeTruthy();
    expect(screen.getByRole("dialog")).toBe(panel);
  });

  it("has an accessible title, explicit close action, and restores the opening control", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const trigger = screen.getByRole("button", { name: "Open" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(trigger);
    expect(screen.getByRole("dialog", { name: "Create resource" })).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Create resource" }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
  it("does not dismiss on a content click and honors a platform cancel request", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const panel = screen.getByRole("dialog");
    await user.click(panel);
    expect(screen.getByRole("dialog")).toBe(panel);
    fireEvent(panel, new Event("cancel", { cancelable: true }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("cannot dismiss a mutation in progress, including Escape", async () => {
    const user = userEvent.setup();
    render(<Harness busy />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const panel = screen.getByRole("dialog");
    expect((screen.getByRole("button", { name: "Close" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent(panel, new Event("cancel", { cancelable: true }));
    expect(screen.getByRole("dialog")).toBe(panel);
  });
  it("keeps a native disclosure in the keyboard sequence instead of jumping to the footer", () => {
    const rects = vi.spyOn(HTMLElement.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
    try {
      render(<Dialog open title="Review" closeLabel="Close" onClose={() => {}} footer={<Button>Save</Button>}><details><summary>Documents</summary><p>Full document</p></details></Dialog>);
      const summary = screen.getByText("Documents");
      // jsdom lacks native summary focusability; model that browser property without adding an attribute.
      Object.defineProperty(summary, "tabIndex", { configurable: true, get: () => 0 });
      const focus = vi.spyOn(summary, "focus");
      summary.focus();
      const backward = new KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true, cancelable: true });
      fireEvent(summary, backward);
      expect(backward.defaultPrevented).toBe(false);
      expect(focus).toHaveBeenCalledOnce();
      const forward = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
      screen.getByRole("button", { name: "Save" }).focus();
      fireEvent(screen.getByRole("button", { name: "Save" }), forward);
      expect(forward.defaultPrevented).toBe(true);
      expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
    } finally { rects.mockRestore(); }
  });
});
