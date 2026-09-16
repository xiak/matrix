import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LOADING_FEEDBACK_DELAY_MS, PageSkeleton, TableSkeleton, type PageSkeletonLayout } from "./PageSkeleton";

afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("PageSkeleton", () => {
  it.each<PageSkeletonLayout>(["dashboard", "table", "cards", "list", "access"])("announces %s loading without presenting placeholder data as controls or real rows", (layout) => {
    render(<PageSkeleton label="Opening resource center…" layout={layout} />);
    expect(screen.getByRole("status").textContent).toBe("Opening resource center…");
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("announces a local table read without exposing placeholder rows as data", () => {
    render(<TableSkeleton label="Loading member relationships…" rows={3} header={false} />);
    expect(screen.getByRole("status").textContent).toBe("Loading member relationships…");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("row")).toBeNull();
  });

  it.each([PageSkeleton, TableSkeleton])("acknowledges immediately, but mounts placeholder DOM only for sustained regional waits", (Feedback) => {
    vi.useFakeTimers();
    render(<Feedback label="Loading resources…" />);
    const status = screen.getByRole("status");
    expect(status.textContent).toBe("Loading resources…");
    expect(status.querySelector("[aria-hidden]")).toBeNull();
    act(() => vi.advanceTimersByTime(LOADING_FEEDBACK_DELAY_MS - 1));
    expect(status.querySelector("[aria-hidden]")).toBeNull();
    act(() => vi.advanceTimersByTime(1));
    expect(status.querySelector("[aria-hidden]")).not.toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("restarts feedback for a new destination and cancels the regional timer on fast completion", () => {
    vi.useFakeTimers();
    const view = render(<PageSkeleton label="Opening users…" />);
    act(() => vi.advanceTimersByTime(LOADING_FEEDBACK_DELAY_MS));
    expect(screen.getByRole("status").querySelector("[aria-hidden]")).not.toBeNull();
    view.rerender(<PageSkeleton label="Opening roles…" />);
    expect(screen.getByRole("status").textContent).toBe("Opening roles…");
    expect(screen.getByRole("status").querySelector("[aria-hidden]")).toBeNull();
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
