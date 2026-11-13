import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ContentPage } from "../content/ContentPage";
import { CardGridSkeleton, LoadingNotice, LOADING_FEEDBACK_DELAY_MS, PageSkeleton, TableSkeleton, type PageSkeletonLayout } from "./PageSkeleton";

afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("PageSkeleton", () => {
  it.each<PageSkeletonLayout>(["dashboard", "table", "cards", "list", "access"])("announces %s loading without presenting placeholder data as controls or real rows", (layout) => {
    render(<PageSkeleton label="Opening resource center…" layout={layout} />);
    const status = screen.getByRole("status");
    expect(status.textContent).toBe("Opening resource center…");
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(status.querySelector("[data-visible]")?.getAttribute("data-visible")).toBe("false");
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

  it.each([PageSkeleton, TableSkeleton, CardGridSkeleton])("acknowledges immediately, but mounts placeholder DOM only for sustained regional waits", (Feedback) => {
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

  it("announces a short read without scheduling or painting inline status text", () => {
    vi.useFakeTimers();
    render(<LoadingNotice label="Refreshing account data…" />);
    const status = screen.getByRole("status");
    expect(status.textContent).toBe("Refreshing account data…");
    expect(status.querySelector('[aria-hidden="true"]')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("routes visual loading feedback to the page header and removes it with the read", () => {
    const page = (loading: boolean) => <ContentPage>
      <ContentPage.Header title="Groups" />
      <ContentPage.Body>{loading ? <TableSkeleton label="Loading groups…" /> : <p>Groups loaded</p>}</ContentPage.Body>
    </ContentPage>;
    const view = render(page(true));
    expect(screen.getByRole("progressbar", { name: "Loading groups…" })).toBeTruthy();
    expect(screen.getByRole("status").querySelector("[data-visible]")?.getAttribute("data-visible")).toBe("false");
    view.rerender(page(false));
    expect(screen.queryByRole("progressbar", { name: "Loading groups…" })).toBeNull();
    expect(screen.getByText("Groups loaded")).toBeTruthy();
  });

  it("keeps page progress active until every concurrent read has settled", () => {
    const page = (groups: boolean, policies: boolean) => <ContentPage>
      <ContentPage.Header title="Access" />
      <ContentPage.Body>
        {groups ? <LoadingNotice key="groups" label="Loading groups…" /> : null}
        {policies ? <LoadingNotice key="policies" label="Loading policies…" /> : null}
      </ContentPage.Body>
    </ContentPage>;
    const view = render(page(true, true));
    expect(screen.getByRole("progressbar", { name: "Loading policies…" })).toBeTruthy();
    view.rerender(page(true, false));
    expect(screen.getByRole("progressbar", { name: "Loading groups…" })).toBeTruthy();
    view.rerender(page(false, false));
    expect(screen.queryByRole("progressbar")).toBeNull();
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
