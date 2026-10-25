import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReadBoundary } from "./ReadBoundary";

const labels = { copied: "Copied", copyDiagnostic: "Copy diagnostic", copyFailed: "Copy failed", retry: "Retry" };

afterEach(cleanup);

describe("ReadBoundary", () => {
  it("keeps loading, ready and empty presentations mutually exclusive", () => {
    const view = render(<ReadBoundary status="loading" loading={<p>Loading rows</p>} failure={{ title: "Failure" }} labels={labels}><p>Rows</p></ReadBoundary>);
    expect(screen.getByText("Loading rows")).toBeTruthy();
    expect(screen.queryByText("Rows")).toBeNull();

    view.rerender(<ReadBoundary status="ready" loading={null} failure={{ title: "Failure" }} labels={labels}><p>Rows</p></ReadBoundary>);
    expect(screen.getByText("Rows")).toBeTruthy();
    expect(screen.queryByText("Loading rows")).toBeNull();

    view.rerender(<ReadBoundary status="empty" loading={null} empty={{ title: "No rows", description: "The read succeeded." }} failure={{ title: "Failure" }} labels={labels}><p>Rows</p></ReadBoundary>);
    expect(screen.getByRole("heading", { name: "No rows" })).toBeTruthy();
    expect(screen.queryByText("Rows")).toBeNull();
  });

  it("offers only caller-owned recovery actions and copies a bounded diagnostic", async () => {
    const retry = vi.fn();
    const user = userEvent.setup();
    render(<ReadBoundary status="unavailable" loading={null} failure={{ title: "Temporarily unavailable" }} labels={labels}
      diagnostic={{ code: "managedservice.temporarily-unavailable", requestId: "request-safe-1", status: 503 }} onRetry={retry} />);

    await user.click(screen.getByRole("button", { name: "Retry" }));
    await user.click(screen.getByRole("button", { name: "Copy diagnostic" }));

    expect(retry).toHaveBeenCalledOnce();
    expect(await navigator.clipboard.readText()).toBe(JSON.stringify({
      requestId: "request-safe-1",
      status: 503,
      code: "managedservice.temporarily-unavailable"
    }, null, 2));
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
  });

  it("does not expose a copy action for an unbounded diagnostic", () => {
    render(<ReadBoundary status="forbidden" loading={null} failure={{ title: "Forbidden" }} labels={labels}
      diagnostic={{ code: "managedservice.denied\nAuthorization: Bearer private", requestId: "request-safe-1", status: 403 }} />);

    expect(screen.queryByRole("button", { name: "Copy diagnostic" })).toBeNull();
    expect(screen.getByRole("heading", { name: "Forbidden" })).toBeTruthy();
  });
});
