import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { PageSkeleton, type PageSkeletonLayout } from "./PageSkeleton";

afterEach(cleanup);

describe("PageSkeleton", () => {
  it.each<PageSkeletonLayout>(["dashboard", "table", "cards", "list", "access"])("announces %s loading without presenting placeholder data as controls or real rows", (layout) => {
    render(<PageSkeleton label="Opening resource center…" layout={layout} />);
    expect(screen.getByRole("status").textContent).toBe("Opening resource center…");
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("textbox")).toBeNull();
  });
});
