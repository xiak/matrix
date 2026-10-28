import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { ConsoleRouteLayout } from "./ConsoleRouteLayout";

const route = vi.hoisted(() => ({ pathname: "/console/" }));

vi.mock("next/navigation", () => ({
  usePathname: () => route.pathname
}));

vi.mock("../renderers/ConsoleShellRenderer", () => ({
  ConsoleShellRenderer: ({ selection }: { selection: { section: string } }) => (
    <output data-testid="section">{selection.section}</output>
  )
}));

afterEach(() => {
  cleanup();
  localStorage.clear();
  route.pathname = "/console/";
});

describe("ConsoleRouteLayout", () => {
  it("keeps one console shell while the child route changes its scene", () => {
    const view = render(
      <LocaleProvider>
        <ConsoleRouteLayout><span>overview route</span></ConsoleRouteLayout>
      </LocaleProvider>
    );
    const shell = screen.getByTestId("section");
    expect(screen.getByTestId("section").textContent).toBe("overview");
    expect(screen.getByText("overview route")).toBeTruthy();

    route.pathname = "/console/quotas/";
    view.rerender(
      <LocaleProvider>
        <ConsoleRouteLayout><span>quota route</span></ConsoleRouteLayout>
      </LocaleProvider>
    );

    expect(screen.getByTestId("section")).toBe(shell);
    expect(screen.getByTestId("section").textContent).toBe("quotas");
    expect(screen.getByText("quota route")).toBeTruthy();
  });
});
