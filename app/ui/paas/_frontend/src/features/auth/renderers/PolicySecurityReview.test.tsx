import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import type { AccessPolicy } from "../domain/accessWorkspace";
import { PolicySecurityReview } from "./PolicySecurityReview";

afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); });

const policy = (id: string, name: string, action: string[]): AccessPolicy => ({
  id, name, description: "", kind: "custom", tags: [], defaultVersion: 1, lastVersion: 1,
  createdAt: "2026-09-30T00:00:00Z", updatedAt: "2026-09-30T00:00:00Z",
  versions: [{
    id: 1,
    createdAt: "2026-09-30T00:00:00Z",
    document: { version: "1", statement: [{ effect: "allow", action, resource: ["*"] }] }
  }]
});

describe("policy security review", () => {
  it("reuses the authoring risk vocabulary without turning a safe policy into a finding", () => {
    render(<LocaleProvider><PolicySecurityReview policies={[
      policy("risky", "Tenant administrator", ["iam:*"]),
      policy("safe", "Log reader", ["logs:read"])
    ]} /></LocaleProvider>);

    const review = screen.getByText("安全复核 · 3 项").closest<HTMLElement>("[data-status='warning']");
    expect(review).not.toBeNull();
    expect(within(review!).getByText("Tenant administrator")).toBeTruthy();
    expect(within(review!).queryByText("Log reader")).toBeNull();
    expect(within(review!).getByText(/使用操作通配符/)).toBeTruthy();
    expect(within(review!).getByText(/不是最终有效权限/)).toBeTruthy();
  });
});
