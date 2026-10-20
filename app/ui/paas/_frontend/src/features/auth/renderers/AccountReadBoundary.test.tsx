import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { AccountReadBoundary } from "./AccountReadBoundary";

afterEach(cleanup);

describe("AccountReadBoundary", () => {
  it("does not offer a blind retry for an authoritative denial", () => {
    render(<LocaleProvider><AccountReadBoundary status="forbidden" loading={null} onRetry={vi.fn()} /></LocaleProvider>);

    expect(screen.getByRole("heading", { name: "当前身份无权读取" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "重试读取" })).toBeNull();
  });

  it("copies only the safe problem reference when one is available", async () => {
    const user = userEvent.setup();
    const problem = new HttpProblem(403, "iam.authorization.forbidden", "request-safe-diagnostic");
    render(<LocaleProvider><AccountReadBoundary status="forbidden" loading={null} problem={problem} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "复制诊断信息" }));

    expect(await navigator.clipboard.readText()).toBe(JSON.stringify({
      requestId: "request-safe-diagnostic",
      status: 403,
      code: "iam.authorization.forbidden"
    }, null, 2));
    expect(screen.getByRole("button", { name: "诊断信息已复制" })).toBeTruthy();
  });

  it("reports a copy failure when the browser does not expose the clipboard API", async () => {
    const user = userEvent.setup();
    const clipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    const problem = new HttpProblem(503, "iam.temporarily.unavailable", "request-safe-diagnostic");

    render(<LocaleProvider><AccountReadBoundary status="unavailable" loading={null} problem={problem} /></LocaleProvider>);
    await user.click(screen.getByRole("button", { name: "复制诊断信息" }));

    expect(screen.getByRole("button", { name: "无法复制，请稍后重试" })).toBeTruthy();
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
  });

  it("offers one retry only for a temporary read failure", async () => {
    const retry = vi.fn();
    const user = userEvent.setup();
    render(<LocaleProvider><AccountReadBoundary status="unavailable" loading={null} onRetry={retry} /></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "重试读取" }));

    expect(retry).toHaveBeenCalledOnce();
  });
});
