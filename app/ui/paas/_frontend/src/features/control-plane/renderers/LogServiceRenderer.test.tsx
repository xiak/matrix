import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { LogServiceRenderer } from "./LogServiceRenderer";

afterEach(() => { cleanup(); localStorage.clear(); });
const data = previewExperienceSnapshot.logs;

describe("LogServiceRenderer", () => {
  it("combines keyword, topic and severity filters and reveals event fields", async () => {
    const user = userEvent.setup();
    render(<LocaleProvider><LogServiceRenderer scene={{ kind: "logs", view: "search", data }} /></LocaleProvider>);
    expect(screen.getByRole("status").textContent).toBe("6 条日志");
    await user.type(screen.getByRole("searchbox", { name: "搜索日志" }), "TRACE-PAY-8F42");
    expect(screen.getByRole("status").textContent).toBe("2 条日志");
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "日志主题" }));
    await user.click(screen.getByRole("option", { name: "application-production" }));
    await user.click(screen.getByRole("combobox", { name: "日志级别" }));
    await user.click(screen.getByRole("option", { name: "ERROR" }));
    expect(screen.getByRole("status").textContent).toBe("1 条日志");
    const message = screen.getByText("Upstream payment provider timed out after 3000 ms");
    await user.click(message);
    expect(message.closest("details")?.open).toBe(true);
    expect(screen.getByText("trace-pay-8f42")).toBeTruthy();
    await user.type(screen.getByRole("searchbox"), " missing");
    expect(screen.getByText("没有匹配的日志")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重置查询" }));
    expect(screen.getByRole("status").textContent).toBe("6 条日志");
  });

  it("keeps topic and collection pages inside the selected region", () => {
    const view = render(<LocaleProvider><LogServiceRenderer regionId="shanghai-b" scene={{ kind: "logs", view: "topics", data }} /></LocaleProvider>);
    expect(screen.getByText("host-system")).toBeTruthy();
    expect(screen.getByText("14 天")).toBeTruthy();
    expect(screen.queryByText("application-production")).toBeNull();
    view.rerender(<LocaleProvider><LogServiceRenderer regionId="shanghai-b" scene={{ kind: "logs", view: "collection", data }} /></LocaleProvider>);
    expect(screen.getByText("/var/log/syslog")).toBeTruthy();
    expect(screen.getByText("已暂停")).toBeTruthy();
  });

  it("never presents preview log data as a connected live service", () => {
    render(<LocaleProvider><LogServiceRenderer scene={{ kind: "logs", data: null }} /></LocaleProvider>);
    expect(screen.getByText("日志服务尚未接入")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("searchbox")).toBeNull();
  });

  it("localizes the workspace and uses explicit sample timestamps", () => {
    localStorage.setItem("matrix.locale", "en");
    render(<LocaleProvider><LogServiceRenderer scene={{ kind: "logs", view: "search", data }} /></LocaleProvider>);
    expect(screen.getByRole("status").textContent).toBe("6 log events");
    expect(screen.getByText(/Fixed sample window/)).toBeTruthy();
    expect(screen.getByText("09:14:28")).toBeTruthy();
  });
});
