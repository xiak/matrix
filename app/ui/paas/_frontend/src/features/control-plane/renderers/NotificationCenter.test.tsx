import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import type { AlertScene } from "../scenes/consoleScene";
import { NotificationCenter } from "./NotificationCenter";

const notices: AlertScene[] = [{
  id: "alert-payment",
  title: "支付服务错误率升高",
  serviceName: "支付服务",
  severityLabel: "严重",
  status: "danger",
  stateLabel: "触发中",
  startedAt: "8 分钟前",
  owner: "SRE 值班组"
}];

function NotificationCenterHarness() {
  const [open, setOpen] = useState(false);
  return <NotificationCenter count={1} notices={notices} onOpenChange={setOpen} open={open} />;
}

afterEach(cleanup);

describe("NotificationCenter", () => {
  it("announces open state, focuses the first notice, and restores its trigger", async () => {
    const user = userEvent.setup();
    render(<NotificationCenterHarness />);
    const trigger = screen.getByRole("button", { name: "打开通知中心，1 个待处理" });

    await user.click(trigger);
    expect(trigger.getAttribute("aria-controls")).toBe("global-notification-center");
    expect(screen.getByRole("dialog", { name: "通知中心" })).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("link", { name: /支付服务错误率升高/ }));

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "通知中心" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(screen.getByRole("button", { name: "打开通知中心，1 个待处理" })).toBe(trigger);
  });
});
