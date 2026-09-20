import { act, cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { previewCredential, previewIamRepository } from "../repositories/previewIamRepository";
import { OwnSessionsPage } from "./OwnSessionsPage";

function Harness() {
  const session = useSession();
  return session.current
    ? <OwnSessionsPage />
    : <button onClick={() => { void session.login("admin", "preview"); }}>进入体验</button>;
}

afterEach(async () => {
  cleanup();
  localStorage.clear();
  await previewIamRepository.logout(previewCredential);
});

describe("OwnSessionsPage", () => {
  it("renders fixed semantics immediately and revokes only a confirmed other session", async () => {
    const screen = render(<LocaleProvider><SessionProvider repository={previewIamRepository}><Harness /></SessionProvider></LocaleProvider>);
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "进入体验" })));
    expect(screen.getByRole("heading", { name: "登录会话" })).toBeTruthy();
    expect(screen.getByText(/会话不是物理设备/)).toBeTruthy();
    await waitFor(() => expect(screen.getByText("session-ux-preview-002")).toBeTruthy());

    expect(screen.getByRole("columnheader", { name: "会话 ID" })).toBeTruthy();
    expect(screen.queryByRole("columnheader", { name: /IP/ })).toBeNull();
    expect(screen.queryByRole("columnheader", { name: /最近活动/ })).toBeNull();
    const currentRow = screen.getByText("session-ux-preview").closest("tr");
    expect(currentRow).not.toBeNull();
    expect(within(currentRow!).getByRole("button", { name: /退出当前会话/ })).toBeTruthy();

    const otherRow = screen.getByText("session-ux-preview-002").closest("tr");
    expect(otherRow).not.toBeNull();
    fireEvent.click(within(otherRow!).getByRole("button", { name: "结束会话" }));
    expect(screen.getByText("结束后，该会话的后续受保护请求会被拒绝。")).toBeTruthy();
    await act(async () => fireEvent.click(within(otherRow!).getByRole("button", { name: "确认结束" })));
    await waitFor(() => expect(screen.queryByText("session-ux-preview-002")).toBeNull());
    expect(screen.getByText("登录会话已结束。")).toBeTruthy();
  });

  it("keeps the bulk action stable and confirms it inline before preserving the current session", async () => {
    const screen = render(<LocaleProvider><SessionProvider repository={previewIamRepository}><Harness /></SessionProvider></LocaleProvider>);
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "进入体验" })));
    await waitFor(() => expect(screen.getByText("session-ux-preview-003")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "结束其他会话" }));
    expect(screen.getByText("保留当前会话，结束其余登录会话？")).toBeTruthy();
    expect(screen.getByText(/包括后续分页中的会话/)).toBeTruthy();
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "确认结束其他会话" })));
    await waitFor(() => expect(screen.queryByText("session-ux-preview-003")).toBeNull());
    expect(screen.getByText("session-ux-preview")).toBeTruthy();
    expect(screen.getByText("已结束 2 个其他登录会话，当前会话保留。")).toBeTruthy();
  });
});
