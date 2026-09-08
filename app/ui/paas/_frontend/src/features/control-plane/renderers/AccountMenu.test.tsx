import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountMenu, type AccountIdentity } from "./AccountMenu";

const identity: AccountIdentity = {
  accountType: "主账号",
  loginName: "preview-admin",
  principalId: "principal-admin",
  tenant: { id: "org-xiak", name: "Xiak 科技" }
};

function AccountMenuHarness({ onLogout = vi.fn() }: { onLogout?: () => void }) {
  const [open, setOpen] = useState(false);
  return <AccountMenu identity={identity} onLogout={onLogout} onOpenChange={setOpen} open={open} revoking={false} />;
}

afterEach(cleanup);

describe("AccountMenu", () => {
  it("renders identity and account actions as one semantic menu", async () => {
    const user = userEvent.setup();
    const onLogout = vi.fn();
    render(<AccountMenuHarness onLogout={onLogout} />);

    await user.click(screen.getByRole("button", { name: "打开账号菜单，当前用户 preview-admin" }));

    const dialog = screen.getByRole("dialog", { name: "账号菜单" });
    expect(dialog.textContent).toContain("preview-admin");
    expect(dialog.textContent).toContain("principal-admin");
    expect(dialog.textContent).toContain("Xiak 科技");
    expect(screen.getByRole("menu", { name: "账号操作" })).toBeTruthy();
    expect(screen.getAllByRole("menuitem")).toHaveLength(2);
    expect(screen.getByRole("menuitem", { name: /账号与权限.*用户、角色与租户/ })).toBeTruthy();

    await user.click(screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" }));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("supports roving menu focus and restores the trigger on Escape", async () => {
    const user = userEvent.setup();
    render(<AccountMenuHarness />);
    const trigger = screen.getByRole("button", { name: "打开账号菜单，当前用户 preview-admin" });

    await user.click(trigger);
    const access = screen.getByRole("menuitem", { name: /账号与权限/ });
    const logout = screen.getByRole("menuitem", { name: "注销并撤销 IAM 会话" });
    expect(document.activeElement).toBe(access);

    await user.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(logout);
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(access);
    await user.keyboard("{End}");
    expect(document.activeElement).toBe(logout);
    await user.keyboard("{Home}");
    expect(document.activeElement).toBe(access);
    await user.keyboard("{ArrowUp}");
    expect(document.activeElement).toBe(logout);
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog", { name: "账号菜单" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
