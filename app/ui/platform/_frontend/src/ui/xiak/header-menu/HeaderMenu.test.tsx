import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { afterEach, expect, it } from "vitest";
import { HeaderMenu, HeaderMenuTrigger } from "./HeaderMenu";

afterEach(cleanup);
function Surface() {
  const trigger = useRef<HTMLButtonElement>(null); const background = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  return <><HeaderMenuTrigger label="Products" icon={<span />} controls="products" open={open} onClick={() => setOpen(value => !value)} triggerRef={trigger} /><div ref={background} data-testid="workspace">Resource page</div>{open ? <HeaderMenu id="products" label="Products" closeLabel="Close products" persistent wide onClose={() => setOpen(false)} triggerRef={trigger} backgroundRef={background}><input aria-label="Find product" /><button>Open product</button></HeaderMenu> : null}</>;
}
it("opens an immediate surface, focuses search, toggles and restores background/focus", async () => {
  const user = userEvent.setup(); render(<Surface />);
  const trigger = screen.getByRole("button", { name: "Products" });
  await user.click(trigger);
  expect(screen.getByRole("dialog", { name: "Products" })).toBeTruthy();
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("textbox")));
  expect(screen.getByTestId("workspace").inert).toBe(true);
  await user.click(trigger);
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByTestId("workspace").inert).toBe(false);
  expect(document.activeElement).toBe(trigger);
  await user.click(trigger); await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull(); expect(document.activeElement).toBe(trigger);
});
