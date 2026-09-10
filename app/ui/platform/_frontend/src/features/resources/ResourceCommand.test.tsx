import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, expect, it, vi } from "vitest";
import messages from "@/i18n/messages/en.json";
import { UnsavedChangesProvider } from "@ui/xiak";
import { ResourceCommand } from "./ResourceCommand";

afterEach(cleanup);
it("opens immediately, then blocks duplicate submissions and dismissal while pending", async () => {
  const user = userEvent.setup();
  let finish!: () => void;
  const command = vi.fn(() => new Promise<void>(resolve => { finish = resolve; }));
  render(<NextIntlClientProvider locale="en" messages={messages}><UnsavedChangesProvider><ResourceCommand label="Stop deployment" disabled={false} run={command} /></UnsavedChangesProvider></NextIntlClientProvider>);
  await user.click(screen.getByRole("button", { name: "Stop deployment" }));
  const dialog = screen.getByRole("dialog");
  expect(command).not.toHaveBeenCalled();
  await user.dblClick(within(dialog).getByRole("button", { name: "Stop deployment" }));
  expect(command).toHaveBeenCalledTimes(1);
  expect(within(dialog).getByRole("status")).toBeTruthy();
  fireEvent(dialog, new Event("cancel", { cancelable: true }));
  expect(dialog.hasAttribute("open")).toBe(true);
  finish();
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});
