import { cleanup, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, expect, it, vi } from "vitest";
import messages from "@/i18n/messages/en.json";
import { validators } from "@/api/paasContract";
import { matchesContract } from "@/api/validation";
import { ResourceIdentityFields } from "./ResourceIdentityFields";

afterEach(cleanup);
it("uses HTML v-flag patterns consistent with the public resource identity contract", () => {
  render(<NextIntlClientProvider locale="en" messages={messages}><ResourceIdentityFields id="" name="" onId={vi.fn()} onName={vi.fn()} /></NextIntlClientProvider>);
  const id = screen.getByRole("textbox", { name: messages.Collection.id }) as HTMLInputElement;
  const name = screen.getByRole("textbox", { name: messages.Collection.name }) as HTMLInputElement;
  const idPattern = new RegExp(`^(?:${id.pattern})$`, "v");
  const namePattern = new RegExp(`^(?:${name.pattern})$`, "v");
  for (const value of ["App:Prod_01.2-a", "resource-1", "a".repeat(128), "../other", "a/b", "a%2fb", "a".repeat(129)]) {
    expect(idPattern.test(value)).toBe(matchesContract(validators, "CreateApplicationRequest", { id: value, name: "valid-name" }));
  }
  for (const value of ["app", "app-1", "a".repeat(63), "Mixed Name", "-start", "end-", "a".repeat(64)]) {
    expect(namePattern.test(value)).toBe(matchesContract(validators, "CreateApplicationRequest", { id: "resource", name: value }));
  }
  expect(name.maxLength).toBe(63);
  expect(name.getAttribute("aria-describedby")).toBeTruthy();
});
