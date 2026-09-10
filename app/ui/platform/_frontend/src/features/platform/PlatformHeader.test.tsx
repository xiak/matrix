import { useRef } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, expect, it, vi } from "vitest";
import en from "@/i18n/messages/en.json";
import zh from "@/i18n/messages/zh-CN.json";
import { createApiSession } from "@/api/client";
import { UnsavedChangesProvider } from "@ui/xiak";
import { SessionProvider } from "../auth/SessionProvider";
import { ProductProvider } from "./ProductProvider";
import { PlatformHeader } from "./PlatformHeader";

vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ push: vi.fn() }) }));
afterEach(cleanup);

function Header() {
  const background = useRef<HTMLElement>(null);
  return <><PlatformHeader backgroundRef={background} /><main ref={background}>Workspace</main></>;
}

async function renderHeader(locale: "en" | "zh-CN", messages: typeof en | typeof zh, withDevops = true) {
  const now = new Date().toISOString();
  const api = createApiSession(async url => new Response(JSON.stringify(String(url).endsWith("/login") ? {
    credential: "mx1.TestOnlyCredentialNotARealSecret00000000001",
    session: { apiVersion: "iam.matrix.xiak.com/v1", kind: "Session", id: "session-a", organizationId: "organization-a", principalId: "principal-a", status: "ACTIVE", issuedAt: now, expiresAt: new Date(Date.now() + 60000).toISOString() },
  } : {
    apiVersion: "installation.matrix.xiak.com/v1", kind: "InstalledProductList", releaseVersion: "v0.3.0", releaseId: "matrix-v0.3.0-0123456789ab", observedAt: now,
    products: withDevops ? [{ id: "DEVOPS", routeKey: "devops", version: "v0.3.0", state: "READY", observedAt: now }] : [],
  }), { headers: { "Content-Type": "application/json" } }));
  await api.login("admin", "test-only");
  render(<NextIntlClientProvider locale={locale} messages={messages}><UnsavedChangesProvider><SessionProvider client={api}><ProductProvider><Header /></ProductProvider></SessionProvider></UnsavedChangesProvider></NextIntlClientProvider>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: messages.Platform.products }));
  await screen.findByRole("link", { name: messages.Platform.account });
  return { user, dialog: within(screen.getByRole("dialog")), input: screen.getByRole("searchbox") };
}

for (const [locale, messages] of [["en", en], ["zh-CN", zh]] as const) {
  it(`${locale}: uses the same case-insensitive, trimmed query for account and installed products`, async () => {
    const { user, dialog, input } = await renderHeader(locale, messages);
    await user.type(input, `  ${messages.Platform.account.toUpperCase()}  `);
    expect(dialog.getByRole("link", { name: messages.Platform.account })).toBeTruthy();
    expect(dialog.queryByRole("link", { name: messages.Platform.productNames.DEVOPS })).toBeNull();
    expect(dialog.queryByText(messages.Platform.noMatches)).toBeNull();
    await user.clear(input);
    await user.type(input, `  ${messages.Platform.productNames.DEVOPS.toUpperCase()}  `);
    expect(dialog.getByRole("link", { name: messages.Platform.productNames.DEVOPS })).toBeTruthy();
    expect(dialog.queryByRole("link", { name: messages.Platform.account })).toBeNull();
    await user.clear(input);
    await user.type(input, "   ");
    expect(dialog.getByRole("link", { name: messages.Platform.account })).toBeTruthy();
    expect(dialog.getByRole("link", { name: messages.Platform.productNames.DEVOPS })).toBeTruthy();
  });

  it(`${locale}: matches visible category labels without claiming an empty result`, async () => {
    const { user, dialog, input } = await renderHeader(locale, messages);
    await user.type(input, ` ${messages.Platform.identity.toUpperCase()} `);
    expect(dialog.getByRole("link", { name: messages.Platform.account })).toBeTruthy();
    expect(dialog.queryByText(messages.Platform.noMatches)).toBeNull();
    await user.clear(input);
    await user.type(input, messages.Platform.categories.DEVOPS.toUpperCase());
    expect(dialog.getByRole("link", { name: messages.Platform.productNames.DEVOPS })).toBeTruthy();
  });

  it(`${locale}: clears an empty-result query in place and restores input focus`, async () => {
    const { user, dialog, input } = await renderHeader(locale, messages);
    await user.type(input, "no-such-product");
    expect(dialog.getByText(messages.Platform.noMatches)).toBeTruthy();
    expect(dialog.getAllByRole("searchbox")).toHaveLength(1);
    await user.click(dialog.getByRole("button", { name: messages.Platform.clearSearch }));
    expect((input as HTMLInputElement).value).toBe("");
    expect(document.activeElement).toBe(input);
    expect(dialog.queryByText(messages.Platform.noMatches)).toBeNull();
    expect(dialog.getByRole("link", { name: messages.Platform.account })).toBeTruthy();
    expect(dialog.getByRole("link", { name: messages.Platform.productNames.DEVOPS })).toBeTruthy();
    expect(dialog.queryByRole("button", { name: messages.Platform.clearSearch })).toBeNull();
  });
}

it("does not turn searchable compiled metadata into an installed product", async () => {
  const { user, dialog, input } = await renderHeader("en", en, false);
  await user.type(input, "DEVOPS");
  expect(dialog.queryByRole("link", { name: en.Platform.productNames.DEVOPS })).toBeNull();
  expect(dialog.getByText(en.Platform.noMatches)).toBeTruthy();
});
