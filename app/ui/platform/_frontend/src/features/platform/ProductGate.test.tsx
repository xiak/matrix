import { cleanup, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, expect, it } from "vitest";
import messages from "@/i18n/messages/en.json";
import { createApiSession } from "@/api/client";
import { SessionProvider } from "../auth/SessionProvider";
import { ProductProvider, useProduct } from "./ProductProvider";
import { ProductGate } from "./ProductGate";
function json(value: unknown) { return new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json" } }); }
afterEach(cleanup);
function Mutation() { const product = useProduct("DEVOPS"); return <button disabled={!product.canMutate}>Create pipeline</button>; }
async function client(products: unknown[]) {
  const now = new Date().toISOString();
  const api = createApiSession(async url => String(url).endsWith("/login") ? json({ credential: "mx1.TestOnlyCredentialNotARealSecret00000000001", session: { apiVersion: "iam.matrix.xiak.com/v1", kind: "Session", id: "session-a", organizationId: "organization-a", principalId: "principal-a", status: "ACTIVE", issuedAt: now, expiresAt: new Date(Date.now() + 60000).toISOString() } }) : json({ apiVersion: "installation.matrix.xiak.com/v1", kind: "InstalledProductList", releaseVersion: "v0.3.0", releaseId: "matrix-v0.3.0-0123456789ab", observedAt: now, products }));
  await api.login("admin", "test-only"); return api;
}
it("does not reveal a compiled but uninstalled DevOps deep link", async () => {
  const api = await client([{ id: "APPLICATION_PAAS", routeKey: "paas", version: "v0.3.0", state: "READY", observedAt: new Date().toISOString() }]);
  render(<NextIntlClientProvider locale="en" messages={messages}><SessionProvider client={api}><ProductProvider><ProductGate id="DEVOPS"><Mutation /></ProductGate></ProductProvider></SessionProvider></NextIntlClientProvider>);
  await screen.findByText(messages.Platform.emptyProducts);
  expect(screen.queryByRole("button", { name: "Create pipeline" })).toBeNull();
});
it("keeps an installed unavailable product read-only", async () => {
  const api = await client([{ id: "DEVOPS", routeKey: "devops", version: "v0.3.0", state: "UNAVAILABLE", reason: "DEPENDENCY_UNAVAILABLE", observedAt: new Date().toISOString() }]);
  render(<NextIntlClientProvider locale="en" messages={messages}><SessionProvider client={api}><ProductProvider><ProductGate id="DEVOPS"><Mutation /></ProductGate></ProductProvider></SessionProvider></NextIntlClientProvider>);
  expect((await screen.findByRole("button", { name: "Create pipeline" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(messages.Platform.readOnly)).toBeTruthy();
});
