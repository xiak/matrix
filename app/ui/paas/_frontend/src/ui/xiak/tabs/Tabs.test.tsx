import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Tabs } from "./Tabs";

describe("static tab panel contract", () => {
  it("renders accessible server-side panels without CSP-blocked inline styles", () => {
    const html = renderToStaticMarkup(<Tabs.Root defaultValue="account">
      <Tabs.List aria-label="Sign-in method"><Tabs.Trigger value="account">Account</Tabs.Trigger></Tabs.List>
      <Tabs.Content value="account"><form id="login-form"><input aria-label="Username" /></form></Tabs.Content>
    </Tabs.Root>);
    expect(html).toContain('role="tabpanel"');
    expect(html).toContain('aria-labelledby=');
    expect(html).toContain('id="login-form"');
    expect(html).not.toMatch(/\sstyle=/);
  });
});
