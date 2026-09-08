import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import type { GlobalSearchResultScene } from "../scenes/consoleScene";
import { ProductLauncher } from "./ProductLauncher";

const products: GlobalSearchResultScene[] = [{
  id: "foundation",
  label: "云基础平台",
  description: "区域、计算、网络与存储",
  href: "/console/regions/",
  category: "产品",
  icon: "foundation"
}];

function ProductLauncherHarness() {
  const [open, setOpen] = useState(false);
  return <ProductLauncher onOpenChange={setOpen} open={open} products={products} />;
}

afterEach(cleanup);

describe("ProductLauncher", () => {
  it("keeps its compact trigger named and restores focus after keyboard dismissal", async () => {
    const user = userEvent.setup();
    render(<ProductLauncherHarness />);
    const trigger = screen.getByRole("button", { name: "打开产品与服务" });

    await user.click(trigger);
    expect(trigger.getAttribute("aria-controls")).toBe("global-product-launcher");
    expect(screen.getByRole("dialog", { name: "云产品入口" })).toBeTruthy();
    const firstProduct = screen.getByRole("link", { name: /云基础平台/ });
    expect(document.activeElement).toBe(firstProduct);

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "云产品入口" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(screen.getByRole("button", { name: "打开产品与服务" })).toBe(trigger);
  });
});
