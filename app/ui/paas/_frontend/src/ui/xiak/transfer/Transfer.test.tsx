import { useState, type ComponentProps } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { Transfer } from "../index";

afterEach(cleanup);

const labels = { available: "Available", selected: "Selected", search: "Search", clearSearch: "Reset search", clearSelected: "Clear all", empty: "No selection", emptyHint: "Choose an item", noResults: "No results", remove: (name: string) => `Remove ${name}`, previous: "Previous page", next: "Next page", page: (page: number, pages: number) => `${page} / ${pages}`, selectPage: "Select this page", clearPage: "Clear this page", pageSelection: (selected: number, total: number) => `${selected} of ${total} on this page`, limit: (remaining: number, needed: number) => `Space for ${remaining}; ${needed} unselected` };

const sample = [{ id: "a", label: "Alpha", description: "Read resources" }, { id: "b", label: "Beta" }, { id: "c", label: "Gamma" }, { id: "d", label: "Delta" }];
function Example({ options = sample, initial = [], capacity = Infinity, onBatch, pageSize, filterKey }: Pick<ComponentProps<typeof Transfer>, "options" | "pageSize" | "filterKey"> & { initial?: string[]; capacity?: number; onBatch?: ComponentProps<typeof Transfer>["onSelect"] }) {
  const [ids, setIds] = useState(initial);
  return <Transfer options={options} pageSize={pageSize} filterKey={filterKey} remaining={capacity - ids.length} selected={options.filter((item) => ids.includes(item.id))} onSelect={(batch, checked) => { onBatch?.(batch, checked); setIds(checked ? [...new Set([...ids, ...batch])] : ids.filter((id) => !batch.includes(id))); }} onRemove={(id) => setIds(ids.filter((item) => item !== id))} onClear={() => setIds([])} labels={labels} />;
}

it("keeps selections across searches and supports removing and clearing them", async () => {
  const user = userEvent.setup();
  render(<Example options={sample.slice(0, 2)} />);
  await user.click(screen.getByText("Alpha", { exact: true }));
  expect(screen.getByRole("checkbox", { name: "Alpha" })).toHaveProperty("checked", true);
  await user.type(screen.getByRole("searchbox"), "Beta");
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
  expect(within(screen.getByRole("region", { name: "Selected" })).getByText("Alpha")).toBeTruthy();
  await user.click(screen.getByRole("checkbox", { name: "Beta" }));
  await user.click(screen.getByRole("button", { name: "Remove Alpha" }));
  expect(within(screen.getByRole("region", { name: "Selected" })).queryByText("Alpha")).toBeNull();
  await user.click(screen.getByRole("button", { name: "Clear all" }));
  expect(screen.getByText("No selection")).toBeTruthy();
  await user.clear(screen.getByRole("searchbox"));
  await user.type(screen.getByRole("searchbox"), "ＡＬＰＨＡ resources");
  expect(screen.getByRole("checkbox", { name: "Alpha" })).toBeTruthy();
  expect(screen.queryByRole("checkbox", { name: "Beta" })).toBeNull();
});

it("bounds large available lists while searching all options and retaining off-page selections", async () => {
  const options = Array.from({ length: 2500 }, (_, id) => ({ id: String(id), label: `Policy ${id}` }));
  const selected = [options[0]!, options[2499]!];
  const onSelect = vi.fn();
  const user = userEvent.setup();
  const props = { selected, onSelect, onRemove: vi.fn(), onClear: vi.fn(), labels };
  const { rerender } = render(<Transfer {...props} options={options} />);
  expect(screen.getAllByRole("checkbox")).toHaveLength(21);
  expect(screen.getByRole("status").textContent).toBe("1 / 125");
  await user.click(screen.getByRole("button", { name: labels.next }));
  expect(screen.getByRole("checkbox", { name: "Policy 20" })).toBeTruthy();
  await user.click(screen.getByRole("checkbox", { name: "Policy 20" }));
  expect(onSelect).toHaveBeenCalledWith(["20"], true);
  expect(within(screen.getByRole("region", { name: "Selected" })).getByText("Policy 0")).toBeTruthy();
  await user.type(screen.getByRole("searchbox"), "Policy 2499");
  expect(screen.getAllByRole("checkbox")).toHaveLength(2);
  expect((screen.getByRole("checkbox", { name: "Policy 2499" }) as HTMLInputElement).checked).toBe(true);
  await user.click(screen.getByRole("button", { name: labels.clearSearch }));
  expect(screen.getByRole("status").textContent).toBe("1 / 125");
  await user.click(screen.getByRole("button", { name: labels.next }));
  rerender(<Transfer {...props} options={options.slice(0, 3)} />);
  expect(screen.getAllByRole("checkbox")).toHaveLength(4);
  expect(screen.queryByRole("button", { name: labels.next })).toBeNull();
});

it("selects a page in one update, exposes mixed state, and clears only the current page", async () => {
  const user = userEvent.setup();
  const onBatch = vi.fn();
  render(<Example options={sample} initial={["a", "c"]} pageSize={2} onBatch={onBatch} />);
  const header = screen.getByRole("checkbox", { name: labels.selectPage });
  expect(header).toHaveProperty("indeterminate", true);
  expect(header.getAttribute("aria-checked")).toBe("mixed");
  header.focus();
  await user.keyboard("[Space]");
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["b"], true);
  expect(header).toHaveProperty("checked", true);
  expect(header).toHaveProperty("indeterminate", false);
  expect(screen.getByRole("button", { name: "Remove Gamma" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.next }));
  expect(screen.getByRole("checkbox", { name: "Gamma" })).toHaveProperty("checked", true);
  expect(screen.getByRole("checkbox", { name: "Delta" })).toHaveProperty("checked", false);
  await user.click(screen.getByRole("button", { name: labels.clearPage }));
  expect(onBatch).toHaveBeenLastCalledWith(["c"], false);
  expect(screen.getByRole("button", { name: "Remove Alpha" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Remove Beta" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Remove Gamma" })).toBeNull();
  await user.click(screen.getByRole("button", { name: labels.previous }));
  await user.click(screen.getByRole("checkbox", { name: labels.selectPage }));
  expect(onBatch).toHaveBeenLastCalledWith(["a", "b"], false);
  expect(screen.getByText("No selection")).toBeTruthy();
});

it("does not partially select an over-capacity page and still permits deselection at the limit", async () => {
  const user = userEvent.setup();
  const onBatch = vi.fn();
  render(<Example options={sample} initial={["d"]} pageSize={3} capacity={3} onBatch={onBatch} />);
  expect(screen.getByRole("checkbox", { name: labels.selectPage })).toHaveProperty("disabled", true);
  expect(screen.getByText("Space for 2; 3 unselected")).toBeTruthy();
  expect(document.getElementById(screen.getByRole("checkbox", { name: labels.selectPage }).getAttribute("aria-describedby")!)?.textContent).toBe("Space for 2; 3 unselected");
  await user.click(screen.getByRole("checkbox", { name: labels.selectPage }));
  expect(onBatch).not.toHaveBeenCalled();
  await user.click(screen.getByRole("checkbox", { name: "Alpha" }));
  await user.click(screen.getByRole("checkbox", { name: "Beta" }));
  expect(screen.getByRole("checkbox", { name: "Gamma" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("checkbox", { name: "Alpha" })).toHaveProperty("disabled", false);
  expect(screen.getByRole("checkbox", { name: labels.selectPage })).toHaveProperty("indeterminate", true);
  expect(screen.getByText("Space for 0; 1 unselected")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.clearPage }));
  expect(screen.getByRole("button", { name: "Remove Delta" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Remove Alpha" })).toBeNull();
  expect(screen.getByRole("checkbox", { name: "Gamma" })).toHaveProperty("disabled", false);
});

it("excludes unavailable rows from bulk selection and disables the empty-result header", async () => {
  const user = userEvent.setup();
  const onBatch = vi.fn();
  render(<Example options={[sample[0]!, { ...sample[1]!, disabled: true }]} onBatch={onBatch} />);
  await user.click(screen.getByRole("checkbox", { name: labels.selectPage }));
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["a"], true);
  expect(screen.getByText("1 of 1 on this page")).toBeTruthy();
  await user.type(screen.getByRole("searchbox"), "no-match");
  expect(screen.getByRole("checkbox", { name: labels.selectPage })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: labels.clearPage })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Remove Alpha" })).toBeTruthy();
});

it("resets the page on every source filter change without losing the query or selections", async () => {
  const options = sample.map((option) => ({ ...option, description: "Policy" }));
  const user = userEvent.setup();
  const { rerender } = render(<Example options={options} initial={["a"]} pageSize={2} filterKey="all" />);
  await user.type(screen.getByRole("searchbox"), "Policy");
  await user.click(screen.getByRole("button", { name: labels.next }));
  expect(screen.getByText("2 / 2")).toBeTruthy();
  rerender(<Example options={options} initial={["a"]} pageSize={2} filterKey="system" />);
  expect(screen.getByText("1 / 2")).toBeTruthy();
  rerender(<Example options={options} initial={["a"]} pageSize={2} filterKey="all" />);
  expect(screen.getByText("1 / 2")).toBeTruthy();
  expect(screen.getByRole("searchbox")).toHaveProperty("value", "Policy");
  expect(screen.getByRole("checkbox", { name: "Alpha" })).toHaveProperty("checked", true);
});

it("searches metadata and IDs, and limits bulk changes to the filtered result", async () => {
  const user = userEvent.setup();
  const onBatch = vi.fn();
  render(<Example options={[...sample, { id: "policy-ops", label: "Operator", keywords: "environment production" }]} initial={["a"]} onBatch={onBatch} />);
  await user.type(screen.getByRole("searchbox"), "ＰＲＯＤＵＣＴＩＯＮ ops");
  expect(screen.getByRole("checkbox", { name: "Operator" })).toBeTruthy();
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
  await user.click(screen.getByRole("checkbox", { name: labels.selectPage }));
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["policy-ops"], true);
  await user.click(screen.getByRole("button", { name: labels.clearPage }));
  expect(screen.getByRole("button", { name: "Remove Alpha" })).toBeTruthy();
});
