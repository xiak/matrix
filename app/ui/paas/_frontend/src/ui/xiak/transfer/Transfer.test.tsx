import { useState, type ComponentProps } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { Transfer } from "../index";

afterEach(cleanup);

const labels = { available: "Available", selected: "Selected", onlySelected: "Selected only", selectedName: "Name", search: "Search", searchSelected: "Search selected", clearSearch: "Reset search", clearSelected: "Clear all", empty: "No selection", noResults: "No results", previous: "Previous page", next: "Next page", page: (page: number, pages: number) => `${page} / ${pages}`, selectPage: "Select this page", clearPage: "Clear this page", pageSelection: (selected: number, total: number) => `${selected} of ${total} on this page`, limit: (remaining: number, needed: number) => `Space for ${remaining}; ${needed} unselected` };

const sample = [{ id: "a", label: "Alpha", description: "Read resources" }, { id: "b", label: "Beta" }, { id: "c", label: "Gamma" }, { id: "d", label: "Delta" }];
function Example({ options = sample, initial = [], capacity = Infinity, onBatch, pageSize, filterKey }: Partial<Pick<ComponentProps<typeof Transfer>, "options" | "pageSize" | "filterKey">> & { initial?: string[]; capacity?: number; onBatch?: ComponentProps<typeof Transfer>["onSelect"] }) {
  const [ids, setIds] = useState(initial);
  return <Transfer options={options} pageSize={pageSize} filterKey={filterKey} remaining={capacity - ids.length} selected={options.filter((item) => ids.includes(item.id))} onSelect={(batch, checked) => { onBatch?.(batch, checked); setIds(checked ? [...new Set([...ids, ...batch])] : ids.filter((id) => !batch.includes(id))); }} onClear={() => setIds([])} labels={labels} />;
}

const scope = () => screen.getByRole("button", { name: labels.onlySelected });
const row = (name: string) => screen.getByRole("checkbox", { name });

it("shows a checked item once, reviews all choices in the same table and restores the candidate query", async () => {
  const user = userEvent.setup();
  render(<Example options={sample.slice(0, 2)} />);
  expect(scope()).toHaveProperty("disabled", true);
  await user.click(screen.getByText("Alpha"));
  expect(row("Alpha")).toHaveProperty("checked", true);
  expect(screen.getAllByText("Alpha")).toHaveLength(1);
  expect(scope().textContent).toContain("1");
  await user.type(screen.getByRole("searchbox"), "Beta");
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
  await user.click(row("Beta"));
  await user.click(scope());
  expect(scope().getAttribute("aria-pressed")).toBe("true");
  expect(screen.getAllByRole("table")).toHaveLength(1);
  expect(screen.getByRole("searchbox", { name: labels.searchSelected })).toHaveProperty("value", "");
  await user.click(row("Alpha"));
  expect(row("Beta")).toBe(document.activeElement);
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
  await user.type(screen.getByRole("searchbox"), "nothing");
  await user.click(screen.getByRole("button", { name: labels.clearSelected }));
  expect(screen.getByText(labels.empty)).toBeTruthy();
  expect(scope()).toBe(document.activeElement);
  await user.click(scope());
  const search = screen.getByRole("searchbox", { name: labels.search });
  expect(search).toHaveProperty("value", "Beta");
  expect(row("Beta")).toHaveProperty("checked", false);
  await user.clear(search);
  await user.paste("ＡＬＰＨＡ resources");
  expect(row("Alpha")).toBeTruthy();
  expect(screen.queryByRole("checkbox", { name: "Beta" })).toBeNull();
});

it("bounds both views and restores page two after reviewing items outside the current candidates", async () => {
  const options = Array.from({ length: 2500 }, (_, id) => ({ id: String(id), label: `Policy ${id}` }));
  const selected = [options[0]!, options[2499]!];
  const user = userEvent.setup(), onSelect = vi.fn();
  const props = { selected, onSelect, onClear: vi.fn(), labels };
  const { rerender } = render(<Transfer {...props} options={options} />);
  expect(screen.getAllByRole("checkbox")).toHaveLength(21);
  expect(screen.getByText("1 / 125")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.next }));
  await user.click(row("Policy 20"));
  expect(onSelect).toHaveBeenCalledWith(["20"], true);
  await user.click(scope());
  expect(row("Policy 0")).toHaveProperty("checked", true);
  expect(row("Policy 2499")).toHaveProperty("checked", true);
  await user.click(scope());
  expect(screen.getByText("2 / 125")).toBeTruthy();
  await user.click(screen.getByRole("searchbox"));
  await user.paste("Policy 2499");
  expect(screen.getAllByRole("checkbox")).toHaveLength(2);
  expect(row("Policy 2499")).toHaveProperty("checked", true);
  await user.click(screen.getByRole("button", { name: labels.clearSearch }));
  expect(screen.getByText("1 / 125")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.next }));
  rerender(<Transfer {...props} options={options.slice(0, 3)} />);
  expect(screen.getAllByRole("checkbox")).toHaveLength(4);
  expect(screen.queryByRole("button", { name: labels.next })).toBeNull();
  await user.click(scope());
  expect(row("Policy 2499")).toHaveProperty("checked", true);
});

it("selects a page atomically, exposes mixed state, and clears only that page", async () => {
  const user = userEvent.setup(), onBatch = vi.fn();
  render(<Example initial={["a", "c"]} pageSize={2} onBatch={onBatch} />);
  const header = row(labels.selectPage);
  expect(header).toHaveProperty("indeterminate", true);
  expect(header.getAttribute("aria-checked")).toBe("mixed");
  header.focus();
  await user.keyboard("[Space]");
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["b"], true);
  expect(header).toHaveProperty("checked", true);
  expect(scope().textContent).toContain("3");
  await user.click(screen.getByRole("button", { name: labels.next }));
  expect(row("Gamma")).toHaveProperty("checked", true);
  expect(row("Delta")).toHaveProperty("checked", false);
  await user.click(screen.getByRole("button", { name: labels.clearPage }));
  expect(onBatch).toHaveBeenLastCalledWith(["c"], false);
  await user.click(scope());
  expect(row("Alpha")).toHaveProperty("checked", true);
  expect(row("Beta")).toHaveProperty("checked", true);
  expect(screen.queryByRole("checkbox", { name: "Gamma" })).toBeNull();
  await user.click(scope());
  await user.click(screen.getByRole("button", { name: labels.previous }));
  await user.click(row(labels.clearPage));
  expect(onBatch).toHaveBeenLastCalledWith(["a", "b"], false);
  expect(scope()).toHaveProperty("disabled", true);
});

it("paginates and searches the selected collection independently and repairs focus after removing its last row", async () => {
  const user = userEvent.setup(), onBatch = vi.fn();
  render(<Example initial={["a", "b", "c"]} pageSize={2} onBatch={onBatch} />);
  await user.click(scope());
  await user.click(screen.getByRole("button", { name: labels.next }));
  await user.click(row("Gamma"));
  expect(onBatch).toHaveBeenLastCalledWith(["c"], false);
  expect(row("Alpha")).toBe(document.activeElement);
  await user.type(screen.getByRole("searchbox"), "Alpha");
  await user.click(row(labels.clearPage));
  expect(onBatch).toHaveBeenLastCalledWith(["a"], false);
  expect(screen.getByText(labels.noResults)).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.clearSearch }));
  await user.click(row("Beta"));
  expect(scope()).toBe(document.activeElement);
  expect(screen.getByText(labels.empty)).toBeTruthy();
  await user.click(scope());
  expect(screen.getByText("1 / 2")).toBeTruthy();
});

it("does not partially select an over-capacity page and still permits deselection at the limit", async () => {
  const user = userEvent.setup(), onBatch = vi.fn();
  render(<Example initial={["d"]} pageSize={3} capacity={3} onBatch={onBatch} />);
  const header = row(labels.selectPage);
  expect(header).toHaveProperty("disabled", true);
  expect(document.getElementById(header.getAttribute("aria-describedby")!)?.textContent).toBe("Space for 2; 3 unselected");
  await user.click(header);
  expect(onBatch).not.toHaveBeenCalled();
  await user.click(row("Alpha"));
  await user.click(row("Beta"));
  expect(row("Gamma")).toHaveProperty("disabled", true);
  expect(row("Alpha")).toHaveProperty("disabled", false);
  expect(header).toHaveProperty("indeterminate", true);
  expect(screen.getByText("Space for 0; 1 unselected")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: labels.clearPage }));
  expect(row("Gamma")).toHaveProperty("disabled", false);
  await user.click(scope());
  expect(row("Delta")).toHaveProperty("checked", true);
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
});

it("excludes unavailable rows from bulk selection and keeps review available for empty search results", async () => {
  const user = userEvent.setup(), onBatch = vi.fn();
  render(<Example options={[sample[0]!, { ...sample[1]!, disabled: true }]} onBatch={onBatch} />);
  await user.click(row(labels.selectPage));
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["a"], true);
  expect(row("Beta")).toHaveProperty("disabled", true);
  await user.type(screen.getByRole("searchbox"), "no-match");
  expect(row(labels.selectPage)).toHaveProperty("disabled", true);
  await user.click(scope());
  expect(within(screen.getByRole("table", { name: labels.selected })).getByRole("checkbox", { name: "Alpha" })).toHaveProperty("checked", true);
});

it("resets the page on a source filter change without losing the query or selections", async () => {
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
  expect(row("Alpha")).toHaveProperty("checked", true);
});

it("searches metadata and IDs and limits bulk changes to filtered items", async () => {
  const user = userEvent.setup(), onBatch = vi.fn();
  render(<Example options={[...sample, { id: "policy-ops", label: "Operator", keywords: "environment production" }]} initial={["a"]} onBatch={onBatch} />);
  await user.type(screen.getByRole("searchbox"), "ＰＲＯＤＵＣＴＩＯＮ ops");
  expect(row("Operator")).toBeTruthy();
  expect(screen.queryByRole("checkbox", { name: "Alpha" })).toBeNull();
  await user.click(row(labels.selectPage));
  expect(onBatch).toHaveBeenCalledExactlyOnceWith(["policy-ops"], true);
  await user.click(row(labels.clearPage));
  expect(onBatch).toHaveBeenLastCalledWith(["policy-ops"], false);
  await user.click(scope());
  expect(row("Alpha")).toHaveProperty("checked", true);
});
