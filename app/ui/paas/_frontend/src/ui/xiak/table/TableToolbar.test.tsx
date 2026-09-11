import { useState } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { TableToolbar, type TableToolbarLabels } from "./TableToolbar";

afterEach(cleanup);
const labels: TableToolbarLabels = { filters: "Filters", clearSearch: "Clear search", clearFilters: "Clear filters", removeFilter: (label) => "Remove " + label };
function Collection() {
  const [query, setQuery] = useState("");
  const [state, setState] = useState("all");
  const [type, setType] = useState("all");
  return <TableToolbar labels={labels} search={{ label: "Search users", value: query, onChange: setQuery }} filters={[
    { id: "state", label: "State", value: state, onChange: setState, options: [{ value: "all", label: "All states" }, { value: "active", label: "Active" }] },
    { id: "type", label: "Type", value: type, onChange: setType, options: [{ value: "all", label: "All types" }, { value: "subuser", label: "Subuser" }] }
  ]} status={`${state}/${type}/${query}`} />;
}

describe("TableToolbar collection search", () => {
  it("discloses structured filters and keeps removable criteria visible when collapsed", async () => {
    const user = userEvent.setup();
    render(<Collection />);
    expect(screen.getAllByRole("searchbox")).toHaveLength(1);
    expect(screen.queryByRole("combobox")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Filters" }));
    await user.click(screen.getByRole("combobox", { name: "State" }));
    await user.click(screen.getByRole("option", { name: "Active" }));
    await user.click(screen.getByRole("button", { name: "Filters 1" }));
    expect(screen.queryByRole("combobox")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Remove State: Active" }));
    expect(screen.getByRole("status").textContent).toBe("all/all/");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Filters" }));
  });

  it("resets structured conditions together without clearing the independent keyword", async () => {
    const user = userEvent.setup();
    render(<Collection />);
    await user.type(screen.getByRole("searchbox"), "lin");
    await user.click(screen.getByRole("button", { name: "Filters" }));
    for (const [name, value] of [["State", "Active"], ["Type", "Subuser"]]) {
      await user.click(screen.getByRole("combobox", { name }));
      await user.click(screen.getByRole("option", { name: value }));
    }
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByRole("status").textContent).toBe("all/all/lin");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Filters" }));
    expect(screen.getByRole("button", { name: "Filters" }).getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("group", { name: "Filters" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect(screen.getByRole("status").textContent).toBe("all/all/");
  });

  it("uses Escape for the nested select first, then closes filters and restores trigger focus", async () => {
    const user = userEvent.setup();
    render(<Collection />);
    await user.click(screen.getByRole("button", { name: "Filters" }));
    await user.click(screen.getByRole("combobox", { name: "State" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(screen.getByRole("group", { name: "Filters" })).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("group", { name: "Filters" })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Filters" }));
  });
});
