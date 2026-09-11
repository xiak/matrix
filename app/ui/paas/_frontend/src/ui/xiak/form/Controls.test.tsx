import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Alert, Badge, Button, Checkbox, Dialog, FormField, Input, RadioGroup, SearchInput, Select, Table, TablePagination, TableActions, TableSelectionCell, TagEditor } from "../index";

afterEach(cleanup);
describe("shared themed controls", () => {
  it("keeps table selection mixed state keyboard-operable without making the row itself an action", async () => {
    const user = userEvent.setup(), select = vi.fn();
    render(<Table aria-label="Users"><thead><tr><TableSelectionCell header label="Select this page" checked="mixed" onChange={select} /><th>Name</th></tr></thead><tbody><tr><td /><td>admin</td></tr></tbody></Table>);
    const checkbox = screen.getByRole("checkbox", { name: "Select this page" }) as HTMLInputElement;
    expect(checkbox.indeterminate).toBe(true);
    expect(checkbox.getAttribute("aria-checked")).toBe("mixed");
    checkbox.focus();
    await user.keyboard(" ");
    expect(select).toHaveBeenCalledWith(true);
  });
  it("pages a controlled collection and preserves the caller's size change contract", async () => {
    const user = userEvent.setup(), size = vi.fn();
    function Pages() {
      const [page, setPage] = useState(1);
      return <TablePagination page={page} pages={2} pageSize={10} onPageChange={setPage} onPageSizeChange={size} labels={{ summary: `Page ${page} of 2`, pageSize: "Page size", previous: "Previous page", next: "Next page" }} />;
    }
    render(<Pages />);
    expect((screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByRole("status").textContent).toBe("Page 2 of 2");
    expect((screen.getByRole("button", { name: "Next page" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("combobox", { name: "Page size" }));
    await user.click(screen.getByRole("option", { name: "20" }));
    expect(size).toHaveBeenCalledWith(20);
  });
  it("returns focus to a stable table command after its menu opens a dialog", async () => {
    const user = userEvent.setup();
    function Commands() {
      const [open, setOpen] = useState(false);
      return <><TableActions label="More actions" hint="Select a row" clearLabel="Clear" onClear={() => {}} actions={[{ id: "review", label: "Review access", onSelect: () => setOpen(true) }]} />
        <Dialog open={open} title="Review" closeLabel="Close review" onClose={() => setOpen(false)}>Selected policy</Dialog></>;
    }
    render(<Commands />);
    const trigger = screen.getByRole("button", { name: "More actions" });
    expect(trigger.getAttribute("title")).toBeNull();
    await user.click(trigger);
    await user.click(screen.getByRole("menuitem", { name: "Review access" }));
    expect(screen.getByRole("dialog", { name: "Review" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Close review" }));
    expect(document.activeElement).toBe(trigger);
  });
  it("distinguishes descriptive badges from actual state without dropping their text", () => {
    render(<><Badge>Custom policy</Badge><Badge status="warning">Needs review</Badge></>);
    expect(screen.getByText("Custom policy").hasAttribute("data-status")).toBe(false);
    expect(screen.getByText("Needs review").getAttribute("data-status")).toBe("warning");
  });
  it("edits bounded metadata tags without losing other rows and exposes validation", async () => {
    const user = userEvent.setup();
    function Tags() {
      const [tags, setTags] = useState([{ key: "team", value: "platform" }]);
      const invalid = tags.some((tag) => !tag.key.trim());
      return <TagEditor value={tags} onChange={setTags} limit={2} error={invalid ? "Enter a key" : undefined} labels={{
        key: (index) => "Key " + index, value: (index) => "Value " + index, remove: (index) => "Remove " + index,
        add: "Add tag", empty: "No tags", count: tags.length + "/2"
      }} />;
    }
    render(<Tags />);
    await user.click(screen.getByRole("button", { name: "Add tag" }));
    expect(screen.getByRole("button", { name: "Add tag" }).hasAttribute("disabled")).toBe(true);
    const key = screen.getByLabelText("Key 2");
    expect(key.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(key.getAttribute("aria-describedby")!)?.textContent).toBe("Enter a key");
    await user.type(key, "environment");
    await user.type(screen.getByLabelText("Value 2"), "staging");
    expect(screen.queryByRole("alert")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Remove 1" }));
    expect((screen.getByLabelText("Key 1") as HTMLInputElement).value).toBe("environment");
    expect((screen.getByLabelText("Value 1") as HTMLInputElement).value).toBe("staging");
    expect(screen.getByRole("button", { name: "Add tag" }).hasAttribute("disabled")).toBe(false);
    await user.click(screen.getByRole("button", { name: "Remove 1" }));
    expect(screen.getByText("No tags")).toBeTruthy();
  });
  it("keeps fields, hints and validation exposed through native form semantics", async () => {
    const user = userEvent.setup();
    render(<form>
      <FormField id="name" hint="Use a unique name" label="Name"><Input aria-describedby="name-hint" id="name" invalid required /></FormField>
      <FormField id="draft-name" label="Draft name"><Input id="draft-name" aria-required="true" /></FormField>
      <FormField label="Region"><Select aria-required="true" defaultValue="a" name="region" options={[{ value: "a", label: "Region A" }, { value: "b", label: "Region B" }]} /></FormField>
    </form>);
    const input = screen.getByLabelText("Name") as HTMLInputElement;
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveProperty("required", true);
    expect(screen.getByRole("textbox", { name: "Draft name" }).getAttribute("aria-required")).toBe("true");
    expect(screen.getByRole("combobox", { name: "Region" }).getAttribute("aria-required")).toBe("true");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(input.getAttribute("aria-describedby")!)?.textContent).toBe("Use a unique name");
    await user.click(screen.getByRole("combobox", { name: "Region" }));
    expect(screen.getByRole("listbox", { name: "Region" })).toBeTruthy();
    await user.click(screen.getByRole("option", { name: "Region B" }));
    expect(screen.getByRole("combobox", { name: "Region" }).textContent).toBe("Region B");
    expect(new FormData(input.form!).get("region")).toBe("b");
  });
  it("clears a controlled search and returns focus without losing its ref", async () => {
    const user = userEvent.setup();
    function Search() {
      const [value, setValue] = useState("matrix");
      return <SearchInput aria-label="Search" clearAction={value ? { label: "Clear search", onClear: () => setValue("") } : undefined} onChange={(e) => setValue(e.target.value)} value={value} />;
    }
    render(<Search />);
    const search = screen.getByRole("searchbox");
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect((search as HTMLInputElement).value).toBe("");
    expect(document.activeElement).toBe(search);
    expect(screen.queryByRole("button")).toBeNull();
  });
  it("opens at the selected option, skips disabled choices and returns keyboard focus", async () => {
    const user = userEvent.setup();
    render(<Select aria-label="Region" defaultValue="b" options={[{ value: "a", label: "Alpha", disabled: true }, { value: "b", label: "Beta" }, { value: "c", label: "Charlie" }]} />);
    const trigger = screen.getByRole("combobox", { name: "Region" });
    trigger.focus();
    await user.keyboard("{ArrowDown}");
    expect(trigger.getAttribute("aria-haspopup")).toBe("listbox");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("option", { name: "Beta" })));
    expect(screen.getByRole("option", { name: "Beta" }).getAttribute("aria-selected")).toBe("true");
    await user.keyboard("{Home}");
    expect(document.activeElement).toBe(screen.getByRole("option", { name: "Beta" }));
    await user.keyboard("c{Enter}");
    expect(trigger.textContent).toBe("Charlie");
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    await user.keyboard("{ArrowUp}{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });
  it("keeps a dropdown inside a native dialog and dismisses only that dropdown", async () => {
    const user = userEvent.setup();
    const close = vi.fn();
    render(<Dialog open title="Create user" closeLabel="Close form" onClose={close}>
      <div data-surface="shell"><Select aria-label="Role" defaultValue="" options={[{ value: "", label: "No grant" }, { value: "reader", label: "Reader" }]} /></div>
    </Dialog>);
    const trigger = screen.getByRole("combobox", { name: "Role" });
    await user.click(trigger);
    const list = screen.getByRole("listbox");
    expect(list.closest("dialog")).toBe(screen.getByRole("dialog"));
    expect(list.getAttribute("data-surface")).toBe("shell");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(close).not.toHaveBeenCalled();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });
  it.each([false, true])("closes a select on Tab (backwards: %s) so keyboard users can continue through the form", async (shift) => {
    const user = userEvent.setup();
    render(<><Input aria-label="Before" /><Select aria-label="Region" defaultValue="a" options={[{ value: "a", label: "Alpha" }, { value: "b", label: "Beta" }]} /><Input aria-label="After" /></>);
    const trigger = screen.getByRole("combobox", { name: "Region" });
    trigger.focus();
    await user.keyboard("{ArrowDown}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("option", { name: "Alpha" })));
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(screen.getByRole("option", { name: "Beta" }));
    await user.tab({ shift });
    expect(screen.queryByRole("listbox")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(trigger.textContent).toBe("Beta");
    await user.tab({ shift });
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: shift ? "Before" : "After" }));
  });
  it("keeps the committed value when Escape cancels an explored option", async () => {
    const user = userEvent.setup();
    const onValueChange = vi.fn();
    render(<Select aria-label="Region" defaultValue="a" onValueChange={onValueChange} options={[{ value: "a", label: "Alpha" }, { value: "b", label: "Beta" }]} />);
    const trigger = screen.getByRole("combobox", { name: "Region" });
    await user.click(trigger);
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("option", { name: "Alpha" })));
    await user.keyboard("{ArrowDown}{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(trigger.textContent).toBe("Alpha");
    expect(onValueChange).not.toHaveBeenCalled();
  });
  it("allows outside focus and never opens a disabled dropdown", async () => {
    const user = userEvent.setup();
    const options = [{ value: "a", label: "Alpha" }];
    render(<><Select aria-label="Available" options={options} /><Input aria-label="Name" /><Select aria-label="Disabled" disabled options={options} /></>);
    await user.click(screen.getByRole("combobox", { name: "Disabled" }));
    expect(screen.queryByRole("listbox")).toBeNull();
    await user.click(screen.getByRole("combobox", { name: "Available" }));
    expect(screen.getByRole("listbox")).toBeTruthy();
    const input = screen.getByRole("textbox", { name: "Name" });
    await user.click(input);
    expect(screen.queryByRole("listbox")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(input));
  });
  it("preserves required validation, empty values and native form reset", async () => {
    const user = userEvent.setup();
    const submit = vi.fn((event: React.FormEvent) => event.preventDefault());
    render(<form aria-label="Configuration" onSubmit={submit}>
      <Select aria-label="Region" name="region" placeholder="Choose a region" required options={[{ value: "a", label: "Alpha" }, { value: "b", label: "Beta" }]} />
      <Button type="submit">Save</Button><Button type="reset">Reset</Button>
    </form>);
    const trigger = screen.getByRole("combobox", { name: "Region" });
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(submit).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(trigger);
    expect(trigger.getAttribute("aria-invalid")).toBe("true");
    await user.click(trigger);
    await user.click(screen.getByRole("option", { name: "Beta" }));
    expect(trigger.getAttribute("aria-invalid")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(submit).toHaveBeenCalledOnce();
    expect(new FormData(screen.getByRole("form") as HTMLFormElement).get("region")).toBe("b");
    await user.click(screen.getByRole("button", { name: "Reset" }));
    expect(trigger.textContent).toBe("Choose a region");
    expect(new FormData(screen.getByRole("form") as HTMLFormElement).get("region")).toBe("");
  });
  it("keeps native radio exclusivity, checkbox toggling and disabled behavior", async () => {
    const user = userEvent.setup();
    function Choices() {
      const [value, setValue] = useState("dark");
      return <><RadioGroup label="Theme" onValueChange={setValue} options={[{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }]} value={value} />
        <Checkbox name="confirm">I understand</Checkbox><Checkbox disabled>Unavailable</Checkbox></>;
    }
    render(<Choices />);
    await user.click(screen.getByRole("radio", { name: "Light" }));
    expect((screen.getByRole("radio", { name: "Dark" }) as HTMLInputElement).checked).toBe(false);
    expect((screen.getByRole("radio", { name: "Light" }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: "I understand" }));
    expect((screen.getByRole("checkbox", { name: "I understand" }) as HTMLInputElement).checked).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: "Unavailable" }));
    expect((screen.getByRole("checkbox", { name: "Unavailable" }) as HTMLInputElement).checked).toBe(false);
  });
  it("styles a real link as a button without nesting interactive elements", async () => {
    const onClick = vi.fn((event: React.MouseEvent) => event.preventDefault());
    const user = userEvent.setup();
    render(<Button asChild><a href="/console/" onClick={onClick}>Dashboard</a></Button>);
    const link = screen.getByRole("link", { name: "Dashboard" });
    expect(screen.queryByRole("button")).toBeNull();
    expect(link.getAttribute("href")).toBe("/console/");
    await user.click(link);
    expect(onClick).toHaveBeenCalledTimes(1);
  });
  it("keeps tables native and scrollable, with status announcements separate from data", () => {
    render(<><Table aria-label="Resources"><thead><tr><th scope="col">Name</th></tr></thead><tbody><tr><td>PostgreSQL</td></tr></tbody></Table><Alert status="danger">Could not save</Alert><Alert status="success">Saved</Alert></>);
    const table = screen.getByRole("table", { name: "Resources" });
    expect(within(table).getByRole("columnheader", { name: "Name" }).getAttribute("scope")).toBe("col");
    expect(screen.getByRole("region", { name: "Resources" }).tabIndex).toBe(0);
    expect(screen.getByRole("alert").textContent).toContain("Could not save");
    expect(screen.getByRole("status").textContent).toContain("Saved");
  });
});
