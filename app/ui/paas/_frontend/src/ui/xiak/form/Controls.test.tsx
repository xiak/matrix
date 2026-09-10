import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Alert, Button, Checkbox, Dialog, FormField, Input, RadioGroup, SearchInput, Select, Table, TagEditor } from "../index";

afterEach(cleanup);
describe("shared themed controls", () => {
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
      <FormField label="Region"><Select defaultValue="a" name="region" options={[{ value: "a", label: "Region A" }, { value: "b", label: "Region B" }]} /></FormField>
    </form>);
    const input = screen.getByLabelText("Name") as HTMLInputElement;
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
