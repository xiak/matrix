import { createContext, useContext, useState } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ContentPage } from "./ContentPage";

afterEach(cleanup);

describe("ContentPage context heading", () => {
  it("contributes one heading and local-context actions, without rerendering shell tools on input", async () => {
    const user = userEvent.setup();
    const toolsRendered = vi.fn();
    const Feature = createContext("wrong");
    function Tools() { toolsRendered(); return <button>Refresh</button>; }
    function Detail() {
      const label = useContext(Feature);
      const [name, setName] = useState("admin");
      return <><ContentPage.Heading title={name} actions={<button>{label}</button>} /><input aria-label="Name" value={name} onChange={(event) => setName(event.target.value)} /></>;
    }
    render(<ContentPage><ContentPage.Header trailing={<Tools />}><h1>Users</h1></ContentPage.Header><ContentPage.Body><Feature.Provider value="Save changes"><Detail /></Feature.Provider></ContentPage.Body></ContentPage>);
    const count = toolsRendered.mock.calls.length;
    expect(screen.getAllByRole("heading")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Refresh" })).toBeNull();
    await user.type(screen.getByRole("textbox"), "-edited");
    expect(screen.getByRole("heading", { name: "admin-edited" })).toBeTruthy();
    expect(within(screen.getByRole("banner")).getByRole("button", { name: "Save changes" })).toBeTruthy();
    expect(toolsRendered).toHaveBeenCalledTimes(count);
  });

  it("uses local actions instead of duplicating shell actions and restores the default on exit", () => {
    const page = (detail: boolean) => <ContentPage><ContentPage.Header trailing={<button>Refresh</button>}><h1>Resources</h1></ContentPage.Header><ContentPage.Body>{detail ? <ContentPage.Heading title="Application" actions={<button>Refresh</button>} /> : <ContentPage.Heading title="Resources" />}</ContentPage.Body></ContentPage>;
    const view = render(page(true));
    expect(screen.getAllByRole("button", { name: "Refresh" })).toHaveLength(1);
    view.rerender(page(false));
    expect(screen.getAllByRole("button", { name: "Refresh" })).toHaveLength(1);
    expect(screen.getByRole("heading", { name: "Resources" })).toBeTruthy();
  });

  it("hides outgoing actions while pending and restores them on cancellation; cleans up on exit", () => {
    const action = vi.fn();
    const page = (pending: boolean, detail: boolean) => <ContentPage parentLabel="Users" pending={pending}>
      <ContentPage.Header><h1>Users</h1></ContentPage.Header>
      <ContentPage.Body pending={pending} transitionKey="users" loading={<p>Loading</p>}>
        {detail ? <ContentPage.Heading title="admin" back={{ label: "Back to users", onClick: action }} actions={<button>Edit user</button>} focus /> : <p>User list</p>}
      </ContentPage.Body>
    </ContentPage>;
    const view = render(page(false, true));
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "admin" }));
    view.rerender(page(true, true));
    expect(screen.getAllByRole("heading")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Edit user" })).toBeNull();
    view.rerender(page(false, true));
    expect(screen.getByRole("button", { name: "Back to users" }).textContent).toBe("Users");
    view.rerender(page(false, false));
    expect(screen.getByRole("heading", { name: "Users" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Edit user" })).toBeNull();
    expect(action).not.toHaveBeenCalled();
  });

  it("restores a collection scroll position without retaining its outgoing DOM", () => {
    const page = (key: string) => <ContentPage><ContentPage.Body aria-label="Viewport" transitionKey={key}>{key}</ContentPage.Body></ContentPage>;
    const view = render(page("users"));
    const original = screen.getByLabelText("Viewport");
    fireEvent.scroll(original, { target: { scrollTop: 300 } });
    view.rerender(page("admin"));
    expect(screen.getByLabelText("Viewport").scrollTop).toBe(0);
    view.rerender(page("users"));
    expect(screen.getByLabelText("Viewport")).not.toBe(original);
    expect(screen.getByLabelText("Viewport").scrollTop).toBe(300);
  });
});

describe("ContentPage transition", () => {
  it("immediately hides the old draft behind loading, then restores it if navigation is cancelled", async () => {
    const user = userEvent.setup();
    const body = (pending: boolean) => <ContentPage.Body transitionKey="resources" pending={pending} loading={<p role="status">Opening logs…</p>}><input aria-label="Filter resources" /></ContentPage.Body>;
    const view = render(body(false));
    const input = screen.getByRole("textbox");
    await user.type(input, "postgres");
    view.rerender(body(true));
    expect(input.closest("[inert]")).toBeTruthy();
    expect(input.closest("[hidden]")).toBeTruthy();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.getByRole("status").textContent).toBe("Opening logs…");
    view.rerender(body(false));
    expect(screen.getByRole("textbox")).toBe(input);
    expect((input as HTMLInputElement).value).toBe("postgres");
    expect(input.closest("[inert]")).toBeNull();
    expect(input.closest("[hidden]")).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("commits the new page without retaining the outgoing page's scroll container", () => {
    const body = (page: string) => <ContentPage.Body transitionKey={page}><h2>{page}</h2></ContentPage.Body>;
    const view = render(body("Resources"));
    const previous = screen.getByRole("heading").parentElement!.parentElement;
    view.rerender(body("Logs"));
    expect(screen.queryByRole("heading", { name: "Resources" })).toBeNull();
    expect(screen.getByRole("heading", { name: "Logs" }).parentElement!.parentElement).not.toBe(previous);
  });
});
