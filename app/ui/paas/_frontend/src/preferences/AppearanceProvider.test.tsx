import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useTranslations } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppearanceProvider } from "./AppearanceProvider";
import { AppearanceControls } from "./AppearanceControls";

function Probe() {
  const t = useTranslations("Auth");
  return <><AppearanceControls /><p>{t("firstLogin", { name: "matrix-admin" })}</p><input aria-label="draft" defaultValue="" /></>;
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", vi.fn().mockImplementation(() => ({
    matches: false, addListener: vi.fn(), removeListener: vi.fn()
  })));
});
afterEach(() => { cleanup(); localStorage.clear(); vi.unstubAllGlobals(); vi.restoreAllMocks(); document.documentElement.removeAttribute("data-theme"); });

describe("application appearance preferences", () => {
  it("changes the whole app from the account panel without remounting drafts", async () => {
    const user = userEvent.setup();
    render(<AppearanceProvider><AppearanceControls variant="panel" /><input aria-label="draft" defaultValue="" /></AppearanceProvider>);
    await user.type(screen.getByLabelText("draft"), "keep me");
    await user.click(screen.getByRole("radio", { name: "混色" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("mixed"));
    expect(localStorage.getItem("matrix.theme")).toBe("mixed");
    expect((screen.getByLabelText("draft") as HTMLInputElement).value).toBe("keep me");
    await user.click(screen.getByRole("radio", { name: "浅色" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(screen.getByRole("group", { name: "Theme" })).toBeTruthy();
    expect((screen.getByLabelText("draft") as HTMLInputElement).value).toBe("keep me");
    expect((screen.getByRole("radio", { name: "Light" }) as HTMLInputElement).checked).toBe(true);
    expect(screen.getByRole("radio", { name: "Mixed" })).toBeTruthy();
  });

  it("defaults to dark and changes themes with an accessible radio menu", async () => {
    const user = userEvent.setup();
    render(<AppearanceProvider><Probe /></AppearanceProvider>);
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("dark"));
    await user.click(screen.getByRole("button", { name: "主题" }));
    const current = screen.getByRole("menuitemradio", { name: "深色" });
    expect(current.getAttribute("aria-checked")).toBe("true");
    expect(screen.getAllByRole("menuitemradio")).toHaveLength(4);
    await user.click(screen.getByRole("menuitemradio", { name: "混色" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("mixed"));
    expect(localStorage.getItem("matrix.theme")).toBe("mixed");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "主题" }));
    await user.click(screen.getByRole("button", { name: "主题" }));
    await user.click(screen.getByRole("menuitemradio", { name: "浅色" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(localStorage.getItem("matrix.theme")).toBe("light");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "主题" }));
    await user.click(screen.getByRole("button", { name: "主题" }));
    await user.click(screen.getByRole("menuitemradio", { name: "跟随系统" }));
    expect(localStorage.getItem("matrix.theme")).toBe("system");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it.each(["dark", "mixed", "light"])("restores the saved %s theme without rewriting the preference", (theme) => {
    localStorage.setItem("matrix.theme", theme);
    render(<AppearanceProvider><AppearanceControls variant="panel" /></AppearanceProvider>);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect((document.querySelector(`input[value="${theme}"]`) as HTMLInputElement).checked).toBe(true);
    expect(localStorage.getItem("matrix.theme")).toBe(theme);
    expect(document.documentElement.getAttribute("style")).toBeNull();
  });

  it("follows live OS changes only in system mode and keeps mixed as an explicit preference", async () => {
    const user = userEvent.setup();
    const listeners = new Set<(event: { matches: boolean }) => void>();
    const media = { matches: true, addListener: (listener: (event: { matches: boolean }) => void) => listeners.add(listener), removeListener: (listener: (event: { matches: boolean }) => void) => listeners.delete(listener) };
    vi.stubGlobal("matchMedia", vi.fn(() => media));
    localStorage.setItem("matrix.theme", "system");
    render(<AppearanceProvider><AppearanceControls variant="panel" /><input aria-label="draft" defaultValue="unsaved" /></AppearanceProvider>);
    expect(document.documentElement.dataset.theme).toBe("dark");
    act(() => { media.matches = false; listeners.forEach((listener) => listener(media)); });
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("matrix.theme")).toBe("system");
    await user.click(screen.getByRole("radio", { name: "混色" }));
    act(() => { media.matches = true; listeners.forEach((listener) => listener(media)); });
    expect(document.documentElement.dataset.theme).toBe("mixed");
    expect(localStorage.getItem("matrix.theme")).toBe("mixed");
    await user.click(screen.getByRole("radio", { name: "跟随系统" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect((screen.getByLabelText("draft") as HTMLInputElement).value).toBe("unsaved");
  });

  it("syncs all explicit themes from another tab without remounting a draft", () => {
    render(<AppearanceProvider><AppearanceControls variant="panel" /><input aria-label="draft" defaultValue="unsaved" /></AppearanceProvider>);
    for (const theme of ["mixed", "light", "dark"]) {
      act(() => { fireEvent(window, new StorageEvent("storage", { key: "matrix.theme", newValue: theme })); });
      expect(document.documentElement.dataset.theme).toBe(theme);
      expect((document.querySelector(`input[value="${theme}"]`) as HTMLInputElement).checked).toBe(true);
      expect((screen.getByLabelText("draft") as HTMLInputElement).value).toBe("unsaved");
    }
  });

  it("switches language without remounting form state, and restores it on a new mount", async () => {
    const user = userEvent.setup();
    const view = render(<AppearanceProvider><Probe /></AppearanceProvider>);
    await user.type(screen.getByLabelText("draft"), "unsaved-account");
    await user.click(screen.getByRole("button", { name: "语言" }));
    await user.click(screen.getByRole("menuitemradio", { name: "English" }));
    expect(screen.getByText("First sign-in · matrix-admin")).toBeTruthy();
    expect((screen.getByLabelText("draft") as HTMLInputElement).value).toBe("unsaved-account");
    expect(document.documentElement.lang).toBe("en");
    expect(localStorage.getItem("matrix.locale")).toBe("en");
    view.unmount();
    render(<AppearanceProvider><Probe /></AppearanceProvider>);
    expect(screen.getByText("First sign-in · matrix-admin")).toBeTruthy();
    expect(Object.keys(localStorage)).toEqual(["matrix.locale"]);
  });

  it("uses keyboard navigation and Escape returns focus to the trigger", async () => {
    const user = userEvent.setup();
    render(<AppearanceProvider><Probe /></AppearanceProvider>);
    const trigger = screen.getByRole("button", { name: "语言" });
    trigger.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("menu");
    await user.keyboard("{End}{Enter}");
    expect(document.documentElement.lang).toBe("en");
    await user.click(screen.getByRole("button", { name: "Language" }));
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Language" }));
  });

  it("syncs language changes from another tab and rejects unsupported stored locales", () => {
    render(<AppearanceProvider><Probe /></AppearanceProvider>);
    act(() => {
      localStorage.setItem("matrix.locale", "en");
      fireEvent(window, new StorageEvent("storage", { key: "matrix.locale", newValue: "en" }));
    });
    expect(document.documentElement.lang).toBe("en");
    act(() => {
      localStorage.setItem("matrix.locale", "unsupported");
      fireEvent(window, new StorageEvent("storage", { key: "matrix.locale", newValue: "unsupported" }));
    });
    expect(document.documentElement.lang).toBe("zh-CN");
  });

  it("keeps language switching usable when browser storage is blocked", async () => {
    const user = userEvent.setup();
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    render(<AppearanceProvider><Probe /></AppearanceProvider>);
    await user.click(screen.getByRole("button", { name: /^(语言|Language)$/ }));
    await user.click(screen.getByRole("menuitemradio", { name: "简体中文" }));
    await user.click(screen.getByRole("button", { name: "语言" }));
    await user.click(screen.getByRole("menuitemradio", { name: "English" }));
    expect(screen.getByText("First sign-in · matrix-admin")).toBeTruthy();
  });
});
