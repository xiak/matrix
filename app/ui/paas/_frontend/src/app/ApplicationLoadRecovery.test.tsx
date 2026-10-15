import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { isChunkLoadFailure, reloadDocumentOnce } from "@/infrastructure/runtime/applicationLoadRecovery";
import { ApplicationLoadRecovery, ApplicationRouteError } from "./ApplicationLoadRecovery";

function chunk(message = "Failed to load chunk /_next/static/chunks/0lu8sn3n2-2vc.js from module 64893") {
  return Object.assign(new Error(message), { name: "ChunkLoadError" });
}
function reject(reason: unknown) {
  const event = new Event("unhandledrejection");
  Object.defineProperty(event, "reason", { value: reason });
  act(() => { window.dispatchEvent(event); });
}
function fixture() {
  const reload = vi.fn();
  render(<LocaleProvider><ApplicationLoadRecovery reloadDocument={reload}>
    <input aria-label="Sensitive draft" defaultValue="synthetic-current-password" type="password" />
    <code>synthetic-once-only-material</code>
  </ApplicationLoadRecovery></LocaleProvider>);
  return reload;
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); localStorage.clear(); sessionStorage.clear(); });

describe("owned console asset recovery", () => {
  it.each([
    "/_next/static/chunks/0lu8sn3n2-2vc.js", "http://localhost/_next/static/chunks/current-hash.js"
  ])("recognizes a named same-origin Turbopack failure at %s", (path) => {
    expect(isChunkLoadFailure(chunk(`Failed to load chunk ${path} from module 64893`), "http://localhost")).toBe(true);
  });
  it("recognizes the bounded webpack missing asset shape", () => {
    expect(isChunkLoadFailure(chunk("Loading chunk 12 failed.\n(missing: http://localhost/_next/static/chunks/current.js)"), "http://localhost")).toBe(true);
  });
  it.each([
    new Error("Failed to load chunk /_next/static/chunks/a.js from module 64893"),
    chunk("ordinary render failed"), chunk("Failed to load chunk /api/iam/v1/users from module 64893"),
    chunk("Failed to load chunk https://other.invalid/_next/static/chunks/a.js from module 64893"),
    chunk("Failed to load chunk /_next/static/chunks/a.js?secret=synthetic from module 64893"),
    chunk("Failed to load chunk /_next/static/chunks/a.js#fragment from module 64893"),
    chunk("Failed to load chunk javascript:alert(1) from module 64893"),
    { name: "ChunkLoadError", message: "Failed to load chunk /_next/static/chunks/a.js" }, null, "ChunkLoadError"
  ])("rejects unproven runtime, API or foreign-resource errors %#", (error) => {
    expect(isChunkLoadFailure(error, "http://localhost")).toBe(false);
  });
  it("does not throw when an unknown Error has a hostile property getter", () => {
    const error = new Error("opaque");
    Object.defineProperty(error, "name", { get() { throw new Error("opaque getter"); } });
    expect(isChunkLoadFailure(error, "http://localhost")).toBe(false);
  });
  it("preserves the same draft and one-time material without an automatic reload or persistence", () => {
    const reload = fixture(); const input = screen.getByLabelText("Sensitive draft");
    reject(chunk()); reject(chunk());
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(screen.getByLabelText("Sensitive draft")).toBe(input);
    expect((input as HTMLInputElement).value).toBe("synthetic-current-password");
    expect(screen.getByText("synthetic-once-only-material")).toBeTruthy();
    expect(reload).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
    expect(screen.queryByText(/64893/)).toBeNull();
    expect(screen.queryByText(/0lu8sn3n2/)).toBeNull();
  });
  it("allows a user to stay and copy current materials without repeated errors reopening the prompt", () => {
    const reload = fixture(); reject(chunk());
    fireEvent.click(screen.getByRole("button", { name: "保留当前页面" }));
    reject(chunk());
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByLabelText("Sensitive draft")).toBeTruthy();
    expect(reload).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "查看恢复方式" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
  });
  it("requires explicit acknowledgement and permits at most one document reload per mounted application", () => {
    const reload = fixture(); reject(chunk());
    const button = screen.getByRole("button", { name: "确认刷新页面" });
    fireEvent.click(button); expect(reload).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: /我已保存/ }));
    fireEvent.click(button); fireEvent.click(button); reject(chunk());
    expect(reload).toHaveBeenCalledTimes(1);
    expect((screen.getByRole("button", { name: "已请求刷新" }) as HTMLButtonElement).disabled).toBe(true);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
  it("keeps the document navigation latch across replacement application mounts", () => {
    const reload = vi.fn();
    const current = { location: { reload } } as unknown as Document;
    const application = (key: string) => <LocaleProvider><ApplicationLoadRecovery key={key} reloadDocument={() => reloadDocumentOnce(current)}><p>Same document</p></ApplicationLoadRecovery></LocaleProvider>;
    const view = render(application("first"));
    reject(chunk()); fireEvent.click(screen.getByRole("checkbox", { name: /我已保存/ }));
    fireEvent.click(screen.getByRole("button", { name: "确认刷新页面" }));
    view.rerender(application("replacement"));
    reject(chunk()); fireEvent.click(screen.getByRole("checkbox", { name: /我已保存/ }));
    fireEvent.click(screen.getByRole("button", { name: "确认刷新页面" }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
  it("allows a distinct document its own single explicit navigation attempt", () => {
    const first = vi.fn(); const next = vi.fn();
    const firstDocument = { location: { reload: first } } as unknown as Document;
    const nextDocument = { location: { reload: next } } as unknown as Document;
    reloadDocumentOnce(firstDocument); reloadDocumentOnce(firstDocument);
    reloadDocumentOnce(nextDocument); reloadDocumentOnce(nextDocument);
    expect(first).toHaveBeenCalledTimes(1); expect(next).toHaveBeenCalledTimes(1);
  });
  it("never repeats a document navigation that threw before replacing the page", () => {
    const reload = vi.fn(() => { throw new Error("synthetic-browser-refusal"); });
    const current = { location: { reload } } as unknown as Document;
    expect(() => reloadDocumentOnce(current)).toThrow("synthetic-browser-refusal");
    expect(() => reloadDocumentOnce(current)).not.toThrow();
    expect(reload).toHaveBeenCalledTimes(1);
  });
  it("leaves an ordinary unhandled rejection to the normal error boundary without offering reload", () => {
    const reload = fixture(); reject(new Error("ordinary runtime exception"));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("button", { name: "确认刷新页面" })).toBeNull();
    expect(reload).not.toHaveBeenCalled();
  });
  it("handles a proven script error but does not consume an ordinary window error", () => {
    const reload = fixture();
    const ordinary = new ErrorEvent("error", { error: new Error("ordinary runtime error"), cancelable: true });
    act(() => { window.dispatchEvent(ordinary); });
    expect(ordinary.defaultPrevented).toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
    const known = new ErrorEvent("error", { error: chunk(), cancelable: true });
    act(() => { window.dispatchEvent(known); });
    expect(known.defaultPrevented).toBe(true);
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(reload).not.toHaveBeenCalled();
  });
  it("handles the actual route boundary through the same provider without exposing raw error or replacing its parent", () => {
    const reload = vi.fn(); const reset = vi.fn();
    render(<LocaleProvider><ApplicationLoadRecovery reloadDocument={reload}>
      <input aria-label="Parent draft" defaultValue="synthetic-parent-draft" />
      <ApplicationRouteError error={chunk()} reset={reset} />
    </ApplicationLoadRecovery></LocaleProvider>);
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect((screen.getByLabelText("Parent draft") as HTMLInputElement).value).toBe("synthetic-parent-draft");
    expect(reload).not.toHaveBeenCalled(); expect(reset).not.toHaveBeenCalled();
  });
  it("uses only an explicit render reset for an ordinary route runtime error", () => {
    const reload = vi.fn(); const reset = vi.fn();
    render(<LocaleProvider><ApplicationLoadRecovery reloadDocument={reload}><ApplicationRouteError error={new Error("synthetic-sensitive-runtime-error")} reset={reset} /></ApplicationLoadRecovery></LocaleProvider>);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText("synthetic-sensitive-runtime-error")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "重新尝试显示" }));
    expect(reset).toHaveBeenCalledTimes(1); expect(reload).not.toHaveBeenCalled();
  });
  it("keeps a rejected reload explicit and never attempts another after a browser refusal", () => {
    const reload = fixture(); reload.mockImplementation(() => { throw new Error("synthetic-browser-refusal"); });
    reject(chunk()); fireEvent.click(screen.getByRole("checkbox", { name: /我已保存/ }));
    fireEvent.click(screen.getByRole("button", { name: "确认刷新页面" }));
    expect(screen.getByText(/浏览器未能执行刷新/)).toBeTruthy();
    reject(chunk()); expect(reload).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("Sensitive draft")).toBeTruthy();
  });
});
