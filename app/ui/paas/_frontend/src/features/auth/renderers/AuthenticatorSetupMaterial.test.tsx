import { cleanup, render, screen } from "@testing-library/react";
import jsQR from "jsqr";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleProvider";
import { AuthenticatorSetupMaterial } from "./AuthenticatorSetupMaterial";

const seed = "JBSWY3DPEHPK3PXP";
const uri = `otpauth://totp/Matrix:alice?secret=${seed}&issuer=Matrix&algorithm=SHA1&digits=6&period=30`;

/** Rasterize the actual rendered vector geometry for an independent decoder. */
function scanSymbol() {
  const svg = screen.getByRole("img", { name: "身份验证器设置二维码" });
  const size = Number(svg.getAttribute("viewBox")!.split(" ")[3]);
  const scale = 4;
  const width = size * scale;
  const pixels = new Uint8ClampedArray(width * width * 4).fill(255);
  const path = svg.querySelector("path")!.getAttribute("d")!;
  for (const run of path.matchAll(/M(\d+) (\d+)h(\d+)v1h-\d+z/g)) {
    const [left, top, length] = run.slice(1).map(Number) as [number, number, number];
    for (let y = top * scale; y < (top + 1) * scale; y++) {
      for (let x = left * scale; x < (left + length) * scale; x++) {
        const offset = (y * width + x) * 4;
        pixels[offset] = pixels[offset + 1] = pixels[offset + 2] = 0;
      }
    }
  }
  return jsQR(pixels, width, width, { inversionAttempts: "dontInvert" })?.data;
}

afterEach(() => { cleanup(); localStorage.clear(); sessionStorage.clear(); vi.unstubAllGlobals(); });

describe("authenticator setup material", () => {
  it.each([uri, uri.replace("alice", "%E6%9E%97%20alice%40account"), uri.replace("alice", "林😀")])("encodes the exact provisioning URI in a locally decodable QR %#", value => {
    const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
    const { container } = render(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri: value }} /></LocaleProvider>);
    expect(scanSymbol()).toBe(value);
    expect(screen.getByText(seed)).toBeTruthy();
    expect(screen.getByText("仅在当前页面本地生成。二维码与设置密钥是同一份秘密，请勿分享。")).toBeTruthy();
    expect(container.querySelector("[href], [src], canvas")).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("replaces old material synchronously and clears both QR and manual material on unmount", () => {
    const { rerender, unmount } = render(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri }} /></LocaleProvider>);
    const next = { seed: "KRUGS4ZANFZSAYJA", uri: uri.replace(seed, "KRUGS4ZANFZSAYJA").replace("alice", "bob") };
    rerender(<LocaleProvider><AuthenticatorSetupMaterial provisioning={next} /></LocaleProvider>);
    expect(scanSymbol()).toBe(next.uri);
    expect(screen.queryByText(seed)).toBeNull();
    expect(screen.queryByText(uri)).toBeNull();
    unmount();
    expect(screen.queryByRole("img")).toBeNull();
    expect(document.body.textContent).not.toContain(next.seed);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("removes a stale QR and keeps oversized material on the manual path", () => {
    const { rerender } = render(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri }} /></LocaleProvider>);
    rerender(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri: `otpauth://totp/${"a".repeat(8000)}?secret=${seed}` }} /></LocaleProvider>);
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByText(seed)).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("当前因子尚未确认");
    expect(document.body.textContent).not.toMatch(/code length overflow|bad rs block/i);
  });

  it.each([
    `https://example.invalid/?secret=${seed}`,
    `otpauth://hotp/Matrix?secret=${seed}`,
    `otpauth://totp/Matrix?secret=KRUGS4ZANFZSAYJA`,
    `${uri}&secret=${seed}`
  ])("does not present an unsupported or ambiguous URI as an authenticator QR %#", value => {
    render(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri: value }} /></LocaleProvider>);
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByText(seed)).toBeTruthy();
    expect(screen.getByRole("status")).toBeTruthy();
  });

  it("clears an old symbol when only its seed stops matching", () => {
    const { rerender } = render(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed, uri }} /></LocaleProvider>);
    expect(scanSymbol()).toBe(uri);
    rerender(<LocaleProvider><AuthenticatorSetupMaterial provisioning={{ seed: "KRUGS4ZANFZSAYJA", uri }} /></LocaleProvider>);
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.queryByText(seed)).toBeNull();
  });
});
