import { describe, expect, it } from "vitest";
import { withinNewPasswordProductBounds } from "./passwordEntry";

describe("new password product bounds", () => {
  it("counts Unicode code points, not UTF-16 units or bytes", () => {
    expect(withinNewPasswordProductBounds("😀".repeat(14))).toBe(false);
    expect(withinNewPasswordProductBounds("😀".repeat(15))).toBe(true);
    expect(withinNewPasswordProductBounds("😀".repeat(128))).toBe(true);
    expect(withinNewPasswordProductBounds("😀".repeat(129))).toBe(false);
  });

  it("keeps spaces and does not require character classes", () => {
    expect(withinNewPasswordProductBounds("  ordinary words  ")).toBe(true);
    expect(withinNewPasswordProductBounds("x".repeat(15))).toBe(true);
    expect(withinNewPasswordProductBounds("x".repeat(14))).toBe(false);
  });
});
