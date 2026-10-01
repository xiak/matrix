import { describe, expect, it } from "vitest";
import { accessKeyNetworkRestrictionsEqual, accessKeyNetworkRestrictionsValid, parseAccessKeyNetworkDraft } from "./accessKeyNetwork";

describe("AccessKey network restriction preview", () => {
  it("normalizes and sorts strict IPv4 and IPv6 networks", () => {
    expect(parseAccessKeyNetworkDraft("203.0.113.0/24\n2001:0DB8:1200:0000::/48")).toEqual({
      ok: true,
      restrictions: { allowedSourceCidrs: ["2001:db8:1200::/48", "203.0.113.0/24"] }
    });
  });

  it.each([
    "203.0.113.4/24",
    "010.0.0.0/8",
    "2001:db8::1/48",
    "::ffff:192.0.2.0/120",
    "fe80::%eth0/64",
    "203.0.113.0/33"
  ])("rejects non-network, mapped, zoned, or malformed CIDR %s", (value) => {
    expect(parseAccessKeyNetworkDraft(value)).toEqual({ ok: false, issue: "invalid", line: 1 });
  });

  it("rejects canonical duplicates and more than sixteen entries", () => {
    expect(parseAccessKeyNetworkDraft("2001:db8::/32\n2001:0db8::/32")).toEqual({ ok: false, issue: "duplicate" });
    expect(parseAccessKeyNetworkDraft(Array.from({ length: 17 }, (_, index) => `198.51.${index}.0/24`).join("\n"))).toEqual({ ok: false, issue: "tooMany" });
  });

  it("accepts an explicit empty layer but requires stored entries to be canonical and sorted", () => {
    expect(accessKeyNetworkRestrictionsValid({ allowedSourceCidrs: [] })).toBe(true);
    expect(accessKeyNetworkRestrictionsValid({ allowedSourceCidrs: ["203.0.113.0/24", "2001:db8::/32"] })).toBe(false);
    expect(accessKeyNetworkRestrictionsValid({ allowedSourceCidrs: ["2001:db8::/32", "203.0.113.0/24"] })).toBe(true);
  });

  it("compares canonical restriction values without relying on object serialization", () => {
    expect(accessKeyNetworkRestrictionsEqual({ allowedSourceCidrs: ["2001:db8::/32"] }, { allowedSourceCidrs: ["2001:db8::/32"] })).toBe(true);
    expect(accessKeyNetworkRestrictionsEqual({ allowedSourceCidrs: ["2001:db8::/32"] }, { allowedSourceCidrs: ["203.0.113.0/24"] })).toBe(false);
  });
});
