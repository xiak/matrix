import ipaddr from "ipaddr.js";

export type AccessKeyNetworkRestrictions = { allowedSourceCidrs: string[] };

export type AccessKeyAuthorizationObservation = {
  evaluatedAt: string;
  allowed: boolean;
  action: string;
  product: string;
  sourceIp: string;
};

export type AccessKeyUsageObservation = {
  observedAt: string;
  lastAuthorization?: AccessKeyAuthorizationObservation;
};

export type AccessKeyNetworkDraftIssue = "tooMany" | "invalid" | "duplicate";

export type AccessKeyNetworkDraftResult =
  | { ok: true; restrictions: AccessKeyNetworkRestrictions }
  | { ok: false; issue: AccessKeyNetworkDraftIssue; line?: number };

function canonicalCidr(value: string): string | null {
  if (!value || value.length > 80 || /[%\s]/.test(value)) return null;
  const [addressText, prefixText, extra] = value.split("/");
  if (!addressText || !prefixText || extra !== undefined || !/^(?:0|[1-9]\d{0,2})$/.test(prefixText)) return null;
  if (addressText.includes(".")) {
    const dotted = addressText.includes(":") ? addressText.slice(addressText.lastIndexOf(":") + 1) : addressText;
    if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(dotted)) return null;
  }
  try {
    const [address, bits] = ipaddr.parseCIDR(value);
    if (address instanceof ipaddr.IPv6 && address.isIPv4MappedAddress()) return null;
    const bytes = address.toByteArray();
    if (bytes.some((byte, index) => {
      const retained = Math.max(0, Math.min(8, bits - index * 8));
      const mask = retained === 0 ? 0 : (0xff << (8 - retained)) & 0xff;
      return (byte & ~mask) !== 0;
    })) return null;
    return `${address.toString()}/${bits}`;
  } catch {
    return null;
  }
}

export function parseAccessKeyNetworkDraft(value: string): AccessKeyNetworkDraftResult {
  const lines = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length > 16) return { ok: false, issue: "tooMany" };
  const canonical: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const normalized = canonicalCidr(lines[index]!);
    if (!normalized) return { ok: false, issue: "invalid", line: index + 1 };
    canonical.push(normalized);
  }
  if (new Set(canonical).size !== canonical.length) return { ok: false, issue: "duplicate" };
  return { ok: true, restrictions: { allowedSourceCidrs: canonical.sort() } };
}

export function accessKeyNetworkDraftValue(value: AccessKeyNetworkRestrictions): string {
  return value.allowedSourceCidrs.join("\n");
}

export function accessKeyNetworkRestrictionsEqual(left: AccessKeyNetworkRestrictions, right: AccessKeyNetworkRestrictions): boolean {
  return left.allowedSourceCidrs.length === right.allowedSourceCidrs.length
    && left.allowedSourceCidrs.every((cidr, index) => cidr === right.allowedSourceCidrs[index]);
}

export function accessKeyNetworkRestrictionsValid(value: unknown): value is AccessKeyNetworkRestrictions {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !Array.isArray((value as AccessKeyNetworkRestrictions).allowedSourceCidrs) ||
      (value as AccessKeyNetworkRestrictions).allowedSourceCidrs.some((entry) => typeof entry !== "string") ||
      Object.keys(value).some((key) => key !== "allowedSourceCidrs")) return false;
  const restrictions = value as AccessKeyNetworkRestrictions;
  const parsed = parseAccessKeyNetworkDraft(accessKeyNetworkDraftValue(restrictions));
  return parsed.ok && parsed.restrictions.allowedSourceCidrs.every((cidr, index) => cidr === restrictions.allowedSourceCidrs[index]);
}

export function accessKeyAuthorizationSourceIpValid(value: string): boolean {
  if (!value || value.length > 64 || /[%\s]/.test(value)) return false;
  if (value.includes(".")) {
    const dotted = value.includes(":") ? value.slice(value.lastIndexOf(":") + 1) : value;
    if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(dotted)) return false;
  }
  try {
    const address = ipaddr.parse(value);
    if (address instanceof ipaddr.IPv6 && address.isIPv4MappedAddress()) return false;
    if (address.range() === "unspecified" || address.range() === "multicast") return false;
    return address.toString() === value;
  } catch {
    return false;
  }
}
