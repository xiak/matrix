export type ApplicationResource = {
  apiVersion: "paas.matrix.xiak.com/v1";
  kind: "Application";
  metadata: {
    id: string;
    name: string;
    scope: { kind: "TENANT"; tenantId: string };
    labels?: Record<string, string>;
    resourceVersion: number;
    createdAt: string;
    updatedAt: string;
  };
};

export type ApplicationReadSnapshot = {
  etag: string;
  application: ApplicationResource;
};

export type ApplicationReadLoad =
  | { status: "ready"; snapshot: ApplicationReadSnapshot }
  | { status: "invalid" | "expired" | "forbidden" | "notFound" | "unavailable" };

const applicationIdentifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const applicationNamePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const rawSensitiveMaterialMarkers = [
  "authorization: bearer", "bearer ", "password=", "passwd=", "secret=", "client_secret=", "token=",
  "access_token=", "refresh_token=", "id_token=", "api_key=", "private_key=", "-----begin private key-----",
  "aws_secret_access_key", "credential_material=", "session_cookie="
] as const;

export function validApplicationId(value: string): boolean {
  return applicationIdentifierPattern.test(value);
}

export function validApplicationName(value: string): boolean {
  return applicationNamePattern.test(value);
}

export function applicationLabelLooksSensitive(value: string): boolean {
  const normalized = value.toLowerCase();
  return rawSensitiveMaterialMarkers.some((marker) => normalized.includes(marker));
}

export function validApplicationLabelValue(value: string): boolean {
  return new TextEncoder().encode(value).length <= 128 &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    !applicationLabelLooksSensitive(value);
}

export function validApplicationLabels(value: Record<string, string>): boolean {
  const entries = Object.entries(value);
  return entries.length <= 64 && entries.every(([key, item]) => (
    validApplicationName(key) && validApplicationLabelValue(item)
  ));
}
