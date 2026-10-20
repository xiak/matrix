export class HttpProblem extends Error {
  readonly code: string;
  readonly requestId: string | null;
  readonly status: number;

  constructor(status: number, code: string, requestId: string | null = null) {
    const stableCode = stableProblemCode(code);
    super(stableCode);
    this.name = "HttpProblem";
    this.status = status;
    this.code = stableCode;
    this.requestId = requestId;
  }
}

const genericProblemCode = "PLATFORM_REQUEST_REJECTED";
const namespacedProblemCodePattern = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+){1,15}$/;
const constantProblemCodePattern = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){0,15}$/;
const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function stableProblemCode(value: unknown): string {
  if (typeof value !== "string" || value.length > 96) return genericProblemCode;
  return namespacedProblemCodePattern.test(value) || constantProblemCodePattern.test(value) ? value : genericProblemCode;
}

function problemRequestId(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("requestId" in body) || typeof body.requestId !== "string") return null;
  return requestIdPattern.test(body.requestId) ? body.requestId : null;
}

export async function requestJSONResponse<T>(
  path: string,
  init?: RequestInit
): Promise<{ body: T; headers: Headers; status: number }> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...init?.headers
    }
  });

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new HttpProblem(response.status, "INVALID_PLATFORM_RESPONSE");
  }

  if (!response.ok) {
    const code = typeof body === "object" && body !== null && "code" in body ? stableProblemCode(body.code) : genericProblemCode;
    throw new HttpProblem(response.status, code, problemRequestId(body));
  }

  return { body: body as T, headers: response.headers, status: response.status };
}

export async function requestJSON<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  return (await requestJSONResponse<T>(path, init)).body;
}

export function requestToken(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${prefix}${value}`;
}
