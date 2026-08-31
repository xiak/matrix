export class HttpProblem extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string) {
    super(code);
    this.name = "HttpProblem";
    this.status = status;
    this.code = code;
  }
}

export async function requestJSONWithResponse<T>(
  path: string,
  init?: RequestInit
): Promise<{ body: T; response: Response }> {
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
    const code =
      typeof body === "object" && body !== null && "code" in body &&
      typeof body.code === "string"
        ? body.code
        : "PLATFORM_REQUEST_REJECTED";
    throw new HttpProblem(response.status, code);
  }

  return { body: body as T, response };
}

export async function requestJSON<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  return (await requestJSONWithResponse<T>(path, init)).body;
}

export function requestToken(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${prefix}${value}`;
}
