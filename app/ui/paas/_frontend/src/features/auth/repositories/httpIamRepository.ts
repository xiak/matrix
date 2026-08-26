import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type { IamRepository, LoginCommand, LoginResult } from "./iamRepository";

type LoginWire = {
  session?: {
    id?: unknown;
    organizationId?: unknown;
    principalId?: unknown;
    status?: unknown;
    issuedAt?: unknown;
    expiresAt?: unknown;
  };
  credential?: unknown;
};

function parseLogin(value: LoginWire): LoginResult {
  const session = value.session;
  if (
    !session ||
    typeof session.id !== "string" ||
    typeof session.organizationId !== "string" ||
    typeof session.principalId !== "string" ||
    session.status !== "ACTIVE" ||
    typeof session.issuedAt !== "string" ||
    typeof session.expiresAt !== "string" ||
    typeof value.credential !== "string" ||
    value.credential.length === 0
  ) {
    throw new Error("INVALID_IAM_RESPONSE");
  }

  return {
    credential: value.credential,
    session: {
      id: session.id,
      organizationId: session.organizationId,
      principalId: session.principalId,
      status: "ACTIVE",
      issuedAt: session.issuedAt,
      expiresAt: session.expiresAt
    }
  };
}

export const httpIamRepository: IamRepository = {
  async login(command: LoginCommand): Promise<LoginResult> {
    const wire = await requestJSON<LoginWire>("/api/iam/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        loginName: command.loginName,
        password: command.password,
        requestId: requestToken("ui-login-")
      })
    });
    return parseLogin(wire);
  },

  async logout(credential: string): Promise<void> {
    await requestJSON<unknown>("/api/iam/v1/auth/logout", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ requestId: requestToken("ui-logout-") })
    });
  }
};
