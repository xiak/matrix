import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import type {
  ChangePasswordCommand,
  IamRepository,
  LoginCommand,
  LoginResult
} from "./iamRepository";

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
  mustChangePassword?: unknown;
};

type ChangePasswordWire = {
  changedAt?: unknown;
  bootstrapFileRetirable?: unknown;
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
    value.credential.length === 0 ||
    typeof value.mustChangePassword !== "boolean"
  ) {
    throw new Error("INVALID_IAM_RESPONSE");
  }

  return {
    credential: value.credential,
    mustChangePassword: value.mustChangePassword,
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

  async changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void> {
    const wire = await requestJSON<ChangePasswordWire>("/api/iam/v1/auth/password", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        currentPassword: command.currentPassword,
        newPassword: command.newPassword,
        requestId: requestToken("ui-password-")
      })
    });
    if (
      typeof wire.changedAt !== "string" ||
      typeof wire.bootstrapFileRetirable !== "boolean"
    ) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
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
