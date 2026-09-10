// Generated from api/iam/v1/openapi.json. Run npm run generate:contracts.
import type { ContractValidators } from "./validation";
import * as compiled from "./iamValidate";

export type ChangePasswordRequest = { "currentPassword": Secret; "newPassword": Secret; "requestId": ID; };
export type ChangePasswordResponse = { "bootstrapFileRetirable": boolean; "changedAt": Timestamp; };
export type ID = string;
export type LoginRequest = { "loginName": string; "password": Secret; "requestId": ID; };
export type LoginResponse = { "credential": Secret; "session": Session; };
export type LogoutRequest = { "requestId": ID; };
export type LogoutResponse = { "revokedAt": Timestamp; };
export type Secret = string;
export type Session = ({ "apiVersion": "iam.matrix.xiak.com/v1"; "expiresAt": Timestamp; "id": ID; "issuedAt": Timestamp; "kind": "Session"; "organizationId": ID; "principalId": ID; "revokedAt"?: Timestamp; "status": SessionStatus; }) & (unknown);
export type SessionStatus = "ACTIVE" | "REVOKED" | "EXPIRED";
export type Timestamp = string;

export const validators: ContractValidators = compiled;
