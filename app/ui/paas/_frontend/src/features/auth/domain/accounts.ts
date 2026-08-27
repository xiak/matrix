export const userRoles = ["ORGANIZATION_ADMIN", "PAAS_DEVELOPER", "PAAS_VIEWER", "AUDIT_READER"] as const;
export type UserRole = typeof userRoles[number];
export type IdentityRole = UserRole | "PLATFORM_OPERATOR";

export type Account = {
  organization: { id: string; displayName: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number };
  primaryPrincipalId: string;
  primaryLoginName: string;
  loginAlias: string | null;
};

export type AccountPrincipal = {
  id: string;
  organizationId: string;
  loginName: string;
  displayName: string;
  status: "ACTIVE" | "DISABLED";
  mustChangePassword: boolean;
  resourceVersion: number;
};

export type AccountIdentity = {
  account: Account;
  principal: AccountPrincipal;
  roles: IdentityRole[];
  canCreateOrganizations: boolean;
};

export type UserRoleBinding = { id: string; principalId: string; organizationId: string; role: IdentityRole };
export type AccountUser = { principal: AccountPrincipal; roleBindings: UserRoleBinding[] };
export type DirectoryPage<T> = { items: T[]; nextAfter: string | null };

export type AccountCommand =
  | { kind: "create-user"; loginName: string; displayName: string; initialPassword: string; initialRole?: UserRole }
  | { kind: "create-organization"; id: string; displayName: string; administratorLoginName: string; administratorDisplayName: string; initialPassword: string }
  | { kind: "set-organization-status"; organizationId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "recover-primary"; organizationId: string; principalId: string; initialPassword: string; resourceVersion: number }
  | { kind: "set-alias"; alias: string; resourceVersion: number }
  | { kind: "set-status"; principalId: string; status: "ACTIVE" | "DISABLED"; resourceVersion: number }
  | { kind: "reset-password"; principalId: string; initialPassword: string; resourceVersion: number }
  | { kind: "grant-role"; principalId: string; role: UserRole }
  | { kind: "revoke-role"; bindingId: string };
