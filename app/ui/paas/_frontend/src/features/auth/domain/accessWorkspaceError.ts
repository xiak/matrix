export class AccessWorkspaceError extends Error {
  constructor(public readonly code: "invalid" | "duplicate" | "referenced" | "disableFirst" | "systemPolicy" | "notFound" | "unsupportedPolicy" | "versionLimit" | "defaultVersion" | "immutablePolicyName" | "unknownAction" | "invalidResource" | "tenantResource" | "invalidCondition" | "invalidTrust" | "trustDenied" | "callerDenied" | "sessionLimit" | "staleUsers" | "ineligibleUsers" | "associationLimit") { super(code); }
}
