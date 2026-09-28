import { afterEach, describe, expect, it, vi } from "vitest";
import { httpAccountRepository, httpIamRepository } from "./httpIamRepository";

const apiVersion = "iam.matrix.xiak.com/v1";
const principal = {
  apiVersion, kind: "User", id: "principal-alex", accountId: "account-acme",
  loginName: "alex", displayName: "Alex", status: "ACTIVE", mustChangePassword: true, resourceVersion: 2
};
const account = {
  apiVersion, kind: "Account", id: "account-acme", displayName: "Acme", status: "ACTIVE", resourceVersion: 2,
  rootIdentity: { principalId: "primary-acme", loginName: "acme.owner" }, loginAlias: "acme"
};
const binding = { apiVersion, kind: "PolicyAttachment", id: "binding-viewer", accountId: "account-acme",
  target: { kind: "USER", id: "principal-alex" }, policyId: "policy-viewer", scope: "TENANT", resourceVersion: 3 };
const capability = (action: string, kind: string, id: string, available = true) => ({ action, resource: { kind, id }, available });
const identity = { apiVersion, kind: "CurrentIdentity", account, user: principal, identityKind: "USER",
  policySources: [], permissionBoundary: { apiVersion, kind: "UserPermissionBoundary", accountId: account.id,
    userId: principal.id, resourceVersion: principal.resourceVersion }, capabilities: [] };
const session = {
  apiVersion, kind: "Session", id: "session", organizationId: "account-acme", principalId: "principal-alex",
  status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z"
};
const authenticated = { outcome: "AUTHENTICATED", credential: "transient-bearer", mustChangePassword: false, session };

function reply(body: unknown) {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}

function requestBody(fetcher: ReturnType<typeof reply>) {
  return JSON.parse(firstRequest(fetcher)[1].body) as Record<string, unknown>;
}

function firstRequest(fetcher: ReturnType<typeof reply>) {
  const call = fetcher.mock.calls[0];
  if (!call) throw new Error("Expected an IAM request");
  return call;
}

afterEach(() => { vi.unstubAllGlobals(); });

describe("IAM HTTP account boundary", () => {
  it.each([undefined, true, false])("sends only the password session policy %s, never a retained-session selector", async (revokeOtherSessions) => {
    const fetcher = reply({ changedAt: "2026-08-28T01:02:03Z", bootstrapFileRetirable: false });
    const command = { currentPassword: "Current-Only-Test-Password-49!", newPassword: "New-Only-Test-Password-73!", revokeOtherSessions, sessionId: "forged-session", tenantId: "forged-tenant" };
    await httpIamRepository.changePassword("transient-bearer", command);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/password");
    expect(requestBody(fetcher)).toEqual({
      currentPassword: command.currentPassword, newPassword: command.newPassword, requestId: expect.any(String),
      ...(revokeOtherSessions === undefined ? {} : { revokeOtherSessions })
    });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("sends the qualified username as one login identifier", async () => {
    const fetcher = reply(authenticated);
    await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/login");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex@acme", password: "synthetic-test-password", requestId: expect.any(String) });
  });

  it("keeps login challenges sessionless and binds follow-up secrets to the path challenge", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-a", purpose: "LOGIN",
      nextStep: "TOTP", expiresAt: "2099-08-27T00:01:00Z" };
    let fetcher = reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "challenge-only-secret" });
    const challenged = await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(challenged).toEqual({ outcome: "CHALLENGE_REQUIRED", challenge: {
      id: challenge.id, purpose: "LOGIN", nextStep: "TOTP", expiresAt: challenge.expiresAt
    }, challengeCredential: "challenge-only-secret" });
    expect(JSON.stringify(challenged)).not.toContain("session");

    fetcher = reply(authenticated);
    const verified = await httpIamRepository.authenticationChallenges!.verify({
      challengeId: challenge.id, challengeCredential: "challenge-only-secret", code: "123456"
    });
    expect(verified.outcome).toBe("AUTHENTICATED");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-a:verify");
    expect(requestBody(fetcher)).toEqual({ requestId: expect.any(String), challengeCredential: "challenge-only-secret", code: "123456" });

    fetcher = reply({ nextStep: "REAUTHENTICATE", changedAt: "2026-08-27T00:02:00Z" });
    await httpIamRepository.authenticationChallenges!.changePassword({
      challengeId: challenge.id, challengeCredential: "rotated-challenge-secret", newPassword: "Changed-Password-73!"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-a:password");
    expect(requestBody(fetcher)).toEqual({ requestId: expect.any(String), challengeCredential: "rotated-challenge-secret", newPassword: "Changed-Password-73!" });
  });

  it("uses only a restricted challenge credential for first contact and TOTP enrollment", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-first", purpose: "ENROLLMENT",
      nextStep: "ENROLLMENT", expiresAt: "2026-08-27T01:05:00Z" };
    const contact = { apiVersion, kind: "NotificationContact", accountId: "account-acme", userId: "principal-alex",
      state: "NONE", resourceVersion: 0 };
    let fetcher = reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "first-only-secret" });
    const login = await httpIamRepository.login({ loginName: "alex@acme", password: "Initial-Password-49!" });
    expect(login).toEqual({ outcome: "CHALLENGE_REQUIRED", challenge: { id: challenge.id, purpose: "ENROLLMENT",
      nextStep: "ENROLLMENT", expiresAt: challenge.expiresAt }, challengeCredential: "first-only-secret" });
    expect(JSON.stringify(login)).not.toContain("session");

    fetcher = reply({ challenge, notificationContact: contact });
    const state = await httpIamRepository.authenticationChallenges!.inspectFirstEnrollment!({
      challengeId: challenge.id, challengeCredential: "first-only-secret" });
    expect(state.notificationContact?.state).toBe("NONE");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-first:enrollment-state");
    expect(requestBody(fetcher)).toEqual({ challengeCredential: "first-only-secret" });
    expect(JSON.stringify(firstRequest(fetcher)[1])).not.toContain("Bearer");

    const verification = { apiVersion, kind: "NotificationContactVerification", id: "verification-one",
      accountId: "account-acme", userId: "principal-alex", requestId: "contact-one", email: "first@example.test",
      state: "PENDING", issuedAt: "2026-08-27T01:00:00.000000Z", expiresAt: "2026-08-27T01:10:00.000000Z",
      delivery: { state: "PENDING", attempts: 0, updatedAt: "2026-08-27T01:00:00.000000Z" } };
    fetcher = reply(verification);
    await httpIamRepository.authenticationChallenges!.startFirstContact!({ challengeId: challenge.id,
      challengeCredential: "first-only-secret", email: verification.email, requestId: verification.requestId });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-first/notification-contact/verifications");
    expect(requestBody(fetcher)).toEqual({ challengeCredential: "first-only-secret", email: verification.email,
      requestId: verification.requestId });

    fetcher = reply({ ...verification, state: "VERIFIED", completedAt: "2026-08-27T01:01:00.000000Z" });
    await httpIamRepository.authenticationChallenges!.confirmFirstContact!({ challengeId: challenge.id,
      challengeCredential: "first-only-secret", verificationId: verification.id, code: "12345678", requestId: "confirm-one" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-first/notification-contact/verifications/verification-one:confirm");
    expect(requestBody(fetcher)).toEqual({ challengeCredential: "first-only-secret", code: "12345678", requestId: "confirm-one" });

    const enrollment = { apiVersion, kind: "TOTPEnrollment", id: "enrollment-one", requestId: "factor-one",
      purpose: "INITIAL", factorRevision: 1, state: "PENDING", createdAt: "2026-08-27T01:01:00.000000Z",
      expiresAt: "2026-08-27T01:05:00.000000Z" };
    fetcher = reply({ outcome: "APPLIED", enrollment, provisioning: { seed: "one-time-seed", uri: "otpauth://totp/Matrix:test?secret=one-time-seed" } });
    const started = await httpIamRepository.authenticationChallenges!.startFirstTOTP!({ challengeId: challenge.id,
      challengeCredential: "first-only-secret", requestId: enrollment.requestId });
    expect(started.outcome).toBe("APPLIED");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-first:enroll");
    expect(requestBody(fetcher)).toEqual({ challengeCredential: "first-only-secret", requestId: enrollment.requestId });

    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `private-recovery-${index}`);
    fetcher = reply({ enrollment: { ...enrollment, state: "CONFIRMED", completedAt: "2026-08-27T01:02:00.000000Z" },
      nextStep: "REAUTHENTICATE", recoveryCodes });
    const confirmed = await httpIamRepository.authenticationChallenges!.confirmFirstTOTP!({ challengeId: challenge.id,
      challengeCredential: "first-only-secret", enrollmentId: enrollment.id, code: "123456", requestId: "factor-confirm-one" });
    expect(confirmed.recoveryCodes).toEqual(recoveryCodes);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-first:confirm-enrollment");
    expect(requestBody(fetcher)).toEqual({ challengeCredential: "first-only-secret", code: "123456", requestId: "factor-confirm-one" });
  });

  it("rejects ambiguous first-enrollment state and replayed provisioning material", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-first", purpose: "ENROLLMENT",
      nextStep: "ENROLLMENT", expiresAt: "2026-08-27T01:05:00Z" };
    for (const state of [
      { challenge, notificationContact: { apiVersion, kind: "NotificationContact", accountId: "account-acme", userId: "principal-alex",
        state: "NONE", resourceVersion: 0 }, enrollment: { apiVersion, kind: "TOTPEnrollment", id: "factor-one", requestId: "factor-one",
          purpose: "INITIAL", factorRevision: 1, state: "PENDING", createdAt: "2026-08-27T01:01:00.000000Z", expiresAt: "2026-08-27T01:05:00.000000Z" } },
      { challenge: { ...challenge, purpose: "RECOVERY" }, notificationContact: { apiVersion, kind: "NotificationContact",
        accountId: "account-acme", userId: "principal-alex", state: "NONE", resourceVersion: 0 } }
    ]) {
      reply(state);
      await expect(httpIamRepository.authenticationChallenges!.inspectFirstEnrollment!({ challengeId: challenge.id,
        challengeCredential: "first-only-secret" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ outcome: "EQUAL_REPLAY", enrollment: { apiVersion, kind: "TOTPEnrollment", id: "factor-one",
      requestId: "factor-one", purpose: "INITIAL", factorRevision: 1, state: "PENDING",
      createdAt: "2026-08-27T01:01:00.000000Z", expiresAt: "2026-08-27T01:05:00.000000Z" },
      provisioning: { seed: "leaked", uri: "leaked" } });
    await expect(httpIamRepository.authenticationChallenges!.startFirstTOTP!({ challengeId: challenge.id,
      challengeCredential: "first-only-secret", requestId: "factor-one" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("rejects mixed, recovery-purpose or otherwise ambiguous login results", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-a", purpose: "LOGIN",
      nextStep: "TOTP", expiresAt: "2099-08-27T00:01:00Z" };
    for (const wire of [
      { ...authenticated, challenge },
      { outcome: "CHALLENGE_REQUIRED", challenge: { ...challenge, purpose: "RECOVERY", nextStep: "ENROLLMENT" }, challengeCredential: "secret" },
      { outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "secret", session },
      { ...authenticated, session: { ...session, kind: "Principal" } }
    ]) {
      reply(wire);
      await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" }))
        .rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("creates a user without an implicit role or caller-supplied tenant", async () => {
    const fetcher = reply(principal);
    const command = { kind: "create-user" as const, loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", tenantId: "forged" };
    await httpAccountRepository.execute("transient-bearer", command);
    expect(requestBody(fetcher)).toEqual({ loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", requestId: expect.any(String) });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("keeps user creation grant-free and uses the current account alias endpoint", async () => {
    let fetcher = reply(principal);
    await httpAccountRepository.execute("bearer", { kind: "create-user", loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", requestId: expect.any(String) });
    fetcher = reply(account);
    await httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account:alias");
    expect(requestBody(fetcher)).toEqual({ alias: "acme", resourceVersion: 1, requestId: expect.any(String) });
  });

  it("reads current account, user and capability projections without inventing a platform role", async () => {
    reply({ ...identity, capabilities: [capability("iam.account.create", "ACCOUNT", "collection")] });
    expect((await httpAccountRepository.currentIdentity("bearer")).capabilities[0]?.available).toBe(true);
    reply({ ...identity, user: { ...principal, id: account.rootIdentity.principalId }, identityKind: "ROOT_IDENTITY" });
    expect((await httpAccountRepository.currentIdentity("bearer")).identityKind).toBe("ROOT_IDENTITY");
    for (const patch of [{ user: { ...principal, accountId: "foreign" } }, { identityKind: "ROOT_IDENTITY" },
      { capabilities: [capability("iam.account.create", "ACCOUNT", "collection"), capability("iam.account.create", "ACCOUNT", "collection")] },
      { apiVersion: "future/v2" }]) {
      reply({ ...identity, ...patch });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads bounded current directories and rejects foreign or duplicate attachments", async () => {
    const entry = { user: principal, policyAttachments: [binding], capabilities: [] };
    const fetcher = reply({ apiVersion, kind: "UserList", items: [entry], nextAfter: "ic1.cursor" });
    const page = await httpAccountRepository.listUsers("bearer", "ic1.cursor");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users?after=ic1.cursor");
    expect(page.items[0]?.policyAttachments[0]?.policyId).toBe("policy-viewer");
    for (const attachments of [[{ ...binding, accountId: "foreign" }], [binding, binding]]) {
      reply({ apiVersion, kind: "UserList", items: [{ ...entry, policyAttachments: attachments }] });
      await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "UserList", items: Array.from({ length: 101 }, () => entry) });
    await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "AccountList", items: [{ account, capabilities: [] }] });
    expect((await httpAccountRepository.listAccounts("bearer")).items[0]?.account.id).toBe(account.id);
  });

  it("reads only the account-scoped active policy directory", async () => {
    const policy = { apiVersion, kind: "Policy", id: "policy-viewer", management: "SYSTEM",
      accountId: account.id, displayName: "Viewer", scope: "TENANT", status: "ACTIVE",
      defaultVersionId: "version-one", resourceVersion: 4 };
    const fetcher = reply({ apiVersion, kind: "PolicyList", accountId: account.id, scope: "TENANT", items: [policy] });
    expect((await httpAccountRepository.listPolicies("bearer"))[0]?.displayName).toBe("Viewer");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies");
    for (const changed of [{ ...policy, accountId: "foreign" }, { ...policy, scope: "INSTALLATION" },
      { ...policy, status: "RETIRED" }]) {
      reply({ apiVersion, kind: "PolicyList", accountId: account.id, scope: "TENANT", items: [changed] });
      await expect(httpAccountRepository.listPolicies("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("binds policy attach and revoke to exact user, policy and resource version", async () => {
    let fetcher = reply(binding);
    await httpAccountRepository.execute("bearer", { kind: "attach-policy", userId: principal.id, policyId: binding.policyId, policyResourceVersion: 4 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "USER", id: principal.id }, policyId: binding.policyId,
      policyResourceVersion: 4, requestId: expect.any(String) });
    fetcher = reply({ apiVersion, kind: "Revocation", id: binding.id });
    await httpAccountRepository.execute("bearer", { kind: "revoke-policy", attachmentId: binding.id, resourceVersion: binding.resourceVersion });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments/binding-viewer:revoke");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: binding.resourceVersion, requestId: expect.any(String) });
  });

  it("uses current account lifecycle routes without a caller-selected root", async () => {
    const disabled = { ...account, status: "DISABLED" };
    let fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "set-account-status", accountId: account.id, status: "DISABLED", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/accounts/account-acme:set-status");
    expect(requestBody(fetcher)).toEqual({ status: "DISABLED", resourceVersion: 1, requestId: expect.any(String) });
    fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "recover-root", accountId: account.id,
      initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/accounts/account-acme:recover-root-credentials");
    expect(requestBody(fetcher)).toEqual({ initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1, requestId: expect.any(String) });
  });

  it("rejects successful-looking responses for a different target or unchanged revision", async () => {
    reply({ ...principal, id: "another-user", status: "DISABLED" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-user-status", userId: principal.id,
      status: "DISABLED", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...binding, policyId: "other-policy" });
    await expect(httpAccountRepository.execute("bearer", { kind: "attach-policy", userId: principal.id,
      policyId: binding.policyId, policyResourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...account, status: "DISABLED", resourceVersion: 1 });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-account-status", accountId: account.id,
      status: "DISABLED", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});

describe("IAM HTTP personal security boundary", () => {
  const noneContact = {
    apiVersion,
    kind: "NotificationContact",
    accountId: "account-acme",
    userId: "principal-alex",
    state: "NONE",
    resourceVersion: 0
  };
  const pendingVerification = {
    apiVersion,
    kind: "NotificationContactVerification",
    id: "verification-one",
    accountId: "account-acme",
    userId: "principal-alex",
    requestId: "contact-request-one",
    email: "Alex.Security@mail.example.test",
    state: "PENDING",
    issuedAt: "2026-08-27T00:00:00.123456Z",
    expiresAt: "2026-08-27T00:10:00.123456Z",
    delivery: { state: "PENDING", attempts: 0, updatedAt: "2026-08-27T00:00:00.123456Z" }
  };
  const pendingEnrollment = {
    apiVersion,
    kind: "TOTPEnrollment",
    id: "enrollment-one",
    requestId: "enrollment-request-one",
    factorRevision: 1,
    state: "PENDING",
    createdAt: "2026-08-27T01:00:00.123456Z",
    expiresAt: "2026-08-27T01:05:00.123456Z"
  };

  it("uses only the current bearer and closed personal-security request bodies", async () => {
    let fetcher = reply(noneContact);
    expect(await httpIamRepository.personalSecurity!.notificationContact("transient-bearer")).toEqual({
      accountId: "account-acme", userId: "principal-alex", state: "NONE", resourceVersion: 0, pendingVerificationId: null
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact");
    expect(firstRequest(fetcher)[1]).toMatchObject({ headers: { Authorization: "Bearer transient-bearer" } });

    fetcher = reply(pendingVerification);
    await httpIamRepository.personalSecurity!.startNotificationVerification("transient-bearer", {
      email: pendingVerification.email,
      password: "Current-Test-Password-49!",
      requestId: pendingVerification.requestId
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact/verifications");
    expect(requestBody(fetcher)).toEqual({
      email: pendingVerification.email,
      password: "Current-Test-Password-49!",
      requestId: pendingVerification.requestId
    });

    fetcher = reply({ apiVersion, kind: "AuthenticatorState", enrollmentState: "NEVER_BOUND", factorRevision: 1 });
    expect(await httpIamRepository.personalSecurity!.authenticatorState("transient-bearer"))
      .toEqual({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/authenticators");

    fetcher = reply({ outcome: "APPLIED", enrollment: pendingEnrollment,
      provisioning: { seed: "ONE-TIME-SEED", uri: "otpauth://totp/Matrix:test?secret=ONE-TIME-SEED" } });
    await httpIamRepository.personalSecurity!.startTOTPEnrollment("transient-bearer", {
      requestId: pendingEnrollment.requestId,
      password: "Current-Test-Password-49!",
      expectedFactorRevision: 1
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/totp/enrollments");
    expect(requestBody(fetcher)).toEqual({
      requestId: pendingEnrollment.requestId,
      password: "Current-Test-Password-49!",
      expectedFactorRevision: 1
    });
  });

  it("never invents provisioning material for an equal replay and binds confirmation to one enrollment", async () => {
    let fetcher = reply({ outcome: "EQUAL_REPLAY", enrollment: pendingEnrollment });
    const replay = await httpIamRepository.personalSecurity!.startTOTPEnrollment("transient-bearer", {
      requestId: pendingEnrollment.requestId,
      password: "Current-Test-Password-49!",
      expectedFactorRevision: 1
    });
    expect(replay).toEqual({ outcome: "EQUAL_REPLAY", enrollment: expect.objectContaining({ id: "enrollment-one" }) });
    expect(JSON.stringify(replay)).not.toContain("seed");

    const confirmed = { ...pendingEnrollment, state: "CONFIRMED", completedAt: "2026-08-27T01:01:00.123456Z" };
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `recovery-code-${index}`);
    fetcher = reply({ enrollment: confirmed, nextStep: "REAUTHENTICATE", recoveryCodes });
    const result = await httpIamRepository.personalSecurity!.confirmTOTPEnrollment(
      "transient-bearer",
      pendingEnrollment.id,
      { requestId: "confirm-request-one", code: "123456" }
    );
    expect(result.recoveryCodes).toEqual(recoveryCodes);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/totp/enrollments/enrollment-one:confirm");
    expect(requestBody(fetcher)).toEqual({ requestId: "confirm-request-one", code: "123456" });
  });

  it("rejects ambiguous security projections, invalid chronology and repeated recovery material", async () => {
    for (const wire of [
      { ...noneContact, pendingVerificationId: "pending-one", email: "invented@mail.example.test" },
      { ...pendingVerification, expiresAt: "2026-08-27T00:09:59.123456Z" },
      { outcome: "EQUAL_REPLAY", enrollment: pendingEnrollment, provisioning: { seed: "leaked", uri: "leaked" } },
      { apiVersion, kind: "AuthenticatorState", enrollmentState: "BOUND", factorRevision: 1, factorId: "factor-one" }
    ]) {
      reply(wire);
      const action = "outcome" in wire
        ? httpIamRepository.personalSecurity!.startTOTPEnrollment("transient-bearer", {
            requestId: pendingEnrollment.requestId, password: "Current-Test-Password-49!", expectedFactorRevision: 1
          })
        : wire.kind === "AuthenticatorState"
          ? httpIamRepository.personalSecurity!.authenticatorState("transient-bearer")
          : wire.kind === "NotificationContactVerification"
            ? httpIamRepository.personalSecurity!.notificationVerification("transient-bearer", pendingVerification.id)
            : httpIamRepository.personalSecurity!.notificationContact("transient-bearer");
      await expect(action).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const confirmed = { ...pendingEnrollment, state: "CONFIRMED", completedAt: "2026-08-27T01:01:00.123456Z" };
    reply({ enrollment: confirmed, nextStep: "REAUTHENTICATE", recoveryCodes: Array(10).fill("same-code") });
    await expect(httpIamRepository.personalSecurity!.confirmTOTPEnrollment(
      "transient-bearer", pendingEnrollment.id, { requestId: "confirm-request-one", code: "123456" }
    )).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});
