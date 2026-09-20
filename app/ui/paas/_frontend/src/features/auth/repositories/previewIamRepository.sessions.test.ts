import { afterEach, describe, expect, it } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { previewCredential, previewIamRepository, resetPreviewEnvironment } from "./previewIamRepository";

afterEach(async () => {
  await previewIamRepository.logout(previewCredential);
  resetPreviewEnvironment();
});

describe("preview own login sessions", () => {
  it("ends the restricted credential after a forced password change", async () => {
    const login = await previewIamRepository.login({
      loginName: "preview-admin",
      password: "Initial-Admin-Password-49!"
    });

    await previewIamRepository.changePassword(login.credential, {
      currentPassword: "Initial-Admin-Password-49!",
      newPassword: "Changed-Admin-Password-73!"
    });

    await expect(previewIamRepository.sessions!.list(login.credential)).rejects.toMatchObject({ status: 401 });
    const nextLogin = await previewIamRepository.login({
      loginName: "preview-admin",
      password: "Changed-Admin-Password-73!"
    });
    expect(nextLogin.credential).not.toBe(login.credential);
  });

  it("models login sessions rather than physical devices or online activity", async () => {
    const page = await previewIamRepository.sessions!.list(previewCredential);
    expect(page.currentSessionId).toBe("session-ux-preview");
    expect(page.items.map((item) => item.id)).toEqual([
      "session-ux-preview",
      "session-ux-preview-002",
      "session-ux-preview-003"
    ]);
    expect(page.items.every((item) => item.organizationId === page.accountId && item.principalId === page.userId)).toBe(true);
    expect(page).not.toHaveProperty("devices");
    expect(page).not.toHaveProperty("online");
  });

  it("replays one exact revocation and never permits the current session endpoint", async () => {
    const first = await previewIamRepository.sessions!.revoke(previewCredential, "session-ux-preview-002", "preview-revoke-1");
    const replay = await previewIamRepository.sessions!.revoke(previewCredential, "session-ux-preview-002", "preview-revoke-1");
    expect(first.outcome).toBe("APPLIED");
    expect(replay).toEqual({ ...first, outcome: "EQUAL_REPLAY" });
    expect((await previewIamRepository.sessions!.list(previewCredential)).items.map((item) => item.id)).not.toContain("session-ux-preview-002");
    await expect(previewIamRepository.sessions!.revoke(previewCredential, "session-ux-preview-003", "preview-revoke-1")).rejects.toBeInstanceOf(HttpProblem);
    await expect(previewIamRepository.sessions!.revoke(previewCredential, "session-ux-preview", "preview-revoke-current")).rejects.toMatchObject({ status: 409 });
  });

  it("atomically ends every other session and preserves an exact replay receipt", async () => {
    const first = await previewIamRepository.sessions!.revokeOthers(previewCredential, "preview-revoke-others-1");
    const replay = await previewIamRepository.sessions!.revokeOthers(previewCredential, "preview-revoke-others-1");
    expect(first).toMatchObject({
      outcome: "APPLIED",
      accountId: "org-xiak",
      userId: "principal-admin",
      currentSessionId: "session-ux-preview",
      requestId: "preview-revoke-others-1",
      revokedCount: 2
    });
    expect(replay).toEqual({ ...first, outcome: "EQUAL_REPLAY" });
    expect((await previewIamRepository.sessions!.list(previewCredential)).items.map((item) => item.id)).toEqual(["session-ux-preview"]);
  });
});
