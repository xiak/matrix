import { afterEach, describe, expect, it } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { previewCredential, previewIamRepository } from "./previewIamRepository";

afterEach(async () => {
  await previewIamRepository.logout(previewCredential);
});

describe("preview own login sessions", () => {
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
});
