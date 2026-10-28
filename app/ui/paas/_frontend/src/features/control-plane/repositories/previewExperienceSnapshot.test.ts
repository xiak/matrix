import { describe, expect, it } from "vitest";
import { previewExperienceSnapshot, previewExperienceSnapshotForLocale } from "./previewExperienceSnapshot";

describe("previewExperienceSnapshotForLocale", () => {
  it("keeps the source preview snapshot for Simplified Chinese", () => {
    expect(previewExperienceSnapshotForLocale("zh-CN")).toBe(previewExperienceSnapshot);
  });

  it("provides English preview data without changing resource identity", () => {
    const english = previewExperienceSnapshotForLocale("en");

    expect(JSON.stringify(english)).not.toMatch(/[\u3400-\u9fff]/u);
    expect(english.resources.map(({ id, href }) => ({ id, href }))).toEqual(
      previewExperienceSnapshot.resources.map(({ id, href }) => ({ id, href }))
    );
    expect(english.organization).toEqual({ id: "org-xiak", name: "Xiak Technology" });
  });
});
