import { describe, expect, it } from "vitest";
import { accessFindingRecoveryState, hasAccessRecoveryGap, type AccessFindingRecoveryEvidence, type AccessObservationCoverage } from "./accessAnalysis";

const baseline: AccessFindingRecoveryEvidence = {
  recoveryEpoch: 0,
  recoveryCommandId: null,
  recoveryCompletedAt: null,
  windowStartedAt: "2026-06-11T03:00:00Z"
};

describe("access-analysis recovery trust", () => {
  it("distinguishes the baseline from a recovery-bound observation window", () => {
    expect(accessFindingRecoveryState(baseline)).toBe("BASELINE");
    expect(accessFindingRecoveryState({
      recoveryEpoch: 2,
      recoveryCommandId: "recovery-command-2",
      recoveryCompletedAt: "2026-06-10T03:00:00Z",
      windowStartedAt: "2026-06-11T03:00:00Z"
    })).toBe("POST_RECOVERY");
  });

  it.each<AccessFindingRecoveryEvidence>([
    { ...baseline, recoveryCommandId: "unexpected" },
    { ...baseline, recoveryEpoch: 1 },
    { ...baseline, recoveryEpoch: 1, recoveryCommandId: "   ", recoveryCompletedAt: "2026-06-10T03:00:00Z" },
    { ...baseline, recoveryEpoch: 1, recoveryCommandId: "recovery-command-1", recoveryCompletedAt: "invalid" },
    { ...baseline, recoveryEpoch: 1, recoveryCommandId: "recovery-command-1", recoveryCompletedAt: "2026-06-12T03:00:00Z" }
  ])("fails closed for inconsistent recovery provenance", (evidence) => {
    expect(() => accessFindingRecoveryState(evidence)).toThrow("INVALID_ACCESS_FINDING_RECOVERY");
  });

  it("detects a restore gap without treating other incomplete sources as recovery", () => {
    const coverage: AccessObservationCoverage[] = [{
      source: "IAM_PASSWORD_SESSIONS",
      state: "INSUFFICIENT_COVERAGE",
      observedFrom: "2026-06-11T03:00:00Z",
      observedThrough: "2026-06-12T03:00:00Z",
      reason: "RESTORE_GAP"
    }];
    expect(hasAccessRecoveryGap(coverage)).toBe(true);
    expect(hasAccessRecoveryGap([{
      source: "IAM_PASSWORD_SESSIONS",
      state: "INSUFFICIENT_COVERAGE",
      observedFrom: "2026-06-11T03:00:00Z",
      observedThrough: "2026-06-12T03:00:00Z",
      reason: "OBSERVATION_WINDOW_INCOMPLETE"
    }])).toBe(false);
  });
});
