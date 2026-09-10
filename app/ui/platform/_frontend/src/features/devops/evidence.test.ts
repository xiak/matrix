import { describe, expect, it } from "vitest";
import { mergeLogs } from "./RunLogs";
import { safeCLIIdentity, safeCLIOrigin } from "./SourceOperatorInstructions";
import type { PipelineRunLogPage } from "@/api/devopsContract";
describe("public source and execution evidence", () => {
  it("never interpolates untrusted shell syntax into operator instructions", () => {
    for (const input of ["a; rm", "$(whoami)", "a\nb", "'x'", "a b"]) expect(safeCLIIdentity(input)).toBe("<reference>");
    expect(safeCLIIdentity("ref-fetch-01")).toBe("ref-fetch-01");
    for (const input of ["http://git.example", "https://git.example/x", "https://u:p@git.example", "https://localhost", "https://git.example;whoami"]) expect(safeCLIOrigin(input)).toBe("<canonical-https-origin>");
    expect(safeCLIOrigin("https://git.example:3443")).toBe("https://git.example:3443");
  });
  it("bounds and correlates log pagination instead of treating it as arbitrary text", () => {
    const page: PipelineRunLogPage = { apiVersion: "devops.matrix.xiak.com/v1", kind: "PipelineRunLogPage", runId: "run-a", afterSequence: 0, nextSequence: 1, hasMore: false, truncated: false, readAt: "2026-09-10T10:00:00Z", chunks: [{ content: "<script>alert(1)</script>", expiresAt: "2026-09-11T10:00:00Z", sequence: 1, step: { kind: "GO_TEST", ordinal: 1 } }] };
    expect(mergeLogs("run-a", 0, [], page).chunks).toEqual(page.chunks);
    expect(() => mergeLogs("run-b", 0, [], page)).toThrow();
    expect(() => mergeLogs("run-a", 1, [], page)).toThrow();
    expect(() => mergeLogs("run-a", 0, [], { ...page, nextSequence: 0 })).toThrow();
  });
});
