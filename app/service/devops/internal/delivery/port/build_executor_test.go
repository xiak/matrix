package port

import (
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func TestBuildRequestClosesExecutorAuthority(t *testing.T) {
	valid := buildRequestFixture()
	if err := ValidateBuildRequest(valid); err != nil {
		t.Fatalf("validate build request: %v", err)
	}
	tests := map[string]func(*BuildRequest){
		"tenant": func(value *BuildRequest) { value.TenantID = "invalid tenant" },
		"stage": func(value *BuildRequest) {
			value.CommandID = string(value.RunID) + ":report:1"
		},
		"attempt": func(value *BuildRequest) {
			value.CommandID = string(value.RunID) + ":verify:01"
		},
		"archive digest": func(value *BuildRequest) { value.SourceArchiveDigest = "sha256:changed" },
		"archive bytes":  func(value *BuildRequest) { value.SourceArchiveBytes = 0 },
		"expanded bytes": func(value *BuildRequest) {
			value.SourceExpandedBytes = sourcearchive.MaximumExpandedBytes + 1
		},
		"path count": func(value *BuildRequest) {
			value.SourcePathCount = sourcearchive.MaximumPathCount + 1
		},
		"revision": func(value *BuildRequest) { value.PipelineRevisionID = "revision-other" },
		"verification profile": func(value *BuildRequest) {
			value.VerificationProfile = "ARBITRARY"
		},
		"executor profile": func(value *BuildRequest) { value.ExecutorProfile = "HOST_SHELL" },
		"toolchain":        func(value *BuildRequest) { value.ToolchainImageDigest = digestOf('f') },
		"egress":           func(value *BuildRequest) { value.DependencyEgress = "INTERNET" },
		"steps": func(value *BuildRequest) {
			value.Steps[0], value.Steps[1] = value.Steps[1], value.Steps[0]
		},
		"limits": func(value *BuildRequest) { value.Limits.CPUMillis++ },
		"time precision": func(value *BuildRequest) {
			value.StartedAt = value.StartedAt.Add(time.Nanosecond)
		},
		"deadline": func(value *BuildRequest) { value.DeadlineAt = value.DeadlineAt.Add(time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if ValidateBuildRequest(candidate) == nil {
				t.Fatal("meaning-changing build request was accepted")
			}
		})
	}
}

func TestBuildReceiptBindsRequestAndClosedStepOutcomes(t *testing.T) {
	request := buildRequestFixture()
	receipts := map[string]BuildReceipt{
		"passed":         buildReceiptFixture(request, BuildPassed, BuildStepPassed, BuildStepPassed),
		"test failed":    buildReceiptFixture(request, BuildFailed, BuildStepFailed, BuildStepNotRun),
		"vet failed":     buildReceiptFixture(request, BuildFailed, BuildStepPassed, BuildStepFailed),
		"test cancelled": buildReceiptFixture(request, BuildCancelled, BuildStepCancelled, BuildStepNotRun),
		"vet cancelled":  buildReceiptFixture(request, BuildCancelled, BuildStepPassed, BuildStepCancelled),
	}
	for name, receipt := range receipts {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBuildReceipt(request, receipt); err != nil {
				t.Fatalf("validate build receipt: %v", err)
			}
		})
	}

	valid := receipts["passed"]
	tests := map[string]func(*BuildReceipt){
		"command":    func(value *BuildReceipt) { value.CommandID = string(request.RunID) + ":verify:2" },
		"executor":   func(value *BuildReceipt) { value.ExecutorID = "invalid executor" },
		"source":     func(value *BuildReceipt) { value.SourceArchiveDigest = digestOf('e') },
		"profile":    func(value *BuildReceipt) { value.ExecutorProfile = "HOST" },
		"step kind":  func(value *BuildReceipt) { value.Steps[0].Kind = devopsv1.VerificationStepGoVet },
		"impossible": func(value *BuildReceipt) { value.Steps[1].Conclusion = BuildStepNotRun },
		"digest":     func(value *BuildReceipt) { value.ContentDigest = digestOf('d') },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if ValidateBuildReceipt(request, candidate) == nil {
				t.Fatal("meaning-changing build receipt was accepted")
			}
		})
	}
}

func buildRequestFixture() BuildRequest {
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat("a", 48))
	startedAt := time.Date(2026, 9, 8, 10, 11, 12, 123000, time.UTC)
	return BuildRequest{
		TenantID: "tenant-one", RunID: runID,
		CommandID: string(runID) + ":verify:1", InputDigest: digestOf('1'),
		SourceArchiveDigest: digestOf('2'), SourceArchiveBytes: 1024,
		SourceExpandedBytes: 4096, SourcePathCount: 3,
		PipelineRevisionID:     "pipeline-revision-" + devopsv1.ResourceID(strings.Repeat("b", 48)),
		PipelineRevisionDigest: digestOf('3'),
		VerificationProfile:    devopsv1.VerificationGo126OfflineV1,
		ExecutorProfile:        devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:   devopsv1.Go126OfflineToolchainImageDigest,
		DependencyEgress:       devopsv1.DependencyEgressNone,
		Steps: [2]devopsv1.VerificationStep{
			{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
			{Ordinal: 2, Kind: devopsv1.VerificationStepGoVet},
		},
		Limits: devopsv1.FixedVerificationLimits(), StartedAt: startedAt,
		DeadlineAt: startedAt.Add(time.Duration(devopsv1.FixedRunTimeoutSeconds) * time.Second),
	}
}

func buildReceiptFixture(
	request BuildRequest,
	conclusion BuildConclusion,
	first BuildStepConclusion,
	second BuildStepConclusion,
) BuildReceipt {
	value := BuildReceipt{
		TenantID: request.TenantID, RunID: request.RunID,
		CommandID: request.CommandID, InputDigest: request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             "executor-one", ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest, Conclusion: conclusion,
		Steps: [2]BuildStepReceipt{
			{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Conclusion: first},
			{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Conclusion: second},
		},
	}
	value.ContentDigest = DigestBuildReceipt(value)
	return value
}

func digestOf(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
