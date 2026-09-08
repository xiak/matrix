package port

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

type BuildConclusion string
type BuildStepConclusion string

const (
	BuildPassed    BuildConclusion = "PASSED"
	BuildFailed    BuildConclusion = "FAILED"
	BuildCancelled BuildConclusion = "CANCELLED"
)

const (
	BuildStepPassed    BuildStepConclusion = "PASSED"
	BuildStepFailed    BuildStepConclusion = "FAILED"
	BuildStepCancelled BuildStepConclusion = "CANCELLED"
	BuildStepNotRun    BuildStepConclusion = "NOT_RUN"
)

var (
	// ErrBuildUnavailable means the adapter definitively did not retain an
	// accepted or terminal execution for this command.
	ErrBuildUnavailable = errors.New("build executor is unavailable")
	// ErrBuildOutcomeUnknown means an effect may exist. The caller must retain
	// the same command and let a later fence observe it rather than execute it.
	ErrBuildOutcomeUnknown = errors.New("build execution outcome is unknown")
	// ErrBuildConflict means the executor associated the deterministic command
	// identity with different immutable input.
	ErrBuildConflict = errors.New("build execution identity conflicts")
)

// BuildRequest is the complete, provider-neutral authority an executor needs.
// It contains neither source layout, mutable Pipeline configuration, arbitrary
// argv, environment values, nor a credential.
type BuildRequest struct {
	TenantID               devopsv1.TenantID               `json:"tenantId"`
	RunID                  devopsv1.ResourceID             `json:"runId"`
	CommandID              string                          `json:"commandId"`
	InputDigest            string                          `json:"inputDigest"`
	SourceArchiveDigest    string                          `json:"sourceArchiveDigest"`
	SourceArchiveBytes     int64                           `json:"sourceArchiveBytes"`
	SourceExpandedBytes    int64                           `json:"sourceExpandedBytes"`
	SourcePathCount        uint64                          `json:"sourcePathCount"`
	PipelineRevisionID     devopsv1.ResourceID             `json:"pipelineRevisionId"`
	PipelineRevisionDigest string                          `json:"pipelineRevisionDigest"`
	VerificationProfile    devopsv1.VerificationProfile    `json:"verificationProfile"`
	ExecutorProfile        devopsv1.ExecutorProfile        `json:"executorProfile"`
	ToolchainImageDigest   string                          `json:"toolchainImageDigest"`
	DependencyEgress       devopsv1.DependencyEgressPolicy `json:"dependencyEgress"`
	Steps                  [2]devopsv1.VerificationStep    `json:"steps"`
	Limits                 devopsv1.VerificationLimits     `json:"limits"`
	StartedAt              time.Time                       `json:"startedAt"`
	DeadlineAt             time.Time                       `json:"deadlineAt"`
}

type BuildStepReceipt struct {
	Ordinal    uint32                        `json:"ordinal"`
	Kind       devopsv1.VerificationStepKind `json:"kind"`
	Conclusion BuildStepConclusion           `json:"conclusion"`
}

// BuildReceipt is the normalized terminal evidence returned by an executor.
// Native output, exit text, host paths, container IDs, and runner diagnostics
// are deliberately absent.
type BuildReceipt struct {
	TenantID               devopsv1.TenantID        `json:"tenantId"`
	RunID                  devopsv1.ResourceID      `json:"runId"`
	CommandID              string                   `json:"commandId"`
	InputDigest            string                   `json:"inputDigest"`
	SourceArchiveDigest    string                   `json:"sourceArchiveDigest"`
	PipelineRevisionID     devopsv1.ResourceID      `json:"pipelineRevisionId"`
	PipelineRevisionDigest string                   `json:"pipelineRevisionDigest"`
	ExecutorID             string                   `json:"executorId"`
	ExecutorProfile        devopsv1.ExecutorProfile `json:"executorProfile"`
	ToolchainImageDigest   string                   `json:"toolchainImageDigest"`
	Conclusion             BuildConclusion          `json:"conclusion"`
	Steps                  [2]BuildStepReceipt      `json:"steps"`
	ContentDigest          string                   `json:"contentDigest"`
}

// BuildExecutor is the only delivery boundary allowed to execute untrusted
// verification code. A first fence may Execute; takeover fences may only
// Observe or Cancel the same deterministic command.
type BuildExecutor interface {
	Execute(context.Context, BuildRequest, io.Reader) (BuildReceipt, error)
	Observe(context.Context, BuildRequest) (BuildReceipt, bool, error)
	Cancel(context.Context, BuildRequest) (BuildReceipt, bool, error)
}

func ValidateBuildRequest(value BuildRequest) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("build.tenantId", string(value.TenantID)),
		devopsv1.ValidatePipelineRunID("build.runId", value.RunID),
		devopsv1.ValidateID("build.commandId", value.CommandID),
		devopsv1.ValidateDigest("build.inputDigest", value.InputDigest),
		devopsv1.ValidateDigest("build.sourceArchiveDigest", value.SourceArchiveDigest),
		devopsv1.ValidateID("build.pipelineRevisionId", string(value.PipelineRevisionID)),
		devopsv1.ValidateDigest("build.pipelineRevisionDigest", value.PipelineRevisionDigest),
		devopsv1.ValidateDigest("build.toolchainImageDigest", value.ToolchainImageDigest),
		validateCanonicalBuildTime("build.startedAt", value.StartedAt),
		validateCanonicalBuildTime("build.deadlineAt", value.DeadlineAt),
	)
	attemptText := strings.TrimPrefix(
		value.CommandID,
		string(value.RunID)+":verify:",
	)
	attempt, attemptErr := strconv.ParseUint(attemptText, 10, 64)
	if attemptErr != nil || attempt < 1 || attempt > 100 ||
		strconv.FormatUint(attempt, 10) != attemptText ||
		value.CommandID != string(value.RunID)+":verify:"+attemptText {
		problems = append(problems, errors.New("build command identity is invalid"))
	}
	if value.SourceArchiveBytes < 1 || value.SourceArchiveBytes > sourcearchive.MaximumArchiveBytes ||
		value.SourceExpandedBytes < 0 || value.SourceExpandedBytes > sourcearchive.MaximumExpandedBytes ||
		value.SourcePathCount > sourcearchive.MaximumPathCount {
		problems = append(problems, errors.New("build source archive limits are invalid"))
	}
	if !validLowerHexID(string(value.PipelineRevisionID), "pipeline-revision-", 48) {
		problems = append(problems, errors.New("build PipelineRevision identity is invalid"))
	}
	wantSteps := fixedBuildSteps()
	if value.VerificationProfile != devopsv1.VerificationGo126OfflineV1 ||
		value.ExecutorProfile != devopsv1.ExecutorMatrixNativeIsolatedV1 ||
		value.ToolchainImageDigest != devopsv1.Go126OfflineToolchainImageDigest ||
		value.DependencyEgress != devopsv1.DependencyEgressNone ||
		value.Steps != wantSteps ||
		value.Limits != devopsv1.FixedVerificationLimits() {
		problems = append(problems, errors.New("build execution profile is invalid"))
	}
	if value.DeadlineAt.Sub(value.StartedAt) != time.Duration(devopsv1.FixedRunTimeoutSeconds)*time.Second {
		problems = append(problems, errors.New("build execution deadline is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateBuildReceipt(request BuildRequest, value BuildReceipt) error {
	var problems []error
	problems = append(problems,
		ValidateBuildRequest(request),
		devopsv1.ValidateID("buildReceipt.executorId", value.ExecutorID),
		devopsv1.ValidateDigest("buildReceipt.contentDigest", value.ContentDigest),
	)
	if value.TenantID != request.TenantID || value.RunID != request.RunID ||
		value.CommandID != request.CommandID || value.InputDigest != request.InputDigest ||
		value.SourceArchiveDigest != request.SourceArchiveDigest ||
		value.PipelineRevisionID != request.PipelineRevisionID ||
		value.PipelineRevisionDigest != request.PipelineRevisionDigest ||
		value.ExecutorProfile != request.ExecutorProfile ||
		value.ToolchainImageDigest != request.ToolchainImageDigest {
		problems = append(problems, errors.New("build receipt does not bind its request"))
	}
	for index, step := range value.Steps {
		if step.Ordinal != request.Steps[index].Ordinal ||
			step.Kind != request.Steps[index].Kind {
			problems = append(problems, errors.New("build receipt step identity is invalid"))
			break
		}
	}
	if !validBuildConclusions(value.Conclusion, value.Steps) {
		problems = append(problems, errors.New("build receipt conclusion is invalid"))
	}
	if value.ContentDigest != DigestBuildReceipt(value) {
		problems = append(problems, errors.New("build receipt digest is invalid"))
	}
	return errors.Join(problems...)
}

func DigestBuildReceipt(value BuildReceipt) string {
	digest := sha256.New()
	writeBuildString(digest, "matrix-devops-build-receipt-v1")
	for _, field := range []string{
		string(value.TenantID), string(value.RunID), value.CommandID,
		value.InputDigest, value.SourceArchiveDigest,
		string(value.PipelineRevisionID), value.PipelineRevisionDigest,
		value.ExecutorID, string(value.ExecutorProfile), value.ToolchainImageDigest,
		string(value.Conclusion),
	} {
		writeBuildString(digest, field)
	}
	for _, step := range value.Steps {
		writeBuildUint64(digest, uint64(step.Ordinal))
		writeBuildString(digest, string(step.Kind))
		writeBuildString(digest, string(step.Conclusion))
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func fixedBuildSteps() [2]devopsv1.VerificationStep {
	steps := devopsv1.FixedVerificationSteps()
	return [2]devopsv1.VerificationStep{steps[0], steps[1]}
}

func validBuildConclusions(
	conclusion BuildConclusion,
	steps [2]BuildStepReceipt,
) bool {
	left := steps[0].Conclusion
	right := steps[1].Conclusion
	switch conclusion {
	case BuildPassed:
		return left == BuildStepPassed && right == BuildStepPassed
	case BuildFailed:
		return (left == BuildStepFailed && right == BuildStepNotRun) ||
			(left == BuildStepPassed && right == BuildStepFailed)
	case BuildCancelled:
		return (left == BuildStepCancelled && right == BuildStepNotRun) ||
			(left == BuildStepPassed && right == BuildStepCancelled)
	default:
		return false
	}
}

func validateCanonicalBuildTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return errors.New(name + " is invalid")
	}
	return nil
}

func validLowerHexID(value, prefix string, digits int) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+digits {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func writeBuildString(destination hash.Hash, value string) {
	writeBuildUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeBuildUint64(destination hash.Hash, value uint64) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], value)
	_, _ = destination.Write(framed[:])
}
