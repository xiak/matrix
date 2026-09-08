// Package devopsbuildv1 owns the versioned cross-process contract between the
// Matrix DevOps build worker and an isolated build-executor gateway.
package devopsbuildv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	APIVersion     = "devopsbuild.adapter.matrix.xiak.com/v1"
	SubmissionKind = "BuildSubmission"
	ReceiptKind    = "BuildReceipt"

	MaximumDocumentBytes = 64 * 1024
)

var (
	ErrInvalidRequest    = errors.New("build request is invalid")
	ErrInvalidReceipt    = errors.New("build receipt is invalid")
	ErrInvalidDocument   = errors.New("build document is invalid")
	ErrInvalidSubmission = errors.New("build submission is invalid")
)

type Conclusion string
type StepConclusion string

const (
	ConclusionPassed    Conclusion = "PASSED"
	ConclusionFailed    Conclusion = "FAILED"
	ConclusionCancelled Conclusion = "CANCELLED"
)

const (
	StepConclusionPassed    StepConclusion = "PASSED"
	StepConclusionFailed    StepConclusion = "FAILED"
	StepConclusionCancelled StepConclusion = "CANCELLED"
	StepConclusionNotRun    StepConclusion = "NOT_RUN"
)

// Request is the complete, provider-neutral authority an executor needs. It
// contains neither source layout, mutable Pipeline configuration, arbitrary
// argv, environment values, nor a credential.
type Request struct {
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

type StepReceipt struct {
	Ordinal    uint32                        `json:"ordinal"`
	Kind       devopsv1.VerificationStepKind `json:"kind"`
	Conclusion StepConclusion                `json:"conclusion"`
}

// Receipt is the normalized terminal evidence returned by an executor.
// Native output, exit text, host paths, container IDs, and runner diagnostics
// are deliberately absent.
type Receipt struct {
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
	Conclusion             Conclusion               `json:"conclusion"`
	Steps                  [2]StepReceipt           `json:"steps"`
	ContentDigest          string                   `json:"contentDigest"`
}

type Submission struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Request    Request `json:"request"`
}

type ReceiptDocument struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Receipt    Receipt `json:"receipt"`
}

func ValidateRequest(value Request) error {
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
		validateCanonicalTime("build.startedAt", value.StartedAt),
		validateCanonicalTime("build.deadlineAt", value.DeadlineAt),
	)
	attemptText := strings.TrimPrefix(value.CommandID, string(value.RunID)+":verify:")
	attempt, attemptErr := strconv.ParseUint(attemptText, 10, 64)
	if attemptErr != nil || attempt < 1 || attempt > 100 ||
		strconv.FormatUint(attempt, 10) != attemptText ||
		value.CommandID != string(value.RunID)+":verify:"+attemptText {
		problems = append(problems, errors.New("build command identity is invalid"))
	}
	if value.SourceArchiveBytes < 1 ||
		value.SourceArchiveBytes > devopsv1.MaximumSourceArchiveBytes ||
		value.SourceExpandedBytes < 0 ||
		value.SourceExpandedBytes > devopsv1.MaximumSourceExpandedBytes ||
		value.SourcePathCount > devopsv1.MaximumSourcePathCount {
		problems = append(problems, errors.New("build source archive limits are invalid"))
	}
	if !validLowerHexID(string(value.PipelineRevisionID), "pipeline-revision-", 48) {
		problems = append(problems, errors.New("build PipelineRevision identity is invalid"))
	}
	if value.VerificationProfile != devopsv1.VerificationGo126OfflineV1 ||
		value.ExecutorProfile != devopsv1.ExecutorMatrixNativeIsolatedV1 ||
		value.ToolchainImageDigest != devopsv1.Go126OfflineToolchainImageDigest ||
		value.DependencyEgress != devopsv1.DependencyEgressNone ||
		value.Steps != fixedSteps() || value.Limits != devopsv1.FixedVerificationLimits() {
		problems = append(problems, errors.New("build execution profile is invalid"))
	}
	if value.DeadlineAt.Sub(value.StartedAt) !=
		time.Duration(devopsv1.FixedRunTimeoutSeconds)*time.Second {
		problems = append(problems, errors.New("build execution deadline is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	return nil
}

func ValidateReceipt(request Request, value Receipt) error {
	var problems []error
	problems = append(problems,
		ValidateRequest(request),
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
		if step.Ordinal != request.Steps[index].Ordinal || step.Kind != request.Steps[index].Kind {
			problems = append(problems, errors.New("build receipt step identity is invalid"))
			break
		}
	}
	if !validConclusions(value.Conclusion, value.Steps) {
		problems = append(problems, errors.New("build receipt conclusion is invalid"))
	}
	if value.ContentDigest != DigestReceipt(value) {
		problems = append(problems, errors.New("build receipt digest is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidReceipt, err)
	}
	return nil
}

func DigestReceipt(value Receipt) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-build-receipt-v1")
	for _, field := range []string{
		string(value.TenantID), string(value.RunID), value.CommandID,
		value.InputDigest, value.SourceArchiveDigest,
		string(value.PipelineRevisionID), value.PipelineRevisionDigest,
		value.ExecutorID, string(value.ExecutorProfile), value.ToolchainImageDigest,
		string(value.Conclusion),
	} {
		writeString(digest, field)
	}
	for _, step := range value.Steps {
		writeUint64(digest, uint64(step.Ordinal))
		writeString(digest, string(step.Kind))
		writeString(digest, string(step.Conclusion))
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

// ExecutionID is stable for every retry of one immutable VERIFY command. A
// gateway must still compare the complete Request and reject a changed replay.
func ExecutionID(value Request) (string, error) {
	if err := ValidateRequest(value); err != nil {
		return "", err
	}
	digest := sha256.New()
	writeString(digest, "matrix-devops-build-execution-v1")
	for _, field := range []string{
		value.CommandID,
		value.InputDigest,
		value.PipelineRevisionDigest,
		value.SourceArchiveDigest,
	} {
		writeString(digest, field)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func EncodeSubmission(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	return encodeDocument(Submission{
		APIVersion: APIVersion,
		Kind:       SubmissionKind,
		Request:    request,
	})
}

func DecodeSubmission(content []byte) (Request, error) {
	var document Submission
	if err := decodeDocument(content, &document); err != nil ||
		document.APIVersion != APIVersion || document.Kind != SubmissionKind ||
		ValidateRequest(document.Request) != nil {
		return Request{}, ErrInvalidDocument
	}
	canonical, err := EncodeSubmission(document.Request)
	if err != nil || !bytes.Equal(canonical, content) {
		return Request{}, ErrInvalidDocument
	}
	return document.Request, nil
}

func EncodeReceipt(request Request, receipt Receipt) ([]byte, error) {
	if err := ValidateReceipt(request, receipt); err != nil {
		return nil, err
	}
	return encodeDocument(ReceiptDocument{
		APIVersion: APIVersion,
		Kind:       ReceiptKind,
		Receipt:    receipt,
	})
}

func DecodeReceipt(request Request, content []byte) (Receipt, error) {
	var document ReceiptDocument
	if err := decodeDocument(content, &document); err != nil ||
		document.APIVersion != APIVersion || document.Kind != ReceiptKind ||
		ValidateReceipt(request, document.Receipt) != nil {
		return Receipt{}, ErrInvalidDocument
	}
	canonical, err := EncodeReceipt(request, document.Receipt)
	if err != nil || !bytes.Equal(canonical, content) {
		return Receipt{}, ErrInvalidDocument
	}
	return document.Receipt, nil
}

// WriteSubmission writes an eight-byte big-endian metadata length, one
// canonical Submission document, and exactly the request's archive bytes.
func WriteSubmission(destination io.Writer, request Request, archive io.Reader) error {
	if destination == nil || archive == nil {
		return ErrInvalidSubmission
	}
	metadata, err := EncodeSubmission(request)
	if err != nil {
		return errors.Join(ErrInvalidSubmission, err)
	}
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(len(metadata)))
	if err := writeAll(destination, header[:]); err != nil {
		return errors.Join(ErrInvalidSubmission, err)
	}
	if err := writeAll(destination, metadata); err != nil {
		return errors.Join(ErrInvalidSubmission, err)
	}
	if err := copyArchive(destination, archive, request); err != nil {
		return errors.Join(ErrInvalidSubmission, err)
	}
	return nil
}

// ReadSubmission validates the frame and archive while streaming the archive
// into caller-owned staging storage. Staging must be discarded on any error.
func ReadSubmission(source io.Reader, archiveDestination io.Writer) (Request, error) {
	if source == nil || archiveDestination == nil {
		return Request{}, ErrInvalidSubmission
	}
	var header [8]byte
	if _, err := io.ReadFull(source, header[:]); err != nil {
		return Request{}, errors.Join(ErrInvalidSubmission, err)
	}
	metadataBytes := binary.BigEndian.Uint64(header[:])
	if metadataBytes == 0 || metadataBytes > MaximumDocumentBytes {
		return Request{}, ErrInvalidSubmission
	}
	metadata := make([]byte, int(metadataBytes))
	if _, err := io.ReadFull(source, metadata); err != nil {
		return Request{}, errors.Join(ErrInvalidSubmission, err)
	}
	request, err := DecodeSubmission(metadata)
	if err != nil {
		return Request{}, errors.Join(ErrInvalidSubmission, err)
	}
	if err := copyArchive(archiveDestination, source, request); err != nil {
		return Request{}, errors.Join(ErrInvalidSubmission, err)
	}
	return request, nil
}

func encodeDocument(value any) ([]byte, error) {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > MaximumDocumentBytes {
		return nil, ErrInvalidDocument
	}
	return content, nil
}

func decodeDocument(content []byte, destination any) error {
	if len(content) == 0 || len(content) > MaximumDocumentBytes {
		return ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.Join(ErrInvalidDocument, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidDocument
	}
	return nil
}

func copyArchive(destination io.Writer, source io.Reader, request Request) error {
	digest := sha256.New()
	written, err := io.CopyN(
		io.MultiWriter(destination, digest),
		source,
		request.SourceArchiveBytes,
	)
	if err != nil || written != request.SourceArchiveBytes {
		return errors.New("build archive length is invalid")
	}
	var trailing [1]byte
	trailingBytes, trailingErr := source.Read(trailing[:])
	if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) {
		return errors.New("build archive has trailing content")
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if actualDigest != request.SourceArchiveDigest {
		return errors.New("build archive digest is invalid")
	}
	return nil
}

func writeAll(destination io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := destination.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func fixedSteps() [2]devopsv1.VerificationStep {
	steps := devopsv1.FixedVerificationSteps()
	return [2]devopsv1.VerificationStep{steps[0], steps[1]}
}

func validConclusions(conclusion Conclusion, steps [2]StepReceipt) bool {
	left := steps[0].Conclusion
	right := steps[1].Conclusion
	switch conclusion {
	case ConclusionPassed:
		return left == StepConclusionPassed && right == StepConclusionPassed
	case ConclusionFailed:
		return (left == StepConclusionFailed && right == StepConclusionNotRun) ||
			(left == StepConclusionPassed && right == StepConclusionFailed)
	case ConclusionCancelled:
		return (left == StepConclusionCancelled && right == StepConclusionNotRun) ||
			(left == StepConclusionPassed && right == StepConclusionCancelled)
	default:
		return false
	}
}

func validateCanonicalTime(name string, value time.Time) error {
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

func writeString(destination hash.Hash, value string) {
	writeUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeUint64(destination hash.Hash, value uint64) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], value)
	_, _ = destination.Write(framed[:])
}
