package devopsbuildv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestRequestClosesExecutorAuthority(t *testing.T) {
	valid := requestFixture([]byte("canonical source archive"))
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("validate build request: %v", err)
	}
	tests := map[string]func(*Request){
		"tenant": func(value *Request) { value.TenantID = "invalid tenant" },
		"stage": func(value *Request) {
			value.CommandID = string(value.RunID) + ":report:1"
		},
		"attempt": func(value *Request) {
			value.CommandID = string(value.RunID) + ":verify:01"
		},
		"archive digest": func(value *Request) { value.SourceArchiveDigest = "sha256:changed" },
		"archive bytes":  func(value *Request) { value.SourceArchiveBytes = 0 },
		"expanded bytes": func(value *Request) {
			value.SourceExpandedBytes = devopsv1.MaximumSourceExpandedBytes + 1
		},
		"path count": func(value *Request) {
			value.SourcePathCount = devopsv1.MaximumSourcePathCount + 1
		},
		"revision": func(value *Request) { value.PipelineRevisionID = "revision-other" },
		"verification profile": func(value *Request) {
			value.VerificationProfile = "ARBITRARY"
		},
		"executor profile": func(value *Request) { value.ExecutorProfile = "HOST_SHELL" },
		"toolchain":        func(value *Request) { value.ToolchainImageDigest = digestOf('f') },
		"egress":           func(value *Request) { value.DependencyEgress = "INTERNET" },
		"steps": func(value *Request) {
			value.Steps[0], value.Steps[1] = value.Steps[1], value.Steps[0]
		},
		"limits": func(value *Request) { value.Limits.CPUMillis++ },
		"time precision": func(value *Request) {
			value.StartedAt = value.StartedAt.Add(time.Nanosecond)
		},
		"deadline": func(value *Request) { value.DeadlineAt = value.DeadlineAt.Add(time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if ValidateRequest(candidate) == nil {
				t.Fatal("meaning-changing build request was accepted")
			}
		})
	}
}

func TestReceiptBindsRequestAndClosedStepOutcomes(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	receipts := map[string]Receipt{
		"passed": receiptFixture(
			request, ConclusionPassed, StepConclusionPassed, StepConclusionPassed,
		),
		"test failed": receiptFixture(
			request, ConclusionFailed, StepConclusionFailed, StepConclusionNotRun,
		),
		"vet failed": receiptFixture(
			request, ConclusionFailed, StepConclusionPassed, StepConclusionFailed,
		),
		"test cancelled": receiptFixture(
			request, ConclusionCancelled, StepConclusionCancelled, StepConclusionNotRun,
		),
		"vet cancelled": receiptFixture(
			request, ConclusionCancelled, StepConclusionPassed, StepConclusionCancelled,
		),
	}
	for name, receipt := range receipts {
		t.Run(name, func(t *testing.T) {
			if err := ValidateReceipt(request, receipt); err != nil {
				t.Fatalf("validate build receipt: %v", err)
			}
		})
	}

	valid := receipts["passed"]
	tests := map[string]func(*Receipt){
		"command":  func(value *Receipt) { value.CommandID = string(request.RunID) + ":verify:2" },
		"executor": func(value *Receipt) { value.ExecutorID = "invalid executor" },
		"source":   func(value *Receipt) { value.SourceArchiveDigest = digestOf('e') },
		"profile":  func(value *Receipt) { value.ExecutorProfile = "HOST" },
		"step kind": func(value *Receipt) {
			value.Steps[0].Kind = devopsv1.VerificationStepGoVet
		},
		"impossible": func(value *Receipt) { value.Steps[1].Conclusion = StepConclusionNotRun },
		"digest":     func(value *Receipt) { value.ContentDigest = digestOf('d') },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if ValidateReceipt(request, candidate) == nil {
				t.Fatal("meaning-changing build receipt was accepted")
			}
		})
	}
}

func TestReceiptShapeCanBeVerifiedWithoutOriginalRequest(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	receipt := receiptFixture(
		request, ConclusionFailed, StepConclusionPassed, StepConclusionFailed,
	)
	if err := ValidateReceiptShape(receipt); err != nil {
		t.Fatalf("validate standalone build receipt: %v", err)
	}

	for name, mutate := range map[string]func(*Receipt){
		"run": func(value *Receipt) {
			value.RunID = "run-one"
		},
		"command": func(value *Receipt) {
			value.CommandID = string(value.RunID) + ":fetch:1"
		},
		"revision": func(value *Receipt) {
			value.PipelineRevisionID = "revision-one"
		},
		"profile": func(value *Receipt) {
			value.ExecutorProfile = "HOST"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			candidate.ContentDigest = DigestReceipt(candidate)
			if ValidateReceiptShape(candidate) == nil {
				t.Fatal("invalid standalone build receipt was accepted")
			}
		})
	}
}

func TestCanonicalDocumentsRejectUnknownNoncanonicalAndTrailingContent(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	submission, err := EncodeSubmission(request)
	if err != nil {
		t.Fatalf("encode submission: %v", err)
	}
	decodedRequest, err := DecodeSubmission(submission)
	if err != nil || decodedRequest != request {
		t.Fatalf("decode submission = %#v / %v", decodedRequest, err)
	}
	receipt := receiptFixture(
		request, ConclusionPassed, StepConclusionPassed, StepConclusionPassed,
	)
	receiptDocument, err := EncodeReceipt(request, receipt)
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	decodedReceipt, err := DecodeReceipt(request, receiptDocument)
	if err != nil || decodedReceipt != receipt {
		t.Fatalf("decode receipt = %#v / %v", decodedReceipt, err)
	}

	for name, content := range map[string][]byte{
		"unknown field": bytes.Replace(
			submission,
			[]byte(`"request":`),
			[]byte(`"unexpected":true,"request":`),
			1,
		),
		"noncanonical whitespace": append([]byte(" "), submission...),
		"trailing document":       append(append([]byte(nil), submission...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSubmission(content); err == nil {
				t.Fatal("meaning-changing submission document was accepted")
			}
		})
	}
	unknownReceipt := bytes.Replace(
		receiptDocument,
		[]byte(`"receipt":`),
		[]byte(`"unexpected":true,"receipt":`),
		1,
	)
	if _, err := DecodeReceipt(request, unknownReceipt); err == nil {
		t.Fatal("unknown receipt field was accepted")
	}
}

func TestSubmissionFrameBindsExactArchive(t *testing.T) {
	archive := []byte("canonical source archive")
	request := requestFixture(archive)
	var frame bytes.Buffer
	if err := WriteSubmission(&frame, request, bytes.NewReader(archive)); err != nil {
		t.Fatalf("write submission: %v", err)
	}
	var restored bytes.Buffer
	decoded, err := ReadSubmission(bytes.NewReader(frame.Bytes()), &restored)
	if err != nil || decoded != request || !bytes.Equal(restored.Bytes(), archive) {
		t.Fatalf("read submission = %#v / %q / %v", decoded, restored.Bytes(), err)
	}

	for name, source := range map[string][]byte{
		"short archive": archive[:len(archive)-1],
		"long archive":  append(append([]byte(nil), archive...), 'x'),
		"changed archive": append(
			append([]byte(nil), archive[:len(archive)-1]...),
			'x',
		),
	} {
		t.Run("write "+name, func(t *testing.T) {
			if err := WriteSubmission(&bytes.Buffer{}, request, bytes.NewReader(source)); err == nil {
				t.Fatal("invalid outbound archive was accepted")
			}
		})
	}

	validFrame := frame.Bytes()
	for name, candidate := range map[string][]byte{
		"short archive": validFrame[:len(validFrame)-1],
		"long archive":  append(append([]byte(nil), validFrame...), 'x'),
		"changed archive": append(
			append([]byte(nil), validFrame[:len(validFrame)-1]...),
			'x',
		),
	} {
		t.Run("read "+name, func(t *testing.T) {
			if _, err := ReadSubmission(bytes.NewReader(candidate), &bytes.Buffer{}); err == nil {
				t.Fatal("invalid inbound archive was accepted")
			}
		})
	}

	var oversizedHeader [8]byte
	binary.BigEndian.PutUint64(oversizedHeader[:], MaximumDocumentBytes+1)
	if _, err := ReadSubmission(bytes.NewReader(oversizedHeader[:]), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized metadata frame was accepted")
	}
}

func TestExecutionIDIsDeterministicAndFramed(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	first, err := ExecutionID(request)
	if err != nil {
		t.Fatalf("derive execution identity: %v", err)
	}
	second, err := ExecutionID(request)
	if err != nil || second != first {
		t.Fatalf("replayed identity = %q / %v, want %q", second, err, first)
	}
	changed := request
	changed.CommandID = string(request.RunID) + ":verify:2"
	changedID, err := ExecutionID(changed)
	if err != nil || changedID == first {
		t.Fatalf("changed command identity = %q / %v", changedID, err)
	}
	if err := devopsv1.ValidateDigest("executionId", first); err != nil {
		t.Fatalf("execution identity is not a canonical digest: %v", err)
	}
}

func TestDigestRequestBindsFieldsOutsideExecutionIdentity(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	first, err := DigestRequest(request)
	if err != nil {
		t.Fatalf("digest request: %v", err)
	}
	replayed, err := DigestRequest(request)
	if err != nil || replayed != first {
		t.Fatalf("replayed digest = %q / %v, want %q", replayed, err, first)
	}

	changed := request
	changed.SourceExpandedBytes++
	changedExecutionID, err := ExecutionID(changed)
	if err != nil {
		t.Fatalf("derive changed execution identity: %v", err)
	}
	originalExecutionID, err := ExecutionID(request)
	if err != nil || changedExecutionID != originalExecutionID {
		t.Fatalf("execution identity unexpectedly changed: %q / %v, want %q", changedExecutionID, err, originalExecutionID)
	}
	changedDigest, err := DigestRequest(changed)
	if err != nil || changedDigest == first {
		t.Fatalf("changed request digest = %q / %v, original %q", changedDigest, err, first)
	}
	if err := devopsv1.ValidateDigest("requestDigest", first); err != nil {
		t.Fatalf("request digest is not canonical: %v", err)
	}

	invalid := request
	invalid.DeadlineAt = invalid.StartedAt
	if _, err := DigestRequest(invalid); err == nil {
		t.Fatal("invalid request was digested")
	}
}

func requestFixture(archive []byte) Request {
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat("a", 48))
	startedAt := time.Date(2026, 9, 8, 10, 11, 12, 123000, time.UTC)
	return Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID: string(runID) + ":verify:1", InputDigest: digestOf('1'),
		SourceArchiveDigest: digestBytes(archive), SourceArchiveBytes: int64(len(archive)),
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

func receiptFixture(
	request Request,
	conclusion Conclusion,
	first StepConclusion,
	second StepConclusion,
) Receipt {
	value := Receipt{
		TenantID: request.TenantID, RunID: request.RunID,
		CommandID: request.CommandID, InputDigest: request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             "executor-one", ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest, Conclusion: conclusion,
		Steps: [2]StepReceipt{
			{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Conclusion: first},
			{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Conclusion: second},
		},
	}
	value.ContentDigest = DigestReceipt(value)
	return value
}

func digestOf(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
