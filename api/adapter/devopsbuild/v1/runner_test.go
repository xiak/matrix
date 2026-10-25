package devopsbuildv1

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestAssignmentFramesArchiveOnlyForFirstExecution(t *testing.T) {
	archive := []byte("canonical source archive")
	request := requestFixture(archive)
	executionID, err := ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	execute := Assignment{
		APIVersion: APIVersion, Kind: AssignmentKind,
		Mode: AssignmentExecute, ExecutionID: executionID, FencingToken: 1,
		LeaseExpiresAt: request.StartedAt.Add(30 * time.Second), Request: request,
	}
	var frame bytes.Buffer
	if err := WriteAssignment(&frame, execute, bytes.NewReader(archive)); err != nil {
		t.Fatalf("write execute assignment: %v", err)
	}
	var restored bytes.Buffer
	decoded, err := ReadAssignment(
		bytes.NewReader(frame.Bytes()),
		func(Assignment) (io.Writer, error) { return &restored, nil },
	)
	if err != nil || decoded != execute || !bytes.Equal(restored.Bytes(), archive) {
		t.Fatalf("read execute assignment = %#v / %q / %v", decoded, restored.Bytes(), err)
	}
	if err := WriteAssignment(&bytes.Buffer{}, execute, nil); err == nil {
		t.Fatal("execute assignment without archive was accepted")
	}
	if _, err := ReadAssignment(
		bytes.NewReader(frame.Bytes()),
		func(Assignment) (io.Writer, error) { return nil, nil },
	); err == nil {
		t.Fatal("execute assignment without archive destination was accepted")
	}
	destinationFailure := errors.New("destination failed")
	bound := Assignment{}
	if _, err := ReadAssignment(
		bytes.NewReader(frame.Bytes()),
		func(actual Assignment) (io.Writer, error) {
			bound = actual
			return nil, destinationFailure
		},
	); !errors.Is(err, ErrInvalidSubmission) || !errors.Is(err, destinationFailure) ||
		bound != execute {
		t.Fatalf("destination failure = %v after binding %#v", err, bound)
	}

	for _, mode := range []AssignmentMode{AssignmentObserve, AssignmentCancel} {
		t.Run(string(mode), func(t *testing.T) {
			recovery := execute
			recovery.Mode = mode
			recovery.FencingToken = 2
			var recoveryFrame bytes.Buffer
			if err := WriteAssignment(&recoveryFrame, recovery, nil); err != nil {
				t.Fatalf("write recovery assignment: %v", err)
			}
			bound := false
			decoded, err := ReadAssignment(
				bytes.NewReader(recoveryFrame.Bytes()),
				func(actual Assignment) (io.Writer, error) {
					bound = actual == recovery
					return nil, nil
				},
			)
			if err != nil || decoded != recovery || !bound {
				t.Fatalf("read recovery assignment = %#v / %v", decoded, err)
			}
			if err := WriteAssignment(
				&bytes.Buffer{}, recovery, bytes.NewReader(archive),
			); err == nil {
				t.Fatal("recovery assignment carried an archive")
			}
			if _, err := ReadAssignment(
				bytes.NewReader(recoveryFrame.Bytes()),
				func(Assignment) (io.Writer, error) { return &bytes.Buffer{}, nil },
			); err == nil {
				t.Fatal("recovery assignment accepted an archive destination")
			}
			withTrailing := append(append([]byte(nil), recoveryFrame.Bytes()...), 'x')
			if _, err := ReadAssignment(
				bytes.NewReader(withTrailing),
				func(Assignment) (io.Writer, error) { return nil, nil },
			); err == nil {
				t.Fatal("recovery assignment accepted trailing content")
			}
		})
	}
}

func TestAssignmentDocumentClosesModeFenceDeadlineAndIdentity(t *testing.T) {
	archive := []byte("canonical source archive")
	request := requestFixture(archive)
	executionID, err := ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	valid := Assignment{
		APIVersion: APIVersion, Kind: AssignmentKind,
		Mode: AssignmentExecute, ExecutionID: executionID, FencingToken: 1,
		LeaseExpiresAt: request.StartedAt.Add(30 * time.Second), Request: request,
	}
	content, err := EncodeAssignment(valid)
	if err != nil {
		t.Fatalf("encode assignment: %v", err)
	}
	decoded, err := DecodeAssignment(content)
	if err != nil || decoded != valid {
		t.Fatalf("decode assignment = %#v / %v", decoded, err)
	}

	for name, mutate := range map[string]func(*Assignment){
		"type":     func(value *Assignment) { value.Kind = "RunnerTask" },
		"mode":     func(value *Assignment) { value.Mode = "SHELL" },
		"fence":    func(value *Assignment) { value.FencingToken = 2 },
		"identity": func(value *Assignment) { value.ExecutionID = "sha256:changed" },
		"deadline": func(value *Assignment) { value.LeaseExpiresAt = request.DeadlineAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := EncodeAssignment(candidate); err == nil {
				t.Fatal("invalid assignment was accepted")
			}
		})
	}
	if _, err := DecodeAssignment(append([]byte(" "), content...)); err == nil {
		t.Fatal("noncanonical assignment was accepted")
	}
}

func TestRunnerClaimRenewalAndCompletionDocumentsAreClosed(t *testing.T) {
	claim, err := EncodeClaim()
	if err != nil || DecodeClaim(claim) != nil {
		t.Fatalf("claim document = %q / %v", claim, err)
	}
	if err := DecodeClaim(append([]byte(" "), claim...)); err == nil {
		t.Fatal("noncanonical claim was accepted")
	}
	unknownClaim := bytes.Replace(
		claim, []byte(`"kind":`), []byte(`"extra":true,"kind":`), 1,
	)
	if err := DecodeClaim(unknownClaim); err == nil {
		t.Fatal("unknown claim field was accepted")
	}

	request := requestFixture([]byte("canonical source archive"))
	executionID, err := ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	renewalRequest, err := EncodeRenewalRequest(executionID, 7)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := DecodeRenewalRequest(renewalRequest)
	if err != nil || decodedRequest.ExecutionID != executionID ||
		decodedRequest.FencingToken != 7 {
		t.Fatalf("renewal request = %#v / %v", decodedRequest, err)
	}
	if _, err := EncodeRenewalRequest("sha256:changed", 7); err == nil {
		t.Fatal("invalid renewal identity was accepted")
	}

	renewal := Renewal{
		APIVersion: APIVersion, Kind: RenewalKind,
		ExecutionID: executionID, FencingToken: 7,
		LeaseExpiresAt:        request.StartedAt.Add(45 * time.Second),
		CancellationRequested: true,
	}
	renewalDocument, err := EncodeRenewal(request, renewal)
	if err != nil {
		t.Fatal(err)
	}
	decodedRenewal, err := DecodeRenewal(request, renewalDocument)
	if err != nil || decodedRenewal != renewal {
		t.Fatalf("renewal = %#v / %v", decodedRenewal, err)
	}
	invalidRenewal := renewal
	invalidRenewal.LeaseExpiresAt = request.DeadlineAt.Add(time.Second)
	if _, err := EncodeRenewal(request, invalidRenewal); err == nil {
		t.Fatal("renewal beyond the build deadline was accepted")
	}

	receipt := receiptFixture(
		request, ConclusionPassed, StepConclusionPassed, StepConclusionPassed,
	)
	completion := Completion{
		APIVersion: APIVersion, Kind: CompletionKind,
		ExecutionID: executionID, FencingToken: 7, Receipt: receipt,
	}
	completionDocument, err := EncodeCompletion(request, completion)
	if err != nil {
		t.Fatal(err)
	}
	decodedCompletion, err := DecodeCompletion(request, completionDocument)
	if err != nil || decodedCompletion != completion {
		t.Fatalf("completion = %#v / %v", decodedCompletion, err)
	}
	changedCompletion := completion
	changedCompletion.FencingToken = 0
	if _, err := EncodeCompletion(request, changedCompletion); err == nil {
		t.Fatal("zero-fence completion was accepted")
	}
	unknownCompletion := bytes.Replace(
		completionDocument,
		[]byte(`"receipt":`),
		[]byte(`"nativeOutput":"secret","receipt":`),
		1,
	)
	if _, err := DecodeCompletion(request, unknownCompletion); err == nil {
		t.Fatal("native completion output was accepted")
	}
}
