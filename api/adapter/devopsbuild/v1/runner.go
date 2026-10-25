package devopsbuildv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	ClaimKind          = "BuildClaim"
	AssignmentKind     = "BuildAssignment"
	RenewalRequestKind = "BuildRenewalRequest"
	RenewalKind        = "BuildRenewal"
	CompletionKind     = "BuildCompletion"
)

type AssignmentMode string

const (
	AssignmentExecute AssignmentMode = "EXECUTE"
	AssignmentObserve AssignmentMode = "OBSERVE"
	AssignmentCancel  AssignmentMode = "CANCEL"
)

// Assignment is returned only on the runner listener. Runner identity is
// derived from the mutually authenticated connection and is never supplied
// by this document. Only the first EXECUTE assignment carries archive bytes.
type Assignment struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	Mode           AssignmentMode `json:"mode"`
	ExecutionID    string         `json:"executionId"`
	FencingToken   uint64         `json:"fencingToken"`
	LeaseExpiresAt time.Time      `json:"leaseExpiresAt"`
	Request        Request        `json:"request"`
}

// Claim carries version negotiation only. The runner identity and eligibility
// come from its mutually authenticated connection, not request data.
type Claim struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

type RenewalRequest struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	ExecutionID  string `json:"executionId"`
	FencingToken uint64 `json:"fencingToken"`
}

type Renewal struct {
	APIVersion            string    `json:"apiVersion"`
	Kind                  string    `json:"kind"`
	ExecutionID           string    `json:"executionId"`
	FencingToken          uint64    `json:"fencingToken"`
	LeaseExpiresAt        time.Time `json:"leaseExpiresAt"`
	CancellationRequested bool      `json:"cancellationRequested"`
}

type Completion struct {
	APIVersion   string  `json:"apiVersion"`
	Kind         string  `json:"kind"`
	ExecutionID  string  `json:"executionId"`
	FencingToken uint64  `json:"fencingToken"`
	Receipt      Receipt `json:"receipt"`
}

func EncodeClaim() ([]byte, error) {
	return encodeDocument(Claim{APIVersion: APIVersion, Kind: ClaimKind})
}

func DecodeClaim(content []byte) error {
	var document Claim
	if err := decodeDocument(content, &document); err != nil ||
		document.APIVersion != APIVersion || document.Kind != ClaimKind {
		return ErrInvalidDocument
	}
	canonical, err := EncodeClaim()
	if err != nil || !bytes.Equal(canonical, content) {
		return ErrInvalidDocument
	}
	return nil
}

func EncodeRenewalRequest(executionID string, fencingToken uint64) ([]byte, error) {
	value := RenewalRequest{
		APIVersion: APIVersion, Kind: RenewalRequestKind,
		ExecutionID: executionID, FencingToken: fencingToken,
	}
	if !validRunnerFence(value.ExecutionID, value.FencingToken) {
		return nil, ErrInvalidDocument
	}
	return encodeDocument(value)
}

func DecodeRenewalRequest(content []byte) (RenewalRequest, error) {
	var document RenewalRequest
	if err := decodeDocument(content, &document); err != nil ||
		document.APIVersion != APIVersion || document.Kind != RenewalRequestKind ||
		!validRunnerFence(document.ExecutionID, document.FencingToken) {
		return RenewalRequest{}, ErrInvalidDocument
	}
	canonical, err := EncodeRenewalRequest(document.ExecutionID, document.FencingToken)
	if err != nil || !bytes.Equal(canonical, content) {
		return RenewalRequest{}, ErrInvalidDocument
	}
	return document, nil
}

func EncodeRenewal(request Request, value Renewal) ([]byte, error) {
	if err := ValidateRenewal(request, value); err != nil {
		return nil, err
	}
	return encodeDocument(value)
}

func DecodeRenewal(request Request, content []byte) (Renewal, error) {
	var document Renewal
	if err := decodeDocument(content, &document); err != nil ||
		ValidateRenewal(request, document) != nil {
		return Renewal{}, ErrInvalidDocument
	}
	canonical, err := EncodeRenewal(request, document)
	if err != nil || !bytes.Equal(canonical, content) {
		return Renewal{}, ErrInvalidDocument
	}
	return document, nil
}

func ValidateRenewal(request Request, value Renewal) error {
	executionID, err := ExecutionID(request)
	if err != nil || value.APIVersion != APIVersion || value.Kind != RenewalKind ||
		value.ExecutionID != executionID ||
		!validRunnerFence(value.ExecutionID, value.FencingToken) ||
		validateCanonicalTime("buildRenewal.leaseExpiresAt", value.LeaseExpiresAt) != nil ||
		!value.LeaseExpiresAt.After(request.StartedAt) ||
		value.LeaseExpiresAt.After(request.DeadlineAt) {
		return ErrInvalidDocument
	}
	return nil
}

func EncodeCompletion(request Request, value Completion) ([]byte, error) {
	if err := ValidateCompletion(request, value); err != nil {
		return nil, err
	}
	return encodeDocument(value)
}

func DecodeCompletion(request Request, content []byte) (Completion, error) {
	var document Completion
	if err := decodeDocument(content, &document); err != nil ||
		ValidateCompletion(request, document) != nil {
		return Completion{}, ErrInvalidDocument
	}
	canonical, err := EncodeCompletion(request, document)
	if err != nil || !bytes.Equal(canonical, content) {
		return Completion{}, ErrInvalidDocument
	}
	return document, nil
}

func ValidateCompletion(request Request, value Completion) error {
	executionID, err := ExecutionID(request)
	if err != nil || value.APIVersion != APIVersion || value.Kind != CompletionKind ||
		value.ExecutionID != executionID ||
		!validRunnerFence(value.ExecutionID, value.FencingToken) ||
		ValidateReceipt(request, value.Receipt) != nil {
		return ErrInvalidDocument
	}
	return nil
}

func EncodeAssignment(value Assignment) ([]byte, error) {
	if err := ValidateAssignment(value); err != nil {
		return nil, err
	}
	return encodeDocument(value)
}

func DecodeAssignment(content []byte) (Assignment, error) {
	var document Assignment
	if err := decodeDocument(content, &document); err != nil ||
		ValidateAssignment(document) != nil {
		return Assignment{}, ErrInvalidDocument
	}
	canonical, err := EncodeAssignment(document)
	if err != nil || !bytes.Equal(canonical, content) {
		return Assignment{}, ErrInvalidDocument
	}
	return document, nil
}

func ValidateAssignment(value Assignment) error {
	if value.APIVersion != APIVersion || value.Kind != AssignmentKind ||
		ValidateRequest(value.Request) != nil ||
		value.FencingToken == 0 || value.FencingToken > devopsv1.MaximumContractInteger ||
		validateCanonicalTime("buildAssignment.leaseExpiresAt", value.LeaseExpiresAt) != nil ||
		!value.LeaseExpiresAt.After(value.Request.StartedAt) ||
		value.LeaseExpiresAt.After(value.Request.DeadlineAt) {
		return ErrInvalidDocument
	}
	executionID, err := ExecutionID(value.Request)
	if err != nil || value.ExecutionID != executionID {
		return ErrInvalidDocument
	}
	switch value.Mode {
	case AssignmentExecute:
		if value.FencingToken != 1 {
			return ErrInvalidDocument
		}
	case AssignmentObserve, AssignmentCancel:
		if value.FencingToken < 2 {
			return ErrInvalidDocument
		}
	default:
		return ErrInvalidDocument
	}
	return nil
}

// WriteAssignment frames canonical metadata exactly like a Submission. An
// EXECUTE assignment must provide the bound archive; recovery assignments
// must not provide one.
func WriteAssignment(destination io.Writer, value Assignment, archive io.Reader) error {
	if destination == nil || (value.Mode == AssignmentExecute) != (archive != nil) {
		return ErrInvalidSubmission
	}
	metadata, err := EncodeAssignment(value)
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
	if value.Mode == AssignmentExecute {
		if err := copyArchive(destination, archive, value.Request); err != nil {
			return errors.Join(ErrInvalidSubmission, err)
		}
	}
	return nil
}

// AssignmentDestination binds canonical metadata to caller-owned staging
// before any archive byte is consumed. It must return a writer exactly for an
// EXECUTE assignment and nil for an archive-free recovery assignment.
type AssignmentDestination func(Assignment) (io.Writer, error)

func ReadAssignment(
	source io.Reader,
	destination AssignmentDestination,
) (Assignment, error) {
	if source == nil || destination == nil {
		return Assignment{}, ErrInvalidSubmission
	}
	var header [8]byte
	if _, err := io.ReadFull(source, header[:]); err != nil {
		return Assignment{}, errors.Join(ErrInvalidSubmission, err)
	}
	metadataBytes := binary.BigEndian.Uint64(header[:])
	if metadataBytes == 0 || metadataBytes > MaximumDocumentBytes {
		return Assignment{}, ErrInvalidSubmission
	}
	metadata := make([]byte, int(metadataBytes))
	if _, err := io.ReadFull(source, metadata); err != nil {
		return Assignment{}, errors.Join(ErrInvalidSubmission, err)
	}
	assignment, err := DecodeAssignment(metadata)
	if err != nil {
		return Assignment{}, ErrInvalidSubmission
	}
	archiveDestination, destinationErr := destination(assignment)
	if destinationErr != nil {
		return Assignment{}, errors.Join(ErrInvalidSubmission, destinationErr)
	}
	if (assignment.Mode == AssignmentExecute) != (archiveDestination != nil) {
		return Assignment{}, ErrInvalidSubmission
	}
	if assignment.Mode == AssignmentExecute {
		if err := copyArchive(archiveDestination, source, assignment.Request); err != nil {
			return Assignment{}, errors.Join(ErrInvalidSubmission, err)
		}
		return assignment, nil
	}
	var trailing [1]byte
	read, readErr := source.Read(trailing[:])
	if read != 0 || !errors.Is(readErr, io.EOF) {
		return Assignment{}, ErrInvalidSubmission
	}
	return assignment, nil
}

func validRunnerFence(executionID string, fencingToken uint64) bool {
	return devopsv1.ValidateDigest("executionId", executionID) == nil &&
		fencingToken > 0 && fencingToken <= devopsv1.MaximumContractInteger
}
