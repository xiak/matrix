// Package nodeenrollment owns the short-lived admission ceremony that can
// atomically publish an existing ExecutionTarget. It never owns ongoing host
// health, capacity, placement, or execution.
package nodeenrollment

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var (
	ErrInvalidArgument      = errors.New("node enrollment request is invalid")
	ErrNotFound             = errors.New("node enrollment was not found")
	ErrConflict             = errors.New("node enrollment conflicts with stored authority")
	ErrIdempotencyConflict  = errors.New("node enrollment idempotency conflict")
	ErrResourceVersion      = errors.New("node enrollment resource version conflict")
	ErrExpired              = errors.New("node enrollment expired")
	ErrRevoked              = errors.New("node enrollment was revoked")
	ErrCredentialConsumed   = errors.New("node enrollment credential was consumed")
	ErrRetryableTransaction = errors.New("node enrollment transaction must be retried")
	ErrUnavailable          = errors.New("node enrollment dependency is unavailable")
)

type JoinIssueRequest struct {
	EnrollmentID        paasv1.ResourceID
	ExecutionTargetID   paasv1.ResourceID
	ExpiresAt           time.Time
	WrappingPublicKey   string
	ControlPlaneBaseURL string
}

// IssuedJoin contains public creation output plus the only server-side
// credential verifier. It never contains or returns the raw credential.
type IssuedJoin struct {
	Join               paasv1.NodeEnrollmentJoin
	WrappedCredential  paasv1.WrappedJoinCredential
	CredentialSalt     []byte `json:"-"`
	CredentialVerifier string `json:"-"`
}

func (IssuedJoin) String() string   { return "issued node join <redacted>" }
func (IssuedJoin) GoString() string { return "issued node join <redacted>" }

func (value IssuedJoin) Clear() {
	clear(value.CredentialSalt)
}

func ValidateControlPlaneBaseURL(value string) error {
	baseURL, err := url.Parse(value)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.Opaque != "" || baseURL.Path != "/api/paas/v1" || baseURL.RawPath != "" ||
		baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" {
		return errors.New("node enrollment control-plane base URL is invalid")
	}
	return nil
}

func ValidateIssuedJoin(value IssuedJoin, request JoinIssueRequest) error {
	var problems []error
	if paasv1.ValidateNodeEnrollmentJoin(value.Join) != nil ||
		paasv1.ValidateWrappedJoinCredential(value.WrappedCredential) != nil {
		problems = append(problems, errors.New("issued node join public contract is invalid"))
	}
	if value.Join.EnrollmentID != request.EnrollmentID ||
		value.Join.ExecutionTargetID != request.ExecutionTargetID ||
		!value.Join.ExpiresAt.Equal(request.ExpiresAt) {
		problems = append(problems, errors.New("issued node join differs from its request"))
	}
	if len(value.CredentialSalt) != 32 ||
		paasv1.ValidateDigest("credentialVerifier", value.CredentialVerifier) != nil ||
		strings.Trim(value.CredentialVerifier, "0") == "sha256:" {
		problems = append(problems, errors.New("issued node join verifier is invalid"))
	}
	return errors.Join(problems...)
}

// JoinIssuer isolates protected enrollment signing material and entropy from
// the use case and browser-facing transport.
type JoinIssuer interface {
	Issue(context.Context, JoinIssueRequest) (IssuedJoin, error)
}

type Config struct {
	InstallationID         string
	Lifetime               time.Duration
	MaxTransactionAttempts int
}

type CreateCommand struct {
	Authorization       port.Authorization
	Request             paasv1.CreateNodeEnrollmentRequest
	IdempotencyKey      string
	ControlPlaneBaseURL string
}

type CreateResult struct {
	Response  paasv1.CreateNodeEnrollmentResponse
	Operation paasv1.Operation
	Replayed  bool
}

type StoredEnrollment struct {
	Enrollment          paasv1.NodeEnrollment
	Operation           paasv1.Operation
	Join                paasv1.NodeEnrollmentJoin
	WrappedCredential   paasv1.WrappedJoinCredential
	CredentialSalt      []byte `json:"-"`
	CredentialVerifier  string `json:"-"`
	CreateAuthorization port.Authorization
}

func (StoredEnrollment) String() string   { return "stored node enrollment <redacted>" }
func (StoredEnrollment) GoString() string { return "stored node enrollment <redacted>" }

func (value StoredEnrollment) Clear() {
	clear(value.CredentialSalt)
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindByFingerprint(context.Context, string) (StoredEnrollment, bool, error)
	LoadEnrollment(context.Context, paasv1.ResourceID) (StoredEnrollment, bool, error)
	LoadExecutionPool(context.Context, paasv1.ResourceID) (paasv1.ExecutionPool, bool, error)
	ListEnrollments(context.Context, int) ([]StoredEnrollment, error)
	InsertEnrollment(context.Context, StoredEnrollment) error
	ExpireEnrollment(context.Context, StoredEnrollment, paasv1.NodeEnrollment, paasv1.Operation) error
}

type Repository interface {
	WithinInstallation(context.Context, string, func(context.Context, Transaction) error) error
}

type Service struct {
	repository Repository
	issuer     JoinIssuer
	config     Config
}
