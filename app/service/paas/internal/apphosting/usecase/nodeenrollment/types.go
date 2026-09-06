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

const (
	StoredExchangeAPIVersion    = "node.enrollment.matrix.xiak.com/v1"
	StoredExchangeKind          = "NodeEnrollmentExchange"
	ExchangeResultSealAlgorithm = "AES_256_GCM"
)

var (
	ErrInvalidArgument      = errors.New("node enrollment request is invalid")
	ErrNotFound             = errors.New("node enrollment was not found")
	ErrConflict             = errors.New("node enrollment conflicts with stored authority")
	ErrInvalidTransition    = errors.New("node enrollment lifecycle transition is invalid")
	ErrIdempotencyConflict  = errors.New("node enrollment idempotency conflict")
	ErrResourceVersion      = errors.New("node enrollment resource version conflict")
	ErrExpired              = errors.New("node enrollment expired")
	ErrRevoked              = errors.New("node enrollment was revoked")
	ErrCredentialRejected   = errors.New("node enrollment credential was rejected")
	ErrCredentialConsumed   = errors.New("node enrollment credential was consumed")
	ErrRuntimeUnsupported   = errors.New("node enrollment runtime is unsupported")
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

func (value *IssuedJoin) Clear() {
	if value == nil {
		return
	}
	clear(value.CredentialSalt)
	value.CredentialSalt = nil
	value.CredentialVerifier = ""
	value.WrappedCredential = paasv1.WrappedJoinCredential{}
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

type ExchangeIssueRequest struct {
	EnrollmentID          paasv1.ResourceID
	InstallationID        string
	ExecutionTargetID     paasv1.ResourceID
	ExchangeID            string
	MachineFingerprint    string
	RuntimeContractDigest string
	Listener              paasv1.NodeEnrollmentListenerClaim
	NodePublicKey         []byte
	CollectorPublicKey    []byte
	ObservedPeerAddress   string
	BindingRef            string
	ControllerID          string
	CertificateNotBefore  time.Time
	CertificateNotAfter   time.Time
}

type SealedExchangeResult struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyId"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (SealedExchangeResult) String() string   { return "sealed node exchange result <redacted>" }
func (SealedExchangeResult) GoString() string { return "sealed node exchange result <redacted>" }

type IssuedExchange struct {
	Response paasv1.NodeEnrollmentExchangeResponse
	Sealed   SealedExchangeResult
}

func (IssuedExchange) String() string   { return "issued node exchange <redacted>" }
func (IssuedExchange) GoString() string { return "issued node exchange <redacted>" }

// EnrollmentIssuer isolates protected enrollment signing/sealing material and
// entropy from both browser and node-facing transports.
type EnrollmentIssuer interface {
	IssueJoin(context.Context, JoinIssueRequest) (IssuedJoin, error)
	IssueExchange(context.Context, ExchangeIssueRequest) (IssuedExchange, error)
}

type Config struct {
	InstallationID                 string
	Lifetime                       time.Duration
	CertificateLifetime            time.Duration
	SupportedRuntimeContractDigest string
	ControllerID                   string
	ManagementPort                 uint16
	CollectorPort                  uint16
	MaxTransactionAttempts         int
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

type RevokeCommand struct {
	Authorization           port.Authorization
	EnrollmentID            paasv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type RevokeResult struct {
	Enrollment paasv1.NodeEnrollment
	Replayed   bool
}

type RegenerateCommand struct {
	Authorization           port.Authorization
	EnrollmentID            paasv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
	Request                 paasv1.RegenerateNodeEnrollmentRequest
	ControlPlaneBaseURL     string
}

type ExchangeCommand struct {
	EnrollmentID        paasv1.ResourceID
	ObservedPeerAddress string
	Request             paasv1.ExchangeNodeEnrollmentRequest
}

func (ExchangeCommand) String() string   { return "node enrollment exchange command <redacted>" }
func (ExchangeCommand) GoString() string { return "node enrollment exchange command <redacted>" }

type ExchangeResult struct {
	Enrollment paasv1.NodeEnrollment
	Response   paasv1.NodeEnrollmentExchangeResponse
}

// StoredExchange is the normalized public-key and machine identity fixed by a
// successful one-time credential exchange. CSR bodies and the raw credential
// are deliberately absent; the exact certificate response is stored only in
// sealed form beside this document.
type StoredExchange struct {
	APIVersion                    string            `json:"apiVersion"`
	Kind                          string            `json:"kind"`
	EnrollmentID                  paasv1.ResourceID `json:"enrollmentId"`
	InstallationID                string            `json:"installationId"`
	ExecutionTargetID             paasv1.ResourceID `json:"executionTargetId"`
	ExchangeID                    string            `json:"exchangeId"`
	MachineFingerprint            string            `json:"machineFingerprint"`
	RuntimeContractDigest         string            `json:"runtimeContractDigest"`
	ControllerID                  string            `json:"controllerId"`
	BindingRef                    string            `json:"bindingRef"`
	NodeListenAddress             string            `json:"nodeListenAddress"`
	CollectorEndpoint             string            `json:"collectorEndpoint"`
	NodePublicKey                 string            `json:"nodePublicKey"`
	NodePublicKeyFingerprint      string            `json:"nodePublicKeyFingerprint"`
	CollectorPublicKey            string            `json:"collectorPublicKey"`
	CollectorPublicKeyFingerprint string            `json:"collectorPublicKeyFingerprint"`
	ResultDigest                  string            `json:"resultDigest"`
	ConsumedAt                    time.Time         `json:"consumedAt"`
}

type StoredEnrollment struct {
	Enrollment               paasv1.NodeEnrollment
	Operation                paasv1.Operation
	Join                     paasv1.NodeEnrollmentJoin
	WrappedCredential        paasv1.WrappedJoinCredential
	CredentialSalt           []byte `json:"-"`
	CredentialVerifier       string `json:"-"`
	Exchange                 *StoredExchange
	SealedExchangeResult     *SealedExchangeResult `json:"-"`
	TerminationFingerprint   string                `json:"-"`
	TerminationRequestDigest string                `json:"-"`
	CreateAuthorization      port.Authorization
}

func (StoredEnrollment) String() string   { return "stored node enrollment <redacted>" }
func (StoredEnrollment) GoString() string { return "stored node enrollment <redacted>" }

func (value *StoredEnrollment) Clear() {
	if value == nil {
		return
	}
	clear(value.CredentialSalt)
	value.CredentialSalt = nil
	value.CredentialVerifier = ""
	value.WrappedCredential = paasv1.WrappedJoinCredential{}
	if value.Exchange != nil {
		value.Exchange.NodePublicKey = ""
		value.Exchange.CollectorPublicKey = ""
	}
	value.Exchange = nil
	value.SealedExchangeResult = nil
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindByFingerprint(context.Context, string) (StoredEnrollment, bool, error)
	FindByTerminationFingerprint(context.Context, string) (StoredEnrollment, bool, error)
	LoadEnrollment(context.Context, paasv1.ResourceID) (StoredEnrollment, bool, error)
	LoadExecutionPool(context.Context, paasv1.ResourceID) (paasv1.ExecutionPool, bool, error)
	ListEnrollments(context.Context, int) ([]StoredEnrollment, error)
	InsertEnrollment(context.Context, StoredEnrollment) error
	ExchangeEnrollment(context.Context, StoredEnrollment, StoredEnrollment) error
	ExpireEnrollment(context.Context, StoredEnrollment, paasv1.NodeEnrollment, paasv1.Operation) error
	RevokeEnrollment(context.Context, StoredEnrollment, StoredEnrollment) error
	ReplaceEnrollment(context.Context, StoredEnrollment, StoredEnrollment, StoredEnrollment) error
}

type Repository interface {
	WithinInstallation(context.Context, string, func(context.Context, Transaction) error) error
}

type Service struct {
	repository Repository
	issuer     EnrollmentIssuer
	config     Config
}
