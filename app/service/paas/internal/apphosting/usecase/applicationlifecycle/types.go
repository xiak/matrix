package applicationlifecycle

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var (
	ErrNotFound                = errors.New("application lifecycle resource not found")
	ErrInvalidArgument         = errors.New("application lifecycle request is invalid")
	ErrAlreadyExists           = errors.New("application lifecycle resource already exists")
	ErrResourceVersionConflict = errors.New("Deployment resource version conflict")
	ErrIdempotencyConflict     = errors.New("application lifecycle idempotency conflict")
	ErrNoDesiredChange         = errors.New("Deployment desired content is unchanged")
	ErrOperationInProgress     = errors.New("Deployment has an operation in progress")
	ErrRetryableTransaction    = errors.New("application lifecycle transaction must be retried")
)

type SubmitCommand struct {
	Authorization           port.Authorization
	DeploymentID            paasv1.ResourceID
	Name                    string
	Spec                    paasv1.DeploymentSpec
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type RollbackCommand struct {
	Authorization           port.Authorization
	DeploymentID            paasv1.ResourceID
	SourceGeneration        uint64
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type CreateApplicationCommand struct {
	Authorization  port.Authorization
	Request        paasv1.CreateApplicationRequest
	IdempotencyKey string
}

type CreateConfigurationCommand struct {
	Authorization  port.Authorization
	Request        paasv1.CreateConfigurationRequest
	IdempotencyKey string
}

type CreateConfigurationRevisionCommand struct {
	Authorization  port.Authorization
	Request        paasv1.CreateConfigurationRevisionRequest
	IdempotencyKey string
}

type CreateApplicationRevisionCommand struct {
	Authorization  port.Authorization
	Request        paasv1.CreateApplicationRevisionRequest
	IdempotencyKey string
}

type Result struct {
	Deployment paasv1.Deployment
	Generation paasv1.DeploymentGeneration
	Operation  paasv1.Operation
	Replayed   bool
}

type Submission struct {
	ExpectedResourceVersion uint64
	Deployment              paasv1.Deployment
	Generation              paasv1.DeploymentGeneration
	Operation               paasv1.Operation
	AuditEvent              audit.Event
}

type ResourceSubmission struct {
	Operation  paasv1.Operation
	AuditEvent audit.Event
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindOperationByFingerprint(
		context.Context,
		string,
	) (paasv1.Operation, bool, error)
	LoadDeployment(
		context.Context,
		paasv1.ResourceID,
	) (paasv1.Deployment, bool, error)
	ListDeployments(
		context.Context,
		paasv1.ResourceID,
		int,
	) ([]paasv1.Deployment, paasv1.ResourceID, error)
	LoadDeploymentRuntime(
		context.Context,
		paasv1.ResourceID,
	) (paasv1.DeploymentRuntimeSnapshot, bool, error)
	LoadApplication(context.Context, paasv1.ResourceID) (paasv1.Application, bool, error)
	LoadConfiguration(context.Context, paasv1.ResourceID) (paasv1.Configuration, bool, error)
	LoadConfigurationRevision(
		context.Context,
		paasv1.ResourceID,
	) (paasv1.ConfigurationRevision, bool, error)
	LoadApplicationRevision(
		context.Context,
		paasv1.ResourceID,
	) (paasv1.ApplicationRevision, error)
	ValidateConfigurationBindings(
		context.Context,
		paasv1.DeploymentSpec,
		paasv1.ResourceID,
	) error
	LoadPlacementPolicy(
		context.Context,
		paasv1.ResourceID,
	) (paasv1.PlacementPolicy, error)
	LoadAcceptedGeneration(
		context.Context,
		paasv1.ResourceID,
		uint64,
	) (paasv1.DeploymentGeneration, error)
	LoadGenerationByOperation(
		context.Context,
		paasv1.OperationID,
	) (paasv1.DeploymentGeneration, error)
	LoadOperation(context.Context, paasv1.OperationID) (paasv1.Operation, bool, error)
	CreateApplication(context.Context, paasv1.Application, ResourceSubmission) error
	CreateConfiguration(context.Context, paasv1.Configuration, ResourceSubmission) error
	CreateConfigurationRevision(
		context.Context,
		paasv1.ConfigurationRevision,
		ResourceSubmission,
	) error
	CreateApplicationRevision(
		context.Context,
		paasv1.ApplicationRevision,
		ResourceSubmission,
	) error
	SubmitDeployment(context.Context, Submission) error
}

type Repository interface {
	WithinTransaction(
		context.Context,
		paasv1.TenantID,
		func(context.Context, Transaction) error,
	) error
}

type Config struct {
	MaxTransactionAttempts int
}

type Usecase struct {
	repository Repository
	config     Config
}
