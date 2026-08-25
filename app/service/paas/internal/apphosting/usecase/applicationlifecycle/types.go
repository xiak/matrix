package applicationlifecycle

import (
	"context"
	"errors"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrNotFound                = errors.New("application lifecycle resource not found")
	ErrResourceVersionConflict = errors.New("Deployment resource version conflict")
	ErrIdempotencyConflict     = errors.New("application lifecycle idempotency conflict")
	ErrNoDesiredChange         = errors.New("Deployment desired content is unchanged")
	ErrOperationInProgress     = errors.New("Deployment has an operation in progress")
	ErrRetryableTransaction    = errors.New("application lifecycle transaction must be retried")
)

type SubmitCommand struct {
	TenantID                paasv1.TenantID
	DeploymentID            paasv1.ResourceID
	Name                    string
	Spec                    paasv1.DeploymentSpec
	ExpectedResourceVersion uint64
	IdempotencyKey          string
	RequestedBy             paasv1.SubjectRef
}

type RollbackCommand struct {
	TenantID                paasv1.TenantID
	DeploymentID            paasv1.ResourceID
	SourceGeneration        uint64
	ExpectedResourceVersion uint64
	IdempotencyKey          string
	RequestedBy             paasv1.SubjectRef
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
