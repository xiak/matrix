// Package pipelineconfiguration owns the authenticated transaction workflow
// for configuring repository delivery and activating immutable Pipelines.
package pipelineconfiguration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

var traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

var (
	ErrInvalidArgument         = errors.New("invalid delivery configuration command")
	ErrNotFound                = errors.New("delivery configuration resource not found")
	ErrAlreadyExists           = errors.New("delivery configuration resource already exists")
	ErrIdempotencyConflict     = errors.New("idempotency key was reused for a different request")
	ErrResourceVersionConflict = errors.New("delivery configuration resource version conflict")
	ErrNoDesiredChange         = errors.New("delivery configuration contains no desired change")
	ErrPreconditionFailed      = errors.New("delivery configuration precondition failed")
	ErrRetryableTransaction    = errors.New("retryable delivery configuration transaction")
)

type MutationKind string
type MutationResultKind string

const (
	MutationCreateProject            MutationKind = "CREATE_PROJECT"
	MutationCreateSourceConnection   MutationKind = "CREATE_SOURCE_CONNECTION"
	MutationUpdateSourceConnection   MutationKind = "UPDATE_SOURCE_CONNECTION"
	MutationRecheckSourceConnection  MutationKind = "RECHECK_SOURCE_CONNECTION"
	MutationCreateRepositoryBinding  MutationKind = "CREATE_REPOSITORY_BINDING"
	MutationUpdateRepositoryBinding  MutationKind = "UPDATE_REPOSITORY_BINDING"
	MutationRecheckRepositoryBinding MutationKind = "RECHECK_REPOSITORY_BINDING"
	MutationCreatePipeline           MutationKind = "CREATE_PIPELINE"
	MutationUpdatePipelineDraft      MutationKind = "UPDATE_PIPELINE_DRAFT"
	MutationActivatePipeline         MutationKind = "ACTIVATE_PIPELINE"
)

const (
	ResultDevOpsProject      MutationResultKind = "DevOpsProject"
	ResultSourceConnection   MutationResultKind = "SourceConnection"
	ResultRepositoryBinding  MutationResultKind = "RepositoryBinding"
	ResultPipeline           MutationResultKind = "Pipeline"
	ResultPipelineActivation MutationResultKind = "PipelineActivation"
)

type MutationContract struct {
	IAMAction       iamv1.Action
	IAMResourceKind iamv1.ResourceKind
	AuditAction     auditv1.Action
	AuditTargetKind auditv1.TargetKind
	ResultKind      MutationResultKind
}

func ContractForMutation(kind MutationKind) (MutationContract, bool) {
	switch kind {
	case MutationCreateProject:
		return MutationContract{iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, auditv1.ActionDevOpsProjectCreated, auditv1.TargetDevOpsProject, ResultDevOpsProject}, true
	case MutationCreateSourceConnection:
		return MutationContract{iamv1.ActionDevOpsSourceConnectionCreate, iamv1.ResourceSourceConnection, auditv1.ActionDevOpsSourceConnectionCreated, auditv1.TargetSourceConnection, ResultSourceConnection}, true
	case MutationUpdateSourceConnection:
		return MutationContract{iamv1.ActionDevOpsSourceConnectionUpdate, iamv1.ResourceSourceConnection, auditv1.ActionDevOpsSourceConnectionUpdated, auditv1.TargetSourceConnection, ResultSourceConnection}, true
	case MutationRecheckSourceConnection:
		return MutationContract{iamv1.ActionDevOpsSourceConnectionRecheck, iamv1.ResourceSourceConnection, auditv1.ActionDevOpsSourceConnectionRecheckScheduled, auditv1.TargetSourceConnection, ResultSourceConnection}, true
	case MutationCreateRepositoryBinding:
		return MutationContract{iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, auditv1.ActionDevOpsRepositoryBindingCreated, auditv1.TargetRepositoryBinding, ResultRepositoryBinding}, true
	case MutationUpdateRepositoryBinding:
		return MutationContract{iamv1.ActionDevOpsRepositoryBindingUpdate, iamv1.ResourceRepositoryBinding, auditv1.ActionDevOpsRepositoryBindingUpdated, auditv1.TargetRepositoryBinding, ResultRepositoryBinding}, true
	case MutationRecheckRepositoryBinding:
		return MutationContract{iamv1.ActionDevOpsRepositoryBindingRecheck, iamv1.ResourceRepositoryBinding, auditv1.ActionDevOpsRepositoryBindingRecheckScheduled, auditv1.TargetRepositoryBinding, ResultRepositoryBinding}, true
	case MutationCreatePipeline:
		return MutationContract{iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, auditv1.ActionDevOpsPipelineCreated, auditv1.TargetPipeline, ResultPipeline}, true
	case MutationUpdatePipelineDraft:
		return MutationContract{iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, auditv1.ActionDevOpsPipelineDraftUpdated, auditv1.TargetPipeline, ResultPipeline}, true
	case MutationActivatePipeline:
		return MutationContract{iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, auditv1.ActionDevOpsPipelineRevisionActivated, auditv1.TargetPipelineRevision, ResultPipelineActivation}, true
	default:
		return MutationContract{}, false
	}
}

// MutationRecord is delivery's durable command identity. It is internal, not
// a public DevOps resource, and contains no caller credential or provider data.
type MutationRecord struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	ID                     string                  `json:"id"`
	TenantID               devopsv1.TenantID       `json:"tenantId"`
	Kind                   MutationKind            `json:"kind"`
	CommandTargetID        devopsv1.ResourceID     `json:"commandTargetId"`
	RequestedBy            devopsv1.SubjectRef     `json:"requestedBy"`
	IAMDecisionID          string                  `json:"iamDecisionId"`
	IAMAction              iamv1.Action            `json:"iamAction"`
	IAMResource            iamv1.ResourceReference `json:"iamResource"`
	IdempotencyFingerprint string                  `json:"idempotencyFingerprint"`
	RequestDigest          string                  `json:"requestDigest"`
	ResultKind             MutationResultKind      `json:"resultKind"`
	Target                 auditv1.TargetReference `json:"target"`
	RequestID              string                  `json:"requestId"`
	CorrelationID          string                  `json:"correlationId"`
	TraceParent            string                  `json:"traceparent,omitempty"`
	CreatedAt              time.Time               `json:"createdAt"`
}

// MutationResult is a closed in-process union used to persist and replay the
// exact successful response even after the mutable resource changes again.
type MutationResult struct {
	Kind               MutationResultKind           `json:"kind"`
	Project            *devopsv1.DevOpsProject      `json:"project,omitempty"`
	SourceConnection   *devopsv1.SourceConnection   `json:"sourceConnection,omitempty"`
	RepositoryBinding  *devopsv1.RepositoryBinding  `json:"repositoryBinding,omitempty"`
	Pipeline           *devopsv1.Pipeline           `json:"pipeline,omitempty"`
	PipelineActivation *devopsv1.PipelineActivation `json:"pipelineActivation,omitempty"`
}

type StoredMutation struct {
	Record MutationRecord
	Result MutationResult
}

type Submission struct {
	Record     MutationRecord
	Result     MutationResult
	AuditEvent auditv1.Event
}

type Transaction interface {
	TransactionTime(context.Context) (time.Time, error)
	FindMutation(context.Context, string) (StoredMutation, bool, error)
	LoadProject(context.Context, devopsv1.ResourceID) (devopsv1.DevOpsProject, bool, error)
	LoadSourceConnection(context.Context, devopsv1.ResourceID) (devopsv1.SourceConnection, bool, error)
	LoadRepositoryBinding(context.Context, devopsv1.ResourceID) (devopsv1.RepositoryBinding, bool, error)
	LoadPipeline(context.Context, devopsv1.ResourceID) (devopsv1.Pipeline, bool, error)
	LoadPipelineRevision(context.Context, devopsv1.ResourceID) (devopsv1.PipelineRevision, bool, error)
	CreateProject(context.Context, devopsv1.DevOpsProject, Submission) error
	CreateSourceConnection(context.Context, devopsv1.SourceConnection, Submission) error
	UpdateSourceConnection(context.Context, uint64, devopsv1.SourceConnection, Submission) error
	RecheckSourceConnection(context.Context, uint64, devopsv1.SourceConnection, Submission) error
	CreateRepositoryBinding(context.Context, devopsv1.RepositoryBinding, Submission) error
	UpdateRepositoryBinding(context.Context, uint64, devopsv1.RepositoryBinding, Submission) error
	RecheckRepositoryBinding(context.Context, uint64, devopsv1.RepositoryBinding, Submission) error
	CreatePipeline(context.Context, devopsv1.Pipeline, Submission) error
	UpdatePipelineDraft(context.Context, uint64, devopsv1.Pipeline, Submission) error
	ActivatePipeline(context.Context, uint64, devopsv1.PipelineActivation, Submission) error
}

type Repository interface {
	WithinTransaction(context.Context, devopsv1.TenantID, func(context.Context, Transaction) error) error
}

type Config struct {
	MaxTransactionAttempts int
}

type Usecase struct {
	repository Repository
	config     Config
}

type Result[T any] struct {
	Value    T
	Replayed bool
}

type GetProjectQuery struct {
	Authorization port.Authorization
	ProjectID     devopsv1.ResourceID
}

type GetSourceConnectionQuery struct {
	Authorization      port.Authorization
	SourceConnectionID devopsv1.ResourceID
}

type GetRepositoryBindingQuery struct {
	Authorization       port.Authorization
	RepositoryBindingID devopsv1.ResourceID
}

type GetPipelineQuery struct {
	Authorization port.Authorization
	PipelineID    devopsv1.ResourceID
}

type GetPipelineRevisionQuery struct {
	Authorization      port.Authorization
	PipelineID         devopsv1.ResourceID
	PipelineRevisionID devopsv1.ResourceID
}

type CreateProjectCommand struct {
	Authorization  port.Authorization
	Request        devopsv1.CreateDevOpsProjectRequest
	IdempotencyKey string
}

type CreateSourceConnectionCommand struct {
	Authorization  port.Authorization
	Request        devopsv1.CreateSourceConnectionRequest
	IdempotencyKey string
}

type UpdateSourceConnectionCommand struct {
	Authorization           port.Authorization
	SourceConnectionID      devopsv1.ResourceID
	ExpectedResourceVersion uint64
	Request                 devopsv1.UpdateSourceConnectionRequest
	IdempotencyKey          string
}

type RecheckSourceConnectionCommand struct {
	Authorization           port.Authorization
	SourceConnectionID      devopsv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type CreateRepositoryBindingCommand struct {
	Authorization  port.Authorization
	Request        devopsv1.CreateRepositoryBindingRequest
	IdempotencyKey string
}

type UpdateRepositoryBindingCommand struct {
	Authorization           port.Authorization
	RepositoryBindingID     devopsv1.ResourceID
	ExpectedResourceVersion uint64
	Request                 devopsv1.UpdateRepositoryBindingRequest
	IdempotencyKey          string
}

type RecheckRepositoryBindingCommand struct {
	Authorization           port.Authorization
	RepositoryBindingID     devopsv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

type CreatePipelineCommand struct {
	Authorization  port.Authorization
	Request        devopsv1.CreatePipelineRequest
	IdempotencyKey string
}

type UpdatePipelineDraftCommand struct {
	Authorization           port.Authorization
	PipelineID              devopsv1.ResourceID
	ExpectedResourceVersion uint64
	Request                 devopsv1.UpdatePipelineDraftRequest
	IdempotencyKey          string
}

type ActivatePipelineCommand struct {
	Authorization           port.Authorization
	PipelineID              devopsv1.ResourceID
	ExpectedResourceVersion uint64
	IdempotencyKey          string
}

func NewUsecase(repository Repository, config Config) (*Usecase, error) {
	if repository == nil {
		return nil, errors.New("pipeline configuration repository is required")
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("maximum transaction attempts must be between 1 and 10")
	}
	return &Usecase{repository: repository, config: config}, nil
}

func ValidateMutationRecord(value MutationRecord) error {
	var problems []error
	contract, known := ContractForMutation(value.Kind)
	if !known {
		problems = append(problems, fmt.Errorf("unknown mutation kind %q", value.Kind))
	}
	problems = append(problems,
		devopsv1.ValidateID("mutation.id", value.ID),
		devopsv1.ValidateID("mutation.tenantId", string(value.TenantID)),
		devopsv1.ValidateID("mutation.commandTargetId", string(value.CommandTargetID)),
		devopsv1.ValidateSubjectRef(value.RequestedBy),
		devopsv1.ValidateID("mutation.iamDecisionId", value.IAMDecisionID),
		devopsv1.ValidateID("mutation.iamResource.id", value.IAMResource.ID),
		devopsv1.ValidateDigest("mutation.idempotencyFingerprint", value.IdempotencyFingerprint),
		devopsv1.ValidateDigest("mutation.requestDigest", value.RequestDigest),
		devopsv1.ValidateID("mutation.target.id", value.Target.ID),
		devopsv1.ValidateID("mutation.requestId", value.RequestID),
		devopsv1.ValidateID("mutation.correlationId", value.CorrelationID),
	)
	if value.SchemaVersion != "v1" {
		problems = append(problems, errors.New("mutation schemaVersion must be v1"))
	}
	if value.ID != operationID(value.IdempotencyFingerprint) {
		problems = append(problems, errors.New("mutation ID is not derived from its idempotency fingerprint"))
	}
	if known && (value.IAMAction != contract.IAMAction ||
		value.IAMResource.Kind != contract.IAMResourceKind ||
		value.IAMResource.ID != string(value.CommandTargetID) ||
		value.ResultKind != contract.ResultKind || value.Target.Kind != contract.AuditTargetKind) {
		problems = append(problems, errors.New("mutation does not match its closed contract"))
	}
	if value.CreatedAt.IsZero() || value.CreatedAt.Location() != time.UTC ||
		value.CreatedAt != value.CreatedAt.Round(0) || value.CreatedAt.Nanosecond()%1_000 != 0 {
		problems = append(problems, errors.New("mutation createdAt must be UTC with microsecond precision"))
	}
	if value.TraceParent != "" && !traceParentPattern.MatchString(value.TraceParent) {
		problems = append(problems, errors.New("mutation traceparent is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateMutationResult(value MutationResult) error {
	count := 0
	var validation error
	var targetID string
	if value.Project != nil {
		count++
		validation = errors.Join(validation, devopsv1.ValidateDevOpsProject(*value.Project))
		targetID = string(value.Project.Metadata.ID)
	}
	if value.SourceConnection != nil {
		count++
		validation = errors.Join(validation, devopsv1.ValidateSourceConnection(*value.SourceConnection))
		targetID = string(value.SourceConnection.Metadata.ID)
	}
	if value.RepositoryBinding != nil {
		count++
		validation = errors.Join(validation, devopsv1.ValidateRepositoryBinding(*value.RepositoryBinding))
		targetID = string(value.RepositoryBinding.Metadata.ID)
	}
	if value.Pipeline != nil {
		count++
		validation = errors.Join(validation, devopsv1.ValidatePipeline(*value.Pipeline))
		targetID = string(value.Pipeline.Metadata.ID)
	}
	if value.PipelineActivation != nil {
		count++
		validation = errors.Join(validation, devopsv1.ValidatePipelineActivation(*value.PipelineActivation))
		targetID = string(value.PipelineActivation.Revision.ID)
	}
	if count != 1 {
		return errors.Join(validation, errors.New("mutation result must contain exactly one value"))
	}
	expected := MutationResultKind("")
	switch {
	case value.Project != nil:
		expected = ResultDevOpsProject
	case value.SourceConnection != nil:
		expected = ResultSourceConnection
	case value.RepositoryBinding != nil:
		expected = ResultRepositoryBinding
	case value.Pipeline != nil:
		expected = ResultPipeline
	case value.PipelineActivation != nil:
		expected = ResultPipelineActivation
	}
	if value.Kind != expected || targetID == "" {
		validation = errors.Join(validation, errors.New("mutation result discriminator is invalid"))
	}
	return validation
}

func ValidateStoredMutation(value StoredMutation) error {
	var problems []error
	problems = append(problems, ValidateMutationRecord(value.Record), ValidateMutationResult(value.Result))
	if value.Record.ResultKind != value.Result.Kind || value.Record.Target.ID != resultTargetID(value.Result) ||
		value.Record.TenantID != resultTenantID(value.Result) {
		problems = append(problems, errors.New("stored mutation and result identities differ"))
	}
	if value.Record.Kind == MutationActivatePipeline {
		if value.Result.PipelineActivation == nil ||
			value.Result.PipelineActivation.Pipeline.Metadata.ID != value.Record.CommandTargetID {
			problems = append(problems, errors.New("Pipeline activation does not belong to its command target"))
		}
	} else if value.Record.Target.ID != string(value.Record.CommandTargetID) {
		problems = append(problems, errors.New("mutation result does not belong to its command target"))
	}
	return errors.Join(problems...)
}

func ValidateSubmission(value Submission) error {
	var problems []error
	problems = append(problems,
		ValidateStoredMutation(StoredMutation{Record: value.Record, Result: value.Result}),
		auditv1.ValidateEventForSource(auditv1.SourceDevOps, value.AuditEvent),
	)
	actorType := auditv1.ActorType(value.Record.RequestedBy.Kind)
	if value.AuditEvent.TenantID != auditv1.TenantID(value.Record.TenantID) ||
		value.AuditEvent.Actor.Type != actorType ||
		string(value.AuditEvent.Actor.ID) != value.Record.RequestedBy.ID ||
		string(value.AuditEvent.IAMDecisionID) != value.Record.IAMDecisionID ||
		value.AuditEvent.Action != mustMutationContract(value.Record.Kind).AuditAction ||
		value.AuditEvent.Target != value.Record.Target ||
		value.AuditEvent.Result != auditv1.ResultSucceeded ||
		value.AuditEvent.RequestDigest != value.Record.RequestDigest ||
		value.AuditEvent.RequestID != value.Record.RequestID ||
		value.AuditEvent.CorrelationID != value.Record.CorrelationID ||
		string(value.AuditEvent.OperationID) != value.Record.ID ||
		value.AuditEvent.TraceParent != value.Record.TraceParent ||
		!value.AuditEvent.OccurredAt.Equal(value.Record.CreatedAt) {
		problems = append(problems, errors.New("mutation and Audit event identities differ"))
	}
	return errors.Join(problems...)
}

func mustMutationContract(kind MutationKind) MutationContract {
	contract, _ := ContractForMutation(kind)
	return contract
}

func resultTargetID(value MutationResult) string {
	switch {
	case value.Project != nil:
		return string(value.Project.Metadata.ID)
	case value.SourceConnection != nil:
		return string(value.SourceConnection.Metadata.ID)
	case value.RepositoryBinding != nil:
		return string(value.RepositoryBinding.Metadata.ID)
	case value.Pipeline != nil:
		return string(value.Pipeline.Metadata.ID)
	case value.PipelineActivation != nil:
		return string(value.PipelineActivation.Revision.ID)
	default:
		return ""
	}
}

func resultTenantID(value MutationResult) devopsv1.TenantID {
	switch {
	case value.Project != nil:
		return value.Project.Metadata.Scope.TenantID
	case value.SourceConnection != nil:
		return value.SourceConnection.Metadata.Scope.TenantID
	case value.RepositoryBinding != nil:
		return value.RepositoryBinding.Metadata.Scope.TenantID
	case value.Pipeline != nil:
		return value.Pipeline.Metadata.Scope.TenantID
	case value.PipelineActivation != nil:
		return value.PipelineActivation.Pipeline.Metadata.Scope.TenantID
	default:
		return ""
	}
}
