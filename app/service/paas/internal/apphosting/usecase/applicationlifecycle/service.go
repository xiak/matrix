package applicationlifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
)

const maxResourceVersion = uint64(9007199254740991)

type mutation struct {
	tenantID                paasv1.TenantID
	deploymentID            paasv1.ResourceID
	name                    string
	spec                    paasv1.DeploymentSpec
	sourceGeneration        uint64
	expectedResourceVersion uint64
	idempotencyKey          string
	requestedBy             paasv1.SubjectRef
	kind                    string
}

type requestIdentity struct {
	Kind                    string            `json:"kind"`
	DeploymentID            paasv1.ResourceID `json:"deploymentId"`
	Name                    string            `json:"name,omitempty"`
	ExpectedResourceVersion uint64            `json:"expectedResourceVersion"`
	SourceGeneration        uint64            `json:"sourceGeneration,omitempty"`
	SpecContentDigest       string            `json:"specContentDigest"`
}

type idempotencyIdentity struct {
	TenantID       paasv1.TenantID    `json:"tenantId"`
	SubjectType    paasv1.SubjectType `json:"subjectType"`
	SubjectID      string             `json:"subjectId"`
	CommandKind    string             `json:"commandKind"`
	DeploymentID   paasv1.ResourceID  `json:"deploymentId"`
	IdempotencyKey string             `json:"idempotencyKey"`
}

func NewUsecase(repository Repository, config Config) (*Usecase, error) {
	if repository == nil {
		return nil, errors.New("application lifecycle repository is required")
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("maximum transaction attempts must be between 1 and 10")
	}
	return &Usecase{repository: repository, config: config}, nil
}

func (usecase *Usecase) Submit(ctx context.Context, command SubmitCommand) (Result, error) {
	if err := validateSubmitCommand(command); err != nil {
		return Result{}, err
	}
	return usecase.execute(ctx, mutation{
		tenantID:                command.TenantID,
		deploymentID:            command.DeploymentID,
		name:                    command.Name,
		spec:                    command.Spec,
		expectedResourceVersion: command.ExpectedResourceVersion,
		idempotencyKey:          command.IdempotencyKey,
		requestedBy:             command.RequestedBy,
		kind:                    "SUBMIT_DEPLOYMENT",
	})
}

func (usecase *Usecase) Rollback(ctx context.Context, command RollbackCommand) (Result, error) {
	if err := validateRollbackCommand(command); err != nil {
		return Result{}, err
	}
	return usecase.execute(ctx, mutation{
		tenantID:                command.TenantID,
		deploymentID:            command.DeploymentID,
		sourceGeneration:        command.SourceGeneration,
		expectedResourceVersion: command.ExpectedResourceVersion,
		idempotencyKey:          command.IdempotencyKey,
		requestedBy:             command.RequestedBy,
		kind:                    "ROLLBACK_DEPLOYMENT",
	})
}

func (usecase *Usecase) execute(ctx context.Context, command mutation) (Result, error) {
	if usecase == nil || usecase.repository == nil {
		return Result{}, errors.New("application lifecycle use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("application lifecycle context is nil")
	}
	fingerprint, err := idempotencyFingerprint(command)
	if err != nil {
		return Result{}, err
	}

	var result Result
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result{}
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			command.tenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				result, err = executeInTransaction(
					transactionContext,
					transaction,
					command,
					fingerprint,
				)
				return err
			},
		)
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return Result{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	return Result{}, fmt.Errorf("application lifecycle transaction attempts exhausted: %w", transactionErr)
}

func executeInTransaction(
	ctx context.Context,
	transaction Transaction,
	command mutation,
	fingerprint string,
) (Result, error) {
	if transaction == nil {
		return Result{}, errors.New("application lifecycle transaction is nil")
	}
	current, found, err := transaction.LoadDeployment(ctx, command.deploymentID)
	if err != nil {
		return Result{}, err
	}

	spec := command.spec
	if command.kind == "ROLLBACK_DEPLOYMENT" {
		source, err := transaction.LoadAcceptedGeneration(
			ctx,
			command.deploymentID,
			command.sourceGeneration,
		)
		if err != nil {
			return Result{}, err
		}
		spec = source.Spec
	}
	requestDigest, err := mutationRequestDigest(command, spec)
	if err != nil {
		return Result{}, err
	}
	storedOperation, replayed, err := transaction.FindOperationByFingerprint(ctx, fingerprint)
	if err != nil {
		return Result{}, err
	}
	if replayed {
		if storedOperation.RequestDigest != requestDigest ||
			storedOperation.Target.ID != command.deploymentID {
			return Result{}, ErrIdempotencyConflict
		}
		generation, err := transaction.LoadGenerationByOperation(ctx, storedOperation.ID)
		if err != nil {
			return Result{}, err
		}
		deployment, deploymentFound, err := transaction.LoadDeployment(ctx, command.deploymentID)
		if err != nil {
			return Result{}, err
		}
		if !deploymentFound {
			return Result{}, ErrNotFound
		}
		return Result{
			Deployment: deployment,
			Generation: generation,
			Operation:  storedOperation,
			Replayed:   true,
		}, nil
	}
	if command.kind == "ROLLBACK_DEPLOYMENT" &&
		spec.DesiredState != paasv1.DeploymentDesiredRunning {
		return Result{}, errors.New("rollback source must have RUNNING desired state")
	}

	if command.expectedResourceVersion == 0 {
		if found {
			return Result{}, ErrResourceVersionConflict
		}
	} else if !found || current.Metadata.ResourceVersion != command.expectedResourceVersion {
		return Result{}, ErrResourceVersionConflict
	}
	if found && containsActivePhase(current.Status.Phase) {
		return Result{}, ErrOperationInProgress
	}
	if !found && spec.DesiredState == paasv1.DeploymentDesiredStopped {
		return Result{}, errors.New("a new Deployment must start in RUNNING desired state")
	}
	if found && spec.DesiredState == paasv1.DeploymentDesiredStopped {
		stopSpec := current.Spec
		stopSpec.DesiredState = paasv1.DeploymentDesiredStopped
		if paasv1.DeploymentSpecContentDigest(spec) !=
			paasv1.DeploymentSpecContentDigest(stopSpec) {
			return Result{}, errors.New("stop can only change Deployment desiredState")
		}
	}
	if command.kind == "ROLLBACK_DEPLOYMENT" &&
		(!found || command.sourceGeneration >= current.Generation) {
		return Result{}, errors.New("rollback source must be an earlier accepted generation")
	}
	if found &&
		(current.Metadata.ResourceVersion >= maxResourceVersion ||
			current.Generation >= maxResourceVersion) {
		return Result{}, ErrResourceVersionConflict
	}

	revision, err := transaction.LoadApplicationRevision(ctx, spec.ApplicationRevisionID)
	if err != nil {
		return Result{}, err
	}
	if _, err := transaction.LoadPlacementPolicy(ctx, spec.PlacementPolicyID); err != nil {
		return Result{}, err
	}
	if err := transaction.ValidateConfigurationBindings(ctx, spec, revision.Spec.ApplicationID); err != nil {
		return Result{}, err
	}
	if found && command.kind != "ROLLBACK_DEPLOYMENT" &&
		paasv1.DeploymentSpecContentDigest(spec) == paasv1.DeploymentSpecContentDigest(current.Spec) {
		return Result{}, ErrNoDesiredChange
	}

	transactionTime, err := transaction.TransactionTime(ctx)
	if err != nil {
		return Result{}, err
	}
	operationID := operationIDFromFingerprint(fingerprint)
	action := operationAction(command, found, spec)
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion,
		Kind:       "Operation",
		ID:         operationID,
		Scope: paasv1.ResourceScope{
			Kind:     paasv1.AuthorityTenant,
			TenantID: command.tenantID,
		},
		Action:                 action,
		Target:                 paasv1.ResourceRef{Kind: "Deployment", ID: command.deploymentID},
		RequestedBy:            command.requestedBy,
		IdempotencyFingerprint: fingerprint,
		RequestDigest:          requestDigest,
		State:                  paasv1.OperationAccepted,
		Attempt:                1,
		CreatedAt:              transactionTime,
		UpdatedAt:              transactionTime,
	}

	deployment := newDeployment(command, current, found, spec, operationID, transactionTime)
	if err := paasv1.ValidateDeploymentAgainstRevision(deployment, revision); err != nil {
		return Result{}, fmt.Errorf("invalid Deployment mutation: %w", err)
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion:           paasv1.APIVersion,
		Kind:                 "DeploymentGeneration",
		Scope:                deployment.Metadata.Scope,
		DeploymentID:         deployment.Metadata.ID,
		Generation:           deployment.Generation,
		Spec:                 deployment.Spec,
		CreatedByOperationID: operation.ID,
		CreatedAt:            transactionTime,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	if err := paasv1.ValidateDeploymentGenerationAgainstRevision(generation, revision); err != nil {
		return Result{}, fmt.Errorf("invalid DeploymentGeneration mutation: %w", err)
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return Result{}, fmt.Errorf("invalid Operation mutation: %w", err)
	}
	if err := transaction.SubmitDeployment(ctx, Submission{
		ExpectedResourceVersion: command.expectedResourceVersion,
		Deployment:              deployment,
		Generation:              generation,
		Operation:               operation,
	}); err != nil {
		return Result{}, err
	}
	return Result{Deployment: deployment, Generation: generation, Operation: operation}, nil
}

func newDeployment(
	command mutation,
	current paasv1.Deployment,
	found bool,
	spec paasv1.DeploymentSpec,
	operationID paasv1.OperationID,
	transactionTime time.Time,
) paasv1.Deployment {
	if !found {
		return paasv1.Deployment{
			APIVersion: paasv1.APIVersion,
			Kind:       "Deployment",
			Metadata: paasv1.ResourceMetadata{
				ID: command.deploymentID, Name: command.name,
				Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: command.tenantID},
				ResourceVersion: 1, CreatedAt: transactionTime, UpdatedAt: transactionTime,
			},
			Generation: 1,
			Spec:       spec,
			Status: paasv1.DeploymentStatus{
				Phase: paasv1.DeploymentPending, ObservedGeneration: 0,
				CurrentOperationID: operationID, ReadyComponents: 0, ObservedAt: transactionTime,
			},
		}
	}
	metadata := current.Metadata
	metadata.ResourceVersion++
	metadata.UpdatedAt = transactionTime
	status := current.Status
	status.Phase = paasv1.DeploymentPending
	status.CurrentOperationID = operationID
	return paasv1.Deployment{
		APIVersion: paasv1.APIVersion,
		Kind:       "Deployment",
		Metadata:   metadata,
		Generation: current.Generation + 1,
		Spec:       spec,
		Status:     status,
	}
}

func operationAction(command mutation, found bool, spec paasv1.DeploymentSpec) paasv1.OperationAction {
	if command.kind == "ROLLBACK_DEPLOYMENT" {
		return paasv1.OperationRollback
	}
	if !found {
		return paasv1.OperationDeploy
	}
	if spec.DesiredState == paasv1.DeploymentDesiredStopped {
		return paasv1.OperationStop
	}
	return paasv1.OperationUpdate
}

func idempotencyFingerprint(command mutation) (string, error) {
	encoded, err := json.Marshal(idempotencyIdentity{
		TenantID: command.tenantID, SubjectType: command.requestedBy.Type,
		SubjectID: command.requestedBy.ID, CommandKind: command.kind,
		DeploymentID: command.deploymentID, IdempotencyKey: command.idempotencyKey,
	})
	if err != nil {
		return "", fmt.Errorf("encode idempotency identity: %w", err)
	}
	return domain.DigestPayload(encoded), nil
}

func mutationRequestDigest(command mutation, spec paasv1.DeploymentSpec) (string, error) {
	encoded, err := json.Marshal(requestIdentity{
		Kind: command.kind, DeploymentID: command.deploymentID, Name: command.name,
		ExpectedResourceVersion: command.expectedResourceVersion,
		SourceGeneration:        command.sourceGeneration,
		SpecContentDigest:       paasv1.DeploymentSpecContentDigest(spec),
	})
	if err != nil {
		return "", fmt.Errorf("encode deployment mutation identity: %w", err)
	}
	return domain.DigestPayload(encoded), nil
}

func operationIDFromFingerprint(fingerprint string) paasv1.OperationID {
	digest := sha256.Sum256([]byte(fingerprint))
	return paasv1.OperationID("operation-" + hex.EncodeToString(digest[:]))
}

func validateSubmitCommand(command SubmitCommand) error {
	var problems []error
	problems = append(problems,
		validateCommandIdentity(command.TenantID, command.DeploymentID, command.IdempotencyKey, command.RequestedBy),
	)
	if command.ExpectedResourceVersion > maxResourceVersion {
		problems = append(problems, errors.New("expected resource version exceeds the v1 contract"))
	}
	if command.ExpectedResourceVersion == 0 && command.Name == "" {
		problems = append(problems, errors.New("new Deployment name is required"))
	}
	if command.ExpectedResourceVersion > 0 && command.Name != "" {
		problems = append(problems, errors.New("Deployment update cannot rename the resource"))
	}
	return errors.Join(problems...)
}

func validateRollbackCommand(command RollbackCommand) error {
	var problems []error
	problems = append(problems,
		validateCommandIdentity(command.TenantID, command.DeploymentID, command.IdempotencyKey, command.RequestedBy),
	)
	if command.SourceGeneration == 0 || command.SourceGeneration > maxResourceVersion {
		problems = append(problems, errors.New("rollback source generation is invalid"))
	}
	if command.ExpectedResourceVersion == 0 || command.ExpectedResourceVersion > maxResourceVersion {
		problems = append(problems, errors.New("rollback requires a valid expected resource version"))
	}
	return errors.Join(problems...)
}

func validateCommandIdentity(
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
	idempotencyKey string,
	requestedBy paasv1.SubjectRef,
) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(tenantID)),
		paasv1.ValidateID("deploymentId", string(deploymentID)),
		paasv1.ValidateSafeExternalText("Idempotency-Key", idempotencyKey, 128, true),
		paasv1.ValidateID("requestedBy.id", requestedBy.ID),
	)
	if requestedBy.Type != paasv1.SubjectUser &&
		requestedBy.Type != paasv1.SubjectServiceAccount &&
		requestedBy.Type != paasv1.SubjectAgent &&
		requestedBy.Type != paasv1.SubjectSystemUser {
		problems = append(problems, fmt.Errorf("unknown requester type %q", requestedBy.Type))
	}
	return errors.Join(problems...)
}

func containsActivePhase(phase paasv1.DeploymentPhase) bool {
	return phase == paasv1.DeploymentPending ||
		phase == paasv1.DeploymentPlacing ||
		phase == paasv1.DeploymentApplying ||
		phase == paasv1.DeploymentStopping
}
