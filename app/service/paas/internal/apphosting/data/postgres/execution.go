package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
)

var _ reconciledeployment.Repository = (*DeploymentExecutionRepository)(nil)

type DeploymentExecutionRepository struct {
	pool *pgxpool.Pool
}

func NewDeploymentExecutionRepository(
	pool *pgxpool.Pool,
) (*DeploymentExecutionRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &DeploymentExecutionRepository{pool: pool}, nil
}

func (repository *DeploymentExecutionRepository) Load(
	ctx context.Context,
	guard operationqueue.LeaseGuard,
) (reconciledeployment.State, error) {
	if repository == nil || repository.pool == nil {
		return reconciledeployment.State{}, errors.New("Deployment execution repository is nil")
	}
	if ctx == nil {
		return reconciledeployment.State{}, errors.New("Deployment execution load context is nil")
	}
	var state reconciledeployment.State
	err := repository.withinLeaseTransaction(
		ctx,
		guard,
		func(tx pgx.Tx) error {
			var err error
			state, err = loadExecutionState(ctx, tx, guard)
			return err
		},
	)
	if err != nil {
		return reconciledeployment.State{}, mapExecutionError("load Deployment execution", err)
	}
	return state, nil
}

func (repository *DeploymentExecutionRepository) PrepareEffect(
	ctx context.Context,
	lease operationqueue.Lease,
	action paasv1.AdapterAction,
	bindingRef string,
	deadline time.Time,
) (paasv1.DeploymentExecutionRequest, bool, error) {
	if err := validateExecutionPreparation(lease, bindingRef, deadline); err != nil {
		return paasv1.DeploymentExecutionRequest{}, false, err
	}
	var request paasv1.DeploymentExecutionRequest
	var replayed bool
	err := repository.withinLeaseTransaction(
		ctx,
		lease.Guard(),
		func(tx pgx.Tx) error {
			state, err := loadExecutionState(ctx, tx, lease.Guard())
			if err != nil {
				return err
			}
			if state.Placement == nil || state.Placement.Outcome != paasv1.PlacementScheduled {
				return errors.New("Deployment effect requires a scheduled placement")
			}
			if expectedEffectAction(lease.Operation.Action) != action {
				return errors.New("adapter effect action does not match Operation action")
			}
			replayed = state.EffectRequest != nil
			command, err := deploymentCommand(
				lease,
				action,
				state,
				bindingRef,
				deadline,
			)
			if err != nil {
				return err
			}
			request = paasv1.DeploymentExecutionRequest{
				Command: command, Generation: state.Generation,
				ApplicationRevision: state.ApplicationRevision,
				ConfigurationRevisions: append(
					[]paasv1.ConfigurationRevision(nil),
					state.ConfigurationRevisions...,
				),
				Placement: *state.Placement,
			}
			request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
			if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
				return fmt.Errorf("prepare invalid Deployment execution request: %w", err)
			}
			stored, err := storeAdapterCommand(ctx, tx, lease.Guard(), request.Command)
			if err != nil {
				return err
			}
			request.Command = stored
			return paasv1.ValidateDeploymentExecutionRequest(request)
		},
	)
	if err != nil {
		return paasv1.DeploymentExecutionRequest{}, false, mapExecutionError(
			"prepare Deployment effect",
			err,
		)
	}
	return request, replayed, nil
}

func (repository *DeploymentExecutionRepository) PrepareObservation(
	ctx context.Context,
	lease operationqueue.Lease,
	bindingRef string,
	deadline time.Time,
) (paasv1.ObserveDeploymentRequest, bool, error) {
	if err := validateExecutionPreparation(lease, bindingRef, deadline); err != nil {
		return paasv1.ObserveDeploymentRequest{}, false, err
	}
	var request paasv1.ObserveDeploymentRequest
	var replayed bool
	err := repository.withinLeaseTransaction(
		ctx,
		lease.Guard(),
		func(tx pgx.Tx) error {
			state, err := loadExecutionState(ctx, tx, lease.Guard())
			if err != nil {
				return err
			}
			if state.Placement == nil || state.Placement.Outcome != paasv1.PlacementScheduled {
				return errors.New("Deployment observation requires a scheduled placement")
			}
			replayed = state.ObserveRequest != nil
			command, err := deploymentCommand(
				lease,
				paasv1.AdapterObserveDeployment,
				state,
				bindingRef,
				deadline,
			)
			if err != nil {
				return err
			}
			request = paasv1.ObserveDeploymentRequest{
				Command: command, Generation: state.Generation.Generation,
				ExpectedContentDigest: state.Generation.ContentDigest,
			}
			request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(request)
			if err := paasv1.ValidateObserveDeploymentRequest(request); err != nil {
				return fmt.Errorf("prepare invalid Deployment observation request: %w", err)
			}
			stored, err := storeAdapterCommand(ctx, tx, lease.Guard(), request.Command)
			if err != nil {
				return err
			}
			request.Command = stored
			return paasv1.ValidateObserveDeploymentRequest(request)
		},
	)
	if err != nil {
		return paasv1.ObserveDeploymentRequest{}, false, mapExecutionError(
			"prepare Deployment observation",
			err,
		)
	}
	return request, replayed, nil
}

func (repository *DeploymentExecutionRepository) withinLeaseTransaction(
	ctx context.Context,
	guard operationqueue.LeaseGuard,
	callback func(pgx.Tx) error,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("Deployment execution repository is nil")
	}
	if ctx == nil {
		return errors.New("Deployment execution transaction context is nil")
	}
	if err := operationqueue.ValidateLeaseGuard(guard); err != nil {
		return err
	}
	if callback == nil {
		return errors.New("Deployment execution transaction callback is required")
	}
	return withinTenantTransaction(
		ctx,
		repository.pool,
		guard.TenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			if err := assertOperationLease(ctx, tx, guard); err != nil {
				return err
			}
			return callback(tx)
		},
	)
}

func assertOperationLease(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
) error {
	var action string
	var deploymentID string
	var state string
	return tx.QueryRow(
		ctx,
		`SELECT operation_action, deployment_id, operation_state
		   FROM paas.assert_current_operation_lease($1, $2, $3)`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
	).Scan(&action, &deploymentID, &state)
}

func loadExecutionState(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
) (reconciledeployment.State, error) {
	base := &placementTransaction{tx: tx, tenantID: guard.TenantID, leaseGuard: guard}
	loader := &applicationTransaction{placementTransaction: base}
	generation, err := loader.LoadGenerationByOperation(ctx, guard.OperationID)
	if err != nil {
		return reconciledeployment.State{}, err
	}
	deployment, err := base.loadDeployment(ctx, generation.DeploymentID)
	if err != nil {
		return reconciledeployment.State{}, err
	}
	if deployment.Generation != generation.Generation ||
		deployment.Metadata.Scope != generation.Scope ||
		deployment.Status.CurrentOperationID != guard.OperationID {
		return reconciledeployment.State{}, errors.New(
			"current Deployment does not match leased Operation generation",
		)
	}
	revision, err := base.loadApplicationRevision(ctx, generation.Spec.ApplicationRevisionID)
	if err != nil {
		return reconciledeployment.State{}, err
	}
	configurations, err := loadExecutionConfigurations(
		ctx,
		tx,
		guard.TenantID,
		revision.Spec.ApplicationID,
		generation.Spec,
	)
	if err != nil {
		return reconciledeployment.State{}, err
	}
	state := reconciledeployment.State{
		Deployment: deployment, Generation: generation,
		ApplicationRevision: revision, ConfigurationRevisions: configurations,
	}
	placement, found, err := loadOperationPlacement(ctx, tx, guard)
	if err != nil {
		return reconciledeployment.State{}, err
	}
	if found {
		state.Placement = &placement
	}
	if err := loadExecutionCommands(ctx, tx, guard, &state); err != nil {
		return reconciledeployment.State{}, err
	}
	if err := loadExecutionReceipt(ctx, tx, guard, &state); err != nil {
		return reconciledeployment.State{}, err
	}
	if err := loadExecutionObservation(ctx, tx, guard, &state); err != nil {
		return reconciledeployment.State{}, err
	}
	return state, nil
}

func loadExecutionConfigurations(
	ctx context.Context,
	tx pgx.Tx,
	tenantID paasv1.TenantID,
	applicationID paasv1.ResourceID,
	spec paasv1.DeploymentSpec,
) ([]paasv1.ConfigurationRevision, error) {
	set := make(map[string]struct{})
	for _, component := range spec.Components {
		for _, binding := range component.Bindings {
			if binding.ConfigurationRevisionID != "" {
				set[string(binding.ConfigurationRevisionID)] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(
		ctx,
		`SELECT revision.id, configuration.application_id, revision.document
		   FROM paas.configuration_revisions AS revision
		   JOIN paas.configurations AS configuration
		     ON configuration.tenant_id = revision.tenant_id
		    AND configuration.id = revision.configuration_id
		  WHERE revision.tenant_id = $1
		    AND revision.id = ANY($2::text[])
		  ORDER BY revision.id COLLATE "C"`,
		string(tenantID),
		ids,
	)
	if err != nil {
		return nil, fmt.Errorf("load execution ConfigurationRevisions: %w", err)
	}
	defer rows.Close()
	values := make([]paasv1.ConfigurationRevision, 0, len(ids))
	for rows.Next() {
		var id string
		var ownerID string
		var document []byte
		if err := rows.Scan(&id, &ownerID, &document); err != nil {
			return nil, fmt.Errorf("scan execution ConfigurationRevision: %w", err)
		}
		var value paasv1.ConfigurationRevision
		if err := decodeDocument("ConfigurationRevision", document, &value); err != nil {
			return nil, err
		}
		if err := paasv1.ValidateConfigurationRevision(value); err != nil {
			return nil, fmt.Errorf("validate execution ConfigurationRevision: %w", err)
		}
		if string(value.Metadata.ID) != id ||
			value.Metadata.Scope.TenantID != tenantID ||
			ownerID != string(applicationID) {
			return nil, errors.New("execution ConfigurationRevision ownership mismatch")
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate execution ConfigurationRevisions: %w", err)
	}
	if len(values) != len(ids) {
		return nil, reconciledeployment.ErrNotFound
	}
	return values, nil
}

func loadOperationPlacement(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
) (paasv1.PlacementDecision, bool, error) {
	var document []byte
	err := tx.QueryRow(
		ctx,
		`SELECT document
		   FROM paas.placement_decisions
		  WHERE tenant_id = $1
		    AND operation_id = $2`,
		string(guard.TenantID),
		string(guard.OperationID),
	).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.PlacementDecision{}, false, nil
	}
	if err != nil {
		return paasv1.PlacementDecision{}, false, fmt.Errorf("load Operation placement: %w", err)
	}
	var value paasv1.PlacementDecision
	if err := decodeDocument("PlacementDecision", document, &value); err != nil {
		return paasv1.PlacementDecision{}, false, err
	}
	if err := paasv1.ValidatePlacementDecision(value); err != nil {
		return paasv1.PlacementDecision{}, false, fmt.Errorf("validate Operation placement: %w", err)
	}
	return value, true, nil
}

func loadExecutionCommands(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	state *reconciledeployment.State,
) error {
	rows, err := tx.Query(
		ctx,
		`SELECT action, document
		   FROM paas.adapter_commands
		  WHERE tenant_id = $1
		    AND operation_id = $2
		  ORDER BY action COLLATE "C"`,
		string(guard.TenantID),
		string(guard.OperationID),
	)
	if err != nil {
		return fmt.Errorf("load Deployment adapter commands: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var document []byte
		if err := rows.Scan(&action, &document); err != nil {
			return fmt.Errorf("scan Deployment adapter command: %w", err)
		}
		var command paasv1.AdapterCommandEnvelope
		if err := decodeDocument("AdapterCommandEnvelope", document, &command); err != nil {
			return err
		}
		if err := paasv1.ValidateAdapterCommand(command); err != nil {
			return fmt.Errorf("validate stored Deployment adapter command: %w", err)
		}
		if string(command.Action) != action || command.OperationID != guard.OperationID {
			return errors.New("stored Deployment adapter command identity mismatch")
		}
		if command.Action == paasv1.AdapterObserveDeployment {
			if state.ObserveRequest != nil {
				return errors.New("Operation has multiple observation commands")
			}
			request := paasv1.ObserveDeploymentRequest{
				Command: command, Generation: state.Generation.Generation,
				ExpectedContentDigest: state.Generation.ContentDigest,
			}
			if err := paasv1.ValidateObserveDeploymentRequest(request); err != nil {
				return fmt.Errorf("validate stored observation request: %w", err)
			}
			state.ObserveRequest = &request
			continue
		}
		if state.EffectRequest != nil {
			return errors.New("Operation has multiple effect commands")
		}
		if state.Placement == nil {
			return errors.New("effect command exists without PlacementDecision")
		}
		request := paasv1.DeploymentExecutionRequest{
			Command: command, Generation: state.Generation,
			ApplicationRevision: state.ApplicationRevision,
			ConfigurationRevisions: append(
				[]paasv1.ConfigurationRevision(nil),
				state.ConfigurationRevisions...,
			),
			Placement: *state.Placement,
		}
		if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
			return fmt.Errorf("validate stored Deployment execution request: %w", err)
		}
		state.EffectRequest = &request
	}
	return rows.Err()
}

func loadExecutionReceipt(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	state *reconciledeployment.State,
) error {
	var (
		commandID       string
		requestDigest   string
		resultState     string
		receiptDigest   *string
		normalizedError []byte
		evidence        []byte
		observedAt      time.Time
	)
	err := tx.QueryRow(
		ctx,
		`SELECT receipt.command_id,
		        receipt.request_digest,
		        receipt.state,
		        receipt.receipt_digest,
		        receipt.normalized_error,
		        receipt.evidence,
		        receipt.observed_at
		   FROM paas.adapter_receipts AS receipt
		   JOIN paas.adapter_commands AS command
		     ON command.tenant_id = receipt.tenant_id
		    AND command.id = receipt.command_id
		  WHERE command.tenant_id = $1
		    AND command.operation_id = $2
		    AND command.action <> 'OBSERVE_DEPLOYMENT'`,
		string(guard.TenantID),
		string(guard.OperationID),
	).Scan(
		&commandID,
		&requestDigest,
		&resultState,
		&receiptDigest,
		&normalizedError,
		&evidence,
		&observedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load Deployment adapter receipt: %w", err)
	}
	var normalized *paasv1.NormalizedAdapterError
	if len(normalizedError) > 0 {
		var value paasv1.NormalizedAdapterError
		if err := decodeDocument("NormalizedAdapterError", normalizedError, &value); err != nil {
			return err
		}
		if err := paasv1.ValidateNormalizedAdapterError(value); err != nil {
			return fmt.Errorf("validate stored normalized adapter error: %w", err)
		}
		normalized = &value
	}
	var storedEvidence []paasv1.Evidence
	if err := json.Unmarshal(evidence, &storedEvidence); err != nil {
		return fmt.Errorf("decode stored adapter receipt evidence: %w", err)
	}
	for index, value := range storedEvidence {
		if err := paasv1.ValidateEvidence(value); err != nil {
			return fmt.Errorf("validate stored adapter receipt evidence %d: %w", index, err)
		}
	}
	receipt := reconciledeployment.StoredReceipt{
		CommandID: paasv1.CommandID(commandID), RequestDigest: requestDigest,
		State: paasv1.AdapterResultState(resultState), Error: normalized,
		ObservedAt: databaseTime(observedAt),
	}
	if receiptDigest != nil {
		receipt.ReceiptDigest = *receiptDigest
	}
	if state.EffectRequest == nil ||
		receipt.CommandID != state.EffectRequest.Command.CommandID ||
		receipt.RequestDigest != state.EffectRequest.Command.RequestDigest ||
		!validStoredReceipt(receipt) {
		return errors.New("stored Deployment adapter receipt identity is invalid")
	}
	state.Receipt = &receipt
	return nil
}

func validStoredReceipt(value reconciledeployment.StoredReceipt) bool {
	if value.CommandID == "" || value.RequestDigest == "" || value.ObservedAt.IsZero() {
		return false
	}
	switch value.State {
	case paasv1.AdapterResultSucceeded:
		return value.ReceiptDigest != "" && value.Error == nil
	case paasv1.AdapterResultInProgress:
		return value.Error == nil
	case paasv1.AdapterResultFailed, paasv1.AdapterResultUnknown:
		return value.Error != nil
	default:
		return false
	}
}

func loadExecutionObservation(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	state *reconciledeployment.State,
) error {
	var document []byte
	err := tx.QueryRow(
		ctx,
		`SELECT observation.document
		   FROM paas.deployment_observations AS observation
		   JOIN paas.adapter_commands AS command
		     ON command.tenant_id = observation.tenant_id
		    AND command.id = observation.command_id
		  WHERE command.tenant_id = $1
		    AND command.operation_id = $2
		    AND command.action = 'OBSERVE_DEPLOYMENT'`,
		string(guard.TenantID),
		string(guard.OperationID),
	).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load Deployment observation: %w", err)
	}
	var value paasv1.DeploymentObservation
	if err := decodeDocument("DeploymentObservation", document, &value); err != nil {
		return err
	}
	if err := paasv1.ValidateDeploymentObservation(value); err != nil {
		return fmt.Errorf("validate stored Deployment observation: %w", err)
	}
	if state.ObserveRequest == nil ||
		value.DeploymentID != state.ObserveRequest.Command.DeploymentID ||
		value.Generation != state.ObserveRequest.Generation ||
		value.ApplicationRevisionID != state.ObserveRequest.Command.ApplicationRevisionID {
		return errors.New("stored Deployment observation identity mismatch")
	}
	state.Observation = &value
	return nil
}

func deploymentCommand(
	lease operationqueue.Lease,
	action paasv1.AdapterAction,
	state reconciledeployment.State,
	bindingRef string,
	deadline time.Time,
) (paasv1.AdapterCommandEnvelope, error) {
	if state.Placement == nil {
		return paasv1.AdapterCommandEnvelope{}, errors.New("adapter command requires placement")
	}
	commandID, err := domain.DeriveCommandID(domain.CommandIdentityInput{
		OperationID: lease.Operation.ID, Action: action,
		ExecutionTargetID:     state.Placement.ExecutionTargetID,
		DeploymentID:          state.Generation.DeploymentID,
		ApplicationRevisionID: state.Generation.Spec.ApplicationRevisionID,
	})
	if err != nil {
		return paasv1.AdapterCommandEnvelope{}, err
	}
	return paasv1.AdapterCommandEnvelope{
		OperationID: lease.Operation.ID, CommandID: commandID,
		Attempt: lease.Operation.Attempt, Action: action, Scope: state.Generation.Scope,
		ApplicationID:         state.ApplicationRevision.Spec.ApplicationID,
		ApplicationRevisionID: state.ApplicationRevision.Metadata.ID,
		DeploymentID:          state.Generation.DeploymentID,
		ExecutionTargetID:     state.Placement.ExecutionTargetID,
		BindingRef:            bindingRef, Deadline: deadline,
	}, nil
}

func storeAdapterCommand(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	command paasv1.AdapterCommandEnvelope,
) (paasv1.AdapterCommandEnvelope, error) {
	document, err := json.Marshal(command)
	if err != nil {
		return paasv1.AdapterCommandEnvelope{}, fmt.Errorf("encode adapter command: %w", err)
	}
	var storedDocument []byte
	if err := tx.QueryRow(
		ctx,
		`SELECT paas.prepare_adapter_command($1, $2, $3, $4::jsonb)`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
		document,
	).Scan(&storedDocument); err != nil {
		return paasv1.AdapterCommandEnvelope{}, err
	}
	var stored paasv1.AdapterCommandEnvelope
	if err := decodeDocument("AdapterCommandEnvelope", storedDocument, &stored); err != nil {
		return paasv1.AdapterCommandEnvelope{}, err
	}
	if err := paasv1.ValidateAdapterCommand(stored); err != nil {
		return paasv1.AdapterCommandEnvelope{}, fmt.Errorf("validate prepared adapter command: %w", err)
	}
	return stored, nil
}

func validateExecutionPreparation(
	lease operationqueue.Lease,
	bindingRef string,
	deadline time.Time,
) error {
	var problems []error
	problems = append(problems,
		operationqueue.ValidateLeaseGuard(lease.Guard()),
		paasv1.ValidateOperation(lease.Operation),
		paasv1.ValidateID("bindingRef", bindingRef),
	)
	if deadline.IsZero() || deadline.Location() != time.UTC ||
		deadline != deadline.Round(0) || deadline.Nanosecond()%1_000 != 0 {
		problems = append(problems, errors.New("adapter command deadline is invalid"))
	}
	return errors.Join(problems...)
}

func expectedEffectAction(action paasv1.OperationAction) paasv1.AdapterAction {
	switch action {
	case paasv1.OperationDeploy, paasv1.OperationUpdate:
		return paasv1.AdapterApplyDeployment
	case paasv1.OperationRollback:
		return paasv1.AdapterRollbackDeployment
	case paasv1.OperationStop:
		return paasv1.AdapterStopDeployment
	default:
		return ""
	}
}
