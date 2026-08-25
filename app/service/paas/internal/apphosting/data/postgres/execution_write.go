package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/reconciledeployment"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/transitionreservation"
)

type executionReservation struct {
	ID              paasv1.ResourceID
	State           placement.CapacityClaimState
	ResourceVersion uint64
}

func (repository *DeploymentExecutionRepository) UpdatePhase(
	ctx context.Context,
	guard operationqueue.LeaseGuard,
	phase paasv1.DeploymentPhase,
) (paasv1.Deployment, error) {
	var deployment paasv1.Deployment
	err := repository.withinLeaseTransaction(
		ctx,
		guard,
		func(tx pgx.Tx) error {
			state, err := loadExecutionState(ctx, tx, guard)
			if err != nil {
				return err
			}
			deployment = state.Deployment
			if deployment.Status.Phase == phase {
				return nil
			}
			if err := domain.ValidateDeploymentTransition(deployment.Status.Phase, phase); err != nil {
				return err
			}
			transactionTime, err := executionTransactionTime(ctx, tx)
			if err != nil {
				return err
			}
			current := deployment
			deployment.Metadata.ResourceVersion++
			deployment.Metadata.UpdatedAt = transactionTime
			deployment.Status.Phase = phase
			if err := paasv1.ValidateDeployment(deployment); err != nil {
				return fmt.Errorf("invalid Deployment phase update: %w", err)
			}
			return updateDeploymentStatusInTx(ctx, tx, guard, current, deployment)
		},
	)
	if err != nil {
		return paasv1.Deployment{}, mapExecutionError("update Deployment phase", err)
	}
	return deployment, nil
}

func (repository *DeploymentExecutionRepository) RecordResult(
	ctx context.Context,
	guard operationqueue.LeaseGuard,
	requestDigest string,
	result paasv1.AdapterResult,
) (bool, error) {
	if err := paasv1.ValidateAdapterResult(result); err != nil {
		return false, err
	}
	if err := paasv1.ValidateDigest("requestDigest", requestDigest); err != nil {
		return false, err
	}
	var changed bool
	err := repository.withinLeaseTransaction(
		ctx,
		guard,
		func(tx pgx.Tx) error {
			var err error
			changed, err = recordResultInTx(ctx, tx, guard, requestDigest, result)
			return err
		},
	)
	if err != nil {
		return false, mapExecutionError("record adapter receipt", err)
	}
	return changed, nil
}

func (repository *DeploymentExecutionRepository) RecordObservation(
	ctx context.Context,
	guard operationqueue.LeaseGuard,
	commandID paasv1.CommandID,
	observation paasv1.DeploymentObservation,
) (bool, error) {
	if err := paasv1.ValidateID("commandId", string(commandID)); err != nil {
		return false, err
	}
	if err := paasv1.ValidateDeploymentObservation(observation); err != nil {
		return false, err
	}
	var changed bool
	err := repository.withinLeaseTransaction(
		ctx,
		guard,
		func(tx pgx.Tx) error {
			var err error
			changed, err = recordObservationInTx(ctx, tx, guard, commandID, observation)
			return err
		},
	)
	if err != nil {
		return false, mapExecutionError("record Deployment observation", err)
	}
	return changed, nil
}

func (repository *DeploymentExecutionRepository) FinalizeSuccess(
	ctx context.Context,
	lease operationqueue.Lease,
	observation paasv1.DeploymentObservation,
) (paasv1.Deployment, paasv1.Operation, error) {
	if lease.Operation.State != paasv1.OperationVerifying {
		return paasv1.Deployment{}, paasv1.Operation{}, errors.New(
			"successful Deployment finalization requires a verifying Operation",
		)
	}
	if err := paasv1.ValidateDeploymentObservation(observation); err != nil {
		return paasv1.Deployment{}, paasv1.Operation{}, err
	}
	var deployment paasv1.Deployment
	var operation paasv1.Operation
	err := repository.withinLeaseTransaction(
		ctx,
		lease.Guard(),
		func(tx pgx.Tx) error {
			state, err := loadExecutionState(ctx, tx, lease.Guard())
			if err != nil {
				return err
			}
			if state.Placement == nil || state.ObserveRequest == nil ||
				observation.DeploymentID != state.Generation.DeploymentID ||
				observation.Generation != state.Generation.Generation ||
				observation.ApplicationRevisionID != state.ApplicationRevision.Metadata.ID {
				return errors.New("successful observation does not match Operation generation")
			}
			if lease.Operation.Action == paasv1.OperationStop {
				if observation.Phase != paasv1.DeploymentStopped ||
					observation.ReadyComponents != 0 {
					return errors.New("STOP success requires an exact stopped observation")
				}
			} else if observation.Phase != paasv1.DeploymentReady ||
				observation.ReadyComponents != uint32(len(state.Generation.Spec.Components)) {
				return errors.New("apply success requires every component ready")
			}
			if _, err := recordObservationInTx(
				ctx,
				tx,
				lease.Guard(),
				state.ObserveRequest.Command.CommandID,
				observation,
			); err != nil {
				return err
			}

			if lease.Operation.Action == paasv1.OperationStop {
				if state.Deployment.Status.PlacementDecisionID == "" {
					return errors.New("STOP finalization has no active observed placement")
				}
				previous, found, err := loadExecutionReservation(
					ctx,
					tx,
					lease.TenantID,
					state.Deployment.Status.PlacementDecisionID,
				)
				if err != nil || !found {
					if err == nil {
						err = errors.New("STOP finalization active reservation was not found")
					}
					return err
				}
				if previous.State != placement.CapacityClaimReleased {
					if _, err := transitionExecutionReservation(
						ctx,
						tx,
						lease.Guard(),
						previous,
						transitionreservation.ActionRelease,
					); err != nil {
						return err
					}
				}
			} else {
				current, found, err := loadExecutionReservation(
					ctx,
					tx,
					lease.TenantID,
					state.Placement.Metadata.ID,
				)
				if err != nil || !found {
					if err == nil {
						err = errors.New("scheduled execution reservation was not found")
					}
					return err
				}
				if current.State == placement.CapacityClaimPending {
					if _, err := transitionExecutionReservation(
						ctx,
						tx,
						lease.Guard(),
						current,
						transitionreservation.ActionActivate,
					); err != nil {
						return err
					}
				} else if current.State != placement.CapacityClaimActive {
					return errors.New("successful execution reservation is not consuming capacity")
				}
				previousDecisionID := state.Deployment.Status.PlacementDecisionID
				if previousDecisionID != "" && previousDecisionID != state.Placement.Metadata.ID {
					previous, found, err := loadExecutionReservation(
						ctx,
						tx,
						lease.TenantID,
						previousDecisionID,
					)
					if err != nil || !found {
						if err == nil {
							err = errors.New("previous active reservation was not found")
						}
						return err
					}
					if previous.State != placement.CapacityClaimReleased {
						if _, err := transitionExecutionReservation(
							ctx,
							tx,
							lease.Guard(),
							previous,
							transitionreservation.ActionRelease,
						); err != nil {
							return err
						}
					}
				}
			}

			transactionTime, err := executionTransactionTime(ctx, tx)
			if err != nil {
				return err
			}
			currentDeployment := state.Deployment
			deployment = state.Deployment
			deployment.Metadata.ResourceVersion++
			deployment.Metadata.UpdatedAt = transactionTime
			deployment.Status.ObservedGeneration = state.Generation.Generation
			deployment.Status.ObservedApplicationRevisionID =
				state.ApplicationRevision.Metadata.ID
			deployment.Status.ReadyComponents = observation.ReadyComponents
			deployment.Status.ObservedAt = observation.ObservedAt
			if lease.Operation.Action == paasv1.OperationStop {
				deployment.Status.Phase = paasv1.DeploymentStopped
				deployment.Status.PlacementDecisionID = ""
			} else {
				deployment.Status.Phase = paasv1.DeploymentReady
				deployment.Status.PlacementDecisionID = state.Placement.Metadata.ID
			}
			if err := paasv1.ValidateDeployment(deployment); err != nil {
				return fmt.Errorf("invalid successful Deployment status: %w", err)
			}
			if err := updateDeploymentStatusInTx(
				ctx,
				tx,
				lease.Guard(),
				currentDeployment,
				deployment,
			); err != nil {
				return err
			}
			operation, err = advanceOperationInTx(
				ctx,
				tx,
				lease,
				paasv1.OperationSucceeded,
				nil,
			)
			return err
		},
	)
	if err != nil {
		return paasv1.Deployment{}, paasv1.Operation{}, mapExecutionError(
			"finalize successful Deployment execution",
			err,
		)
	}
	return deployment, operation, nil
}

func (repository *DeploymentExecutionRepository) FinalizeTerminal(
	ctx context.Context,
	lease operationqueue.Lease,
	terminal reconciledeployment.Terminal,
) (paasv1.Deployment, paasv1.Operation, error) {
	if terminal.State != paasv1.OperationFailed &&
		terminal.State != paasv1.OperationManualIntervention {
		return paasv1.Deployment{}, paasv1.Operation{}, errors.New(
			"Deployment terminal finalization requires FAILED or MANUAL_INTERVENTION",
		)
	}
	if terminal.Problem == nil {
		return paasv1.Deployment{}, paasv1.Operation{}, errors.New(
			"Deployment terminal finalization requires a Problem",
		)
	}
	if err := paasv1.ValidateProblem(*terminal.Problem); err != nil {
		return paasv1.Deployment{}, paasv1.Operation{}, err
	}
	if err := domain.ValidateOperationTransition(lease.Operation.State, terminal.State); err != nil {
		return paasv1.Deployment{}, paasv1.Operation{}, err
	}
	var deployment paasv1.Deployment
	var operation paasv1.Operation
	err := repository.withinLeaseTransaction(
		ctx,
		lease.Guard(),
		func(tx pgx.Tx) error {
			state, err := loadExecutionState(ctx, tx, lease.Guard())
			if err != nil {
				return err
			}
			if terminal.State == paasv1.OperationManualIntervention &&
				lease.Operation.Action != paasv1.OperationStop &&
				state.Placement != nil &&
				state.Placement.Outcome == paasv1.PlacementScheduled {
				reservation, found, err := loadExecutionReservation(
					ctx,
					tx,
					lease.TenantID,
					state.Placement.Metadata.ID,
				)
				if err != nil || !found {
					if err == nil {
						err = errors.New(
							"uncertain execution capacity reservation was not found",
						)
					}
					return err
				}
				switch reservation.State {
				case placement.CapacityClaimPending:
					if _, err := transitionExecutionReservation(
						ctx,
						tx,
						lease.Guard(),
						reservation,
						transitionreservation.ActionActivate,
					); err != nil {
						return err
					}
				case placement.CapacityClaimActive:
				case placement.CapacityClaimReleased:
					return errors.New(
						"uncertain execution capacity reservation was already released",
					)
				default:
					return errors.New("uncertain execution capacity reservation state is invalid")
				}
			}
			if terminal.ReleasePending && state.Placement != nil {
				reservation, found, err := loadExecutionReservation(
					ctx,
					tx,
					lease.TenantID,
					state.Placement.Metadata.ID,
				)
				if err != nil {
					return err
				}
				if found {
					if reservation.State == placement.CapacityClaimActive {
						return errors.New(
							"definitive failure cannot release an active execution reservation",
						)
					}
					if reservation.State == placement.CapacityClaimPending {
						if _, err := transitionExecutionReservation(
							ctx,
							tx,
							lease.Guard(),
							reservation,
							transitionreservation.ActionRelease,
						); err != nil {
							return err
						}
					}
				}
			}
			transactionTime, err := executionTransactionTime(ctx, tx)
			if err != nil {
				return err
			}
			currentDeployment := state.Deployment
			deployment = state.Deployment
			if deployment.Status.Phase != paasv1.DeploymentFailed {
				if err := domain.ValidateDeploymentTransition(
					deployment.Status.Phase,
					paasv1.DeploymentFailed,
				); err != nil {
					return err
				}
				deployment.Metadata.ResourceVersion++
				deployment.Metadata.UpdatedAt = transactionTime
				deployment.Status.Phase = paasv1.DeploymentFailed
				if err := paasv1.ValidateDeployment(deployment); err != nil {
					return fmt.Errorf("invalid failed Deployment status: %w", err)
				}
				if err := updateDeploymentStatusInTx(
					ctx,
					tx,
					lease.Guard(),
					currentDeployment,
					deployment,
				); err != nil {
					return err
				}
			}
			operation, err = advanceOperationInTx(
				ctx,
				tx,
				lease,
				terminal.State,
				terminal.Problem,
			)
			return err
		},
	)
	if err != nil {
		return paasv1.Deployment{}, paasv1.Operation{}, mapExecutionError(
			"finalize terminal Deployment execution",
			err,
		)
	}
	return deployment, operation, nil
}

func recordResultInTx(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	requestDigest string,
	result paasv1.AdapterResult,
) (bool, error) {
	var receiptDigest any
	if result.State == paasv1.AdapterResultSucceeded || result.Receipt != "" {
		receiptDigest = domain.DigestPayload([]byte(result.Receipt))
	}
	var normalizedError any
	var err error
	if result.Error != nil {
		normalizedError, err = json.Marshal(result.Error)
		if err != nil {
			return false, fmt.Errorf("encode normalized adapter error: %w", err)
		}
	}
	evidence := result.Evidence
	if evidence == nil {
		evidence = []paasv1.Evidence{}
	}
	evidenceDocument, err := json.Marshal(evidence)
	if err != nil {
		return false, fmt.Errorf("encode adapter result evidence: %w", err)
	}
	var changed bool
	err = tx.QueryRow(
		ctx,
		`SELECT paas.record_adapter_receipt(
		     $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10
		 )`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
		result.CommandID,
		requestDigest,
		result.State,
		receiptDigest,
		normalizedError,
		evidenceDocument,
		result.ObservedAt,
	).Scan(&changed)
	return changed, err
}

func recordObservationInTx(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	commandID paasv1.CommandID,
	observation paasv1.DeploymentObservation,
) (bool, error) {
	document, err := json.Marshal(observation)
	if err != nil {
		return false, fmt.Errorf("encode Deployment observation: %w", err)
	}
	var changed bool
	err = tx.QueryRow(
		ctx,
		`SELECT paas.record_deployment_observation($1, $2, $3, $4, $5::jsonb)`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
		commandID,
		document,
	).Scan(&changed)
	return changed, err
}

func updateDeploymentStatusInTx(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	current paasv1.Deployment,
	next paasv1.Deployment,
) error {
	document, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode Deployment status: %w", err)
	}
	var resourceVersion uint64
	if err := tx.QueryRow(
		ctx,
		`SELECT paas.update_deployment_status($1, $2, $3, $4, $5, $6, $7::jsonb)`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
		current.Metadata.ID,
		int64(current.Metadata.ResourceVersion),
		int64(current.Generation),
		document,
	).Scan(&resourceVersion); err != nil {
		return err
	}
	if resourceVersion != next.Metadata.ResourceVersion {
		return errors.New("PostgreSQL returned a mismatched Deployment resource version")
	}
	return nil
}

func loadExecutionReservation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID paasv1.TenantID,
	decisionID paasv1.ResourceID,
) (executionReservation, bool, error) {
	var value executionReservation
	var state string
	err := tx.QueryRow(
		ctx,
		`SELECT reservation.id,
		        claim.state,
		        reservation.resource_version
		   FROM paas.capacity_reservations AS reservation
		   JOIN paas.capacity_claims AS claim
		     ON claim.id = reservation.capacity_claim_id
		  WHERE reservation.tenant_id = $1
		    AND reservation.decision_id = $2`,
		string(tenantID),
		string(decisionID),
	).Scan(&value.ID, &state, &value.ResourceVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return executionReservation{}, false, nil
	}
	if err != nil {
		return executionReservation{}, false, fmt.Errorf("load execution reservation: %w", err)
	}
	value.State = placement.CapacityClaimState(state)
	return value, true, nil
}

func transitionExecutionReservation(
	ctx context.Context,
	tx pgx.Tx,
	guard operationqueue.LeaseGuard,
	reservation executionReservation,
	action transitionreservation.Action,
) (executionReservation, error) {
	var state string
	var resourceVersion uint64
	var changed bool
	if err := tx.QueryRow(
		ctx,
		`SELECT claim_state, claim_resource_version, changed
		   FROM paas.transition_capacity_reservation($1, $2, $3, $4, $5, $6)`,
		guard.OperationID,
		guard.WorkerID,
		int64(guard.FencingToken),
		reservation.ID,
		action,
		int64(reservation.ResourceVersion),
	).Scan(&state, &resourceVersion, &changed); err != nil {
		return executionReservation{}, err
	}
	return executionReservation{
		ID: reservation.ID, State: placement.CapacityClaimState(state),
		ResourceVersion: resourceVersion,
	}, nil
}

func advanceOperationInTx(
	ctx context.Context,
	tx pgx.Tx,
	lease operationqueue.Lease,
	state paasv1.OperationState,
	problem *paasv1.Problem,
) (paasv1.Operation, error) {
	var problemDocument any
	var err error
	if problem != nil {
		problemDocument, err = json.Marshal(problem)
		if err != nil {
			return paasv1.Operation{}, fmt.Errorf("encode Operation Problem: %w", err)
		}
	}
	var document []byte
	if err := tx.QueryRow(
		ctx,
		`SELECT paas.advance_operation($1, $2, $3, $4, $5::jsonb, NULL, true)`,
		lease.Operation.ID,
		lease.WorkerID,
		int64(lease.FencingToken),
		state,
		problemDocument,
	).Scan(&document); err != nil {
		return paasv1.Operation{}, err
	}
	var operation paasv1.Operation
	if err := decodeDocument("Operation", document, &operation); err != nil {
		return paasv1.Operation{}, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return paasv1.Operation{}, fmt.Errorf("validate finalized Operation: %w", err)
	}
	return operation, nil
}

func executionTransactionTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var value time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&value); err != nil {
		return time.Time{}, fmt.Errorf("read PostgreSQL transaction time: %w", err)
	}
	return databaseTime(value), nil
}

func mapExecutionError(action string, err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX412":
			return fmt.Errorf("%s: %w", action, reconciledeployment.ErrStaleLease)
		case "MX409":
			return fmt.Errorf("%s: %w", action, reconciledeployment.ErrIdempotencyConflict)
		case "P0002":
			return fmt.Errorf("%s: %w", action, reconciledeployment.ErrNotFound)
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}
