package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
)

func (transaction *placementTransaction) LoadStopBinding(
	ctx context.Context,
	deploymentID paasv1.ResourceID,
) (createplacement.StopBinding, error) {
	if err := paasv1.ValidateID("deploymentId", string(deploymentID)); err != nil {
		return createplacement.StopBinding{}, err
	}
	deployment, err := transaction.loadDeployment(ctx, deploymentID)
	if err != nil {
		return createplacement.StopBinding{}, err
	}
	if deployment.Status.PlacementDecisionID == "" {
		return createplacement.StopBinding{}, errors.New(
			"stopped Deployment has no current observed placement",
		)
	}
	generation, err := (&applicationTransaction{
		placementTransaction: transaction,
	}).loadGeneration(
		ctx,
		`SELECT deployment_id,
		        generation,
		        application_revision_id,
		        policy_id,
		        content_digest,
		        created_by_operation_id,
		        created_at,
		        document
		   FROM paas.deployment_generations
		  WHERE tenant_id = $1
		    AND deployment_id = $2
		    AND generation = $3`,
		string(transaction.tenantID),
		string(deploymentID),
		int64(deployment.Generation),
	)
	if err != nil {
		return createplacement.StopBinding{}, err
	}
	policy, err := transaction.loadPolicy(ctx, generation.Spec.PlacementPolicyID)
	if err != nil {
		return createplacement.StopBinding{}, err
	}

	var (
		decisionDocument []byte
		reservationID    string
		claimState       string
		targetVersion    uint64
		targetDocument   []byte
	)
	err = transaction.tx.QueryRow(
		ctx,
		`SELECT decision.document,
		        reservation.id,
		        claim.state,
		        target.resource_version,
		        target.document
		   FROM paas.placement_decisions AS decision
		   JOIN paas.capacity_reservations AS reservation
		     ON reservation.tenant_id = decision.tenant_id
		    AND reservation.decision_id = decision.id
		   JOIN paas.capacity_claims AS claim
		     ON claim.id = reservation.capacity_claim_id
		   JOIN paas.execution_targets AS target
		     ON target.id = decision.execution_target_id
		  WHERE decision.tenant_id = $1
		    AND decision.id = $2
		    AND decision.deployment_id = $3`,
		string(transaction.tenantID),
		string(deployment.Status.PlacementDecisionID),
		string(deploymentID),
	).Scan(
		&decisionDocument,
		&reservationID,
		&claimState,
		&targetVersion,
		&targetDocument,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return createplacement.StopBinding{}, errors.New(
			"current observed placement has no capacity reservation",
		)
	}
	if err != nil {
		return createplacement.StopBinding{}, fmt.Errorf("load stop placement binding: %w", err)
	}
	if placement.CapacityClaimState(claimState) != placement.CapacityClaimActive {
		return createplacement.StopBinding{}, errors.New(
			"current observed placement capacity reservation is not active",
		)
	}
	var decision paasv1.PlacementDecision
	if err := decodeDocument("PlacementDecision", decisionDocument, &decision); err != nil {
		return createplacement.StopBinding{}, err
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		return createplacement.StopBinding{}, fmt.Errorf(
			"validate current PlacementDecision: %w",
			err,
		)
	}
	var target paasv1.ExecutionTarget
	if err := decodeDocument("ExecutionTarget", targetDocument, &target); err != nil {
		return createplacement.StopBinding{}, err
	}
	if err := paasv1.ValidateExecutionTarget(target); err != nil {
		return createplacement.StopBinding{}, fmt.Errorf(
			"validate stop ExecutionTarget: %w",
			err,
		)
	}
	if target.Metadata.ResourceVersion != targetVersion ||
		decision.ExecutionTargetID != target.Metadata.ID ||
		decision.Metadata.Scope.TenantID != transaction.tenantID {
		return createplacement.StopBinding{}, errors.New(
			"stored stop placement relational identity mismatch",
		)
	}
	return createplacement.StopBinding{
		Deployment:       deployment,
		Generation:       generation,
		Policy:           policy,
		PreviousDecision: decision,
		ExecutionTarget:  target,
		ReservationID:    paasv1.ResourceID(reservationID),
	}, nil
}
