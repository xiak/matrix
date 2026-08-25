package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	paasv1 "matrix/api/paas/v1"
	"matrix/app/service/paas/internal/runtime/domain/placement"
	"matrix/app/service/paas/internal/runtime/usecase/createplacement"
)

func (transaction *placementTransaction) CreateDecision(
	ctx context.Context,
	creation createplacement.DecisionCreation,
) error {
	if err := transaction.validateDecisionCreation(creation); err != nil {
		return err
	}
	decision := creation.Decision
	document, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("encode PlacementDecision document: %w", err)
	}
	var reasonDocument any
	if decision.Reason != nil {
		reasonDocument, err = json.Marshal(decision.Reason)
		if err != nil {
			return fmt.Errorf("encode PlacementDecision reason: %w", err)
		}
	}
	var runtimeTargetID any
	var runtimeTargetVersion any
	var grantedIsolation any
	if decision.Outcome == paasv1.PlacementScheduled {
		runtimeTargetID = string(decision.RuntimeTargetID)
		runtimeTargetVersion = int64(decision.RuntimeTargetResourceVersion)
		grantedIsolation = string(decision.GrantedIsolation)
	}

	_, err = transaction.tx.Exec(
		ctx,
		`INSERT INTO paas.placement_decisions (
             tenant_id,
             id,
             operation_id,
             request_digest,
             release_id,
             policy_id,
             policy_resource_version,
             requested_isolation,
             outcome,
             runtime_target_id,
             runtime_target_resource_version,
             granted_isolation,
             candidate_digest,
             reason,
             decided_at,
             document
         ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8,
             $9, $10, $11, $12, $13, $14, $15, $16
         )`,
		string(transaction.tenantID),
		string(decision.Metadata.ID),
		string(creation.OperationID),
		creation.RequestDigest,
		string(decision.WorkloadReleaseID),
		string(decision.PlacementPolicyID),
		int64(decision.PolicyResourceVersion),
		string(decision.RequestedIsolation),
		string(decision.Outcome),
		runtimeTargetID,
		runtimeTargetVersion,
		grantedIsolation,
		decision.CandidateSetDigest,
		reasonDocument,
		decision.DecidedAt,
		document,
	)
	if err != nil {
		return fmt.Errorf("insert PlacementDecision: %w", err)
	}
	if creation.Reservation == nil {
		return nil
	}

	reservation := creation.Reservation
	var claimID string
	err = transaction.tx.QueryRow(
		ctx,
		`INSERT INTO paas.capacity_claims (
             runtime_target_id,
             isolation,
             cpu_millis,
             memory_bytes,
             workload_slots,
             state,
             lease_expires_at,
             resource_version,
             created_at,
             updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
         RETURNING id::text`,
		string(reservation.RuntimeTargetID),
		string(reservation.Isolation),
		reservation.Resources.CPUMillis,
		reservation.Resources.MemoryBytes,
		reservation.Resources.WorkloadSlots,
		string(reservation.State),
		reservation.LeaseExpiresAt,
		int64(reservation.ResourceVersion),
		decision.DecidedAt,
	).Scan(&claimID)
	if err != nil {
		return fmt.Errorf("insert capacity claim: %w", err)
	}

	_, err = transaction.tx.Exec(
		ctx,
		`INSERT INTO paas.capacity_reservations (
             tenant_id,
             id,
             decision_id,
             release_id,
             runtime_target_id,
             isolation,
             capacity_claim_id,
             resource_version,
             created_at,
             updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $9)`,
		string(reservation.TenantID),
		string(reservation.ID),
		string(reservation.DecisionID),
		string(reservation.WorkloadReleaseID),
		string(reservation.RuntimeTargetID),
		string(reservation.Isolation),
		claimID,
		int64(reservation.ResourceVersion),
		decision.DecidedAt,
	)
	if err != nil {
		return fmt.Errorf("insert tenant capacity reservation: %w", err)
	}
	return nil
}

func (transaction *placementTransaction) validateDecisionCreation(
	creation createplacement.DecisionCreation,
) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("operationId", string(creation.OperationID)),
		paasv1.ValidateDigest("requestDigest", creation.RequestDigest),
		paasv1.ValidatePlacementDecision(creation.Decision),
	)
	decision := creation.Decision
	if decision.Metadata.Scope.TenantID != transaction.tenantID {
		problems = append(problems, errors.New("PlacementDecision tenant does not match transaction tenant"))
	}
	if decision.Outcome == paasv1.PlacementScheduled && creation.Reservation == nil {
		problems = append(problems, errors.New("scheduled PlacementDecision requires a capacity reservation"))
	}
	if decision.Outcome == paasv1.PlacementUnschedulable && creation.Reservation != nil {
		problems = append(problems, errors.New("unschedulable PlacementDecision cannot reserve capacity"))
	}
	if creation.Reservation == nil {
		return errors.Join(problems...)
	}

	reservation := creation.Reservation
	problems = append(problems,
		paasv1.ValidateID("reservation.id", string(reservation.ID)),
		paasv1.ValidateID("reservation.tenantId", string(reservation.TenantID)),
		paasv1.ValidateID(
			"reservation.workloadReleaseId",
			string(reservation.WorkloadReleaseID),
		),
		paasv1.ValidateID("reservation.decisionId", string(reservation.DecisionID)),
		paasv1.ValidateID(
			"reservation.runtimeTargetId",
			string(reservation.RuntimeTargetID),
		),
	)
	if reservation.TenantID != transaction.tenantID ||
		reservation.DecisionID != decision.Metadata.ID ||
		reservation.WorkloadReleaseID != decision.WorkloadReleaseID ||
		reservation.RuntimeTargetID != decision.RuntimeTargetID ||
		reservation.Isolation != decision.GrantedIsolation {
		problems = append(problems, errors.New("capacity reservation does not match PlacementDecision"))
	}
	if reservation.Resources.CPUMillis < 0 ||
		reservation.Resources.MemoryBytes < 0 ||
		reservation.Resources.WorkloadSlots <= 0 {
		problems = append(problems, errors.New("capacity reservation resources are invalid"))
	}
	if reservation.State != placement.CapacityClaimPending {
		problems = append(problems, errors.New("new capacity reservation must be pending"))
	}
	if reservation.LeaseExpiresAt.IsZero() ||
		reservation.LeaseExpiresAt.Location() != decision.DecidedAt.Location() ||
		reservation.LeaseExpiresAt != reservation.LeaseExpiresAt.Round(0) ||
		reservation.LeaseExpiresAt.Nanosecond()%1_000 != 0 ||
		!reservation.LeaseExpiresAt.After(decision.DecidedAt) {
		problems = append(problems, errors.New("capacity reservation lease expiry is invalid"))
	}
	if reservation.ResourceVersion != 1 {
		problems = append(problems, errors.New("new capacity reservation resourceVersion must be one"))
	}
	return errors.Join(problems...)
}
