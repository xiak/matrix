package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
)

type capacityReservationDocument struct {
	ID                paasv1.ResourceID            `json:"id"`
	DecisionID        paasv1.ResourceID            `json:"decisionId"`
	DeploymentID      paasv1.ResourceID            `json:"deploymentId"`
	ExecutionTargetID paasv1.ResourceID            `json:"executionTargetId"`
	Isolation         paasv1.IsolationGuarantee    `json:"isolation"`
	CPUMillis         int64                        `json:"cpuMillis"`
	MemoryBytes       int64                        `json:"memoryBytes"`
	WorkloadSlots     int64                        `json:"workloadSlots"`
	State             placement.CapacityClaimState `json:"state"`
	LeaseExpiresAt    time.Time                    `json:"leaseExpiresAt"`
	ResourceVersion   uint64                       `json:"resourceVersion"`
}

func (transaction *placementTransaction) CreateDecision(
	ctx context.Context,
	creation createplacement.DecisionCreation,
) error {
	if err := transaction.validateDecisionCreation(creation); err != nil {
		return err
	}
	document, err := json.Marshal(creation.Decision)
	if err != nil {
		return fmt.Errorf("encode PlacementDecision document: %w", err)
	}
	var reservationDocument any
	if creation.Reservation != nil {
		reservation := creation.Reservation
		reservationDocument, err = json.Marshal(capacityReservationDocument{
			ID:                reservation.ID,
			DecisionID:        reservation.DecisionID,
			DeploymentID:      reservation.DeploymentID,
			ExecutionTargetID: reservation.ExecutionTargetID,
			Isolation:         reservation.Isolation,
			CPUMillis:         reservation.Resources.CPUMillis,
			MemoryBytes:       reservation.Resources.MemoryBytes,
			WorkloadSlots:     reservation.Resources.WorkloadSlots,
			State:             reservation.State,
			LeaseExpiresAt:    reservation.LeaseExpiresAt,
			ResourceVersion:   reservation.ResourceVersion,
		})
		if err != nil {
			return fmt.Errorf("encode capacity reservation: %w", err)
		}
	}
	_, err = transaction.tx.Exec(
		ctx,
		`SELECT paas.create_placement(
		     $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7
		 )`,
		creation.OperationID,
		transaction.leaseGuard.WorkerID,
		int64(transaction.leaseGuard.FencingToken),
		creation.RequestDigest,
		document,
		reservationDocument,
		creation.ReusesActiveReservation,
	)
	if err != nil {
		return fmt.Errorf("create fenced PlacementDecision: %w", err)
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
	if transaction.leaseGuard.TenantID != transaction.tenantID ||
		transaction.leaseGuard.OperationID != creation.OperationID {
		problems = append(problems, errors.New("PlacementDecision lease identity does not match"))
	}
	hasReservation := creation.Reservation != nil
	if decision.Outcome == paasv1.PlacementScheduled &&
		hasReservation == creation.ReusesActiveReservation {
		problems = append(problems, errors.New(
			"scheduled PlacementDecision must create or explicitly reuse one capacity reservation",
		))
	}
	if decision.Outcome == paasv1.PlacementUnschedulable &&
		(hasReservation || creation.ReusesActiveReservation) {
		problems = append(problems, errors.New(
			"unschedulable PlacementDecision cannot reserve or reuse capacity",
		))
	}
	if creation.Reservation == nil {
		return errors.Join(problems...)
	}

	reservation := creation.Reservation
	problems = append(problems,
		paasv1.ValidateID("reservation.id", string(reservation.ID)),
		paasv1.ValidateID("reservation.tenantId", string(reservation.TenantID)),
		paasv1.ValidateID("reservation.deploymentId", string(reservation.DeploymentID)),
		paasv1.ValidateID("reservation.decisionId", string(reservation.DecisionID)),
		paasv1.ValidateID(
			"reservation.executionTargetId",
			string(reservation.ExecutionTargetID),
		),
	)
	if reservation.TenantID != transaction.tenantID ||
		reservation.DecisionID != decision.Metadata.ID ||
		reservation.DeploymentID != decision.DeploymentID ||
		reservation.ExecutionTargetID != decision.ExecutionTargetID ||
		reservation.Isolation != decision.GrantedIsolationGuarantee {
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
