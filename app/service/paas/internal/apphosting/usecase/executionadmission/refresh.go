package executionadmission

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func (service *Service) GetPool(ctx context.Context, authorization port.Authorization, id paasv1.ResourceID) (paasv1.ExecutionPool, error) {
	var result paasv1.ExecutionPool
	if err := service.authorize(ctx, authorization); err != nil {
		return result, err
	}
	if paasv1.ValidateID("poolId", string(id)) != nil {
		return result, ErrInvalidArgument
	}
	err := service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		pool, found, err := transaction.LoadPool(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		targets, err := transaction.ListTargets(ctx)
		if err != nil {
			return err
		}
		result, err = service.poolSnapshot(pool, targets, service.config.Clock().UTC().Truncate(time.Microsecond), false)
		return err
	})
	return result, err
}

func (service *Service) GetTarget(ctx context.Context, authorization port.Authorization, id paasv1.ResourceID) (paasv1.ExecutionTarget, error) {
	var result paasv1.ExecutionTarget
	if err := service.authorize(ctx, authorization); err != nil {
		return result, err
	}
	if paasv1.ValidateID("targetId", string(id)) != nil {
		return result, ErrInvalidArgument
	}
	err := service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		registration, found, err := transaction.LoadTarget(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		result = service.targetSnapshot(registration.Target, service.config.Clock())
		return nil
	})
	return result, err
}

func (service *Service) GetOperation(ctx context.Context, authorization port.Authorization, id paasv1.OperationID) (paasv1.Operation, error) {
	var result paasv1.Operation
	if err := service.authorize(ctx, authorization); err != nil {
		return result, err
	}
	if paasv1.ValidateID("operationId", string(id)) != nil {
		return result, ErrInvalidArgument
	}
	err := service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		var found bool
		var err error
		result, found, err = transaction.LoadOperation(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		return nil
	})
	return result, err
}

// Refresh has no user-scoped command or metrics Audit event. Only bindings
// already admitted in this installation can be observed. Two probes at most
// run concurrently; an unavailable node cannot hold other nodes' transactions.
func (service *Service) Refresh(ctx context.Context) error {
	if service == nil || service.repository == nil || ctx == nil {
		return ErrUnavailable
	}
	var registrations []Registration
	if err := service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		var err error
		registrations, err = transaction.ListTargets(ctx)
		return err
	}); err != nil {
		return err
	}
	if len(registrations) > MaximumTargets {
		return ErrConflict
	}
	work, failures := make(chan Registration, len(registrations)), make(chan error, len(registrations))
	for _, registration := range registrations {
		work <- registration
	}
	close(work)
	var workers sync.WaitGroup
	for range min(2, len(registrations)) {
		workers.Go(func() {
			for registration := range work {
				if err := service.refreshTarget(ctx, registration); err != nil {
					failures <- err
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	var problems []error
	for err := range failures {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func (service *Service) refreshTarget(ctx context.Context, initial Registration) error {
	binding, configured := service.bindings[initial.BindingRef]
	var observation paasv1.ExecutionTargetObservation
	observationErr := ErrUnavailable
	if configured && binding.TargetID == initial.Target.Metadata.ID && binding.IdentityFingerprint == initial.IdentityFingerprint {
		probeContext, cancel := context.WithTimeout(ctx, service.config.ObservationTimeout)
		fingerprint := domain.DigestPayload([]byte("matrix-execution-observation/v1\x00" + service.config.InstallationID + "\x00" + binding.Ref + "\x00" + string(binding.TargetID)))
		command := service.observationCommand(binding, paasv1.AdapterObserveExecutionTarget, fingerprint, fingerprint)
		observation, observationErr = binding.Adapter.ObserveExecutionTarget(probeContext, paasv1.ObserveExecutionTargetRequest{Command: command})
		cancel()
		if observationErr == nil && !service.validObservation(binding, observation, service.config.Clock()) {
			observationErr = ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	err := service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		current, found, err := transaction.LoadTarget(ctx, initial.Target.Metadata.ID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if current.BindingRef != initial.BindingRef || current.IdentityFingerprint != initial.IdentityFingerprint {
			return ErrConflict
		}
		pool, found, err := transaction.LoadPool(ctx, current.Target.Spec.ExecutionPoolID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		now, err := transaction.TransactionTime(ctx)
		if err != nil {
			return err
		}
		if now.Before(current.Target.Metadata.UpdatedAt) {
			return ErrConflict
		}
		next := current.Target
		if observationErr == nil && service.validObservation(binding, observation, now) {
			if observation.ObservedAt.Before(current.Target.Status.ObservedAt) {
				return nil
			}
			next.Status = statusFromObservation(observation, now)
		} else {
			// A late failure must not replace a newer committed observation.
			if current.Target.Metadata.UpdatedAt.After(initial.Target.Metadata.UpdatedAt) {
				return nil
			}
			next = service.targetSnapshot(next, now)
			next.Status.Health = paasv1.ExecutionTargetHealthUnavailable
			next.Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{}
		}
		if placementStatusChanged(current.Target.Status, next.Status) {
			if next.Metadata.ResourceVersion == maximumVersion {
				return ErrConflict
			}
			next.Metadata.ResourceVersion++
		}
		next.Metadata.UpdatedAt = now
		if paasv1.ValidateExecutionTarget(next) != nil {
			return ErrUnavailable
		}
		registrations, err := transaction.ListTargets(ctx)
		if err != nil {
			return err
		}
		for index := range registrations {
			if registrations[index].Target.Metadata.ID == next.Metadata.ID {
				registrations[index].Target = next
			}
		}
		poolVersion := pool.Metadata.ResourceVersion
		pool, err = service.poolSnapshot(pool, registrations, now, true)
		if err != nil {
			return err
		}
		return transaction.RefreshTarget(ctx, current.Target.Metadata.ResourceVersion, next, poolVersion, pool)
	})
	if err != nil {
		return err
	}
	if observationErr != nil {
		return ErrUnavailable
	}
	return nil
}

func placementStatusChanged(before, after paasv1.ExecutionTargetStatus) bool {
	return before.Health != after.Health || before.Capacity != after.Capacity || before.Allocatable != after.Allocatable ||
		!slices.Equal(before.SupportedIsolationGuarantees, after.SupportedIsolationGuarantees)
}

func (service *Service) targetSnapshot(target paasv1.ExecutionTarget, now time.Time) paasv1.ExecutionTarget {
	if now.Before(target.Status.ObservedAt) || !now.Before(target.Status.ObservedAt.Add(service.config.MaximumObservationAge)) {
		target.Status.Health = paasv1.ExecutionTargetHealthUnavailable
		target.Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{}
	}
	if target.Status.Usage != nil {
		usage := target.Status.Usage.Snapshot(now)
		target.Status.Usage = &usage
	}
	return target
}

func (service *Service) poolSnapshot(pool paasv1.ExecutionPool, registrations []Registration, now time.Time, persist bool) (paasv1.ExecutionPool, error) {
	status := paasv1.ExecutionPoolStatus{Phase: paasv1.ExecutionPoolUnavailable, ObservedAt: now}
	for _, registration := range registrations {
		target := service.targetSnapshot(registration.Target, now)
		if target.Spec.ExecutionPoolID != pool.Metadata.ID {
			continue
		}
		status.ExecutionTargetCount++
		if target.Status.Health == paasv1.ExecutionTargetHealthReady && target.Spec.DesiredState == paasv1.ExecutionTargetActive {
			status.ReadyExecutionTargetCount++
		}
	}
	if status.ReadyExecutionTargetCount > 0 {
		status.Phase = paasv1.ExecutionPoolDegraded
		if status.ReadyExecutionTargetCount == status.ExecutionTargetCount {
			status.Phase = paasv1.ExecutionPoolReady
		}
	}
	if persist {
		if now.Before(pool.Metadata.UpdatedAt) {
			return paasv1.ExecutionPool{}, ErrConflict
		}
		if pool.Status.Phase != status.Phase || pool.Status.ExecutionTargetCount != status.ExecutionTargetCount || pool.Status.ReadyExecutionTargetCount != status.ReadyExecutionTargetCount {
			if pool.Metadata.ResourceVersion == maximumVersion {
				return paasv1.ExecutionPool{}, ErrConflict
			}
			pool.Metadata.ResourceVersion++
		}
		pool.Metadata.UpdatedAt = now
	}
	pool.Status = status
	return pool, paasv1.ValidateExecutionPool(pool)
}
