package sourceobservation

import (
	"context"
	"errors"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

type Service struct {
	repository Repository
	provider   Provider
	config     Config
}

func NewService(repository Repository, provider Provider, config Config) (*Service, error) {
	if repository == nil || provider == nil {
		return nil, errors.New("source observation boundaries are required")
	}
	if devopsv1.ValidateID("sourceObserver.workerId", config.WorkerID) != nil ||
		config.LeaseDuration != LeaseDuration {
		return nil, errors.New("source observation configuration is invalid")
	}
	return &Service{repository: repository, provider: provider, config: config}, nil
}

func (service *Service) Heartbeat(ctx context.Context) (time.Time, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return time.Time{}, errors.New("source observer heartbeat is unavailable")
	}
	observedAt, err := service.repository.Heartbeat(ctx, service.config.WorkerID)
	if err != nil {
		return time.Time{}, err
	}
	if validateObservationTime("sourceObserver.heartbeatAt", observedAt) != nil {
		return time.Time{}, errors.New("source observer heartbeat is invalid")
	}
	return observedAt, nil
}

func (service *Service) ObserveOnce(ctx context.Context) (Result, error) {
	if service == nil || service.repository == nil || service.provider == nil || ctx == nil {
		return Result{}, errors.New("source observer is unavailable")
	}
	lease, found, err := service.repository.Claim(
		ctx, service.config.WorkerID, service.config.LeaseDuration,
	)
	if err != nil || !found {
		return Result{}, err
	}
	if err := ValidateLease(lease); err != nil {
		return Result{}, err
	}
	result := Result{Claimed: true, Kind: lease.Kind, ResourceID: lease.ResourceID}
	switch lease.Kind {
	case WorkSourceConnection:
		observation, observeErr := service.provider.ObserveSourceConnection(ctx, lease.Connection)
		if observeErr != nil {
			return Result{}, observeErr
		}
		_, err = service.repository.CompleteSourceConnection(ctx, lease, observation)
	case WorkRepositoryBinding:
		observation := domain.RepositoryBindingHealthObservation{
			Health: devopsv1.RepositoryBindingPending,
			Reason: devopsv1.RepositoryBindingReasonConnectionNotReady,
		}
		if sourceConnectionReadyAt(lease.Connection, lease.ClaimedAt) {
			observation, err = service.provider.ObserveRepositoryBinding(
				ctx, lease.Connection, *lease.Binding,
			)
			if err != nil {
				return Result{}, err
			}
		}
		_, err = service.repository.CompleteRepositoryBinding(ctx, lease, observation)
	default:
		return Result{}, ErrInvalidLease
	}
	return result, err
}

func (service *Service) Readiness(ctx context.Context) (devopsv1.Readiness, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("source observer readiness is unavailable")
	}
	return service.repository.Readiness(ctx)
}

func sourceConnectionReadyAt(connection devopsv1.SourceConnection, observedAt time.Time) bool {
	return connection.Status.Health == devopsv1.SourceConnectionReady &&
		connection.Status.Reason == devopsv1.SourceConnectionReasonObserved &&
		!observedAt.Before(connection.Status.ObservedAt) &&
		observedAt.Sub(connection.Status.ObservedAt) <= domain.MaximumSourceHealthAge
}
