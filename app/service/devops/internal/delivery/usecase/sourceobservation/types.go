// Package sourceobservation owns the fenced workflow that refreshes source
// connection and repository binding health without configuration authority.
package sourceobservation

import (
	"context"
	"errors"
	"fmt"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

const (
	WorkSourceConnection  WorkKind = "SOURCE_CONNECTION"
	WorkRepositoryBinding WorkKind = "REPOSITORY_BINDING"

	LeaseDuration       = 30 * time.Second
	RefreshInterval     = 60 * time.Second
	HeartbeatInterval   = 10 * time.Second
	HeartbeatMaximumAge = 30 * time.Second

	ActorID = "system-devops-source-observer"
)

var (
	ErrInvalidLease = errors.New("source observation lease is invalid")
	ErrStaleLease   = errors.New("source observation lease is stale")
)

type WorkKind string

type Lease struct {
	TenantID        devopsv1.TenantID
	Kind            WorkKind
	ResourceID      devopsv1.ResourceID
	ResourceVersion uint64
	WorkerID        string
	FencingToken    uint64
	ClaimedAt       time.Time
	LeaseExpiresAt  time.Time
	Connection      devopsv1.SourceConnection
	Binding         *devopsv1.RepositoryBinding
}

type Repository interface {
	Heartbeat(context.Context, string) (time.Time, error)
	Claim(context.Context, string, time.Duration) (Lease, bool, error)
	CompleteSourceConnection(
		context.Context, Lease, domain.SourceConnectionHealthObservation,
	) (devopsv1.SourceConnection, error)
	CompleteRepositoryBinding(
		context.Context, Lease, domain.RepositoryBindingHealthObservation,
	) (devopsv1.RepositoryBinding, error)
	Readiness(context.Context) (devopsv1.Readiness, error)
}

type Provider interface {
	ObserveSourceConnection(
		context.Context, devopsv1.SourceConnection,
	) (domain.SourceConnectionHealthObservation, error)
	ObserveRepositoryBinding(
		context.Context, devopsv1.SourceConnection, devopsv1.RepositoryBinding,
	) (domain.RepositoryBindingHealthObservation, error)
}

type Config struct {
	WorkerID      string
	LeaseDuration time.Duration
}

type Result struct {
	Claimed    bool
	Kind       WorkKind
	ResourceID devopsv1.ResourceID
}

func ValidateLease(value Lease) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("sourceObservation.tenantId", string(value.TenantID)),
		devopsv1.ValidateID("sourceObservation.resourceId", string(value.ResourceID)),
		devopsv1.ValidateID("sourceObservation.workerId", value.WorkerID),
		validateObservationTime("sourceObservation.claimedAt", value.ClaimedAt),
		validateObservationTime("sourceObservation.leaseExpiresAt", value.LeaseExpiresAt),
	)
	if value.ResourceVersion < 1 || value.ResourceVersion > devopsv1.MaximumContractInteger ||
		value.FencingToken < 1 || value.FencingToken > devopsv1.MaximumContractInteger {
		problems = append(problems, ErrInvalidLease)
	}
	if !value.LeaseExpiresAt.After(value.ClaimedAt) {
		problems = append(problems, ErrInvalidLease)
	}
	if devopsv1.ValidateSourceConnection(value.Connection) != nil ||
		value.Connection.Metadata.Scope.TenantID != value.TenantID ||
		value.ClaimedAt.Before(value.Connection.Metadata.UpdatedAt) {
		problems = append(problems, ErrInvalidLease)
	}
	switch value.Kind {
	case WorkSourceConnection:
		if value.Binding != nil || value.Connection.Metadata.ID != value.ResourceID ||
			value.Connection.Metadata.ResourceVersion != value.ResourceVersion {
			problems = append(problems, ErrInvalidLease)
		}
	case WorkRepositoryBinding:
		if value.Binding == nil || value.Binding != nil && (devopsv1.ValidateRepositoryBinding(*value.Binding) != nil ||
			value.Binding.Metadata.Scope.TenantID != value.TenantID ||
			value.Binding.Metadata.ID != value.ResourceID ||
			value.Binding.Metadata.ResourceVersion != value.ResourceVersion ||
			value.Binding.Spec.SourceConnectionID != value.Connection.Metadata.ID ||
			value.ClaimedAt.Before(value.Binding.Metadata.UpdatedAt)) {
			problems = append(problems, ErrInvalidLease)
		}
	default:
		problems = append(problems, fmt.Errorf("unknown source observation kind %q", value.Kind))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(err, ErrInvalidLease)
	}
	return nil
}

func validateObservationTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}
