// Package refreshexecutionprofile owns the fixed Phase 1 local execution
// profile and keeps its provider observation fresh for placement.
package refreshexecutionprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

const (
	profileLabelKey   = "matrix-profile"
	profileLabelValue = "local-compose"
	fingerprintLabel  = "matrix-machine-fingerprint"
	maximumVersion    = uint64(9007199254740991)
)

var (
	ErrConflict             = errors.New("execution profile conflicts with stored authority")
	ErrRetryableTransaction = errors.New("execution profile transaction must be retried")
)

type IDs struct {
	PoolID   paasv1.ResourceID
	TargetID paasv1.ResourceID
	PolicyID paasv1.ResourceID
}

type Snapshot struct {
	TransactionTime time.Time
	Pool            *paasv1.ExecutionPool
	Target          *paasv1.ExecutionTarget
	Policy          *paasv1.PlacementPolicy
}

type Versions struct {
	Pool   uint64
	Target uint64
	Policy uint64
}

type Profile struct {
	Pool   paasv1.ExecutionPool
	Target paasv1.ExecutionTarget
	Policy paasv1.PlacementPolicy
}

type Transaction interface {
	Load(context.Context, IDs) (Snapshot, error)
	Save(context.Context, Versions, Profile) error
}

type Repository interface {
	WithinTransaction(
		context.Context,
		paasv1.TenantID,
		func(context.Context, Transaction) error,
	) error
}

type Config struct {
	TenantID               paasv1.TenantID
	IDs                    IDs
	MachineBindingRef      string
	ObservationTimeout     time.Duration
	MaximumObservationAge  time.Duration
	MaxTransactionAttempts int
	Clock                  func() time.Time
}

type Service struct {
	adapter    port.InfrastructureAdapter
	repository Repository
	config     Config
	digest     string
}

func New(
	adapter port.InfrastructureAdapter,
	repository Repository,
	config Config,
) (*Service, error) {
	if adapter == nil || repository == nil {
		return nil, errors.New("execution profile adapter and repository are required")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"matrix-local-execution-profile/v1\x00%s\x00%s\x00%s\x00%s\x00%s",
		config.TenantID,
		config.IDs.PoolID,
		config.IDs.TargetID,
		config.IDs.PolicyID,
		config.MachineBindingRef,
	)))
	return &Service{
		adapter: adapter, repository: repository, config: config,
		digest: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func (service *Service) Refresh(ctx context.Context) error {
	if service == nil || service.adapter == nil || service.repository == nil || ctx == nil {
		return errors.New("execution profile service is unavailable")
	}
	commandTime := service.config.Clock().UTC().Truncate(time.Microsecond)
	request := paasv1.ObserveExecutionTargetRequest{Command: paasv1.AdapterCommandEnvelope{
		OperationID:       paasv1.OperationID("observe-" + service.config.IDs.TargetID),
		CommandID:         paasv1.CommandID("observe-" + service.config.IDs.TargetID),
		Attempt:           1,
		Action:            paasv1.AdapterObserveExecutionTarget,
		Scope:             paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
		ExecutionTargetID: service.config.IDs.TargetID,
		RequestDigest:     service.digest,
		BindingRef:        service.config.MachineBindingRef,
		Deadline:          commandTime.Add(service.config.ObservationTimeout),
	}}
	observation, err := service.adapter.ObserveExecutionTarget(ctx, request)
	if err != nil {
		return errors.New("execution target observation failed")
	}
	if paasv1.ValidateExecutionTargetObservation(observation) != nil ||
		observation.ExecutionTargetID != service.config.IDs.TargetID ||
		!validLocalIsolationObservation(observation) {
		return errors.New("execution target observation is invalid")
	}

	for attempt := 0; attempt < service.config.MaxTransactionAttempts; attempt++ {
		err = service.repository.WithinTransaction(
			ctx,
			service.config.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				snapshot, loadErr := transaction.Load(transactionContext, service.config.IDs)
				if loadErr != nil {
					return loadErr
				}
				profile, versions, buildErr := service.build(snapshot, observation)
				if buildErr != nil {
					return buildErr
				}
				return transaction.Save(transactionContext, versions, profile)
			},
		)
		if !errors.Is(err, ErrRetryableTransaction) {
			return err
		}
	}
	return ErrRetryableTransaction
}

func (service *Service) Ready(ctx context.Context) error {
	if service == nil || service.repository == nil || ctx == nil {
		return errors.New("execution profile service is unavailable")
	}
	return service.repository.WithinTransaction(
		ctx,
		service.config.TenantID,
		func(transactionContext context.Context, transaction Transaction) error {
			snapshot, err := transaction.Load(transactionContext, service.config.IDs)
			if err != nil {
				return err
			}
			if err := service.validateCurrent(snapshot); err != nil {
				return errors.New("execution profile is not ready")
			}
			if snapshot.Pool.Status.Phase != paasv1.ExecutionPoolReady ||
				snapshot.Pool.Status.ExecutionTargetCount != 1 ||
				snapshot.Pool.Status.ReadyExecutionTargetCount != 1 ||
				snapshot.Target.Status.Health != paasv1.ExecutionTargetHealthReady ||
				snapshot.Target.Status.ObservedAt.After(snapshot.TransactionTime) ||
				snapshot.TransactionTime.Sub(snapshot.Target.Status.ObservedAt) >
					service.config.MaximumObservationAge {
				return errors.New("execution profile is not ready")
			}
			return nil
		},
	)
}

func (service *Service) build(
	snapshot Snapshot,
	observation paasv1.ExecutionTargetObservation,
) (Profile, Versions, error) {
	if snapshot.TransactionTime.IsZero() ||
		snapshot.TransactionTime.Location() != time.UTC ||
		snapshot.TransactionTime != snapshot.TransactionTime.Round(0) ||
		snapshot.TransactionTime.Nanosecond()%1_000 != 0 ||
		observation.ObservedAt.After(snapshot.TransactionTime.Add(service.config.ObservationTimeout)) ||
		snapshot.TransactionTime.Sub(observation.ObservedAt) > service.config.MaximumObservationAge {
		return Profile{}, Versions{}, errors.New("execution target observation time is invalid")
	}
	if err := service.validateCurrent(snapshot); err != nil &&
		(snapshot.Pool != nil || snapshot.Target != nil || snapshot.Policy != nil) {
		return Profile{}, Versions{}, err
	}
	versions := Versions{
		Pool:   currentPoolVersion(snapshot.Pool),
		Target: currentTargetVersion(snapshot.Target),
		Policy: currentPolicyVersion(snapshot.Policy),
	}
	if versions.Pool == maximumVersion || versions.Target == maximumVersion {
		return Profile{}, Versions{}, errors.New("execution profile resource version is exhausted")
	}

	targetLabels := maps.Clone(observation.Labels)
	if targetLabels == nil {
		targetLabels = make(map[string]string)
	}
	for key, value := range map[string]string{
		profileLabelKey:  profileLabelValue,
		fingerprintLabel: observation.IdentityFingerprint,
	} {
		if current, found := targetLabels[key]; found && current != value {
			return Profile{}, Versions{}, ErrConflict
		}
		targetLabels[key] = value
	}
	if snapshot.Target != nil &&
		snapshot.Target.Metadata.Labels[fingerprintLabel] != observation.IdentityFingerprint {
		return Profile{}, Versions{}, ErrConflict
	}

	var currentPoolMetadata *paasv1.ResourceMetadata
	if snapshot.Pool != nil {
		currentPoolMetadata = &snapshot.Pool.Metadata
	}
	var currentTargetMetadata *paasv1.ResourceMetadata
	if snapshot.Target != nil {
		currentTargetMetadata = &snapshot.Target.Metadata
	}
	poolMetadata := nextMetadata(
		currentPoolMetadata,
		service.config.IDs.PoolID,
		"local",
		paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
		map[string]string{profileLabelKey: profileLabelValue},
		snapshot.TransactionTime,
	)
	targetMetadata := nextMetadata(
		currentTargetMetadata,
		service.config.IDs.TargetID,
		"local",
		paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
		targetLabels,
		snapshot.TransactionTime,
	)
	poolPhase := paasv1.ExecutionPoolUnavailable
	readyCount := uint32(0)
	if observation.Health == paasv1.ExecutionTargetHealthReady {
		poolPhase = paasv1.ExecutionPoolReady
		readyCount = 1
	} else if observation.Health == paasv1.ExecutionTargetHealthDegraded {
		poolPhase = paasv1.ExecutionPoolDegraded
	}
	pool := paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata:   poolMetadata,
		Spec: paasv1.ExecutionPoolSpec{
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				profileLabelKey: profileLabelValue,
			}},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase: poolPhase, ExecutionTargetCount: 1,
			ReadyExecutionTargetCount: readyCount, ObservedAt: observation.ObservedAt,
		},
	}
	target := paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata:   targetMetadata,
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: service.config.IDs.PoolID,
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind: paasv1.AdapterInfrastructure, Name: "localmachine", ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health: observation.Health, Capacity: observation.Capacity,
			Allocatable:                  observation.Allocatable,
			SupportedIsolationGuarantees: persistedIsolationGuarantees(observation),
			ObservedAt:                   observation.ObservedAt,
		},
	}
	policy := service.policy(snapshot)
	profile := Profile{Pool: pool, Target: target, Policy: policy}
	if paasv1.ValidateExecutionPool(pool) != nil || paasv1.ValidateExecutionTarget(target) != nil ||
		paasv1.ValidatePlacementPolicy(policy) != nil {
		return Profile{}, Versions{}, errors.New("execution profile cannot be constructed")
	}
	return profile, versions, nil
}

func (service *Service) policy(snapshot Snapshot) paasv1.PlacementPolicy {
	if snapshot.Policy != nil {
		return *snapshot.Policy
	}
	metadata := paasv1.ResourceMetadata{
		ID: service.config.IDs.PolicyID, Name: "default-local",
		Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: service.config.TenantID},
		Labels:          map[string]string{profileLabelKey: profileLabelValue, "purpose": "default"},
		ResourceVersion: 1, CreatedAt: snapshot.TransactionTime, UpdatedAt: snapshot.TransactionTime,
	}
	return paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion, Kind: "PlacementPolicy", Metadata: metadata,
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{service.config.IDs.PoolID},
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				profileLabelKey: profileLabelValue,
			}},
			Strategy: paasv1.PlacementFirstFit,
		},
	}
}

func (service *Service) validateCurrent(snapshot Snapshot) error {
	if snapshot.Pool == nil || snapshot.Target == nil || snapshot.Policy == nil {
		if snapshot.Pool == nil && snapshot.Target == nil && snapshot.Policy == nil {
			return errors.New("execution profile is absent")
		}
		return ErrConflict
	}
	pool := snapshot.Pool
	target := snapshot.Target
	policy := snapshot.Policy
	if pool.Metadata.ID != service.config.IDs.PoolID ||
		pool.Metadata.Name != "local" ||
		pool.Metadata.Scope.Kind != paasv1.AuthorityPlatform ||
		!maps.Equal(pool.Metadata.Labels, map[string]string{
			profileLabelKey: profileLabelValue,
		}) ||
		!maps.Equal(pool.Spec.ExecutionTargetSelector.MatchLabels, map[string]string{
			profileLabelKey: profileLabelValue,
		}) ||
		len(pool.Spec.AllowedIsolationGuarantees) != 1 ||
		pool.Spec.AllowedIsolationGuarantees[0] != paasv1.IsolationWorkload ||
		target.Metadata.ID != service.config.IDs.TargetID ||
		target.Metadata.Name != "local" ||
		target.Metadata.Scope.Kind != paasv1.AuthorityPlatform ||
		target.Metadata.Labels[profileLabelKey] != profileLabelValue ||
		target.Metadata.Labels[fingerprintLabel] == "" ||
		target.Spec.ExecutionPoolID != service.config.IDs.PoolID ||
		target.Spec.InfrastructureAdapter != (paasv1.AdapterRef{
			Kind: paasv1.AdapterInfrastructure, Name: "localmachine", ContractVersion: "v1",
		}) || target.Spec.DeploymentExecutor != (paasv1.AdapterRef{
		Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1",
	}) || target.Spec.GatewayAdapter != nil ||
		target.Spec.DesiredState != paasv1.ExecutionTargetActive ||
		policy.Metadata.ID != service.config.IDs.PolicyID ||
		policy.Metadata.Name != "default-local" ||
		policy.Metadata.Scope != (paasv1.ResourceScope{
			Kind: paasv1.AuthorityTenant, TenantID: service.config.TenantID,
		}) || !maps.Equal(policy.Metadata.Labels, map[string]string{
		profileLabelKey: profileLabelValue,
		"purpose":       "default",
	}) || policy.Spec.RequiredIsolationGuarantee != paasv1.IsolationWorkload ||
		len(policy.Spec.EligibleExecutionPoolIDs) != 1 ||
		policy.Spec.EligibleExecutionPoolIDs[0] != service.config.IDs.PoolID ||
		!maps.Equal(policy.Spec.ExecutionTargetSelector.MatchLabels, map[string]string{
			profileLabelKey: profileLabelValue,
		}) ||
		policy.Spec.Strategy != paasv1.PlacementFirstFit {
		return ErrConflict
	}
	return nil
}

func nextMetadata(
	current *paasv1.ResourceMetadata,
	id paasv1.ResourceID,
	name string,
	scope paasv1.ResourceScope,
	labels map[string]string,
	at time.Time,
) paasv1.ResourceMetadata {
	createdAt := at
	version := uint64(1)
	if current != nil {
		createdAt = current.CreatedAt
		version = current.ResourceVersion + 1
	}
	return paasv1.ResourceMetadata{
		ID: id, Name: name, Scope: scope, Labels: maps.Clone(labels),
		ResourceVersion: version, CreatedAt: createdAt, UpdatedAt: at,
	}
}

func currentPoolVersion(current *paasv1.ExecutionPool) uint64 {
	if current != nil {
		return current.Metadata.ResourceVersion
	}
	return 0
}

func currentTargetVersion(current *paasv1.ExecutionTarget) uint64 {
	if current != nil {
		return current.Metadata.ResourceVersion
	}
	return 0
}

func currentPolicyVersion(current *paasv1.PlacementPolicy) uint64 {
	if current != nil {
		return current.Metadata.ResourceVersion
	}
	return 0
}

func validLocalIsolationObservation(value paasv1.ExecutionTargetObservation) bool {
	if value.Health == paasv1.ExecutionTargetHealthReady {
		return slices.Equal(
			value.SupportedIsolationGuarantees,
			[]paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		)
	}
	return len(value.SupportedIsolationGuarantees) == 0
}

func persistedIsolationGuarantees(
	value paasv1.ExecutionTargetObservation,
) []paasv1.IsolationGuarantee {
	result := slices.Clone(value.SupportedIsolationGuarantees)
	if result == nil {
		result = make([]paasv1.IsolationGuarantee, 0)
	}
	return result
}

func validateConfig(config Config) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(config.TenantID)),
		paasv1.ValidateID("executionPoolId", string(config.IDs.PoolID)),
		paasv1.ValidateID("executionTargetId", string(config.IDs.TargetID)),
		paasv1.ValidateID("placementPolicyId", string(config.IDs.PolicyID)),
		paasv1.ValidateID("machineBindingRef", config.MachineBindingRef),
	)
	if config.IDs.PoolID == config.IDs.TargetID || config.IDs.PoolID == config.IDs.PolicyID ||
		config.IDs.TargetID == config.IDs.PolicyID {
		problems = append(problems, errors.New("execution profile identities must be distinct"))
	}
	if config.ObservationTimeout < time.Second || config.ObservationTimeout > 30*time.Second ||
		config.ObservationTimeout%time.Second != 0 {
		problems = append(problems, errors.New("execution profile observation timeout is invalid"))
	}
	if config.MaximumObservationAge < time.Minute || config.MaximumObservationAge > 10*time.Minute ||
		config.MaximumObservationAge%time.Second != 0 {
		problems = append(problems, errors.New("execution profile freshness bound is invalid"))
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		problems = append(problems, errors.New("execution profile transaction attempts are invalid"))
	}
	return errors.Join(problems...)
}
