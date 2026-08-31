package executionadmission

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

const fingerprintLabel = "matrix-machine-fingerprint"
const maximumVersion = uint64(9007199254740991)
const builtInObservationMaximumAge = 5 * time.Minute
const maximumObservationFutureSkew = 2 * time.Second
const builtInPoolID = paasv1.ResourceID("execution-pool-local")
const builtInTargetID = paasv1.ResourceID("execution-target-local")

func New(repository Repository, config Config) (*Service, error) {
	if repository == nil || paasv1.ValidateID("installationId", config.InstallationID) != nil ||
		len(config.Bindings) > MaximumTargets || config.ObservationTimeout < time.Second ||
		config.ObservationTimeout > 10*time.Second || config.MaximumObservationAge < config.ObservationTimeout ||
		config.MaximumObservationAge > 15*time.Second || config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("execution admission configuration is invalid")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	bindings := make(map[string]Binding, len(config.Bindings))
	targets, fingerprints := map[paasv1.ResourceID]bool{}, map[string]bool{}
	for _, binding := range config.Bindings {
		if binding.Adapter == nil || paasv1.ValidateID("bindingRef", binding.Ref) != nil ||
			paasv1.ValidateID("targetId", string(binding.TargetID)) != nil ||
			paasv1.ValidateDigest("identityFingerprint", binding.IdentityFingerprint) != nil ||
			bindings[binding.Ref].Adapter != nil || targets[binding.TargetID] || fingerprints[binding.IdentityFingerprint] {
			return nil, errors.New("execution admission binding is invalid or duplicated")
		}
		bindings[binding.Ref] = binding
		targets[binding.TargetID], fingerprints[binding.IdentityFingerprint] = true, true
	}
	config.Bindings = nil
	return &Service{repository: repository, config: config, bindings: bindings}, nil
}

func (service *Service) authorize(ctx context.Context, authorization port.Authorization) error {
	if service == nil || service.repository == nil || ctx == nil {
		return ErrUnavailable
	}
	if port.ValidatePlatformAuthorization(authorization) != nil || authorization.InstallationID != service.config.InstallationID {
		return port.ErrPermissionDenied
	}
	return ctx.Err()
}

func (service *Service) transaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	var lastErr error
	for attempt := 0; attempt < service.config.MaxTransactionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := service.repository.WithinTransaction(ctx, service.config.InstallationID, callback)
		lastErr = err
		if !errors.Is(err, ErrRetryableTransaction) {
			return err
		}
	}
	if errors.Is(lastErr, ErrConflict) {
		return ErrConflict
	}
	return ErrRetryableTransaction
}

func creationIdentity(authorization port.Authorization, action paasv1.OperationAction, key string, request any) (string, string, error) {
	if paasv1.ValidateSafeExternalText("Idempotency-Key", key, 128, true) != nil {
		return "", "", ErrInvalidArgument
	}
	identity, err := json.Marshal(struct {
		InstallationID string                 `json:"installationId"`
		Subject        paasv1.SubjectRef      `json:"subject"`
		Action         paasv1.OperationAction `json:"action"`
		Key            string                 `json:"key"`
	}{authorization.InstallationID, authorization.Subject, action, key})
	if err != nil {
		return "", "", ErrInvalidArgument
	}
	payload, err := json.Marshal(struct {
		Action  paasv1.OperationAction `json:"action"`
		Request any                    `json:"request"`
	}{action, request})
	if err != nil {
		return "", "", ErrInvalidArgument
	}
	return domain.DigestPayload(identity), domain.DigestPayload(payload), nil
}

func lifecycleIdentity(authorization port.Authorization, action paasv1.OperationAction, key string, request any) (string, string, error) {
	if paasv1.ValidateSafeExternalText("Idempotency-Key", key, 128, true) != nil {
		return "", "", ErrInvalidArgument
	}
	identity, err := json.Marshal(struct {
		InstallationID string            `json:"installationId"`
		Subject        paasv1.SubjectRef `json:"subject"`
		Purpose        string            `json:"purpose"`
		Key            string            `json:"key"`
	}{authorization.InstallationID, authorization.Subject, "EXECUTION_TARGET_LIFECYCLE", key})
	if err != nil {
		return "", "", ErrInvalidArgument
	}
	payload, err := json.Marshal(struct {
		Action  paasv1.OperationAction `json:"action"`
		Request any                    `json:"request"`
	}{action, request})
	if err != nil {
		return "", "", ErrInvalidArgument
	}
	return domain.DigestPayload(identity), domain.DigestPayload(payload), nil
}

func newSubmission(authorization port.Authorization, action paasv1.OperationAction, id paasv1.ResourceID, fingerprint, digest string, now time.Time) (Submission, error) {
	kind, auditAction := "", ""
	switch action {
	case paasv1.OperationCreateExecutionPool:
		kind, auditAction = "ExecutionPool", audit.ExecutionPoolCreated
	case paasv1.OperationRegisterExecutionTarget:
		kind, auditAction = "ExecutionTarget", audit.ExecutionTargetRegistered
	case paasv1.OperationDrainExecutionTarget:
		kind, auditAction = "ExecutionTarget", audit.ExecutionTargetDrained
	case paasv1.OperationActivateExecutionTarget:
		kind, auditAction = "ExecutionTarget", audit.ExecutionTargetActivated
	case paasv1.OperationRemoveExecutionTarget:
		kind, auditAction = "ExecutionTarget", audit.ExecutionTargetRemoved
	default:
		return Submission{}, ErrInvalidArgument
	}
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: paasv1.OperationID("operation-" + fingerprint[7:]),
		Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, InstallationID: authorization.InstallationID,
		Action: action, Target: paasv1.ResourceRef{Kind: kind, ID: id}, RequestedBy: authorization.Subject,
		IdempotencyFingerprint: fingerprint, RequestDigest: digest, State: paasv1.OperationSucceeded,
		Attempt: 1, CreatedAt: now, UpdatedAt: now, TerminalAt: &now,
	}
	event := audit.Event{
		SchemaVersion: "v1", EventID: "audit-" + fingerprint[7:], InstallationID: authorization.InstallationID,
		Actor: authorization.Subject, IAMDecisionID: authorization.DecisionID, Action: auditAction,
		Target: operation.Target, OperationID: operation.ID, RequestDigest: digest, Result: audit.Succeeded,
		RequestID: authorization.RequestID, AuditID: authorization.AuditID, TraceParent: authorization.TraceParent, OccurredAt: now,
	}
	if paasv1.ValidateOperation(operation) != nil || audit.ValidateEvent(event) != nil {
		return Submission{}, ErrInvalidArgument
	}
	return Submission{Operation: operation, AuditEvent: event}, nil
}

func metadata(id paasv1.ResourceID, name string, labels map[string]string, now time.Time) paasv1.ResourceMetadata {
	return paasv1.ResourceMetadata{ID: id, Name: name, Labels: maps.Clone(labels), Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
}

func (service *Service) CreatePool(ctx context.Context, command CreatePoolCommand) (paasv1.ExecutionPool, paasv1.Operation, bool, error) {
	var pool paasv1.ExecutionPool
	var operation paasv1.Operation
	var replayed bool
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return pool, operation, false, err
	}
	if paasv1.ValidateCreateExecutionPoolRequest(command.Request) != nil {
		return pool, operation, false, ErrInvalidArgument
	}
	if command.Request.ID == builtInPoolID {
		return pool, operation, false, ErrConflict
	}
	fingerprint, digest, err := creationIdentity(command.Authorization, paasv1.OperationCreateExecutionPool, command.IdempotencyKey, command.Request)
	if err != nil {
		return pool, operation, false, err
	}
	err = service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		stored, found, err := transaction.FindOperationByFingerprint(ctx, fingerprint)
		if err != nil {
			return err
		}
		if found {
			if stored.RequestDigest != digest || stored.Target.ID != command.Request.ID || stored.Action != paasv1.OperationCreateExecutionPool {
				return ErrIdempotencyConflict
			}
			pool, found, err = transaction.LoadPool(ctx, command.Request.ID)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			operation, replayed = stored, true
			return nil
		}
		if _, found, err := transaction.LoadPool(ctx, command.Request.ID); err != nil {
			return err
		} else if found {
			return ErrConflict
		}
		now, err := transaction.TransactionTime(ctx)
		if err != nil {
			return err
		}
		spec := command.Request.Spec
		spec.ExecutionTargetSelector.MatchLabels = maps.Clone(spec.ExecutionTargetSelector.MatchLabels)
		spec.AllowedIsolationGuarantees = slices.Clone(spec.AllowedIsolationGuarantees)
		pool = paasv1.ExecutionPool{APIVersion: paasv1.APIVersion, Kind: "ExecutionPool", Metadata: metadata(command.Request.ID, command.Request.Name, command.Request.Labels, now), Spec: spec,
			Status: paasv1.ExecutionPoolStatus{Phase: paasv1.ExecutionPoolUnavailable, ObservedAt: now}}
		if paasv1.ValidateExecutionPool(pool) != nil {
			return ErrInvalidArgument
		}
		submission, err := newSubmission(command.Authorization, paasv1.OperationCreateExecutionPool, command.Request.ID, fingerprint, digest, now)
		if err != nil {
			return err
		}
		if err := transaction.CreatePool(ctx, pool, submission); err != nil {
			return err
		}
		operation, replayed = submission.Operation, false
		return nil
	})
	if err != nil {
		return paasv1.ExecutionPool{}, paasv1.Operation{}, false, err
	}
	return pool, operation, replayed, nil
}

func (service *Service) RegisterTarget(ctx context.Context, command RegisterTargetCommand) (paasv1.ExecutionTarget, paasv1.Operation, bool, error) {
	var target paasv1.ExecutionTarget
	var operation paasv1.Operation
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return target, operation, false, err
	}
	request := command.Request
	if paasv1.ValidateRegisterExecutionTargetRequest(request) != nil {
		return target, operation, false, ErrInvalidArgument
	}
	if request.ID == builtInTargetID {
		return target, operation, false, ErrConflict
	}
	fingerprint, digest, err := creationIdentity(command.Authorization, paasv1.OperationRegisterExecutionTarget, command.IdempotencyKey, request)
	if err != nil {
		return target, operation, false, err
	}
	loadReplay := func(ctx context.Context, transaction Transaction) (bool, error) {
		stored, found, err := transaction.FindOperationByFingerprint(ctx, fingerprint)
		if err != nil || !found {
			return false, err
		}
		if stored.RequestDigest != digest || stored.Target.ID != request.ID || stored.Action != paasv1.OperationRegisterExecutionTarget {
			return false, ErrIdempotencyConflict
		}
		registration, found, err := transaction.LoadTarget(ctx, request.ID)
		if err != nil {
			return false, err
		}
		if !found {
			return false, ErrNotFound
		}
		target, operation = service.targetSnapshot(registration.Target, service.config.Clock()), stored
		return true, nil
	}
	var replayed bool
	// A committed replay remains usable during a node outage. IAM has already
	// authorized this new request; only the historical business fact is reused.
	err = service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		var err error
		replayed, err = loadReplay(ctx, transaction)
		if err != nil || replayed {
			return err
		}
		if _, found, err := transaction.LoadTarget(ctx, request.ID); err != nil {
			return err
		} else if found {
			return ErrConflict
		}
		return nil
	})
	if err != nil || replayed {
		return target, operation, replayed, err
	}
	binding, found := service.bindings[request.BindingRef]
	if !found || binding.TargetID != request.ID {
		return target, operation, false, ErrConflict
	}
	probeContext, cancel := context.WithTimeout(ctx, service.config.ObservationTimeout)
	defer cancel()
	capabilities, err := binding.Adapter.Capabilities(probeContext)
	if err != nil || paasv1.ValidateAdapterCapabilities(capabilities) != nil ||
		capabilities.Adapter.Kind != paasv1.AdapterInfrastructure ||
		capabilities.Adapter.Name == "localmachine" ||
		!slices.Contains(capabilities.Actions, paasv1.AdapterInspectExecutionTarget) || !slices.Contains(capabilities.Actions, paasv1.AdapterObserveExecutionTarget) {
		return target, operation, false, ErrUnavailable
	}
	envelope := service.observationCommand(binding, paasv1.AdapterInspectExecutionTarget, fingerprint, digest)
	observation, err := binding.Adapter.InspectExecutionTarget(probeContext, paasv1.InspectExecutionTargetRequest{Command: envelope})
	if err != nil || !service.validObservation(binding, observation, service.config.Clock()) || observation.Health != paasv1.ExecutionTargetHealthReady {
		return target, operation, false, ErrUnavailable
	}
	err = service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		replayed, err = loadReplay(ctx, transaction)
		if err != nil || replayed {
			return err
		}
		pool, found, err := transaction.LoadPool(ctx, request.ExecutionPoolID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		registrations, err := transaction.ListTargets(ctx)
		if err != nil {
			return err
		}
		if len(registrations) >= MaximumTargets {
			return ErrConflict
		}
		for _, current := range registrations {
			if current.Target.Metadata.ID == request.ID || current.BindingRef == binding.Ref || current.IdentityFingerprint == binding.IdentityFingerprint {
				return ErrConflict
			}
		}
		now, err := transaction.TransactionTime(ctx)
		if err != nil {
			return err
		}
		if !service.validObservation(binding, observation, now) {
			return ErrUnavailable
		}
		labels := maps.Clone(request.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		labels[fingerprintLabel] = binding.IdentityFingerprint
		for key, value := range pool.Spec.ExecutionTargetSelector.MatchLabels {
			if labels[key] != value {
				return ErrConflict
			}
		}
		allowed := false
		for _, guarantee := range observation.SupportedIsolationGuarantees {
			if !slices.Contains(capabilities.IsolationGuarantees, guarantee) {
				return ErrUnavailable
			}
			allowed = allowed || slices.Contains(pool.Spec.AllowedIsolationGuarantees, guarantee)
		}
		if !allowed {
			return ErrConflict
		}
		target = paasv1.ExecutionTarget{APIVersion: paasv1.APIVersion, Kind: "ExecutionTarget", Metadata: metadata(request.ID, request.Name, labels, now),
			Spec: paasv1.ExecutionTargetSpec{ExecutionPoolID: request.ExecutionPoolID, InfrastructureAdapter: capabilities.Adapter,
				DeploymentExecutor: paasv1.AdapterRef{Kind: paasv1.AdapterDeploymentExecutor, Name: "compose", ContractVersion: "v1"}, DesiredState: paasv1.ExecutionTargetActive}, Status: statusFromObservation(observation, now)}
		if paasv1.ValidateExecutionTarget(target) != nil {
			return ErrInvalidArgument
		}
		registration := Registration{Target: target, BindingRef: binding.Ref, IdentityFingerprint: binding.IdentityFingerprint}
		poolTargets, err := transaction.ListPoolTargets(ctx, pool.Metadata.ID)
		if err != nil {
			return err
		}
		poolVersion := pool.Metadata.ResourceVersion
		pool, err = service.poolSnapshot(pool, append(poolTargets, target), now, true)
		if err != nil {
			return err
		}
		submission, err := newSubmission(command.Authorization, paasv1.OperationRegisterExecutionTarget, request.ID, fingerprint, digest, now)
		if err != nil {
			return err
		}
		if err := transaction.RegisterTarget(ctx, registration, poolVersion, pool, submission); err != nil {
			return err
		}
		operation = submission.Operation
		return nil
	})
	if err != nil {
		return paasv1.ExecutionTarget{}, paasv1.Operation{}, false, err
	}
	return target, operation, replayed, nil
}

func (service *Service) TransitionTarget(
	ctx context.Context,
	command TransitionTargetCommand,
) (TransitionTargetResult, error) {
	var result TransitionTargetResult
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return result, err
	}
	nextState, valid := lifecycleTransition(command.Action)
	if !valid || paasv1.ValidateID("targetId", string(command.TargetID)) != nil ||
		command.ExpectedResourceVersion == 0 || command.ExpectedResourceVersion > maximumVersion ||
		command.TargetID == builtInTargetID {
		return result, ErrInvalidArgument
	}
	request := struct {
		TargetID                paasv1.ResourceID                  `json:"targetId"`
		ExpectedResourceVersion uint64                             `json:"expectedResourceVersion"`
		DesiredState            paasv1.ExecutionTargetDesiredState `json:"desiredState"`
	}{command.TargetID, command.ExpectedResourceVersion, nextState}
	fingerprint, digest, err := lifecycleIdentity(
		command.Authorization,
		command.Action,
		command.IdempotencyKey,
		request,
	)
	if err != nil {
		return result, err
	}
	err = service.transaction(ctx, func(ctx context.Context, transaction Transaction) error {
		stored, found, err := transaction.FindOperationByFingerprint(ctx, fingerprint)
		if err != nil {
			return err
		}
		if found {
			if stored.RequestDigest != digest || stored.Target.ID != command.TargetID || stored.Action != command.Action {
				return ErrIdempotencyConflict
			}
			registration, found, err := transaction.LoadTarget(ctx, command.TargetID)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			result = TransitionTargetResult{
				Target:    service.targetSnapshot(registration.Target, service.config.Clock()),
				Operation: stored,
				Replayed:  true,
			}
			return nil
		}
		registration, found, err := transaction.LoadTarget(ctx, command.TargetID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		current := registration.Target
		if current.Metadata.ResourceVersion != command.ExpectedResourceVersion {
			return ErrResourceVersionConflict
		}
		if !validLifecycleSource(command.Action, current.Spec.DesiredState) {
			return ErrInvalidTransition
		}
		if current.Metadata.ResourceVersion == maximumVersion {
			return ErrConflict
		}
		pool, found, err := transaction.LoadPool(ctx, current.Spec.ExecutionPoolID)
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
		if now.Before(current.Metadata.UpdatedAt) {
			return ErrConflict
		}
		target := current
		target.Spec.DesiredState = nextState
		target.Metadata.ResourceVersion++
		target.Metadata.UpdatedAt = now
		if paasv1.ValidateExecutionTarget(target) != nil {
			return ErrInvalidArgument
		}
		targets, err := transaction.ListPoolTargets(ctx, pool.Metadata.ID)
		if err != nil {
			return err
		}
		replaced := false
		for index := range targets {
			if targets[index].Metadata.ID == target.Metadata.ID {
				targets[index], replaced = target, true
			}
		}
		if !replaced {
			return ErrNotFound
		}
		poolVersion := pool.Metadata.ResourceVersion
		pool, err = service.poolSnapshot(pool, targets, now, true)
		if err != nil {
			return err
		}
		submission, err := newSubmission(
			command.Authorization,
			command.Action,
			command.TargetID,
			fingerprint,
			digest,
			now,
		)
		if err != nil {
			return err
		}
		if err := transaction.TransitionTarget(
			ctx,
			current.Metadata.ResourceVersion,
			target,
			poolVersion,
			pool,
			submission,
		); err != nil {
			return err
		}
		result = TransitionTargetResult{Target: target, Operation: submission.Operation}
		return nil
	})
	if err != nil {
		return TransitionTargetResult{}, err
	}
	return result, nil
}

func lifecycleTransition(action paasv1.OperationAction) (paasv1.ExecutionTargetDesiredState, bool) {
	switch action {
	case paasv1.OperationDrainExecutionTarget:
		return paasv1.ExecutionTargetDraining, true
	case paasv1.OperationActivateExecutionTarget:
		return paasv1.ExecutionTargetActive, true
	case paasv1.OperationRemoveExecutionTarget:
		return paasv1.ExecutionTargetRemoved, true
	default:
		return "", false
	}
}

func validLifecycleSource(action paasv1.OperationAction, state paasv1.ExecutionTargetDesiredState) bool {
	switch action {
	case paasv1.OperationDrainExecutionTarget:
		return state == paasv1.ExecutionTargetActive
	case paasv1.OperationActivateExecutionTarget:
		return state == paasv1.ExecutionTargetDraining
	case paasv1.OperationRemoveExecutionTarget:
		return state == paasv1.ExecutionTargetDraining
	default:
		return false
	}
}

func (service *Service) observationCommand(binding Binding, action paasv1.AdapterAction, fingerprint, digest string) paasv1.AdapterCommandEnvelope {
	return paasv1.AdapterCommandEnvelope{OperationID: paasv1.OperationID("observe-" + fingerprint[7:]), CommandID: paasv1.CommandID("observe-" + fingerprint[7:]), Attempt: 1,
		Action: action, Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform}, ExecutionTargetID: binding.TargetID, BindingRef: binding.Ref,
		RequestDigest: digest, Deadline: service.config.Clock().UTC().Truncate(time.Microsecond).Add(service.config.ObservationTimeout)}
}

func (service *Service) validObservation(binding Binding, observation paasv1.ExecutionTargetObservation, now time.Time) bool {
	return paasv1.ValidateExecutionTargetObservation(observation) == nil && observation.ExecutionTargetID == binding.TargetID && observation.IdentityFingerprint == binding.IdentityFingerprint &&
		!observation.ObservedAt.After(now.Add(2*time.Second)) && now.Before(observation.ObservedAt.Add(service.config.MaximumObservationAge)) &&
		observation.Usage != nil && !observation.Usage.ObservedAt.After(now.Add(2*time.Second)) &&
		(observation.Health != paasv1.ExecutionTargetHealthReady || len(observation.SupportedIsolationGuarantees) > 0)
}

func statusFromObservation(observation paasv1.ExecutionTargetObservation, now time.Time) paasv1.ExecutionTargetStatus {
	status := paasv1.ExecutionTargetStatus{Health: observation.Health, Capacity: observation.Capacity, Allocatable: observation.Allocatable,
		SupportedIsolationGuarantees: append([]paasv1.IsolationGuarantee{}, observation.SupportedIsolationGuarantees...), ObservedAt: observation.ObservedAt}
	if observation.Usage != nil {
		usage := observation.Usage.Snapshot(now)
		status.Usage = &usage
	}
	return status
}
