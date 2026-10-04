package applicationlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

type resourceCreation[T any] struct {
	authorization  port.Authorization
	id             paasv1.ResourceID
	idempotencyKey string
	targetKind     string
	action         paasv1.OperationAction
	request        any
	build          func(time.Time) T
	validate       func(T) error
	load           func(context.Context, Transaction, paasv1.ResourceID) (T, bool, error)
	validateParent func(context.Context, Transaction) error
	persist        func(context.Context, Transaction, T, ResourceSubmission) error
}

func (usecase *Usecase) CreateApplication(
	ctx context.Context,
	command CreateApplicationCommand,
) (paasv1.Application, paasv1.Operation, bool, error) {
	request := command.Request
	if port.ValidateAuthorizationTagsForAction(command.Authorization, port.AuthorizeApplicationCreate, request.Labels) != nil {
		return paasv1.Application{}, paasv1.Operation{}, false, ErrInvalidArgument
	}
	return executeResourceCreation(ctx, usecase, resourceCreation[paasv1.Application]{
		authorization: command.Authorization, id: request.ID,
		idempotencyKey: command.IdempotencyKey, targetKind: "Application",
		action: paasv1.OperationCreateApplication, request: request,
		build: func(now time.Time) paasv1.Application {
			return paasv1.Application{
				APIVersion: paasv1.APIVersion,
				Kind:       "Application",
				Metadata:   newResourceMetadata(command.Authorization.TenantID, request.ID, request.Name, request.Labels, now),
			}
		},
		validate: paasv1.ValidateApplication,
		load: func(ctx context.Context, transaction Transaction, id paasv1.ResourceID) (paasv1.Application, bool, error) {
			return transaction.LoadApplication(ctx, id)
		},
		persist: func(ctx context.Context, transaction Transaction, value paasv1.Application, submission ResourceSubmission) error {
			return transaction.CreateApplication(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) SetApplicationLabel(
	ctx context.Context,
	command SetApplicationLabelCommand,
) (ApplicationLabelResult, error) {
	value := command.Value
	return usecase.mutateApplicationLabel(ctx, applicationLabelMutation{
		authorization: command.Authorization, applicationID: command.ApplicationID,
		labelKey: command.LabelKey, value: &value,
		expectedResourceVersion: command.ExpectedResourceVersion,
		idempotencyKey:          command.IdempotencyKey,
		authorizationAction:     port.AuthorizeApplicationLabelSet,
		operationAction:         paasv1.OperationSetApplicationLabel,
	})
}

func (usecase *Usecase) DeleteApplicationLabel(
	ctx context.Context,
	command DeleteApplicationLabelCommand,
) (ApplicationLabelResult, error) {
	return usecase.mutateApplicationLabel(ctx, applicationLabelMutation{
		authorization: command.Authorization, applicationID: command.ApplicationID,
		labelKey: command.LabelKey, expectedResourceVersion: command.ExpectedResourceVersion,
		idempotencyKey:      command.IdempotencyKey,
		authorizationAction: port.AuthorizeApplicationLabelDelete,
		operationAction:     paasv1.OperationDeleteApplicationLabel,
	})
}

type applicationLabelMutation struct {
	authorization           port.Authorization
	applicationID           paasv1.ResourceID
	labelKey                string
	value                   *string
	expectedResourceVersion uint64
	idempotencyKey          string
	authorizationAction     iamv1.Action
	operationAction         paasv1.OperationAction
}

func (usecase *Usecase) mutateApplicationLabel(
	ctx context.Context,
	command applicationLabelMutation,
) (ApplicationLabelResult, error) {
	if usecase == nil || usecase.repository == nil {
		return ApplicationLabelResult{}, errors.New("application lifecycle use case is nil")
	}
	if ctx == nil {
		return ApplicationLabelResult{}, errors.New("application lifecycle context is nil")
	}
	if err := validateApplicationLabelMutation(command); err != nil {
		return ApplicationLabelResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	identity := resourceCreation[paasv1.Application]{
		authorization: command.authorization, id: command.applicationID,
		idempotencyKey: command.idempotencyKey, targetKind: "Application", action: command.operationAction,
	}
	fingerprint, err := resourceCreationFingerprint(identity)
	if err != nil {
		return ApplicationLabelResult{}, err
	}
	requestDigest, err := applicationLabelMutationDigest(command)
	if err != nil {
		return ApplicationLabelResult{}, err
	}

	var operation paasv1.Operation
	var replayed bool
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		operation, replayed = paasv1.Operation{}, false
		transactionErr = usecase.repository.WithinTransaction(ctx, command.authorization.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				stored, found, err := transaction.FindOperationByFingerprint(transactionContext, fingerprint)
				if err != nil {
					return err
				}
				if found {
					if stored.RequestDigest != requestDigest || stored.Action != command.operationAction ||
						stored.Target != (paasv1.ResourceRef{Kind: "Application", ID: command.applicationID}) {
						return ErrIdempotencyConflict
					}
					operation, replayed = stored, true
					return nil
				}
				application, found, err := transaction.LoadApplicationForUpdate(transactionContext, command.applicationID)
				if err != nil {
					return err
				}
				if !found {
					return ErrNotFound
				}
				if application.Metadata.ResourceVersion != command.expectedResourceVersion {
					return ErrResourceVersionConflict
				}
				if port.ValidateAuthorizationResourceTagsForAction(command.authorization, command.authorizationAction, application.Metadata.Labels) != nil {
					return ErrResourceVersionConflict
				}
				currentValue, present := application.Metadata.Labels[command.labelKey]
				requested := make(map[string]string, 1)
				if command.value == nil {
					if !present {
						return ErrNotFound
					}
					requested[command.labelKey] = currentValue
				} else {
					requested[command.labelKey] = *command.value
					if present && currentValue == *command.value {
						return ErrNoDesiredChange
					}
				}
				if port.ValidateAuthorizationTagsForAction(command.authorization, command.authorizationAction, requested) != nil {
					return ErrResourceVersionConflict
				}
				now, err := transaction.TransactionTime(transactionContext)
				if err != nil {
					return err
				}
				application.Metadata.Labels = cloneStringMap(application.Metadata.Labels)
				if application.Metadata.Labels == nil {
					application.Metadata.Labels = make(map[string]string)
				}
				if command.value == nil {
					delete(application.Metadata.Labels, command.labelKey)
				} else {
					application.Metadata.Labels[command.labelKey] = *command.value
				}
				if len(application.Metadata.Labels) == 0 {
					application.Metadata.Labels = nil
				}
				application.Metadata.ResourceVersion++
				application.Metadata.UpdatedAt = now
				if err := paasv1.ValidateApplication(application); err != nil {
					return fmt.Errorf("invalid Application label mutation: %w", err)
				}
				terminalAt := now
				operation = paasv1.Operation{APIVersion: paasv1.APIVersion, Kind: "Operation",
					ID:     operationIDFromFingerprint(fingerprint),
					Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: command.authorization.TenantID},
					Action: command.operationAction, Target: paasv1.ResourceRef{Kind: "Application", ID: command.applicationID},
					RequestedBy: command.authorization.Subject, IdempotencyFingerprint: fingerprint,
					RequestDigest: requestDigest, State: paasv1.OperationSucceeded, Attempt: 1,
					CreatedAt: now, UpdatedAt: now, TerminalAt: &terminalAt}
				if err := paasv1.ValidateOperation(operation); err != nil {
					return fmt.Errorf("invalid Application label Operation: %w", err)
				}
				auditEvent, err := auditEventForOperation(command.authorization, operation, now)
				if err != nil {
					return err
				}
				return transaction.UpdateApplicationLabel(transactionContext, ApplicationLabelSubmission{
					Application: application, Operation: operation, AuditEvent: auditEvent,
					ExpectedResourceVersion: command.expectedResourceVersion,
				})
			})
		if transactionErr == nil {
			return ApplicationLabelResult{Operation: operation, ResourceVersion: command.expectedResourceVersion + 1, Replayed: replayed}, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return ApplicationLabelResult{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return ApplicationLabelResult{}, err
		}
	}
	return ApplicationLabelResult{}, fmt.Errorf("application label transaction attempts exhausted: %w", transactionErr)
}

func validateApplicationLabelMutation(command applicationLabelMutation) error {
	var valueErr error
	if command.value != nil {
		valueErr = paasv1.ValidateSetApplicationLabelRequest(paasv1.SetApplicationLabelRequest{Value: *command.value})
	}
	if command.expectedResourceVersion == 0 || command.expectedResourceVersion > maxResourceVersion {
		valueErr = errors.Join(valueErr, errors.New("application label mutation requires a valid expected resource version"))
	}
	return errors.Join(
		port.ValidateAuthorization(command.authorization),
		port.ValidateApplicationLabelKeyForAction(command.authorizationAction, command.labelKey),
		paasv1.ValidateID("applicationId", string(command.applicationID)),
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.idempotencyKey, 128, true),
		valueErr,
	)
}

func applicationLabelMutationDigest(command applicationLabelMutation) (string, error) {
	encoded, err := json.Marshal(struct {
		Kind                    string            `json:"kind"`
		ApplicationID           paasv1.ResourceID `json:"applicationId"`
		LabelKey                string            `json:"labelKey"`
		Value                   *string           `json:"value,omitempty"`
		ExpectedResourceVersion uint64            `json:"expectedResourceVersion"`
	}{Kind: string(command.operationAction), ApplicationID: command.applicationID, LabelKey: command.labelKey,
		Value: command.value, ExpectedResourceVersion: command.expectedResourceVersion})
	if err != nil {
		return "", fmt.Errorf("encode Application label mutation: %w", err)
	}
	return domain.DigestPayload(encoded), nil
}

func (usecase *Usecase) CreateConfiguration(
	ctx context.Context,
	command CreateConfigurationCommand,
) (paasv1.Configuration, paasv1.Operation, bool, error) {
	request := command.Request
	return executeResourceCreation(ctx, usecase, resourceCreation[paasv1.Configuration]{
		authorization: command.Authorization, id: request.ID,
		idempotencyKey: command.IdempotencyKey, targetKind: "Configuration",
		action: paasv1.OperationCreateConfiguration, request: request,
		build: func(now time.Time) paasv1.Configuration {
			return paasv1.Configuration{
				APIVersion:    paasv1.APIVersion,
				Kind:          "Configuration",
				Metadata:      newResourceMetadata(command.Authorization.TenantID, request.ID, request.Name, request.Labels, now),
				ApplicationID: request.ApplicationID,
			}
		},
		validate: paasv1.ValidateConfiguration,
		load: func(ctx context.Context, transaction Transaction, id paasv1.ResourceID) (paasv1.Configuration, bool, error) {
			return transaction.LoadConfiguration(ctx, id)
		},
		validateParent: func(ctx context.Context, transaction Transaction) error {
			_, found, err := transaction.LoadApplication(ctx, request.ApplicationID)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			return nil
		},
		persist: func(ctx context.Context, transaction Transaction, value paasv1.Configuration, submission ResourceSubmission) error {
			return transaction.CreateConfiguration(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) CreateConfigurationRevision(
	ctx context.Context,
	command CreateConfigurationRevisionCommand,
) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error) {
	request := command.Request
	return executeResourceCreation(ctx, usecase, resourceCreation[paasv1.ConfigurationRevision]{
		authorization: command.Authorization, id: request.ID,
		idempotencyKey: command.IdempotencyKey, targetKind: "ConfigurationRevision",
		action: paasv1.OperationCreateConfigurationRevision, request: request,
		build: func(now time.Time) paasv1.ConfigurationRevision {
			spec := request.Spec
			spec.Values = cloneStringMap(spec.Values)
			return paasv1.ConfigurationRevision{
				APIVersion: paasv1.APIVersion,
				Kind:       "ConfigurationRevision",
				Metadata:   newResourceMetadata(command.Authorization.TenantID, request.ID, request.Name, request.Labels, now),
				Spec:       spec,
			}
		},
		validate: paasv1.ValidateConfigurationRevision,
		load: func(ctx context.Context, transaction Transaction, id paasv1.ResourceID) (paasv1.ConfigurationRevision, bool, error) {
			return transaction.LoadConfigurationRevision(ctx, id)
		},
		validateParent: func(ctx context.Context, transaction Transaction) error {
			_, found, err := transaction.LoadConfiguration(ctx, request.Spec.ConfigurationID)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			return nil
		},
		persist: func(ctx context.Context, transaction Transaction, value paasv1.ConfigurationRevision, submission ResourceSubmission) error {
			return transaction.CreateConfigurationRevision(ctx, value, submission)
		},
	})
}

func (usecase *Usecase) CreateApplicationRevision(
	ctx context.Context,
	command CreateApplicationRevisionCommand,
) (paasv1.ApplicationRevision, paasv1.Operation, bool, error) {
	request := command.Request
	return executeResourceCreation(ctx, usecase, resourceCreation[paasv1.ApplicationRevision]{
		authorization: command.Authorization, id: request.ID,
		idempotencyKey: command.IdempotencyKey, targetKind: "ApplicationRevision",
		action: paasv1.OperationCreateApplicationRevision, request: request,
		build: func(now time.Time) paasv1.ApplicationRevision {
			spec := cloneApplicationRevisionSpec(request.Spec)
			return paasv1.ApplicationRevision{
				APIVersion: paasv1.APIVersion,
				Kind:       "ApplicationRevision",
				Metadata:   newResourceMetadata(command.Authorization.TenantID, request.ID, request.Name, request.Labels, now),
				Spec:       spec,
			}
		},
		validate: paasv1.ValidateApplicationRevision,
		load: func(ctx context.Context, transaction Transaction, id paasv1.ResourceID) (paasv1.ApplicationRevision, bool, error) {
			value, err := transaction.LoadApplicationRevision(ctx, id)
			if errors.Is(err, ErrNotFound) {
				return paasv1.ApplicationRevision{}, false, nil
			}
			return value, err == nil, err
		},
		validateParent: func(ctx context.Context, transaction Transaction) error {
			_, found, err := transaction.LoadApplication(ctx, request.Spec.ApplicationID)
			if err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
			return nil
		},
		persist: func(ctx context.Context, transaction Transaction, value paasv1.ApplicationRevision, submission ResourceSubmission) error {
			return transaction.CreateApplicationRevision(ctx, value, submission)
		},
	})
}

func executeResourceCreation[T any](
	ctx context.Context,
	usecase *Usecase,
	creation resourceCreation[T],
) (T, paasv1.Operation, bool, error) {
	var zero T
	if usecase == nil || usecase.repository == nil {
		return zero, paasv1.Operation{}, false, errors.New("application lifecycle use case is nil")
	}
	if ctx == nil {
		return zero, paasv1.Operation{}, false, errors.New("application lifecycle context is nil")
	}
	if err := validateResourceCreation(creation); err != nil {
		return zero, paasv1.Operation{}, false, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	fingerprint, err := resourceCreationFingerprint(creation)
	if err != nil {
		return zero, paasv1.Operation{}, false, err
	}
	requestDigest, err := resourceCreationRequestDigest(creation)
	if err != nil {
		return zero, paasv1.Operation{}, false, err
	}

	var value T
	var operation paasv1.Operation
	var replayed bool
	var transactionErr error
	for attempt := 0; attempt < usecase.config.MaxTransactionAttempts; attempt++ {
		value, operation, replayed = zero, paasv1.Operation{}, false
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			creation.authorization.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				storedOperation, found, err := transaction.FindOperationByFingerprint(transactionContext, fingerprint)
				if err != nil {
					return err
				}
				if found {
					if storedOperation.RequestDigest != requestDigest ||
						storedOperation.Target.Kind != creation.targetKind ||
						storedOperation.Target.ID != creation.id {
						return ErrIdempotencyConflict
					}
					stored, resourceFound, err := creation.load(transactionContext, transaction, creation.id)
					if err != nil {
						return err
					}
					if !resourceFound {
						return ErrNotFound
					}
					value, operation, replayed = stored, storedOperation, true
					return nil
				}
				_, resourceFound, err := creation.load(transactionContext, transaction, creation.id)
				if err != nil {
					return err
				}
				if resourceFound {
					return ErrAlreadyExists
				}
				if creation.validateParent != nil {
					if err := creation.validateParent(transactionContext, transaction); err != nil {
						return err
					}
				}
				now, err := transaction.TransactionTime(transactionContext)
				if err != nil {
					return err
				}
				value = creation.build(now)
				if err := creation.validate(value); err != nil {
					return fmt.Errorf("%w: invalid %s mutation: %v", ErrInvalidArgument, creation.targetKind, err)
				}
				terminalAt := now
				operation = paasv1.Operation{
					APIVersion: paasv1.APIVersion,
					Kind:       "Operation",
					ID:         operationIDFromFingerprint(fingerprint),
					Scope: paasv1.ResourceScope{
						Kind: paasv1.AuthorityTenant, TenantID: creation.authorization.TenantID,
					},
					Action:                 creation.action,
					Target:                 paasv1.ResourceRef{Kind: creation.targetKind, ID: creation.id},
					RequestedBy:            creation.authorization.Subject,
					IdempotencyFingerprint: fingerprint,
					RequestDigest:          requestDigest,
					State:                  paasv1.OperationSucceeded,
					Attempt:                1,
					CreatedAt:              now, UpdatedAt: now, TerminalAt: &terminalAt,
				}
				if err := paasv1.ValidateOperation(operation); err != nil {
					return fmt.Errorf("invalid Operation mutation: %w", err)
				}
				auditEvent, err := auditEventForOperation(creation.authorization, operation, now)
				if err != nil {
					return err
				}
				return creation.persist(transactionContext, transaction, value, ResourceSubmission{
					Operation: operation, AuditEvent: auditEvent,
				})
			},
		)
		if transactionErr == nil {
			return value, operation, replayed, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return zero, paasv1.Operation{}, false, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return zero, paasv1.Operation{}, false, err
		}
	}
	return zero, paasv1.Operation{}, false,
		fmt.Errorf("application lifecycle transaction attempts exhausted: %w", transactionErr)
}

func validateResourceCreation[T any](creation resourceCreation[T]) error {
	return errors.Join(
		port.ValidateAuthorization(creation.authorization),
		paasv1.ValidateID("resource.id", string(creation.id)),
		paasv1.ValidateSafeExternalText("Idempotency-Key", creation.idempotencyKey, 128, true),
	)
}

func resourceCreationFingerprint[T any](creation resourceCreation[T]) (string, error) {
	encoded, err := json.Marshal(idempotencyIdentity{
		TenantID:       creation.authorization.TenantID,
		SubjectType:    creation.authorization.Subject.Type,
		SubjectID:      creation.authorization.Subject.ID,
		CommandKind:    string(creation.action),
		TargetID:       creation.id,
		IdempotencyKey: creation.idempotencyKey,
		RoleSession:    creation.authorization.Subject.RoleSession,
		AccessKeyID:    creation.authorization.Subject.AccessKeyID,
	})
	if err != nil {
		return "", fmt.Errorf("encode resource idempotency identity: %w", err)
	}
	return domain.DigestPayload(encoded), nil
}

func resourceCreationRequestDigest[T any](creation resourceCreation[T]) (string, error) {
	encoded, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Request any    `json:"request"`
	}{Kind: creation.targetKind, Request: creation.request})
	if err != nil {
		return "", fmt.Errorf("encode resource creation identity: %w", err)
	}
	return domain.DigestPayload(encoded), nil
}

func newResourceMetadata(
	tenantID paasv1.TenantID,
	id paasv1.ResourceID,
	name string,
	labels map[string]string,
	now time.Time,
) paasv1.ResourceMetadata {
	return paasv1.ResourceMetadata{
		ID: id, Name: name,
		Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: tenantID},
		Labels: cloneStringMap(labels), ResourceVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	}
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func cloneApplicationRevisionSpec(value paasv1.ApplicationRevisionSpec) paasv1.ApplicationRevisionSpec {
	cloned := value
	cloned.Components = append([]paasv1.ApplicationRevisionComponent(nil), value.Components...)
	for componentIndex := range cloned.Components {
		component := &cloned.Components[componentIndex]
		component.Endpoints = append([]paasv1.ApplicationEndpoint(nil), component.Endpoints...)
		component.Inputs = append([]paasv1.ComponentInput(nil), component.Inputs...)
	}
	return cloned
}
