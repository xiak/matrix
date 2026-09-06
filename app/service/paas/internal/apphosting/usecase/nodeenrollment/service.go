package nodeenrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

func New(repository Repository, issuer JoinIssuer, config Config) (*Service, error) {
	if repository == nil || issuer == nil || paasv1.ValidateID("installationId", config.InstallationID) != nil ||
		config.Lifetime < time.Minute || config.Lifetime > paasv1.MaximumNodeEnrollmentLifetime ||
		config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("node enrollment service configuration is invalid")
	}
	return &Service{repository: repository, issuer: issuer, config: config}, nil
}

func (service *Service) Create(ctx context.Context, command CreateCommand) (CreateResult, error) {
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return CreateResult{}, err
	}
	if paasv1.ValidateCreateNodeEnrollmentRequest(command.Request) != nil ||
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.IdempotencyKey, 128, true) != nil {
		return CreateResult{}, ErrInvalidArgument
	}
	fingerprint, requestDigest, err := createIdentity(command)
	if err != nil {
		return CreateResult{}, ErrInvalidArgument
	}
	enrollmentID, targetID := identities(fingerprint)
	var replay StoredEnrollment
	var replayed bool
	var issuedAt time.Time
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var loadErr error
		replay, replayed, loadErr = service.loadCreateReplay(
			transactionContext, transaction, fingerprint, requestDigest, enrollmentID,
		)
		if loadErr != nil || replayed {
			return loadErr
		}
		pool, found, loadErr := transaction.LoadExecutionPool(transactionContext, command.Request.ExecutionPoolID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return ErrNotFound
		}
		if paasv1.ValidateExecutionPool(pool) != nil || pool.Metadata.ID != command.Request.ExecutionPoolID {
			return ErrConflict
		}
		issuedAt, loadErr = transaction.TransactionTime(transactionContext)
		if loadErr != nil || validateTime(issuedAt) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return CreateResult{}, err
	}
	if replayed {
		return createResult(replay, true)
	}
	expiresAt := issuedAt.Add(service.config.Lifetime)
	issued, err := service.issuer.Issue(ctx, JoinIssueRequest{
		EnrollmentID: enrollmentID, ExecutionTargetID: targetID,
		ExpiresAt: expiresAt, WrappingPublicKey: command.Request.WrappingPublicKey,
	})
	if err != nil {
		if ctx.Err() != nil {
			return CreateResult{}, ctx.Err()
		}
		return CreateResult{}, ErrUnavailable
	}
	defer issued.Clear()
	var stored StoredEnrollment
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var loadErr error
		stored, replayed, loadErr = service.loadCreateReplay(
			transactionContext, transaction, fingerprint, requestDigest, enrollmentID,
		)
		if loadErr != nil || replayed {
			return loadErr
		}
		pool, found, loadErr := transaction.LoadExecutionPool(transactionContext, command.Request.ExecutionPoolID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return ErrNotFound
		}
		if paasv1.ValidateExecutionPool(pool) != nil || pool.Metadata.ID != command.Request.ExecutionPoolID {
			return ErrConflict
		}
		now, loadErr := transaction.TransactionTime(transactionContext)
		if loadErr != nil || validateTime(now) != nil || !now.Before(expiresAt) {
			return ErrUnavailable
		}
		enrollment := paasv1.NodeEnrollment{
			APIVersion: paasv1.APIVersion, Kind: "NodeEnrollment",
			Metadata: paasv1.ResourceMetadata{
				ID: enrollmentID, Name: command.Request.Name,
				Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
				Labels: maps.Clone(command.Request.Labels), ResourceVersion: 1,
				CreatedAt: now, UpdatedAt: now,
			},
			ExecutionTargetID: targetID, ExecutionPoolID: command.Request.ExecutionPoolID,
			OperationID: paasv1.OperationID("operation-" + fingerprint[7:]),
			State:       paasv1.NodeEnrollmentWaitingInstall, ExpiresAt: expiresAt,
		}
		operation := paasv1.Operation{
			APIVersion: paasv1.APIVersion, Kind: "Operation", ID: enrollment.OperationID,
			Scope:                  paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			InstallationID:         service.config.InstallationID,
			Action:                 paasv1.OperationRegisterExecutionTarget,
			Target:                 paasv1.ResourceRef{Kind: "ExecutionTarget", ID: targetID},
			RequestedBy:            command.Authorization.Subject,
			IdempotencyFingerprint: fingerprint, RequestDigest: requestDigest,
			State: paasv1.OperationAccepted, Attempt: 1, CreatedAt: now, UpdatedAt: now,
		}
		stored = StoredEnrollment{
			Enrollment: enrollment, Operation: operation, Join: issued.Join,
			WrappedCredential:   issued.WrappedCredential,
			CredentialSalt:      bytes.Clone(issued.CredentialSalt),
			CredentialVerifier:  issued.CredentialVerifier,
			CreateAuthorization: command.Authorization,
		}
		if validateStoredEnrollment(stored, service.config.InstallationID) != nil {
			return ErrUnavailable
		}
		return transaction.InsertEnrollment(transactionContext, stored)
	})
	if err != nil {
		return CreateResult{}, err
	}
	return createResult(stored, replayed)
}

func (service *Service) Get(ctx context.Context, authorization port.Authorization, enrollmentID paasv1.ResourceID) (paasv1.NodeEnrollment, error) {
	if err := service.authorize(ctx, authorization); err != nil {
		return paasv1.NodeEnrollment{}, err
	}
	if !validEnrollmentID(enrollmentID) {
		return paasv1.NodeEnrollment{}, ErrInvalidArgument
	}
	var stored StoredEnrollment
	err := service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var found bool
		var err error
		stored, found, err = transaction.LoadEnrollment(transactionContext, enrollmentID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		stored, err = service.expireIfDue(transactionContext, transaction, stored)
		return err
	})
	if err != nil {
		return paasv1.NodeEnrollment{}, err
	}
	return enrollmentSnapshot(stored.Enrollment), nil
}

func (service *Service) List(ctx context.Context, authorization port.Authorization) (paasv1.NodeEnrollmentList, error) {
	if err := service.authorize(ctx, authorization); err != nil {
		return paasv1.NodeEnrollmentList{}, err
	}
	result := paasv1.NodeEnrollmentList{
		APIVersion: paasv1.APIVersion, Kind: "NodeEnrollmentList", Items: []paasv1.NodeEnrollment{},
	}
	err := service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		stored, err := transaction.ListEnrollments(transactionContext, paasv1.MaximumNodeEnrollmentListItems+1)
		if err != nil {
			return err
		}
		if len(stored) > paasv1.MaximumNodeEnrollmentListItems {
			return ErrConflict
		}
		result.Items = make([]paasv1.NodeEnrollment, 0, len(stored))
		for _, item := range stored {
			item, err = service.expireIfDue(transactionContext, transaction, item)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, enrollmentSnapshot(item.Enrollment))
		}
		return nil
	})
	if err != nil {
		return paasv1.NodeEnrollmentList{}, err
	}
	if paasv1.ValidateNodeEnrollmentList(result) != nil {
		return paasv1.NodeEnrollmentList{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) loadCreateReplay(
	ctx context.Context,
	transaction Transaction,
	fingerprint string,
	requestDigest string,
	enrollmentID paasv1.ResourceID,
) (StoredEnrollment, bool, error) {
	stored, found, err := transaction.FindByFingerprint(ctx, fingerprint)
	if err != nil || !found {
		return StoredEnrollment{}, false, err
	}
	if validateStoredEnrollment(stored, service.config.InstallationID) != nil ||
		stored.Operation.RequestDigest != requestDigest || stored.Enrollment.Metadata.ID != enrollmentID {
		return StoredEnrollment{}, false, ErrIdempotencyConflict
	}
	stored, err = service.expireIfDue(ctx, transaction, stored)
	if err != nil {
		return StoredEnrollment{}, false, err
	}
	switch stored.Enrollment.State {
	case paasv1.NodeEnrollmentWaitingInstall:
		return stored, true, nil
	case paasv1.NodeEnrollmentVerifying:
		return StoredEnrollment{}, false, ErrCredentialConsumed
	case paasv1.NodeEnrollmentExpired:
		return StoredEnrollment{}, false, ErrExpired
	case paasv1.NodeEnrollmentRevoked:
		return StoredEnrollment{}, false, ErrRevoked
	default:
		return StoredEnrollment{}, false, ErrConflict
	}
}

func (service *Service) expireIfDue(ctx context.Context, transaction Transaction, stored StoredEnrollment) (StoredEnrollment, error) {
	if validateStoredEnrollment(stored, service.config.InstallationID) != nil {
		return StoredEnrollment{}, ErrConflict
	}
	if stored.Enrollment.State != paasv1.NodeEnrollmentWaitingInstall &&
		stored.Enrollment.State != paasv1.NodeEnrollmentVerifying {
		return stored, nil
	}
	now, err := transaction.TransactionTime(ctx)
	if err != nil {
		return StoredEnrollment{}, err
	}
	if now.Before(stored.Enrollment.ExpiresAt) {
		return stored, nil
	}
	next := enrollmentSnapshot(stored.Enrollment)
	next.State = paasv1.NodeEnrollmentExpired
	next.Metadata.ResourceVersion++
	next.Metadata.UpdatedAt = now
	next.Diagnostic = &paasv1.NodeEnrollmentDiagnostic{
		Code: paasv1.NodeEnrollmentDiagnosticExpired, OccurredAt: now,
	}
	operation := stored.Operation
	operation.State, operation.UpdatedAt, operation.TerminalAt = paasv1.OperationCancelled, now, &now
	if paasv1.ValidateNodeEnrollment(next) != nil || paasv1.ValidateOperation(operation) != nil {
		return StoredEnrollment{}, ErrConflict
	}
	if err := transaction.ExpireEnrollment(ctx, stored, next, operation); err != nil {
		return StoredEnrollment{}, err
	}
	stored.Enrollment, stored.Operation = next, operation
	return stored, nil
}

func (service *Service) authorize(ctx context.Context, authorization port.Authorization) error {
	if service == nil || service.repository == nil || service.issuer == nil || ctx == nil {
		return ErrUnavailable
	}
	if port.ValidatePlatformAuthorization(authorization) != nil ||
		authorization.InstallationID != service.config.InstallationID {
		return port.ErrPermissionDenied
	}
	return ctx.Err()
}

func (service *Service) transaction(ctx context.Context, callback func(context.Context, Transaction) error) error {
	var lastErr error
	for range service.config.MaxTransactionAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = service.repository.WithinInstallation(ctx, service.config.InstallationID, callback)
		if !errors.Is(lastErr, ErrRetryableTransaction) {
			return lastErr
		}
	}
	return ErrRetryableTransaction
}

func createIdentity(command CreateCommand) (string, string, error) {
	identity, err := json.Marshal(struct {
		InstallationID string            `json:"installationId"`
		Subject        paasv1.SubjectRef `json:"subject"`
		Purpose        string            `json:"purpose"`
		Key            string            `json:"key"`
	}{command.Authorization.InstallationID, command.Authorization.Subject, "NODE_ENROLLMENT_CREATE", command.IdempotencyKey})
	if err != nil {
		return "", "", err
	}
	payload, err := json.Marshal(struct {
		Kind    string                             `json:"kind"`
		Request paasv1.CreateNodeEnrollmentRequest `json:"request"`
	}{"CreateNodeEnrollment", command.Request})
	if err != nil {
		return "", "", err
	}
	return domain.DigestPayload(identity), domain.DigestPayload(payload), nil
}

func identities(fingerprint string) (paasv1.ResourceID, paasv1.ResourceID) {
	digest := strings.TrimPrefix(fingerprint, "sha256:")
	return paasv1.ResourceID("node-enrollment-" + digest[:32]),
		paasv1.ResourceID("execution-target-" + digest[32:])
}

func createResult(stored StoredEnrollment, replayed bool) (CreateResult, error) {
	response := paasv1.CreateNodeEnrollmentResponse{
		Enrollment: enrollmentSnapshot(stored.Enrollment), Join: stored.Join,
		WrappedCredential: stored.WrappedCredential,
	}
	if paasv1.ValidateCreateNodeEnrollmentResponse(response) != nil || paasv1.ValidateOperation(stored.Operation) != nil {
		return CreateResult{}, ErrConflict
	}
	return CreateResult{Response: response, Operation: stored.Operation, Replayed: replayed}, nil
}

func validateStoredEnrollment(value StoredEnrollment, installationID string) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateNodeEnrollment(value.Enrollment),
		paasv1.ValidateOperation(value.Operation),
		paasv1.ValidateNodeEnrollmentJoin(value.Join),
		paasv1.ValidateWrappedJoinCredential(value.WrappedCredential),
		port.ValidatePlatformAuthorization(value.CreateAuthorization),
	)
	if value.Enrollment.Metadata.ID != value.Join.EnrollmentID ||
		value.Enrollment.ExecutionTargetID != value.Join.ExecutionTargetID ||
		!value.Enrollment.ExpiresAt.Equal(value.Join.ExpiresAt) ||
		value.Enrollment.OperationID != value.Operation.ID ||
		value.Operation.Action != paasv1.OperationRegisterExecutionTarget ||
		value.Operation.Target != (paasv1.ResourceRef{Kind: "ExecutionTarget", ID: value.Enrollment.ExecutionTargetID}) ||
		value.Operation.InstallationID != installationID || value.Join.InstallationID != installationID ||
		value.CreateAuthorization.InstallationID != installationID ||
		value.Operation.RequestedBy != value.CreateAuthorization.Subject ||
		len(value.CredentialSalt) != 32 ||
		paasv1.ValidateDigest("credentialVerifier", value.CredentialVerifier) != nil ||
		value.CredentialVerifier == value.Join.CredentialDigest {
		problems = append(problems, errors.New("stored node enrollment authority is inconsistent"))
	}
	return errors.Join(problems...)
}

func enrollmentSnapshot(value paasv1.NodeEnrollment) paasv1.NodeEnrollment {
	value.Metadata.Labels = maps.Clone(value.Metadata.Labels)
	if value.CredentialConsumedAt != nil {
		copy := *value.CredentialConsumedAt
		value.CredentialConsumedAt = &copy
	}
	if value.ReadyAt != nil {
		copy := *value.ReadyAt
		value.ReadyAt = &copy
	}
	if value.Diagnostic != nil {
		copy := *value.Diagnostic
		value.Diagnostic = &copy
	}
	return value
}

func validEnrollmentID(value paasv1.ResourceID) bool {
	const prefix = "node-enrollment-"
	if !strings.HasPrefix(string(value), prefix) || len(value) != len(prefix)+32 {
		return false
	}
	for _, character := range string(value)[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validateTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%1000 != 0 {
		return errors.New("transaction time is invalid")
	}
	return nil
}
