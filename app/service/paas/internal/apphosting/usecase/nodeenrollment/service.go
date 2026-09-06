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

const maximumResourceVersion = uint64(9007199254740991)

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
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.IdempotencyKey, 128, true) != nil ||
		ValidateControlPlaneBaseURL(command.ControlPlaneBaseURL) != nil {
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
		return createReplayResult(replay)
	}
	expiresAt := issuedAt.Add(service.config.Lifetime)
	issued, err := service.issuer.Issue(ctx, JoinIssueRequest{
		EnrollmentID: enrollmentID, ExecutionTargetID: targetID,
		ExpiresAt: expiresAt, WrappingPublicKey: command.Request.WrappingPublicKey,
		ControlPlaneBaseURL: command.ControlPlaneBaseURL,
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
		stored, loadErr = service.newStoredEnrollment(
			command.Authorization,
			command.Request,
			fingerprint,
			requestDigest,
			enrollmentID,
			targetID,
			expiresAt,
			now,
			issued,
		)
		if loadErr != nil {
			return loadErr
		}
		return transaction.InsertEnrollment(transactionContext, stored)
	})
	if err != nil {
		return CreateResult{}, err
	}
	if replayed {
		return createReplayResult(stored)
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

func (service *Service) Revoke(ctx context.Context, command RevokeCommand) (RevokeResult, error) {
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return RevokeResult{}, err
	}
	if !validEnrollmentID(command.EnrollmentID) ||
		command.ExpectedResourceVersion == 0 || command.ExpectedResourceVersion > maximumResourceVersion ||
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.IdempotencyKey, 128, true) != nil {
		return RevokeResult{}, ErrInvalidArgument
	}
	fingerprint, requestDigest, err := terminationIdentity(
		command.Authorization,
		"NODE_ENROLLMENT_REVOKE",
		command.IdempotencyKey,
		struct {
			EnrollmentID            paasv1.ResourceID `json:"enrollmentId"`
			ExpectedResourceVersion uint64            `json:"expectedResourceVersion"`
		}{command.EnrollmentID, command.ExpectedResourceVersion},
	)
	if err != nil {
		return RevokeResult{}, ErrInvalidArgument
	}
	var result StoredEnrollment
	var replayed bool
	var stopped error
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		result, replayed, stopped = StoredEnrollment{}, false, nil
		stored, found, loadErr := transaction.FindByTerminationFingerprint(transactionContext, fingerprint)
		if loadErr != nil {
			return loadErr
		}
		if found {
			if !validTerminationReplay(stored, service.config.InstallationID, command.EnrollmentID, fingerprint, requestDigest, false) {
				return ErrIdempotencyConflict
			}
			result, replayed = stored, true
			return nil
		}
		stored, found, loadErr = transaction.LoadEnrollment(transactionContext, command.EnrollmentID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return ErrNotFound
		}
		stored, loadErr = service.expireIfDue(transactionContext, transaction, stored)
		if loadErr != nil {
			return loadErr
		}
		switch stored.Enrollment.State {
		case paasv1.NodeEnrollmentExpired:
			stopped = ErrExpired
			return nil
		case paasv1.NodeEnrollmentRevoked:
			stopped = ErrRevoked
			return nil
		case paasv1.NodeEnrollmentWaitingInstall, paasv1.NodeEnrollmentVerifying:
		default:
			return ErrInvalidTransition
		}
		if stored.Enrollment.Metadata.ResourceVersion != command.ExpectedResourceVersion {
			return ErrResourceVersion
		}
		now, loadErr := transaction.TransactionTime(transactionContext)
		if loadErr != nil || validateTime(now) != nil {
			return ErrUnavailable
		}
		next, loadErr := terminatedEnrollment(
			stored, service.config.InstallationID, now, "", fingerprint, requestDigest,
		)
		if loadErr != nil {
			return loadErr
		}
		if loadErr = transaction.RevokeEnrollment(transactionContext, stored, next); loadErr != nil {
			return loadErr
		}
		result = next
		return nil
	})
	if err != nil {
		return RevokeResult{}, err
	}
	if stopped != nil {
		return RevokeResult{}, stopped
	}
	return RevokeResult{Enrollment: enrollmentSnapshot(result.Enrollment), Replayed: replayed}, nil
}

func (service *Service) Regenerate(ctx context.Context, command RegenerateCommand) (CreateResult, error) {
	if err := service.authorize(ctx, command.Authorization); err != nil {
		return CreateResult{}, err
	}
	if !validEnrollmentID(command.EnrollmentID) ||
		command.ExpectedResourceVersion == 0 || command.ExpectedResourceVersion > maximumResourceVersion ||
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.IdempotencyKey, 128, true) != nil ||
		paasv1.ValidateRegenerateNodeEnrollmentRequest(command.Request) != nil ||
		ValidateControlPlaneBaseURL(command.ControlPlaneBaseURL) != nil {
		return CreateResult{}, ErrInvalidArgument
	}
	fingerprint, requestDigest, err := terminationIdentity(
		command.Authorization,
		"NODE_ENROLLMENT_REGENERATE",
		command.IdempotencyKey,
		struct {
			EnrollmentID            paasv1.ResourceID                      `json:"enrollmentId"`
			ExpectedResourceVersion uint64                                 `json:"expectedResourceVersion"`
			Request                 paasv1.RegenerateNodeEnrollmentRequest `json:"request"`
			ControlPlaneBaseURL     string                                 `json:"controlPlaneBaseUrl"`
		}{command.EnrollmentID, command.ExpectedResourceVersion, command.Request, command.ControlPlaneBaseURL},
	)
	if err != nil {
		return CreateResult{}, ErrInvalidArgument
	}
	replacementID, targetID := identities(fingerprint)
	var inspection regenerationInspection
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var inspectErr error
		inspection, inspectErr = service.inspectRegeneration(
			transactionContext,
			transaction,
			command,
			fingerprint,
			requestDigest,
			replacementID,
		)
		return inspectErr
	})
	if err != nil {
		return CreateResult{}, err
	}
	if inspection.stopped != nil {
		return CreateResult{}, inspection.stopped
	}
	if inspection.replayed {
		return createReplayResult(inspection.replacement)
	}
	expiresAt := inspection.now.Add(service.config.Lifetime)
	issued, err := service.issuer.Issue(ctx, JoinIssueRequest{
		EnrollmentID: replacementID, ExecutionTargetID: targetID,
		ExpiresAt: expiresAt, WrappingPublicKey: command.Request.WrappingPublicKey,
		ControlPlaneBaseURL: command.ControlPlaneBaseURL,
	})
	if err != nil {
		if ctx.Err() != nil {
			return CreateResult{}, ctx.Err()
		}
		return CreateResult{}, ErrUnavailable
	}
	defer issued.Clear()
	var replacement StoredEnrollment
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		var inspectErr error
		inspection, inspectErr = service.inspectRegeneration(
			transactionContext,
			transaction,
			command,
			fingerprint,
			requestDigest,
			replacementID,
		)
		if inspectErr != nil || inspection.replayed || inspection.stopped != nil {
			return inspectErr
		}
		if !inspection.now.Before(expiresAt) {
			return ErrUnavailable
		}
		createRequest := paasv1.CreateNodeEnrollmentRequest{
			Name:              inspection.source.Enrollment.Metadata.Name,
			Labels:            maps.Clone(inspection.source.Enrollment.Metadata.Labels),
			ExecutionPoolID:   inspection.source.Enrollment.ExecutionPoolID,
			WrappingPublicKey: command.Request.WrappingPublicKey,
		}
		replacement, inspectErr = service.newStoredEnrollment(
			command.Authorization,
			createRequest,
			fingerprint,
			requestDigest,
			replacementID,
			targetID,
			expiresAt,
			inspection.now,
			issued,
		)
		if inspectErr != nil {
			return inspectErr
		}
		terminated, inspectErr := terminatedEnrollment(
			inspection.source,
			service.config.InstallationID,
			inspection.now,
			replacementID,
			fingerprint,
			requestDigest,
		)
		if inspectErr != nil {
			return inspectErr
		}
		return transaction.ReplaceEnrollment(
			transactionContext,
			inspection.source,
			terminated,
			replacement,
		)
	})
	if err != nil {
		return CreateResult{}, err
	}
	if inspection.stopped != nil {
		return CreateResult{}, inspection.stopped
	}
	if inspection.replayed {
		return createReplayResult(inspection.replacement)
	}
	return createResult(replacement, false)
}

type regenerationInspection struct {
	source      StoredEnrollment
	replacement StoredEnrollment
	now         time.Time
	replayed    bool
	stopped     error
}

func (service *Service) inspectRegeneration(
	ctx context.Context,
	transaction Transaction,
	command RegenerateCommand,
	fingerprint string,
	requestDigest string,
	replacementID paasv1.ResourceID,
) (regenerationInspection, error) {
	stored, found, err := transaction.FindByTerminationFingerprint(ctx, fingerprint)
	if err != nil {
		return regenerationInspection{}, err
	}
	if found {
		if !validTerminationReplay(stored, service.config.InstallationID, command.EnrollmentID, fingerprint, requestDigest, true) ||
			stored.Enrollment.ReplacedByID != replacementID {
			return regenerationInspection{}, ErrIdempotencyConflict
		}
		replacement, found, err := transaction.LoadEnrollment(ctx, replacementID)
		if err != nil {
			return regenerationInspection{}, err
		}
		if !found || ValidateStoredEnrollment(replacement, service.config.InstallationID) != nil ||
			replacement.Operation.IdempotencyFingerprint != fingerprint ||
			replacement.Operation.RequestDigest != requestDigest {
			return regenerationInspection{}, ErrConflict
		}
		replacement, err = service.expireIfDue(ctx, transaction, replacement)
		return regenerationInspection{
			source: stored, replacement: replacement, replayed: true,
		}, err
	}
	stored, found, err = transaction.LoadEnrollment(ctx, command.EnrollmentID)
	if err != nil {
		return regenerationInspection{}, err
	}
	if !found {
		return regenerationInspection{}, ErrNotFound
	}
	stored, err = service.expireIfDue(ctx, transaction, stored)
	if err != nil {
		return regenerationInspection{}, err
	}
	inspection := regenerationInspection{source: stored}
	switch stored.Enrollment.State {
	case paasv1.NodeEnrollmentExpired:
		inspection.stopped = ErrExpired
		return inspection, nil
	case paasv1.NodeEnrollmentRevoked:
		inspection.stopped = ErrRevoked
		return inspection, nil
	case paasv1.NodeEnrollmentWaitingInstall, paasv1.NodeEnrollmentVerifying:
	default:
		return regenerationInspection{}, ErrInvalidTransition
	}
	if stored.Enrollment.Metadata.ResourceVersion != command.ExpectedResourceVersion {
		return regenerationInspection{}, ErrResourceVersion
	}
	pool, found, err := transaction.LoadExecutionPool(ctx, stored.Enrollment.ExecutionPoolID)
	if err != nil {
		return regenerationInspection{}, err
	}
	if !found {
		return regenerationInspection{}, ErrNotFound
	}
	if paasv1.ValidateExecutionPool(pool) != nil || pool.Metadata.ID != stored.Enrollment.ExecutionPoolID {
		return regenerationInspection{}, ErrConflict
	}
	inspection.now, err = transaction.TransactionTime(ctx)
	if err != nil || validateTime(inspection.now) != nil {
		return regenerationInspection{}, ErrUnavailable
	}
	return inspection, nil
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
	if ValidateStoredEnrollment(stored, service.config.InstallationID) != nil ||
		stored.Operation.RequestDigest != requestDigest || stored.Enrollment.Metadata.ID != enrollmentID {
		return StoredEnrollment{}, false, ErrIdempotencyConflict
	}
	stored, err = service.expireIfDue(ctx, transaction, stored)
	if err != nil {
		return StoredEnrollment{}, false, err
	}
	return stored, true, nil
}

func (service *Service) expireIfDue(ctx context.Context, transaction Transaction, stored StoredEnrollment) (StoredEnrollment, error) {
	if ValidateStoredEnrollment(stored, service.config.InstallationID) != nil {
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
	if stored.Enrollment.Metadata.ResourceVersion == maximumResourceVersion {
		return StoredEnrollment{}, ErrConflict
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

func (service *Service) newStoredEnrollment(
	authorization port.Authorization,
	request paasv1.CreateNodeEnrollmentRequest,
	fingerprint string,
	requestDigest string,
	enrollmentID paasv1.ResourceID,
	targetID paasv1.ResourceID,
	expiresAt time.Time,
	now time.Time,
	issued IssuedJoin,
) (StoredEnrollment, error) {
	enrollment := paasv1.NodeEnrollment{
		APIVersion: paasv1.APIVersion, Kind: "NodeEnrollment",
		Metadata: paasv1.ResourceMetadata{
			ID: enrollmentID, Name: request.Name,
			Scope:  paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			Labels: maps.Clone(request.Labels), ResourceVersion: 1,
			CreatedAt: now, UpdatedAt: now,
		},
		ExecutionTargetID: targetID, ExecutionPoolID: request.ExecutionPoolID,
		OperationID: paasv1.OperationID("operation-" + fingerprint[7:]),
		State:       paasv1.NodeEnrollmentWaitingInstall, ExpiresAt: expiresAt,
	}
	operation := paasv1.Operation{
		APIVersion: paasv1.APIVersion, Kind: "Operation", ID: enrollment.OperationID,
		Scope:                  paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
		InstallationID:         service.config.InstallationID,
		Action:                 paasv1.OperationRegisterExecutionTarget,
		Target:                 paasv1.ResourceRef{Kind: "ExecutionTarget", ID: targetID},
		RequestedBy:            authorization.Subject,
		IdempotencyFingerprint: fingerprint, RequestDigest: requestDigest,
		State: paasv1.OperationAccepted, Attempt: 1, CreatedAt: now, UpdatedAt: now,
	}
	stored := StoredEnrollment{
		Enrollment: enrollment, Operation: operation, Join: issued.Join,
		WrappedCredential:   issued.WrappedCredential,
		CredentialSalt:      bytes.Clone(issued.CredentialSalt),
		CredentialVerifier:  issued.CredentialVerifier,
		CreateAuthorization: authorization,
	}
	if paasv1.ValidateCreateNodeEnrollmentRequest(request) != nil ||
		ValidateStoredEnrollment(stored, service.config.InstallationID) != nil {
		stored.Clear()
		return StoredEnrollment{}, ErrUnavailable
	}
	return stored, nil
}

func terminatedEnrollment(
	stored StoredEnrollment,
	installationID string,
	now time.Time,
	replacementID paasv1.ResourceID,
	fingerprint string,
	requestDigest string,
) (StoredEnrollment, error) {
	if ValidateStoredEnrollment(stored, installationID) != nil ||
		validateTime(now) != nil || stored.Enrollment.Metadata.ResourceVersion == maximumResourceVersion ||
		paasv1.ValidateDigest("terminationFingerprint", fingerprint) != nil ||
		paasv1.ValidateDigest("terminationRequestDigest", requestDigest) != nil {
		return StoredEnrollment{}, ErrConflict
	}
	next := stored
	next.Enrollment = enrollmentSnapshot(stored.Enrollment)
	next.CredentialSalt = bytes.Clone(stored.CredentialSalt)
	next.Enrollment.State = paasv1.NodeEnrollmentRevoked
	next.Enrollment.Metadata.ResourceVersion++
	next.Enrollment.Metadata.UpdatedAt = now
	next.Enrollment.ReplacedByID = replacementID
	next.Enrollment.Diagnostic = &paasv1.NodeEnrollmentDiagnostic{
		Code: paasv1.NodeEnrollmentDiagnosticRevoked, OccurredAt: now,
	}
	next.Operation.State = paasv1.OperationCancelled
	next.Operation.UpdatedAt = now
	next.Operation.TerminalAt = &now
	next.TerminationFingerprint = fingerprint
	next.TerminationRequestDigest = requestDigest
	if ValidateStoredEnrollment(next, installationID) != nil {
		next.Clear()
		return StoredEnrollment{}, ErrConflict
	}
	return next, nil
}

func createReplayResult(stored StoredEnrollment) (CreateResult, error) {
	switch stored.Enrollment.State {
	case paasv1.NodeEnrollmentWaitingInstall:
		return createResult(stored, true)
	case paasv1.NodeEnrollmentVerifying:
		return CreateResult{}, ErrCredentialConsumed
	case paasv1.NodeEnrollmentExpired:
		return CreateResult{}, ErrExpired
	case paasv1.NodeEnrollmentRevoked:
		return CreateResult{}, ErrRevoked
	default:
		return CreateResult{}, ErrConflict
	}
}

func validTerminationReplay(
	stored StoredEnrollment,
	installationID string,
	enrollmentID paasv1.ResourceID,
	fingerprint string,
	requestDigest string,
	replacement bool,
) bool {
	if ValidateStoredEnrollment(stored, installationID) != nil ||
		stored.Enrollment.Metadata.ID != enrollmentID ||
		stored.Enrollment.State != paasv1.NodeEnrollmentRevoked ||
		stored.TerminationFingerprint != fingerprint ||
		stored.TerminationRequestDigest != requestDigest {
		return false
	}
	return replacement == (stored.Enrollment.ReplacedByID != "")
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
		Kind                string                             `json:"kind"`
		Request             paasv1.CreateNodeEnrollmentRequest `json:"request"`
		ControlPlaneBaseURL string                             `json:"controlPlaneBaseUrl"`
	}{"CreateNodeEnrollment", command.Request, command.ControlPlaneBaseURL})
	if err != nil {
		return "", "", err
	}
	return domain.DigestPayload(identity), domain.DigestPayload(payload), nil
}

func terminationIdentity(
	authorization port.Authorization,
	purpose string,
	idempotencyKey string,
	payload any,
) (string, string, error) {
	identity, err := json.Marshal(struct {
		InstallationID string            `json:"installationId"`
		Subject        paasv1.SubjectRef `json:"subject"`
		Purpose        string            `json:"purpose"`
		Key            string            `json:"key"`
	}{authorization.InstallationID, authorization.Subject, purpose, idempotencyKey})
	if err != nil {
		return "", "", err
	}
	request, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	return domain.DigestPayload(identity), domain.DigestPayload(request), nil
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

func ValidateStoredEnrollment(value StoredEnrollment, installationID string) error {
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
	if value.Enrollment.State == paasv1.NodeEnrollmentRevoked {
		if paasv1.ValidateDigest("terminationFingerprint", value.TerminationFingerprint) != nil ||
			paasv1.ValidateDigest("terminationRequestDigest", value.TerminationRequestDigest) != nil {
			problems = append(problems, errors.New("revoked node enrollment lacks its termination identity"))
		}
	} else if value.TerminationFingerprint != "" || value.TerminationRequestDigest != "" {
		problems = append(problems, errors.New("active node enrollment contains a termination identity"))
	}
	expectedOperationState := map[paasv1.NodeEnrollmentState]paasv1.OperationState{
		paasv1.NodeEnrollmentWaitingInstall: paasv1.OperationAccepted,
		paasv1.NodeEnrollmentVerifying:      paasv1.OperationVerifying,
		paasv1.NodeEnrollmentReady:          paasv1.OperationSucceeded,
		paasv1.NodeEnrollmentFailed:         paasv1.OperationFailed,
		paasv1.NodeEnrollmentExpired:        paasv1.OperationCancelled,
		paasv1.NodeEnrollmentRevoked:        paasv1.OperationCancelled,
	}[value.Enrollment.State]
	if expectedOperationState == "" || value.Operation.State != expectedOperationState {
		problems = append(problems, errors.New("node enrollment and operation states are inconsistent"))
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
