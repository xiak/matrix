package nodeenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

const maximumResourceVersion = uint64(9007199254740991)

const certificateClockSkew = 5 * time.Minute

func New(repository Repository, issuer EnrollmentIssuer, config Config) (*Service, error) {
	if repository == nil || issuer == nil || paasv1.ValidateID("installationId", config.InstallationID) != nil ||
		config.Lifetime < time.Minute || config.Lifetime > paasv1.MaximumNodeEnrollmentLifetime ||
		config.CertificateLifetime < time.Hour || config.CertificateLifetime > paasv1.MaximumNodeEnrollmentCertificateLifetime ||
		paasv1.ValidateDigest("supportedRuntimeContractDigest", config.SupportedRuntimeContractDigest) != nil ||
		paasv1.ValidateID("controllerId", config.ControllerID) != nil ||
		config.ManagementPort < paasv1.MinimumNodeEnrollmentListenerPort ||
		config.CollectorPort < paasv1.MinimumNodeEnrollmentListenerPort ||
		config.ManagementPort == config.CollectorPort ||
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
	issued, err := service.issuer.IssueJoin(ctx, JoinIssueRequest{
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

func (service *Service) Exchange(ctx context.Context, command ExchangeCommand) (ExchangeResult, error) {
	if service == nil || service.repository == nil || service.issuer == nil || ctx == nil {
		return ExchangeResult{}, ErrUnavailable
	}
	if !validEnrollmentID(command.EnrollmentID) || command.EnrollmentID != command.Request.EnrollmentID ||
		paasv1.ValidateExchangeNodeEnrollmentRequest(command.Request) != nil {
		return ExchangeResult{}, ErrInvalidArgument
	}
	observedPeer, err := normalizeObservedPeer(command.ObservedPeerAddress)
	if err != nil {
		return ExchangeResult{}, ErrInvalidArgument
	}
	credential, err := decodeExchangeCredential(command.Request.Credential)
	if err != nil {
		return ExchangeResult{}, ErrInvalidArgument
	}
	defer clear(credential)
	nodePublicKey, collectorPublicKey, err := paasv1.NodeEnrollmentExchangePublicKeys(command.Request)
	if err != nil {
		return ExchangeResult{}, ErrInvalidArgument
	}
	defer clear(nodePublicKey)
	defer clear(collectorPublicKey)

	var inspection exchangeInspection
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		inspection.stored.Clear()
		var inspectErr error
		inspection, inspectErr = service.inspectExchange(
			transactionContext, transaction, command, credential,
		)
		return inspectErr
	})
	if err != nil {
		return ExchangeResult{}, err
	}
	defer inspection.stored.Clear()
	if inspection.stopped != nil {
		return ExchangeResult{}, inspection.stopped
	}

	bindingRef := exchangeBindingRef(command.Request)
	notBefore := inspection.now.Truncate(time.Second).Add(-certificateClockSkew)
	notAfter := notBefore.Add(service.config.CertificateLifetime)
	issued, err := service.issuer.IssueExchange(ctx, ExchangeIssueRequest{
		EnrollmentID: command.Request.EnrollmentID, InstallationID: command.Request.InstallationID,
		ExecutionTargetID: command.Request.ExecutionTargetID, ExchangeID: command.Request.ExchangeID,
		MachineFingerprint:    command.Request.MachineFingerprint,
		RuntimeContractDigest: command.Request.RuntimeContractDigest,
		Listener:              command.Request.Listener, NodePublicKey: nodePublicKey,
		CollectorPublicKey: collectorPublicKey, ObservedPeerAddress: observedPeer,
		BindingRef: bindingRef, ControllerID: service.config.ControllerID,
		CertificateNotBefore: notBefore, CertificateNotAfter: notAfter,
	})
	if err != nil {
		if ctx.Err() != nil {
			return ExchangeResult{}, ctx.Err()
		}
		return ExchangeResult{}, ErrUnavailable
	}
	if paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(issued.Response, command.Request) != nil ||
		ValidateSealedExchangeResult(issued.Sealed) != nil ||
		issued.Response.BindingRef != bindingRef || issued.Response.ControllerID != service.config.ControllerID ||
		issued.Response.NodeListenAddress != net.JoinHostPort(observedPeer, strconv.Itoa(int(service.config.ManagementPort))) {
		return ExchangeResult{}, ErrUnavailable
	}

	var enrollment paasv1.NodeEnrollment
	var stopped error
	err = service.transaction(ctx, func(transactionContext context.Context, transaction Transaction) error {
		current, inspectErr := service.inspectExchange(
			transactionContext, transaction, command, credential,
		)
		if inspectErr != nil {
			return inspectErr
		}
		stopped = current.stopped
		if stopped != nil {
			return nil
		}
		defer current.stored.Clear()
		storedExchange, consumeErr := newStoredExchange(
			command.Request, issued.Response, nodePublicKey, collectorPublicKey, current.now,
		)
		if consumeErr != nil {
			return consumeErr
		}
		next, consumeErr := consumedEnrollment(
			current.stored, service.config.InstallationID, storedExchange, issued.Sealed, current.now,
		)
		if consumeErr != nil {
			return consumeErr
		}
		if consumeErr = transaction.ExchangeEnrollment(transactionContext, current.stored, next); consumeErr != nil {
			return consumeErr
		}
		enrollment = enrollmentSnapshot(next.Enrollment)
		return nil
	})
	if err != nil {
		return ExchangeResult{}, err
	}
	if stopped != nil {
		return ExchangeResult{}, stopped
	}
	result := ExchangeResult{Enrollment: enrollment, Response: issued.Response}
	if paasv1.ValidateNodeEnrollment(result.Enrollment) != nil ||
		paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(result.Response, command.Request) != nil ||
		result.Enrollment.State != paasv1.NodeEnrollmentVerifying {
		return ExchangeResult{}, ErrUnavailable
	}
	return result, nil
}

type exchangeInspection struct {
	stored  StoredEnrollment
	now     time.Time
	stopped error
}

func (service *Service) inspectExchange(
	ctx context.Context,
	transaction Transaction,
	command ExchangeCommand,
	credential []byte,
) (exchangeInspection, error) {
	stored, found, err := transaction.LoadEnrollment(ctx, command.EnrollmentID)
	if err != nil {
		return exchangeInspection{}, err
	}
	if !found {
		return exchangeInspection{}, ErrNotFound
	}
	stored, err = service.expireIfDue(ctx, transaction, stored)
	if err != nil {
		stored.Clear()
		return exchangeInspection{}, err
	}
	inspection := exchangeInspection{stored: stored}
	switch stored.Enrollment.State {
	case paasv1.NodeEnrollmentWaitingInstall:
	case paasv1.NodeEnrollmentExpired:
		inspection.stopped = ErrExpired
		return inspection, nil
	case paasv1.NodeEnrollmentRevoked:
		inspection.stopped = ErrRevoked
		return inspection, nil
	default:
		if stored.Enrollment.CredentialConsumedAt != nil {
			inspection.stopped = ErrCredentialConsumed
			return inspection, nil
		}
		stored.Clear()
		return exchangeInspection{}, ErrInvalidTransition
	}
	request := command.Request
	if request.InstallationID != service.config.InstallationID ||
		request.EnrollmentID != stored.Enrollment.Metadata.ID ||
		request.ExecutionTargetID != stored.Enrollment.ExecutionTargetID {
		stored.Clear()
		return exchangeInspection{}, ErrConflict
	}
	if !exchangeCredentialMatches(stored, credential) {
		stored.Clear()
		return exchangeInspection{}, ErrCredentialRejected
	}
	if request.RuntimeContractDigest != service.config.SupportedRuntimeContractDigest {
		stored.Clear()
		return exchangeInspection{}, ErrRuntimeUnsupported
	}
	if request.Listener.ManagementPort != service.config.ManagementPort ||
		request.Listener.CollectorPort != service.config.CollectorPort {
		stored.Clear()
		return exchangeInspection{}, ErrInvalidArgument
	}
	inspection.now, err = transaction.TransactionTime(ctx)
	if err != nil || validateTime(inspection.now) != nil || !inspection.now.Before(stored.Enrollment.ExpiresAt) {
		stored.Clear()
		return exchangeInspection{}, ErrUnavailable
	}
	return inspection, nil
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
	issued, err := service.issuer.IssueJoin(ctx, JoinIssueRequest{
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
	clear(stored.CredentialSalt)
	stored.CredentialSalt = nil
	stored.CredentialVerifier = ""
	stored.WrappedCredential = paasv1.WrappedJoinCredential{}
	stored.SealedExchangeResult = nil
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
	next.CredentialSalt = nil
	next.CredentialVerifier = ""
	next.WrappedCredential = paasv1.WrappedJoinCredential{}
	next.SealedExchangeResult = nil
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

func exchangeBindingRef(request paasv1.ExchangeNodeEnrollmentRequest) string {
	digest := domain.DigestPayload([]byte(
		"matrix-node-binding/v1\x00" + request.InstallationID + "\x00" +
			string(request.ExecutionTargetID) + "\x00" + request.ExchangeID,
	))
	return "node-binding-" + strings.TrimPrefix(digest, "sha256:")[:32]
}

func decodeExchangeCredential(value string) ([]byte, error) {
	if value == "" || strings.ContainsAny(value, "=\r\n\t ") {
		return nil, ErrInvalidArgument
	}
	credential, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(credential) != 32 || base64.RawURLEncoding.EncodeToString(credential) != value {
		clear(credential)
		return nil, ErrInvalidArgument
	}
	return credential, nil
}

func exchangeCredentialMatches(stored StoredEnrollment, credential []byte) bool {
	if len(credential) != 32 || len(stored.CredentialSalt) != 32 ||
		paasv1.ValidateDigest("credentialDigest", stored.Join.CredentialDigest) != nil ||
		paasv1.ValidateDigest("credentialVerifier", stored.CredentialVerifier) != nil {
		return false
	}
	joinDigest := domain.DigestPayload(credential)
	verifierInput := make([]byte, 0, len(stored.CredentialSalt)+len(credential))
	verifierInput = append(verifierInput, stored.CredentialSalt...)
	verifierInput = append(verifierInput, credential...)
	verifier := domain.DigestPayload(verifierInput)
	clear(verifierInput)
	return subtle.ConstantTimeCompare([]byte(joinDigest), []byte(stored.Join.CredentialDigest)) == 1 &&
		subtle.ConstantTimeCompare([]byte(verifier), []byte(stored.CredentialVerifier)) == 1
}

func normalizeObservedPeer(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4In6() || !address.IsPrivate() || address.IsLoopback() ||
		address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.String() != value {
		return "", ErrInvalidArgument
	}
	return address.String(), nil
}

func newStoredExchange(
	request paasv1.ExchangeNodeEnrollmentRequest,
	response paasv1.NodeEnrollmentExchangeResponse,
	nodePublicKey []byte,
	collectorPublicKey []byte,
	consumedAt time.Time,
) (StoredExchange, error) {
	if paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(response, request) != nil ||
		validateTime(consumedAt) != nil || len(nodePublicKey) == 0 || len(collectorPublicKey) == 0 {
		return StoredExchange{}, ErrConflict
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return StoredExchange{}, ErrUnavailable
	}
	exchange := StoredExchange{
		APIVersion: StoredExchangeAPIVersion, Kind: StoredExchangeKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: response.ControllerID, BindingRef: response.BindingRef,
		NodeListenAddress: response.NodeListenAddress, CollectorEndpoint: response.CollectorEndpoint,
		NodePublicKey:                 base64.RawURLEncoding.EncodeToString(nodePublicKey),
		NodePublicKeyFingerprint:      domain.DigestPayload(nodePublicKey),
		CollectorPublicKey:            base64.RawURLEncoding.EncodeToString(collectorPublicKey),
		CollectorPublicKeyFingerprint: domain.DigestPayload(collectorPublicKey),
		ResultDigest:                  domain.DigestPayload(encoded), ConsumedAt: consumedAt,
	}
	clear(encoded)
	if ValidateStoredExchange(exchange) != nil {
		return StoredExchange{}, ErrConflict
	}
	return exchange, nil
}

func consumedEnrollment(
	stored StoredEnrollment,
	installationID string,
	exchange StoredExchange,
	sealed SealedExchangeResult,
	now time.Time,
) (StoredEnrollment, error) {
	if ValidateStoredEnrollment(stored, installationID) != nil ||
		stored.Enrollment.State != paasv1.NodeEnrollmentWaitingInstall ||
		stored.Enrollment.Metadata.ResourceVersion == maximumResourceVersion ||
		ValidateStoredExchange(exchange) != nil || ValidateSealedExchangeResult(sealed) != nil ||
		exchange.EnrollmentID != stored.Enrollment.Metadata.ID ||
		exchange.ExecutionTargetID != stored.Enrollment.ExecutionTargetID ||
		exchange.InstallationID != installationID || !exchange.ConsumedAt.Equal(now) ||
		validateTime(now) != nil || !now.Before(stored.Enrollment.ExpiresAt) {
		return StoredEnrollment{}, ErrConflict
	}
	next := stored
	next.Enrollment = enrollmentSnapshot(stored.Enrollment)
	next.Enrollment.State = paasv1.NodeEnrollmentVerifying
	next.Enrollment.Metadata.ResourceVersion++
	next.Enrollment.Metadata.UpdatedAt = now
	next.Enrollment.CredentialConsumedAt = &now
	next.Operation.State = paasv1.OperationVerifying
	next.Operation.UpdatedAt = now
	next.CredentialSalt = nil
	next.CredentialVerifier = ""
	next.WrappedCredential = paasv1.WrappedJoinCredential{}
	exchangeCopy := exchange
	sealedCopy := sealed
	next.Exchange = &exchangeCopy
	next.SealedExchangeResult = &sealedCopy
	if ValidateStoredEnrollment(next, installationID) != nil {
		next.Clear()
		return StoredEnrollment{}, ErrConflict
	}
	return next, nil
}

func ValidateStoredExchange(value StoredExchange) error {
	var problems []error
	if value.APIVersion != StoredExchangeAPIVersion || value.Kind != StoredExchangeKind ||
		!validPrefixedHexID(value.EnrollmentID, "node-enrollment-") ||
		!validPrefixedHexText(value.ExchangeID, "node-exchange-") ||
		!validPrefixedHexText(value.BindingRef, "node-binding-") {
		problems = append(problems, errors.New("stored node exchange metadata is invalid"))
	}
	problems = append(problems,
		paasv1.ValidateID("installationId", value.InstallationID),
		paasv1.ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		paasv1.ValidateID("controllerId", value.ControllerID),
		paasv1.ValidateDigest("machineFingerprint", value.MachineFingerprint),
		paasv1.ValidateDigest("runtimeContractDigest", value.RuntimeContractDigest),
		paasv1.ValidateDigest("nodePublicKeyFingerprint", value.NodePublicKeyFingerprint),
		paasv1.ValidateDigest("collectorPublicKeyFingerprint", value.CollectorPublicKeyFingerprint),
		paasv1.ValidateDigest("resultDigest", value.ResultDigest),
		validateTime(value.ConsumedAt),
	)
	nodeKey, nodeErr := decodeStoredExchangePublicKey(value.NodePublicKey, value.NodePublicKeyFingerprint)
	collectorKey, collectorErr := decodeStoredExchangePublicKey(value.CollectorPublicKey, value.CollectorPublicKeyFingerprint)
	problems = append(problems, nodeErr, collectorErr)
	if nodeErr == nil && collectorErr == nil && bytes.Equal(nodeKey, collectorKey) {
		problems = append(problems, errors.New("stored node exchange public keys are not distinct"))
	}
	_, nodePort, nodeAddressErr := parseStoredNodeAddress(value.NodeListenAddress)
	_, collectorPort, collectorAddressErr := parseStoredCollectorEndpoint(value.CollectorEndpoint)
	problems = append(problems, nodeAddressErr, collectorAddressErr)
	if nodeAddressErr == nil && collectorAddressErr == nil && nodePort == collectorPort {
		problems = append(problems, errors.New("stored node exchange listener ports are not distinct"))
	}
	return errors.Join(problems...)
}

func ValidateSealedExchangeResult(value SealedExchangeResult) error {
	if value.Algorithm != ExchangeResultSealAlgorithm ||
		paasv1.ValidateDigest("exchangeResult.keyId", value.KeyID) != nil ||
		validateCanonicalBase64(value.Nonce, 12, 12) != nil ||
		validateCanonicalBase64(value.Ciphertext, 32, 64*1024) != nil {
		return errors.New("sealed node exchange result is invalid")
	}
	return nil
}

func decodeStoredExchangePublicKey(value, fingerprint string) ([]byte, error) {
	if validateCanonicalBase64(value, 32, 1024) != nil {
		return nil, errors.New("stored node exchange public key is invalid")
	}
	encoded, _ := base64.RawURLEncoding.Strict().DecodeString(value)
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	ed25519Key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(ed25519Key) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare([]byte(domain.DigestPayload(encoded)), []byte(fingerprint)) != 1 {
		clear(encoded)
		return nil, errors.New("stored node exchange public key is invalid")
	}
	return encoded, nil
}

func validateCanonicalBase64(value string, minimumBytes, maximumBytes int) error {
	if value == "" || strings.ContainsAny(value, "=\r\n\t ") {
		return errors.New("base64url value is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	valid := err == nil && len(decoded) >= minimumBytes && len(decoded) <= maximumBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
	clear(decoded)
	if !valid {
		return errors.New("base64url value is invalid")
	}
	return nil
}

func parseStoredNodeAddress(value string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(value)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	address, addressErr := netip.ParseAddr(host)
	if err != nil || portErr != nil || addressErr != nil || port < paasv1.MinimumNodeEnrollmentListenerPort ||
		address.Is4In6() || !address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsLinkLocalUnicast() ||
		net.JoinHostPort(address.String(), strconv.FormatUint(port, 10)) != value {
		return netip.Addr{}, 0, errors.New("stored node exchange management address is invalid")
	}
	return address, uint16(port), nil
}

func parseStoredCollectorEndpoint(value string) (netip.Addr, uint16, error) {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return netip.Addr{}, 0, errors.New("stored node exchange collector endpoint is invalid")
	}
	host, portText, splitErr := net.SplitHostPort(endpoint.Host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	address, addressErr := netip.ParseAddr(host)
	if splitErr != nil || portErr != nil || addressErr != nil || port < paasv1.MinimumNodeEnrollmentListenerPort ||
		address.Is4In6() || !address.IsLoopback() ||
		"https://"+net.JoinHostPort(address.String(), strconv.FormatUint(port, 10)) != value {
		return netip.Addr{}, 0, errors.New("stored node exchange collector endpoint is invalid")
	}
	return address, uint16(port), nil
}

func validPrefixedHexID(value paasv1.ResourceID, prefix string) bool {
	return validPrefixedHexText(string(value), prefix)
}

func validPrefixedHexText(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
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
		value.Operation.RequestedBy != value.CreateAuthorization.Subject {
		problems = append(problems, errors.New("stored node enrollment authority is inconsistent"))
	}
	if value.Enrollment.State == paasv1.NodeEnrollmentWaitingInstall {
		if paasv1.ValidateWrappedJoinCredential(value.WrappedCredential) != nil ||
			len(value.CredentialSalt) != 32 ||
			paasv1.ValidateDigest("credentialVerifier", value.CredentialVerifier) != nil ||
			value.CredentialVerifier == value.Join.CredentialDigest {
			problems = append(problems, errors.New("waiting node enrollment credential material is invalid"))
		}
	} else if value.WrappedCredential != (paasv1.WrappedJoinCredential{}) ||
		len(value.CredentialSalt) != 0 || value.CredentialVerifier != "" {
		problems = append(problems, errors.New("non-waiting node enrollment retains credential material"))
	}
	if value.Exchange != nil {
		if ValidateStoredExchange(*value.Exchange) != nil || value.Enrollment.CredentialConsumedAt == nil ||
			value.Exchange.EnrollmentID != value.Enrollment.Metadata.ID ||
			value.Exchange.InstallationID != installationID ||
			value.Exchange.ExecutionTargetID != value.Enrollment.ExecutionTargetID ||
			!value.Exchange.ConsumedAt.Equal(*value.Enrollment.CredentialConsumedAt) {
			problems = append(problems, errors.New("stored node enrollment exchange identity is inconsistent"))
		}
	} else if value.Enrollment.CredentialConsumedAt != nil {
		problems = append(problems, errors.New("consumed node enrollment lacks its exchange identity"))
	}
	if value.Enrollment.State == paasv1.NodeEnrollmentVerifying {
		if value.Exchange == nil || value.SealedExchangeResult == nil ||
			(value.SealedExchangeResult != nil && ValidateSealedExchangeResult(*value.SealedExchangeResult) != nil) {
			problems = append(problems, errors.New("verifying node enrollment lacks its sealed exchange result"))
		}
	} else if value.SealedExchangeResult != nil {
		problems = append(problems, errors.New("non-verifying node enrollment retains a sealed exchange result"))
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
