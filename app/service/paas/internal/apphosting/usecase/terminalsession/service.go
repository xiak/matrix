package terminalsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

type idempotencyIdentity struct {
	TenantID       paasv1.TenantID    `json:"tenantId"`
	SubjectType    paasv1.SubjectType `json:"subjectType"`
	SubjectID      string             `json:"subjectId"`
	DeploymentID   paasv1.ResourceID  `json:"deploymentId"`
	IdempotencyKey string             `json:"idempotencyKey"`
}

type requestIdentity struct {
	Kind         string              `json:"kind"`
	DeploymentID paasv1.ResourceID   `json:"deploymentId"`
	InstanceID   paasv1.ResourceID   `json:"instanceId"`
	Size         paasv1.TerminalSize `json:"size"`
}

func New(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("terminal session repository is required")
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("terminal transaction attempts must be between 1 and 10")
	}
	return &Service{repository: repository, config: config}, nil
}

func (service *Service) Create(ctx context.Context, command CreateCommand) (CreateResult, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return CreateResult{}, errors.New("terminal session service is unavailable")
	}
	if err := validateCreateCommand(command); err != nil {
		return CreateResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	fingerprint, err := digestDocument(idempotencyIdentity{
		TenantID:       command.Authorization.TenantID,
		SubjectType:    command.Authorization.Subject.Type,
		SubjectID:      command.Authorization.Subject.ID,
		DeploymentID:   command.DeploymentID,
		IdempotencyKey: command.IdempotencyKey,
	})
	if err != nil {
		return CreateResult{}, err
	}
	requestDigest, err := digestDocument(requestIdentity{
		Kind: "CREATE_TERMINAL_SESSION", DeploymentID: command.DeploymentID,
		InstanceID: command.Request.InstanceID, Size: command.Request.Size,
	})
	if err != nil {
		return CreateResult{}, err
	}
	var result CreateResult
	err = service.retryTenant(ctx, command.Authorization.TenantID, func(transactionContext context.Context, transaction Transaction) error {
		var transactionErr error
		result, transactionErr = createInTransaction(
			transactionContext, transaction, command, fingerprint, requestDigest,
		)
		return transactionErr
	})
	if err != nil {
		return CreateResult{}, err
	}
	return result, nil
}

func createInTransaction(
	ctx context.Context,
	transaction Transaction,
	command CreateCommand,
	fingerprint string,
	requestDigest string,
) (CreateResult, error) {
	now, err := transaction.TransactionTime(ctx)
	if err != nil {
		return CreateResult{}, err
	}
	stored, found, err := transaction.FindByFingerprint(ctx, fingerprint)
	if err != nil {
		return CreateResult{}, err
	}
	if found {
		if validateStoredSession(stored) != nil || stored.RequestDigest != requestDigest ||
			stored.Session.DeploymentID != command.DeploymentID ||
			stored.Session.InstanceID != command.Request.InstanceID ||
			stored.Session.Size != command.Request.Size ||
			stored.Subject != command.Authorization.Subject {
			return CreateResult{}, ErrIdempotencyConflict
		}
		if stored.Session.State != paasv1.TerminalSessionPending {
			return CreateResult{}, ErrConflict
		}
		if !now.Before(stored.Session.ConnectBefore) || !now.Before(stored.Session.ExpiresAt) {
			return CreateResult{}, ErrExpired
		}
		if err := transaction.RotateTicket(ctx, stored.Session.ID, command.TicketDigest); err != nil {
			return CreateResult{}, err
		}
		return CreateResult{Stored: stored, Replayed: true}, nil
	}
	binding, found, err := transaction.LoadAndLockCurrentRuntime(
		ctx, command.DeploymentID, command.Request.InstanceID, now,
	)
	if err != nil {
		return CreateResult{}, err
	}
	if !found {
		return CreateResult{}, ErrNotFound
	}
	if validateRuntimeBinding(binding) != nil || binding.DeploymentID != command.DeploymentID ||
		binding.InstanceID != command.Request.InstanceID {
		return CreateResult{}, ErrConflict
	}
	var replacedID paasv1.ResourceID
	previous, open, err := transaction.LoadAndLockOpenForSubjectInstance(
		ctx, command.Authorization.Subject, command.DeploymentID, command.Request.InstanceID,
	)
	if err != nil {
		return CreateResult{}, err
	}
	if open {
		ended := endedSession(previous.Session, paasv1.TerminalSessionReplaced, now)
		if err := transaction.Transition(ctx, previous, ended, lifecycleEvent(previous, audit.TerminalSessionEnded, audit.Replaced, now)); err != nil {
			return CreateResult{}, err
		}
		replacedID = previous.Session.ID
	}
	session := paasv1.TerminalSession{
		APIVersion: paasv1.APIVersion, Kind: "TerminalSession",
		ID:           terminalSessionID(fingerprint),
		Scope:        paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: command.Authorization.TenantID},
		DeploymentID: binding.DeploymentID, Generation: binding.Generation,
		ApplicationRevisionID: binding.ApplicationRevisionID,
		InstanceID:            binding.InstanceID, Size: command.Request.Size,
		State: paasv1.TerminalSessionPending, CreatedAt: now,
		ConnectBefore: now.Add(paasv1.TerminalSessionConnectTimeout),
		ExpiresAt:     now.Add(paasv1.MaximumTerminalSessionDuration),
	}
	stored = StoredSession{
		Session: session, Binding: binding, Subject: command.Authorization.Subject,
		IAMDecisionID: command.Authorization.DecisionID, RequestID: command.Authorization.RequestID,
		AuditID: command.Authorization.AuditID, TraceParent: command.Authorization.TraceParent,
		IdempotencyFingerprint: fingerprint, RequestDigest: requestDigest,
	}
	if err := validateStoredSession(stored); err != nil {
		return CreateResult{}, err
	}
	if err := transaction.Insert(ctx, stored, command.TicketDigest, lifecycleEvent(stored, audit.TerminalSessionCreated, audit.Accepted, now)); err != nil {
		return CreateResult{}, err
	}
	return CreateResult{Stored: stored, ReplacedID: replacedID}, nil
}

func (service *Service) Consume(ctx context.Context, id paasv1.ResourceID, ticketDigest string) (StoredSession, error) {
	if service == nil || service.repository == nil || ctx == nil ||
		paasv1.ValidateTerminalSessionID(id) != nil || paasv1.ValidateDigest("ticketDigest", ticketDigest) != nil {
		return StoredSession{}, ErrInvalidArgument
	}
	var result StoredSession
	expired := false
	err := service.retryTicket(ctx, id, ticketDigest, func(transactionContext context.Context, transaction Transaction, stored StoredSession) error {
		result, expired = StoredSession{}, false
		if validateStoredSession(stored) != nil || stored.Session.ID != id {
			return ErrConflict
		}
		now, err := transaction.TransactionTime(transactionContext)
		if err != nil {
			return err
		}
		if stored.Session.State != paasv1.TerminalSessionPending {
			return ErrConflict
		}
		if !now.Before(stored.Session.ConnectBefore) || !now.Before(stored.Session.ExpiresAt) {
			ended := endedSession(stored.Session, paasv1.TerminalSessionExpired, now)
			if err := transaction.Transition(transactionContext, stored, ended, lifecycleEvent(stored, audit.TerminalSessionEnded, audit.Expired, now)); err != nil {
				return err
			}
			expired = true
			return nil
		}
		next := stored.Session
		next.State = paasv1.TerminalSessionConnecting
		if err := transaction.ConsumeTicket(transactionContext, stored, next); err != nil {
			return err
		}
		stored.Session = next
		result = stored
		return nil
	})
	if err != nil {
		return StoredSession{}, err
	}
	if expired {
		return StoredSession{}, ErrExpired
	}
	return result, nil
}

func (service *Service) Activate(ctx context.Context, consumed StoredSession) (StoredSession, error) {
	if service == nil || service.repository == nil || ctx == nil || validateStoredSession(consumed) != nil ||
		consumed.Session.State != paasv1.TerminalSessionConnecting {
		return StoredSession{}, ErrInvalidArgument
	}
	var result StoredSession
	err := service.retryTenant(ctx, consumed.Session.Scope.TenantID, func(transactionContext context.Context, transaction Transaction) error {
		current, found, err := transaction.LoadAndLockSession(transactionContext, consumed.Session.ID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if !sameStoredAuthority(current, consumed) || current.Session.State != paasv1.TerminalSessionConnecting {
			return ErrConflict
		}
		now, err := transaction.TransactionTime(transactionContext)
		if err != nil {
			return err
		}
		if !now.Before(current.Session.ExpiresAt) {
			ended := endedSession(current.Session, paasv1.TerminalSessionExpired, now)
			return transaction.Transition(transactionContext, current, ended, lifecycleEvent(current, audit.TerminalSessionEnded, audit.Expired, now))
		}
		next := current.Session
		next.State = paasv1.TerminalSessionActive
		next.ConnectedAt = &now
		if err := transaction.Transition(transactionContext, current, next, lifecycleEvent(current, audit.TerminalSessionStarted, audit.Succeeded, now)); err != nil {
			return err
		}
		current.Session = next
		result = current
		return nil
	})
	if err != nil {
		return StoredSession{}, err
	}
	if result.Session.ID == "" {
		return StoredSession{}, ErrExpired
	}
	return result, nil
}

func (service *Service) End(ctx context.Context, tenantID paasv1.TenantID, id paasv1.ResourceID, outcome paasv1.TerminalSessionOutcome) (StoredSession, bool, error) {
	if service == nil || service.repository == nil || ctx == nil ||
		paasv1.ValidateID("tenantId", string(tenantID)) != nil || paasv1.ValidateTerminalSessionID(id) != nil ||
		!terminalOutcome(outcome) {
		return StoredSession{}, false, ErrInvalidArgument
	}
	return service.end(ctx, tenantID, id, nil, outcome)
}

func (service *Service) Close(ctx context.Context, command CloseCommand) (StoredSession, bool, error) {
	if service == nil || service.repository == nil || ctx == nil ||
		port.ValidateAuthorization(command.Authorization) != nil || command.Authorization.Subject.Type != paasv1.SubjectUser ||
		paasv1.ValidateTerminalSessionID(command.SessionID) != nil {
		return StoredSession{}, false, ErrInvalidArgument
	}
	subject := command.Authorization.Subject
	return service.end(ctx, command.Authorization.TenantID, command.SessionID, &subject, paasv1.TerminalSessionRevoked)
}

func (service *Service) end(ctx context.Context, tenantID paasv1.TenantID, id paasv1.ResourceID, subject *paasv1.SubjectRef, outcome paasv1.TerminalSessionOutcome) (StoredSession, bool, error) {
	var result StoredSession
	changed := false
	err := service.retryTenant(ctx, tenantID, func(transactionContext context.Context, transaction Transaction) error {
		current, found, err := transaction.LoadAndLockSession(transactionContext, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if subject != nil && current.Subject != *subject {
			return ErrPermissionDenied
		}
		result = current
		if current.Session.State == paasv1.TerminalSessionEnded {
			return nil
		}
		now, err := transaction.TransactionTime(transactionContext)
		if err != nil {
			return err
		}
		next := endedSession(current.Session, outcome, now)
		if err := transaction.Transition(transactionContext, current, next, lifecycleEvent(current, audit.TerminalSessionEnded, auditResult(outcome), now)); err != nil {
			return err
		}
		current.Session = next
		result, changed = current, true
		return nil
	})
	return result, changed, err
}

func (service *Service) retryTenant(ctx context.Context, tenantID paasv1.TenantID, callback func(context.Context, Transaction) error) error {
	var err error
	for range service.config.MaxTransactionAttempts {
		err = service.repository.WithinTenant(ctx, tenantID, callback)
		if err == nil || !errors.Is(err, ErrRetryableTransaction) {
			return err
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
	}
	return fmt.Errorf("terminal transaction attempts exhausted: %w", err)
}

func (service *Service) retryTicket(
	ctx context.Context,
	id paasv1.ResourceID,
	ticketDigest string,
	callback func(context.Context, Transaction, StoredSession) error,
) error {
	var err error
	for range service.config.MaxTransactionAttempts {
		err = service.repository.WithinTicket(ctx, id, ticketDigest, callback)
		if err == nil || !errors.Is(err, ErrRetryableTransaction) {
			return err
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
	}
	return fmt.Errorf("terminal ticket transaction attempts exhausted: %w", err)
}

func validateCreateCommand(command CreateCommand) error {
	return errors.Join(
		port.ValidateAuthorization(command.Authorization),
		func() error {
			if command.Authorization.Subject.Type != paasv1.SubjectUser {
				return errors.New("terminal sessions require a user")
			}
			return nil
		}(),
		paasv1.ValidateID("deploymentId", string(command.DeploymentID)),
		paasv1.ValidateCreateTerminalSessionRequest(command.Request),
		paasv1.ValidateSafeExternalText("Idempotency-Key", command.IdempotencyKey, 128, true),
		paasv1.ValidateDigest("ticketDigest", command.TicketDigest),
	)
}

func validateRuntimeBinding(value RuntimeBinding) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("deploymentId", string(value.DeploymentID)),
		paasv1.ValidateID("applicationRevisionId", string(value.ApplicationRevisionID)),
		paasv1.ValidateDigest("contentDigest", value.ContentDigest),
		paasv1.ValidateID("executionTargetId", string(value.ExecutionTargetID)),
		paasv1.ValidateID("placementDecisionId", string(value.PlacementDecisionID)),
		paasv1.ValidateID("bindingRef", value.BindingRef),
		paasv1.ValidateDeploymentInstanceID(value.InstanceID),
	)
	if value.Generation == 0 {
		problems = append(problems, errors.New("runtime generation is invalid"))
	}
	return errors.Join(problems...)
}

// ValidateRuntimeBinding protects adapters from accepting a malformed or
// provider-leaking persisted runtime proof.
func ValidateRuntimeBinding(value RuntimeBinding) error {
	return validateRuntimeBinding(value)
}

func validateStoredSession(value StoredSession) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateTerminalSession(value.Session),
		validateRuntimeBinding(value.Binding),
		paasv1.ValidateID("subject.id", value.Subject.ID),
		paasv1.ValidateID("iamDecisionId", value.IAMDecisionID),
		paasv1.ValidateID("requestId", value.RequestID),
		paasv1.ValidateDigest("idempotencyFingerprint", value.IdempotencyFingerprint),
		paasv1.ValidateDigest("requestDigest", value.RequestDigest),
	)
	if value.Subject.Type != paasv1.SubjectUser || value.Binding.DeploymentID != value.Session.DeploymentID ||
		value.Binding.Generation != value.Session.Generation ||
		value.Binding.ApplicationRevisionID != value.Session.ApplicationRevisionID ||
		value.Binding.InstanceID != value.Session.InstanceID {
		problems = append(problems, errors.New("stored terminal authority binding is invalid"))
	}
	if value.AuditID != "" {
		problems = append(problems, paasv1.ValidateID("auditId", value.AuditID))
	}
	if value.TraceParent != "" {
		problems = append(problems, paasv1.ValidateSafeExternalText("traceparent", value.TraceParent, 55, false))
	}
	return errors.Join(problems...)
}

// ValidateStoredSession is the persistence adapter's closed-document gate.
func ValidateStoredSession(value StoredSession) error {
	return validateStoredSession(value)
}

func lifecycleEvent(stored StoredSession, action string, result audit.Result, occurredAt time.Time) audit.Event {
	return audit.Event{
		SchemaVersion: "v1", EventID: terminalEventID(stored.Session.ID, action),
		TenantID: stored.Session.Scope.TenantID, Actor: stored.Subject,
		IAMDecisionID: stored.IAMDecisionID, Action: action,
		Target:        audit.TargetReference{Kind: audit.TargetTerminalSession, ID: stored.Session.ID},
		RequestDigest: stored.RequestDigest, Result: result, RequestID: stored.RequestID,
		AuditID: stored.AuditID, TraceParent: stored.TraceParent, OccurredAt: occurredAt,
	}
}

func endedSession(current paasv1.TerminalSession, outcome paasv1.TerminalSessionOutcome, now time.Time) paasv1.TerminalSession {
	current.State, current.Outcome = paasv1.TerminalSessionEnded, outcome
	current.EndedAt = &now
	return current
}

func terminalSessionID(fingerprint string) paasv1.ResourceID {
	return paasv1.ResourceID("terminal-session-" + fingerprint[len("sha256:"):len("sha256:")+32])
}

func terminalEventID(id paasv1.ResourceID, action string) string {
	suffix := strings.TrimPrefix(string(id), "terminal-session-")
	verb := strings.TrimPrefix(action, "paas.terminal-session.")
	return "terminal-event-" + suffix + "-" + verb
}

func digestDocument(value any) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("encode terminal identity")
	}
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func sameStoredAuthority(left, right StoredSession) bool {
	return left.Session.ID == right.Session.ID && left.Session.Scope == right.Session.Scope &&
		left.Binding == right.Binding && left.Subject == right.Subject &&
		left.IAMDecisionID == right.IAMDecisionID && left.RequestID == right.RequestID &&
		left.IdempotencyFingerprint == right.IdempotencyFingerprint && left.RequestDigest == right.RequestDigest
}

func terminalOutcome(value paasv1.TerminalSessionOutcome) bool {
	for _, candidate := range paasv1.TerminalSessionOutcomes() {
		if value == candidate {
			return true
		}
	}
	return false
}

func auditResult(value paasv1.TerminalSessionOutcome) audit.Result {
	return audit.Result(value)
}
