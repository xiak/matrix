package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/terminalsession"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var (
	_ terminalsession.Repository  = (*TerminalSessionRepository)(nil)
	_ terminalsession.Transaction = (*terminalSessionTransaction)(nil)
)

// TerminalSessionRepository persists the write-capable terminal authority
// without exposing a ticket digest or an unscoped table read to the API role.
type TerminalSessionRepository struct {
	pool *pgxpool.Pool
}

func NewTerminalSessionRepository(pool *pgxpool.Pool) (*TerminalSessionRepository, error) {
	if pool == nil {
		return nil, errors.New("terminal session PostgreSQL pool is required")
	}
	return &TerminalSessionRepository{pool: pool}, nil
}

func (repository *TerminalSessionRepository) WithinTenant(
	ctx context.Context,
	tenantID paasv1.TenantID,
	callback func(context.Context, terminalsession.Transaction) error,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil {
		return errors.New("terminal session transaction is unavailable")
	}
	if err := paasv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		tenantID,
		pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			return callback(ctx, &terminalSessionTransaction{tx: tx, tenantID: tenantID})
		},
	)
	return mapTerminalSessionError("execute terminal session transaction", err)
}

func (repository *TerminalSessionRepository) WithinTicket(
	ctx context.Context,
	sessionID paasv1.ResourceID,
	ticketDigest string,
	callback func(context.Context, terminalsession.Transaction, terminalsession.StoredSession) error,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil {
		return errors.New("terminal ticket transaction is unavailable")
	}
	if err := paasv1.ValidateTerminalSessionID(sessionID); err != nil {
		return err
	}
	if err := paasv1.ValidateDigest("ticketDigest", ticketDigest); err != nil {
		return err
	}
	tx, err := repository.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite},
	)
	if err != nil {
		return fmt.Errorf("begin terminal ticket transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return fmt.Errorf("set terminal ticket timezone: %w", err)
	}
	stored, found, err := queryStoredTerminal(
		ctx,
		tx,
		"SELECT document FROM paas.open_terminal_session_ticket($1, $2)",
		sessionID,
		ticketDigest,
	)
	if err != nil {
		return mapTerminalSessionError("open terminal ticket", err)
	}
	if !found {
		return terminalsession.ErrNotFound
	}
	var effectiveTenant string
	if err := tx.QueryRow(ctx, "SELECT paas.current_tenant_id()").Scan(&effectiveTenant); err != nil ||
		effectiveTenant != string(stored.Session.Scope.TenantID) {
		return errors.New("terminal ticket tenant context is invalid")
	}
	transaction := &terminalSessionTransaction{
		tx: tx, tenantID: stored.Session.Scope.TenantID,
	}
	if err := callback(ctx, transaction, stored); err != nil {
		return mapTerminalSessionError("execute terminal ticket transaction", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapTerminalSessionError("commit terminal ticket transaction", err)
	}
	return nil
}

type terminalSessionTransaction struct {
	tx       pgx.Tx
	tenantID paasv1.TenantID
}

func (transaction *terminalSessionTransaction) TransactionTime(ctx context.Context) (time.Time, error) {
	var value time.Time
	if transaction == nil || transaction.tx == nil || ctx == nil {
		return time.Time{}, errors.New("terminal transaction is unavailable")
	}
	if err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&value); err != nil {
		return time.Time{}, fmt.Errorf("read terminal transaction time: %w", err)
	}
	return databaseTime(value), nil
}

func (transaction *terminalSessionTransaction) FindByFingerprint(
	ctx context.Context,
	fingerprint string,
) (terminalsession.StoredSession, bool, error) {
	if err := paasv1.ValidateDigest("idempotencyFingerprint", fingerprint); err != nil {
		return terminalsession.StoredSession{}, false, err
	}
	return queryStoredTerminal(
		ctx,
		transaction.tx,
		"SELECT document FROM paas.lock_terminal_session_by_fingerprint($1)",
		fingerprint,
	)
}

func (transaction *terminalSessionTransaction) LoadAndLockSession(
	ctx context.Context,
	sessionID paasv1.ResourceID,
) (terminalsession.StoredSession, bool, error) {
	if err := paasv1.ValidateTerminalSessionID(sessionID); err != nil {
		return terminalsession.StoredSession{}, false, err
	}
	return queryStoredTerminal(
		ctx,
		transaction.tx,
		"SELECT document FROM paas.lock_terminal_session($1)",
		sessionID,
	)
}

func (transaction *terminalSessionTransaction) LoadAndLockOpenForSubjectInstance(
	ctx context.Context,
	subject paasv1.SubjectRef,
	deploymentID paasv1.ResourceID,
	instanceID paasv1.ResourceID,
) (terminalsession.StoredSession, bool, error) {
	if subject.Type != paasv1.SubjectUser || paasv1.ValidateID("subject.id", subject.ID) != nil ||
		paasv1.ValidateID("deploymentId", string(deploymentID)) != nil ||
		paasv1.ValidateDeploymentInstanceID(instanceID) != nil {
		return terminalsession.StoredSession{}, false, errors.New("open terminal selector is invalid")
	}
	return queryStoredTerminal(
		ctx,
		transaction.tx,
		"SELECT document FROM paas.lock_open_terminal_session($1, $2, $3, $4)",
		subject.Type,
		subject.ID,
		deploymentID,
		instanceID,
	)
}

func (transaction *terminalSessionTransaction) LoadAndLockCurrentRuntime(
	ctx context.Context,
	deploymentID paasv1.ResourceID,
	instanceID paasv1.ResourceID,
	now time.Time,
) (terminalsession.RuntimeBinding, bool, error) {
	if paasv1.ValidateID("deploymentId", string(deploymentID)) != nil ||
		paasv1.ValidateDeploymentInstanceID(instanceID) != nil || now.IsZero() {
		return terminalsession.RuntimeBinding{}, false, errors.New("terminal runtime selector is invalid")
	}
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		"SELECT document FROM paas.lock_current_terminal_runtime($1, $2, $3)",
		deploymentID,
		instanceID,
		now,
	).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return terminalsession.RuntimeBinding{}, false, nil
	}
	if err != nil {
		return terminalsession.RuntimeBinding{}, false, fmt.Errorf("lock current terminal runtime: %w", err)
	}
	var binding terminalsession.RuntimeBinding
	if err := decodeDocument("terminal runtime binding", document, &binding); err != nil {
		return terminalsession.RuntimeBinding{}, false, err
	}
	if err := terminalsession.ValidateRuntimeBinding(binding); err != nil {
		return terminalsession.RuntimeBinding{}, false, fmt.Errorf("validate terminal runtime binding: %w", err)
	}
	return binding, true, nil
}

func (transaction *terminalSessionTransaction) Insert(
	ctx context.Context,
	stored terminalsession.StoredSession,
	ticketDigest string,
	event audit.Event,
) error {
	if err := transaction.validateStored(stored); err != nil {
		return err
	}
	if err := paasv1.ValidateDigest("ticketDigest", ticketDigest); err != nil {
		return err
	}
	if err := audit.ValidateEvent(event); err != nil {
		return fmt.Errorf("validate terminal created Audit event: %w", err)
	}
	storedDocument, eventDocument, err := encodeTerminalMutation(stored, event)
	if err != nil {
		return err
	}
	var returned []byte
	if err := transaction.tx.QueryRow(
		ctx,
		"SELECT paas.create_terminal_session($1::jsonb, $2, $3::jsonb)",
		storedDocument,
		ticketDigest,
		eventDocument,
	).Scan(&returned); err != nil {
		return fmt.Errorf("create terminal session: %w", err)
	}
	created, err := decodeStoredTerminal(returned)
	if err != nil {
		return err
	}
	if created.Session.ID != stored.Session.ID || created.RequestDigest != stored.RequestDigest ||
		created.IdempotencyFingerprint != stored.IdempotencyFingerprint {
		return errors.New("created terminal session identity mismatch")
	}
	return nil
}

func (transaction *terminalSessionTransaction) RotateTicket(
	ctx context.Context,
	sessionID paasv1.ResourceID,
	ticketDigest string,
) error {
	if err := paasv1.ValidateTerminalSessionID(sessionID); err != nil {
		return err
	}
	if err := paasv1.ValidateDigest("ticketDigest", ticketDigest); err != nil {
		return err
	}
	if _, err := transaction.tx.Exec(
		ctx,
		"SELECT paas.rotate_terminal_session_ticket($1, $2)",
		sessionID,
		ticketDigest,
	); err != nil {
		return fmt.Errorf("rotate terminal ticket: %w", err)
	}
	return nil
}

func (transaction *terminalSessionTransaction) ConsumeTicket(
	ctx context.Context,
	stored terminalsession.StoredSession,
	next paasv1.TerminalSession,
) error {
	if err := transaction.validateStored(stored); err != nil {
		return err
	}
	if err := paasv1.ValidateTerminalSession(next); err != nil {
		return err
	}
	document, err := json.Marshal(next)
	if err != nil {
		return errors.New("encode consumed terminal session")
	}
	if _, err := transaction.tx.Exec(
		ctx,
		"SELECT paas.consume_terminal_session_ticket($1, $2::jsonb)",
		stored.Session.ID,
		document,
	); err != nil {
		return fmt.Errorf("consume terminal ticket: %w", err)
	}
	return nil
}

func (transaction *terminalSessionTransaction) Transition(
	ctx context.Context,
	stored terminalsession.StoredSession,
	next paasv1.TerminalSession,
	event audit.Event,
) error {
	if err := transaction.validateStored(stored); err != nil {
		return err
	}
	if err := paasv1.ValidateTerminalSession(next); err != nil {
		return err
	}
	if err := audit.ValidateEvent(event); err != nil {
		return fmt.Errorf("validate terminal lifecycle Audit event: %w", err)
	}
	sessionDocument, err := json.Marshal(next)
	if err != nil {
		return errors.New("encode transitioned terminal session")
	}
	eventDocument, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode terminal lifecycle Audit event")
	}
	if _, err := transaction.tx.Exec(
		ctx,
		"SELECT paas.transition_terminal_session($1, $2::jsonb, $3::jsonb)",
		stored.Session.ID,
		sessionDocument,
		eventDocument,
	); err != nil {
		return fmt.Errorf("transition terminal session: %w", err)
	}
	return nil
}

func (transaction *terminalSessionTransaction) validateStored(
	stored terminalsession.StoredSession,
) error {
	if transaction == nil || transaction.tx == nil {
		return errors.New("terminal transaction is unavailable")
	}
	if err := terminalsession.ValidateStoredSession(stored); err != nil {
		return fmt.Errorf("validate stored terminal session: %w", err)
	}
	if stored.Session.Scope.TenantID != transaction.tenantID {
		return errors.New("terminal session transaction tenant mismatch")
	}
	return nil
}

type terminalQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func queryStoredTerminal(
	ctx context.Context,
	querier terminalQueryRower,
	query string,
	arguments ...any,
) (terminalsession.StoredSession, bool, error) {
	var document []byte
	err := querier.QueryRow(ctx, query, arguments...).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return terminalsession.StoredSession{}, false, nil
	}
	if err != nil {
		return terminalsession.StoredSession{}, false, err
	}
	stored, err := decodeStoredTerminal(document)
	return stored, err == nil, err
}

func decodeStoredTerminal(document []byte) (terminalsession.StoredSession, error) {
	var stored terminalsession.StoredSession
	if err := decodeDocument("terminal session proof", document, &stored); err != nil {
		return terminalsession.StoredSession{}, err
	}
	if err := terminalsession.ValidateStoredSession(stored); err != nil {
		return terminalsession.StoredSession{}, fmt.Errorf("validate stored terminal session proof: %w", err)
	}
	return stored, nil
}

func encodeTerminalMutation(
	stored terminalsession.StoredSession,
	event audit.Event,
) ([]byte, []byte, error) {
	storedDocument, err := json.Marshal(stored)
	if err != nil {
		return nil, nil, errors.New("encode terminal session proof")
	}
	eventDocument, err := json.Marshal(event)
	if err != nil {
		return nil, nil, errors.New("encode terminal Audit event")
	}
	return storedDocument, eventDocument, nil
}

func mapTerminalSessionError(action string, err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "P0002":
			return fmt.Errorf("%s: %w", action, terminalsession.ErrNotFound)
		case "MX409", "22023":
			return fmt.Errorf("%s: %w", action, terminalsession.ErrConflict)
		case "40001", "40P01", "23505":
			return fmt.Errorf("%s: %w", action, terminalsession.ErrRetryableTransaction)
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}
