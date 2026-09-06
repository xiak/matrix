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
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var _ nodeenrollment.Repository = (*NodeEnrollmentRepository)(nil)
var _ nodeenrollment.Transaction = (*nodeEnrollmentTransaction)(nil)

type NodeEnrollmentRepository struct {
	pool *pgxpool.Pool
}

func NewNodeEnrollmentRepository(pool *pgxpool.Pool) (*NodeEnrollmentRepository, error) {
	if pool == nil {
		return nil, errors.New("node enrollment database pool is required")
	}
	return &NodeEnrollmentRepository{pool: pool}, nil
}

func (repository *NodeEnrollmentRepository) WithinInstallation(
	ctx context.Context,
	installationID string,
	callback func(context.Context, nodeenrollment.Transaction) error,
) error {
	return repository.withinInstallation(ctx, installationID, pgx.Serializable, callback)
}

func (repository *NodeEnrollmentRepository) withinInstallation(
	ctx context.Context,
	installationID string,
	isolation pgx.TxIsoLevel,
	callback func(context.Context, nodeenrollment.Transaction) error,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil ||
		paasv1.ValidateID("installationId", installationID) != nil {
		return nodeenrollment.ErrInvalidArgument
	}
	err := func() error {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
			IsoLevel: isolation, AccessMode: pgx.ReadWrite,
		})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
			return err
		}
		if _, err := tx.Exec(
			ctx,
			"SELECT set_config('matrix.installation_id', $1, true)",
			installationID,
		); err != nil {
			return err
		}
		var effectiveInstallation string
		if err := tx.QueryRow(ctx, "SELECT paas.current_installation_id()").Scan(&effectiveInstallation); err != nil ||
			effectiveInstallation != installationID {
			return errors.New("node enrollment authority context is invalid")
		}
		if err := callback(ctx, &nodeEnrollmentTransaction{
			tx: tx, installationID: installationID,
		}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}()
	return mapNodeEnrollmentError(err)
}

func mapNodeEnrollmentError(err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "40001", "40P01":
			return nodeenrollment.ErrRetryableTransaction
		case "23505":
			return errors.Join(nodeenrollment.ErrRetryableTransaction, nodeenrollment.ErrConflict)
		case "23503", "MX409":
			return nodeenrollment.ErrConflict
		case "MX404":
			return nodeenrollment.ErrNotFound
		case "MX412":
			return nodeenrollment.ErrResourceVersion
		case "22023", "23514":
			return nodeenrollment.ErrInvalidArgument
		}
	}
	return fmt.Errorf("node enrollment transaction: %w", err)
}

type nodeEnrollmentTransaction struct {
	tx             pgx.Tx
	installationID string
}

func (transaction *nodeEnrollmentTransaction) TransactionTime(ctx context.Context) (time.Time, error) {
	var value time.Time
	if err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&value); err != nil {
		return time.Time{}, err
	}
	return databaseTime(value), nil
}

func (transaction *nodeEnrollmentTransaction) FindByFingerprint(
	ctx context.Context,
	fingerprint string,
) (nodeenrollment.StoredEnrollment, bool, error) {
	if paasv1.ValidateDigest("idempotencyFingerprint", fingerprint) != nil {
		return nodeenrollment.StoredEnrollment{}, false, nodeenrollment.ErrInvalidArgument
	}
	return transaction.load(ctx, "operation.idempotency_fingerprint", fingerprint)
}

func (transaction *nodeEnrollmentTransaction) FindByTerminationFingerprint(
	ctx context.Context,
	fingerprint string,
) (nodeenrollment.StoredEnrollment, bool, error) {
	if paasv1.ValidateDigest("terminationFingerprint", fingerprint) != nil {
		return nodeenrollment.StoredEnrollment{}, false, nodeenrollment.ErrInvalidArgument
	}
	return transaction.load(ctx, "enrollment.termination_idempotency_fingerprint", fingerprint)
}

func (transaction *nodeEnrollmentTransaction) LoadEnrollment(
	ctx context.Context,
	id paasv1.ResourceID,
) (nodeenrollment.StoredEnrollment, bool, error) {
	if paasv1.ValidateID("nodeEnrollmentId", string(id)) != nil {
		return nodeenrollment.StoredEnrollment{}, false, nodeenrollment.ErrInvalidArgument
	}
	return transaction.load(ctx, "enrollment.id", string(id))
}

func (transaction *nodeEnrollmentTransaction) load(
	ctx context.Context,
	column string,
	selector string,
) (nodeenrollment.StoredEnrollment, bool, error) {
	if column != "operation.idempotency_fingerprint" &&
		column != "enrollment.termination_idempotency_fingerprint" &&
		column != "enrollment.id" {
		return nodeenrollment.StoredEnrollment{}, false, nodeenrollment.ErrInvalidArgument
	}
	var (
		enrollmentID, operationID                 string
		credentialSalt                            []byte
		credentialVerifier                        string
		enrollmentDocument, operationDocument     []byte
		joinDocument, wrappedCredentialDocument   []byte
		exchangeDocument, sealedResultDocument    []byte
		actorType, actorID, decisionID, requestID string
		auditID, traceParent                      string
		terminationFingerprint, terminationDigest string
	)
	err := transaction.tx.QueryRow(ctx, `SELECT
			enrollment.id, enrollment.operation_id,
			enrollment.credential_salt, COALESCE(enrollment.credential_verifier, ''),
			enrollment.document, operation.document,
			enrollment.join_document, enrollment.wrapped_credential_document,
			enrollment.exchange_document, enrollment.sealed_exchange_result_document,
			enrollment.actor_type, enrollment.actor_id,
			enrollment.iam_decision_id, enrollment.request_id,
			COALESCE(enrollment.audit_id, ''), COALESCE(enrollment.traceparent, ''),
			COALESCE(enrollment.termination_idempotency_fingerprint, ''),
			COALESCE(enrollment.termination_request_digest, '')
		FROM paas.node_enrollments AS enrollment
		JOIN paas.operations AS operation
		  ON operation.authority_key = 'installation:' || enrollment.installation_id
		 AND operation.id = enrollment.operation_id
		WHERE enrollment.installation_id = $1 AND `+column+` = $2`,
		transaction.installationID,
		selector,
	).Scan(
		&enrollmentID, &operationID,
		&credentialSalt, &credentialVerifier,
		&enrollmentDocument, &operationDocument,
		&joinDocument, &wrappedCredentialDocument,
		&exchangeDocument, &sealedResultDocument,
		&actorType, &actorID, &decisionID, &requestID,
		&auditID, &traceParent, &terminationFingerprint, &terminationDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nodeenrollment.StoredEnrollment{}, false, nil
	}
	if err != nil {
		return nodeenrollment.StoredEnrollment{}, false, err
	}
	stored := nodeenrollment.StoredEnrollment{
		CredentialSalt:     credentialSalt,
		CredentialVerifier: credentialVerifier,
		CreateAuthorization: port.Authorization{
			InstallationID: transaction.installationID,
			Subject: paasv1.SubjectRef{
				Type: paasv1.SubjectType(actorType), ID: actorID,
			},
			DecisionID: decisionID, RequestID: requestID,
			AuditID: auditID, TraceParent: traceParent,
		},
		TerminationFingerprint:   terminationFingerprint,
		TerminationRequestDigest: terminationDigest,
	}
	if decodeDocument("NodeEnrollment", enrollmentDocument, &stored.Enrollment) != nil ||
		decodeDocument("Operation", operationDocument, &stored.Operation) != nil ||
		decodeDocument("NodeEnrollmentJoin", joinDocument, &stored.Join) != nil ||
		(len(wrappedCredentialDocument) > 0 &&
			decodeDocument("WrappedJoinCredential", wrappedCredentialDocument, &stored.WrappedCredential) != nil) ||
		string(stored.Enrollment.Metadata.ID) != enrollmentID || string(stored.Operation.ID) != operationID {
		stored.Clear()
		return nodeenrollment.StoredEnrollment{}, false, errors.New("stored node enrollment is invalid")
	}
	if len(exchangeDocument) > 0 {
		var exchange nodeenrollment.StoredExchange
		if decodeDocument("NodeEnrollmentExchange", exchangeDocument, &exchange) != nil {
			stored.Clear()
			return nodeenrollment.StoredEnrollment{}, false, errors.New("stored node enrollment exchange is invalid")
		}
		stored.Exchange = &exchange
	}
	if len(sealedResultDocument) > 0 {
		var sealed nodeenrollment.SealedExchangeResult
		if decodeDocument("SealedNodeEnrollmentExchange", sealedResultDocument, &sealed) != nil {
			stored.Clear()
			return nodeenrollment.StoredEnrollment{}, false, errors.New("stored sealed node enrollment exchange is invalid")
		}
		stored.SealedExchangeResult = &sealed
	}
	if nodeenrollment.ValidateStoredEnrollment(stored, transaction.installationID) != nil {
		stored.Clear()
		return nodeenrollment.StoredEnrollment{}, false, errors.New("stored node enrollment is invalid")
	}
	return stored, true, nil
}

func (transaction *nodeEnrollmentTransaction) LoadExecutionPool(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.ExecutionPool, bool, error) {
	if paasv1.ValidateID("executionPoolId", string(id)) != nil {
		return paasv1.ExecutionPool{}, false, nodeenrollment.ErrInvalidArgument
	}
	var storedID string
	var version uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx, `SELECT id, resource_version, document
		FROM paas.execution_pools WHERE installation_id = $1 AND id = $2`,
		transaction.installationID, id,
	).Scan(&storedID, &version, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.ExecutionPool{}, false, nil
	}
	if err != nil {
		return paasv1.ExecutionPool{}, false, err
	}
	var value paasv1.ExecutionPool
	if decodeDocument("ExecutionPool", document, &value) != nil ||
		paasv1.ValidateExecutionPool(value) != nil || string(value.Metadata.ID) != storedID ||
		value.Metadata.ResourceVersion != version {
		return paasv1.ExecutionPool{}, false, errors.New("stored execution pool is invalid")
	}
	return value, true, nil
}

func (transaction *nodeEnrollmentTransaction) LoadExecutionTarget(
	ctx context.Context,
	id paasv1.ResourceID,
) (executionadmission.Registration, bool, error) {
	value, found, err := (&executionAdmissionTransaction{
		tx: transaction.tx, installationID: transaction.installationID,
	}).LoadTarget(ctx, id)
	return value, found, mapNodeEnrollmentReadError(err)
}

func (transaction *nodeEnrollmentTransaction) ListExecutionTargets(
	ctx context.Context,
) ([]executionadmission.Registration, error) {
	values, err := (&executionAdmissionTransaction{
		tx: transaction.tx, installationID: transaction.installationID,
	}).ListTargets(ctx)
	return values, mapNodeEnrollmentReadError(err)
}

func (transaction *nodeEnrollmentTransaction) ListExecutionPoolTargets(
	ctx context.Context,
	poolID paasv1.ResourceID,
) ([]paasv1.ExecutionTarget, error) {
	values, err := (&executionAdmissionTransaction{
		tx: transaction.tx, installationID: transaction.installationID,
	}).ListPoolTargets(ctx, poolID)
	return values, mapNodeEnrollmentReadError(err)
}

func mapNodeEnrollmentReadError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, executionadmission.ErrInvalidArgument):
		return nodeenrollment.ErrInvalidArgument
	case errors.Is(err, executionadmission.ErrConflict):
		return nodeenrollment.ErrConflict
	default:
		return err
	}
}

func (transaction *nodeEnrollmentTransaction) LoadEnrolledNodeConnection(
	ctx context.Context,
	targetID paasv1.ResourceID,
) (port.EnrolledNodeConnection, bool, error) {
	if paasv1.ValidateID("executionTargetId", string(targetID)) != nil {
		return port.EnrolledNodeConnection{}, false, nodeenrollment.ErrInvalidArgument
	}
	value := port.EnrolledNodeConnection{InstallationID: transaction.installationID}
	err := transaction.tx.QueryRow(ctx, `SELECT execution_target_id, controller_id, binding_ref,
		endpoint, identity_fingerprint, enabled
		FROM paas.enrolled_node_connections
		WHERE installation_id = $1 AND execution_target_id = $2`,
		transaction.installationID, targetID,
	).Scan(
		&value.ExecutionTargetID, &value.ControllerID, &value.BindingRef,
		&value.Endpoint, &value.IdentityFingerprint, &value.Enabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.EnrolledNodeConnection{}, false, nil
	}
	if err != nil {
		return port.EnrolledNodeConnection{}, false, err
	}
	if port.ValidateEnrolledNodeConnection(value) != nil || value.ExecutionTargetID != targetID {
		return port.EnrolledNodeConnection{}, false, errors.New("stored enrolled node connection is invalid")
	}
	return value, true, nil
}

func (transaction *nodeEnrollmentTransaction) ListEnrollments(
	ctx context.Context,
	limit int,
) ([]nodeenrollment.StoredEnrollment, error) {
	if limit < 1 || limit > paasv1.MaximumNodeEnrollmentListItems+1 {
		return nil, nodeenrollment.ErrInvalidArgument
	}
	rows, err := transaction.tx.Query(ctx, `SELECT id FROM paas.node_enrollments
		WHERE installation_id = $1 ORDER BY created_at DESC, id COLLATE "C" LIMIT $2`,
		transaction.installationID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]paasv1.ResourceID, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, paasv1.ResourceID(id))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	values := make([]nodeenrollment.StoredEnrollment, 0, len(ids))
	for _, id := range ids {
		value, found, err := transaction.LoadEnrollment(ctx, id)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("listed node enrollment disappeared")
		}
		values = append(values, value)
	}
	return values, nil
}

func (transaction *nodeEnrollmentTransaction) InsertEnrollment(
	ctx context.Context,
	stored nodeenrollment.StoredEnrollment,
) error {
	if nodeenrollment.ValidateStoredEnrollment(stored, transaction.installationID) != nil {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(stored.Enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(stored.Operation)
	if err != nil {
		return err
	}
	joinDocument, err := json.Marshal(stored.Join)
	if err != nil {
		return err
	}
	wrappedDocument, err := json.Marshal(stored.WrappedCredential)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.create_node_enrollment(
		$1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12
	)`, enrollmentDocument, operationDocument, joinDocument, wrappedDocument,
		stored.CredentialSalt, stored.CredentialVerifier,
		stored.CreateAuthorization.Subject.Type, stored.CreateAuthorization.Subject.ID,
		stored.CreateAuthorization.DecisionID, stored.CreateAuthorization.RequestID,
		nullableString(stored.CreateAuthorization.AuditID), nullableString(stored.CreateAuthorization.TraceParent),
	)
	return err
}

func (transaction *nodeEnrollmentTransaction) ExchangeEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
) error {
	if nodeenrollment.ValidateStoredEnrollment(before, transaction.installationID) != nil ||
		nodeenrollment.ValidateStoredEnrollment(after, transaction.installationID) != nil ||
		before.Enrollment.State != paasv1.NodeEnrollmentWaitingInstall ||
		after.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		after.Exchange == nil || after.SealedExchangeResult == nil ||
		after.Enrollment.Metadata.ID != before.Enrollment.Metadata.ID {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(after.Enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(after.Operation)
	if err != nil {
		return err
	}
	exchangeDocument, err := json.Marshal(after.Exchange)
	if err != nil {
		return err
	}
	sealedDocument, err := json.Marshal(after.SealedExchangeResult)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.exchange_node_enrollment(
		$1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb
	)`, before.Enrollment.Metadata.ID,
		int64(before.Enrollment.Metadata.ResourceVersion), before.CredentialVerifier,
		enrollmentDocument, operationDocument, exchangeDocument, sealedDocument,
	)
	return err
}

func (transaction *nodeEnrollmentTransaction) ExpireEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	enrollment paasv1.NodeEnrollment,
	operation paasv1.Operation,
) error {
	if nodeenrollment.ValidateStoredEnrollment(before, transaction.installationID) != nil ||
		paasv1.ValidateNodeEnrollment(enrollment) != nil || paasv1.ValidateOperation(operation) != nil {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.expire_node_enrollment($1,$2,$3::jsonb,$4::jsonb)`,
		before.Enrollment.Metadata.ID,
		int64(before.Enrollment.Metadata.ResourceVersion),
		enrollmentDocument,
		operationDocument,
	)
	return err
}

func (transaction *nodeEnrollmentTransaction) RevokeEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
) error {
	return transaction.revokeEnrollment(ctx, before, after, nil, nil)
}

func (transaction *nodeEnrollmentTransaction) ReplaceEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
	replacement nodeenrollment.StoredEnrollment,
) error {
	if nodeenrollment.ValidateStoredEnrollment(replacement, transaction.installationID) != nil ||
		after.Enrollment.ReplacedByID != replacement.Enrollment.Metadata.ID {
		return nodeenrollment.ErrInvalidArgument
	}
	replacementDocument, err := json.Marshal(replacement.Enrollment)
	if err != nil {
		return err
	}
	replacementOperationDocument, err := json.Marshal(replacement.Operation)
	if err != nil {
		return err
	}
	if err := transaction.revokeEnrollment(
		ctx, before, after, replacementDocument, replacementOperationDocument,
	); err != nil {
		return err
	}
	return transaction.InsertEnrollment(ctx, replacement)
}

func (transaction *nodeEnrollmentTransaction) revokeEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
	replacementDocument []byte,
	replacementOperationDocument []byte,
) error {
	if nodeenrollment.ValidateStoredEnrollment(before, transaction.installationID) != nil ||
		nodeenrollment.ValidateStoredEnrollment(after, transaction.installationID) != nil ||
		after.Enrollment.Metadata.ID != before.Enrollment.Metadata.ID ||
		after.TerminationFingerprint == "" || after.TerminationRequestDigest == "" {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(after.Enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(after.Operation)
	if err != nil {
		return err
	}
	var replacementValue any
	if replacementDocument != nil {
		replacementValue = replacementDocument
	}
	var replacementOperationValue any
	if replacementOperationDocument != nil {
		replacementOperationValue = replacementOperationDocument
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.revoke_node_enrollment(
		$1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb
	)`, before.Enrollment.Metadata.ID,
		int64(before.Enrollment.Metadata.ResourceVersion),
		after.TerminationFingerprint,
		after.TerminationRequestDigest,
		enrollmentDocument,
		operationDocument,
		replacementValue,
		replacementOperationValue,
	)
	return err
}

func (transaction *nodeEnrollmentTransaction) CompleteEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
	registration executionadmission.Registration,
	connection port.EnrolledNodeConnection,
	expectedPoolVersion uint64,
	pool paasv1.ExecutionPool,
	event audit.Event,
) error {
	if nodeenrollment.ValidateStoredEnrollment(before, transaction.installationID) != nil ||
		nodeenrollment.ValidateStoredEnrollment(after, transaction.installationID) != nil ||
		before.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		after.Enrollment.State != paasv1.NodeEnrollmentReady ||
		after.Enrollment.Metadata.ID != before.Enrollment.Metadata.ID ||
		paasv1.ValidateExecutionTarget(registration.Target) != nil ||
		registration.Target.Metadata.ID != after.Enrollment.ExecutionTargetID ||
		registration.Target.Spec.ExecutionPoolID != after.Enrollment.ExecutionPoolID ||
		port.ValidateEnrolledNodeConnection(connection) != nil || !connection.Enabled ||
		connection.InstallationID != transaction.installationID ||
		connection.ExecutionTargetID != registration.Target.Metadata.ID ||
		connection.BindingRef != registration.BindingRef ||
		connection.IdentityFingerprint != registration.IdentityFingerprint ||
		expectedPoolVersion < 1 || expectedPoolVersion > 9007199254740991 ||
		paasv1.ValidateExecutionPool(pool) != nil || pool.Metadata.ID != after.Enrollment.ExecutionPoolID ||
		audit.ValidateEvent(event) != nil || event.InstallationID != transaction.installationID ||
		event.OperationID != after.Operation.ID {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(after.Enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(after.Operation)
	if err != nil {
		return err
	}
	targetDocument, err := json.Marshal(registration.Target)
	if err != nil {
		return err
	}
	poolDocument, err := json.Marshal(pool)
	if err != nil {
		return err
	}
	eventDocument, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.complete_node_enrollment(
		$1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb
	)`, before.Enrollment.Metadata.ID, int64(before.Enrollment.Metadata.ResourceVersion),
		enrollmentDocument, operationDocument, targetDocument,
		connection.BindingRef, connection.IdentityFingerprint, connection.ControllerID, connection.Endpoint,
		int64(expectedPoolVersion), poolDocument, eventDocument,
	)
	return err
}

func (transaction *nodeEnrollmentTransaction) FailEnrollment(
	ctx context.Context,
	before nodeenrollment.StoredEnrollment,
	after nodeenrollment.StoredEnrollment,
) error {
	if nodeenrollment.ValidateStoredEnrollment(before, transaction.installationID) != nil ||
		nodeenrollment.ValidateStoredEnrollment(after, transaction.installationID) != nil ||
		before.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		after.Enrollment.State != paasv1.NodeEnrollmentFailed ||
		after.Enrollment.Metadata.ID != before.Enrollment.Metadata.ID {
		return nodeenrollment.ErrInvalidArgument
	}
	enrollmentDocument, err := json.Marshal(after.Enrollment)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(after.Operation)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.fail_node_enrollment(
		$1,$2,$3::jsonb,$4::jsonb
	)`, before.Enrollment.Metadata.ID, int64(before.Enrollment.Metadata.ResourceVersion),
		enrollmentDocument, operationDocument,
	)
	return err
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
