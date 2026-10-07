package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

func (transaction *applicationTransaction) LoadApplication(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Application, bool, error) {
	return transaction.loadApplication(ctx, id, false)
}

func (transaction *applicationTransaction) ListApplicationsAfter(
	ctx context.Context,
	after paasv1.ResourceID,
	limit int,
) ([]paasv1.Application, error) {
	if (after != "" && paasv1.ValidateID("after", string(after)) != nil) || limit < 1 ||
		limit > paasv1.ApplicationDirectoryPageSize+1 {
		return nil, errors.New("application directory query is invalid")
	}
	rows, err := transaction.tx.Query(ctx,
		`SELECT resource_version, document
		   FROM paas.applications
		  WHERE tenant_id = $1
		    AND id > $2 COLLATE "C"
		  ORDER BY id COLLATE "C" ASC
		  LIMIT $3`,
		string(transaction.tenantID), string(after), limit)
	if err != nil {
		return nil, fmt.Errorf("list Applications: %w", err)
	}
	defer rows.Close()
	applications := make([]paasv1.Application, 0, limit)
	for rows.Next() {
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan Application directory: %w", err)
		}
		application, err := decodeStoredApplication(transaction.tenantID, resourceVersion, document)
		if err != nil {
			return nil, err
		}
		if application.Metadata.ID <= after ||
			(len(applications) > 0 && application.Metadata.ID <= applications[len(applications)-1].Metadata.ID) {
			return nil, errors.New("stored Application directory order mismatch")
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Application directory: %w", err)
	}
	return applications, nil
}

func (transaction *applicationTransaction) LoadApplications(
	ctx context.Context,
	ids []paasv1.ResourceID,
) ([]paasv1.Application, error) {
	if ids == nil || len(ids) > paasv1.ApplicationDirectoryPageSize {
		return nil, errors.New("Application snapshot identifiers are invalid")
	}
	values := make([]string, len(ids))
	for index, id := range ids {
		if paasv1.ValidateID("application.id", string(id)) != nil ||
			(index > 0 && id <= ids[index-1]) {
			return nil, errors.New("Application snapshot identifiers are invalid")
		}
		values[index] = string(id)
	}
	if len(values) == 0 {
		return []paasv1.Application{}, nil
	}
	rows, err := transaction.tx.Query(ctx,
		`SELECT resource_version, document
		   FROM paas.applications
		  WHERE tenant_id = $1
		    AND id = ANY($2::text[])
		  ORDER BY id COLLATE "C" ASC`,
		string(transaction.tenantID), values)
	if err != nil {
		return nil, fmt.Errorf("load Application snapshot: %w", err)
	}
	defer rows.Close()
	applications := make([]paasv1.Application, 0, len(ids))
	for rows.Next() {
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan Application snapshot: %w", err)
		}
		application, err := decodeStoredApplication(transaction.tenantID, resourceVersion, document)
		if err != nil {
			return nil, err
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Application snapshot: %w", err)
	}
	return applications, nil
}

func (transaction *applicationTransaction) LoadApplicationForUpdate(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Application, bool, error) {
	return transaction.loadApplication(ctx, id, true)
}

func (transaction *applicationTransaction) loadApplication(
	ctx context.Context,
	id paasv1.ResourceID,
	forUpdate bool,
) (paasv1.Application, bool, error) {
	var resourceVersion uint64
	var document []byte
	query := `SELECT resource_version, document
		   FROM paas.applications
		  WHERE tenant_id = $1 AND id = $2`
	arguments := []any{string(transaction.tenantID), string(id)}
	if forUpdate {
		query = `SELECT resource_version, document
		           FROM paas.load_application_for_update($1)`
		arguments = []any{string(id)}
	}
	err := transaction.tx.QueryRow(
		ctx,
		query,
		arguments...,
	).Scan(&resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Application{}, false, nil
	}
	if err != nil {
		return paasv1.Application{}, false, fmt.Errorf("load Application: %w", err)
	}
	value, err := decodeStoredApplication(transaction.tenantID, resourceVersion, document)
	if err != nil {
		return paasv1.Application{}, false, err
	}
	if value.Metadata.ID != id {
		return paasv1.Application{}, false, errors.New("stored Application relational identity mismatch")
	}
	return value, true, nil
}

func decodeStoredApplication(
	tenantID paasv1.TenantID,
	resourceVersion uint64,
	document []byte,
) (paasv1.Application, error) {
	var value paasv1.Application
	if err := decodeDocument("Application", document, &value); err != nil {
		return paasv1.Application{}, err
	}
	if err := paasv1.ValidateApplication(value); err != nil {
		return paasv1.Application{}, fmt.Errorf("validate stored Application: %w", err)
	}
	if value.Metadata.Scope.TenantID != tenantID || value.Metadata.ResourceVersion != resourceVersion {
		return paasv1.Application{}, errors.New("stored Application relational identity mismatch")
	}
	return value, nil
}

func (transaction *applicationTransaction) LoadConfiguration(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Configuration, bool, error) {
	var applicationID string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT application_id, resource_version, document
		   FROM paas.configurations
		  WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&applicationID, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Configuration{}, false, nil
	}
	if err != nil {
		return paasv1.Configuration{}, false, fmt.Errorf("load Configuration: %w", err)
	}
	var value paasv1.Configuration
	if err := decodeDocument("Configuration", document, &value); err != nil {
		return paasv1.Configuration{}, false, err
	}
	if err := paasv1.ValidateConfiguration(value); err != nil {
		return paasv1.Configuration{}, false, fmt.Errorf("validate stored Configuration: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion ||
		string(value.ApplicationID) != applicationID {
		return paasv1.Configuration{}, false, errors.New("stored Configuration relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *applicationTransaction) LoadConfigurationRevision(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.ConfigurationRevision, bool, error) {
	var configurationID string
	var contentDigest string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT configuration_id, content_digest, resource_version, document
		   FROM paas.configuration_revisions
		  WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&configurationID, &contentDigest, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.ConfigurationRevision{}, false, nil
	}
	if err != nil {
		return paasv1.ConfigurationRevision{}, false,
			fmt.Errorf("load ConfigurationRevision: %w", err)
	}
	var value paasv1.ConfigurationRevision
	if err := decodeDocument("ConfigurationRevision", document, &value); err != nil {
		return paasv1.ConfigurationRevision{}, false, err
	}
	if err := paasv1.ValidateConfigurationRevision(value); err != nil {
		return paasv1.ConfigurationRevision{}, false,
			fmt.Errorf("validate stored ConfigurationRevision: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion ||
		string(value.Spec.ConfigurationID) != configurationID ||
		value.Spec.ContentDigest != contentDigest {
		return paasv1.ConfigurationRevision{}, false,
			errors.New("stored ConfigurationRevision relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *applicationTransaction) LoadOperation(
	ctx context.Context,
	id paasv1.OperationID,
) (paasv1.Operation, bool, error) {
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT document
		   FROM paas.operations
		  WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Operation{}, false, nil
	}
	if err != nil {
		return paasv1.Operation{}, false, fmt.Errorf("load Operation: %w", err)
	}
	var value paasv1.Operation
	if err := decodeDocument("Operation", document, &value); err != nil {
		return paasv1.Operation{}, false, err
	}
	if err := paasv1.ValidateOperation(value); err != nil {
		return paasv1.Operation{}, false, fmt.Errorf("validate stored Operation: %w", err)
	}
	if value.ID != id || value.Scope.TenantID != transaction.tenantID {
		return paasv1.Operation{}, false, errors.New("stored Operation relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *applicationTransaction) CreateApplication(
	ctx context.Context,
	value paasv1.Application,
	submission applicationlifecycle.ResourceSubmission,
) error {
	return transaction.createResource(ctx, "Application", value.Metadata.ID, value, submission)
}

func (transaction *applicationTransaction) UpdateApplicationLabel(
	ctx context.Context,
	submission applicationlifecycle.ApplicationLabelSubmission,
) error {
	if err := validateApplicationLabelSubmission(transaction.tenantID, submission); err != nil {
		return err
	}
	resourceDocument, err := json.Marshal(submission.Application)
	if err != nil {
		return fmt.Errorf("encode Application document: %w", err)
	}
	operationDocument, err := json.Marshal(submission.Operation)
	if err != nil {
		return fmt.Errorf("encode Operation document: %w", err)
	}
	auditDocument, err := json.Marshal(submission.AuditEvent)
	if err != nil {
		return fmt.Errorf("encode Audit event: %w", err)
	}
	if _, err := transaction.tx.Exec(ctx,
		`SELECT paas.update_application_label($1::jsonb, $2::jsonb, $3::jsonb, $4::bigint)`,
		resourceDocument, operationDocument, auditDocument, submission.ExpectedResourceVersion); err != nil {
		return fmt.Errorf("update Application label with Operation and Audit event: %w", err)
	}
	return nil
}

func validateApplicationLabelSubmission(
	tenantID paasv1.TenantID,
	submission applicationlifecycle.ApplicationLabelSubmission,
) error {
	application := submission.Application
	operation := submission.Operation
	auditEvent := submission.AuditEvent
	var problems []error
	problems = append(problems, paasv1.ValidateApplication(application), paasv1.ValidateOperation(operation), audit.ValidateEvent(auditEvent))
	if application.Metadata.Scope.TenantID != tenantID || operation.Scope.TenantID != tenantID ||
		operation.Target != (paasv1.ResourceRef{Kind: "Application", ID: application.Metadata.ID}) ||
		(operation.Action != paasv1.OperationSetApplicationLabel && operation.Action != paasv1.OperationDeleteApplicationLabel) ||
		auditEvent.TenantID != tenantID || auditEvent.Target != operation.Target ||
		auditEvent.OperationID != operation.ID || !auditEvent.Actor.Equal(operation.RequestedBy) ||
		auditEvent.RequestDigest != operation.RequestDigest || !auditEvent.OccurredAt.Equal(operation.CreatedAt) {
		problems = append(problems, errors.New("Application label submission identities do not match"))
	}
	if submission.ExpectedResourceVersion == 0 || submission.ExpectedResourceVersion > 9007199254740991 ||
		application.Metadata.ResourceVersion != submission.ExpectedResourceVersion+1 {
		problems = append(problems, errors.New("Application label submission resource version is invalid"))
	}
	return errors.Join(problems...)
}

func (transaction *applicationTransaction) CreateConfiguration(
	ctx context.Context,
	value paasv1.Configuration,
	submission applicationlifecycle.ResourceSubmission,
) error {
	return transaction.createResource(ctx, "Configuration", value.Metadata.ID, value, submission)
}

func (transaction *applicationTransaction) CreateConfigurationRevision(
	ctx context.Context,
	value paasv1.ConfigurationRevision,
	submission applicationlifecycle.ResourceSubmission,
) error {
	return transaction.createResource(ctx, "ConfigurationRevision", value.Metadata.ID, value, submission)
}

func (transaction *applicationTransaction) CreateApplicationRevision(
	ctx context.Context,
	value paasv1.ApplicationRevision,
	submission applicationlifecycle.ResourceSubmission,
) error {
	return transaction.createResource(ctx, "ApplicationRevision", value.Metadata.ID, value, submission)
}

func (transaction *applicationTransaction) createResource(
	ctx context.Context,
	kind string,
	id paasv1.ResourceID,
	value any,
	submission applicationlifecycle.ResourceSubmission,
) error {
	if err := validateResourceSubmission(transaction.tenantID, kind, id, value, submission); err != nil {
		return err
	}
	resourceDocument, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s document: %w", kind, err)
	}
	operationDocument, err := json.Marshal(submission.Operation)
	if err != nil {
		return fmt.Errorf("encode Operation document: %w", err)
	}
	auditDocument, err := json.Marshal(submission.AuditEvent)
	if err != nil {
		return fmt.Errorf("encode Audit event: %w", err)
	}
	if _, err := transaction.tx.Exec(
		ctx,
		`SELECT paas.create_apphosting_resource($1::jsonb, $2::jsonb, $3::jsonb)`,
		resourceDocument, operationDocument, auditDocument,
	); err != nil {
		return fmt.Errorf("create %s with Operation and Audit event: %w", kind, err)
	}
	return nil
}

func validateResourceSubmission(
	tenantID paasv1.TenantID,
	kind string,
	id paasv1.ResourceID,
	value any,
	submission applicationlifecycle.ResourceSubmission,
) error {
	var resourceErr error
	var expectedAction paasv1.OperationAction
	switch typed := value.(type) {
	case paasv1.Application:
		resourceErr, expectedAction = paasv1.ValidateApplication(typed), paasv1.OperationCreateApplication
	case paasv1.Configuration:
		resourceErr, expectedAction = paasv1.ValidateConfiguration(typed), paasv1.OperationCreateConfiguration
	case paasv1.ConfigurationRevision:
		resourceErr, expectedAction = paasv1.ValidateConfigurationRevision(typed), paasv1.OperationCreateConfigurationRevision
	case paasv1.ApplicationRevision:
		resourceErr, expectedAction = paasv1.ValidateApplicationRevision(typed), paasv1.OperationCreateApplicationRevision
	default:
		resourceErr = fmt.Errorf("unsupported apphosting resource %T", value)
	}
	operation := submission.Operation
	auditEvent := submission.AuditEvent
	var problems []error
	problems = append(problems, resourceErr, paasv1.ValidateOperation(operation), audit.ValidateEvent(auditEvent))
	if operation.Scope.TenantID != tenantID || operation.Target.Kind != kind ||
		operation.Target.ID != id || operation.Action != expectedAction ||
		operation.State != paasv1.OperationSucceeded ||
		auditEvent.TenantID != tenantID || auditEvent.Target != operation.Target ||
		auditEvent.OperationID != operation.ID || !auditEvent.Actor.Equal(operation.RequestedBy) ||
		auditEvent.RequestDigest != operation.RequestDigest ||
		!auditEvent.OccurredAt.Equal(operation.CreatedAt) {
		problems = append(problems, errors.New("resource, Operation, and Audit identities do not match"))
	}
	return errors.Join(problems...)
}
