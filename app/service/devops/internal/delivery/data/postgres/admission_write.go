package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

func (transaction *admissionTransaction) CommitAdmission(
	ctx context.Context,
	value runadmission.Submission,
) error {
	if transaction == nil || transaction.tx == nil {
		return errors.New("run admission transaction is nil")
	}
	if err := runadmission.ValidateSubmission(value); err != nil {
		return fmt.Errorf("validate run admission submission: %w", err)
	}
	if err := validateAdmissionTenant(value.Admission, transaction.tenantID); err != nil {
		return err
	}
	eventDocument, err := json.Marshal(value.Admission.Event)
	if err != nil {
		return fmt.Errorf("encode SourceEvent: %w", err)
	}
	runDocuments, err := json.Marshal(value.Admission.Runs)
	if err != nil {
		return fmt.Errorf("encode PipelineRuns: %w", err)
	}
	auditDocuments, err := json.Marshal(value.AuditEvents)
	if err != nil {
		return fmt.Errorf("encode admission Audit facts: %w", err)
	}
	if _, err := transaction.tx.Exec(ctx,
		"SELECT delivery.commit_run_admission($1::jsonb, $2::jsonb, $3::jsonb)",
		eventDocument, runDocuments, auditDocuments,
	); err != nil {
		return fmt.Errorf("commit run admission: %w", err)
	}
	return nil
}

func validateAdmissionTenant(value runadmission.Admission, tenantID devopsv1.TenantID) error {
	if value.Event.Scope.TenantID != tenantID {
		return errors.New("SourceEvent tenant differs from transaction")
	}
	for _, run := range value.Runs {
		if run.Scope.TenantID != tenantID {
			return errors.New("PipelineRun tenant differs from transaction")
		}
	}
	return nil
}
