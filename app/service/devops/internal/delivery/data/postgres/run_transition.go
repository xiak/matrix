package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runaudit"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

func prepareRunTransition(
	ctx context.Context,
	tx pgx.Tx,
	lease runlifecycle.Lease,
	state devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
) (devopsv1.PipelineRun, []byte, any, any, error) {
	var effectiveNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT greatest(transaction_timestamp(), $1::timestamptz + interval '1 microsecond')`,
		lease.Run.UpdatedAt,
	).Scan(&effectiveNow); err != nil {
		return devopsv1.PipelineRun{}, nil, nil, nil,
			fmt.Errorf("read PipelineRun transition time: %w", err)
	}
	expected, err := domain.AdvancePipelineRun(
		lease.Run, state, reason, effectiveNow.UTC(),
	)
	if err != nil {
		return devopsv1.PipelineRun{}, nil, nil, nil,
			fmt.Errorf("advance PipelineRun task: %w", runlifecycle.ErrInvalidTransition)
	}
	runDocument, err := json.Marshal(expected)
	if err != nil {
		return devopsv1.PipelineRun{}, nil, nil, nil,
			fmt.Errorf("encode PipelineRun transition: %w", err)
	}
	var auditDocument any
	if expected.Status.CompletedAt != nil {
		event, eventErr := runaudit.NewTerminalEvent(
			expected, lease.Intent.CommandID, runaudit.WorkerActorID,
		)
		if eventErr != nil {
			return devopsv1.PipelineRun{}, nil, nil, nil,
				fmt.Errorf("build PipelineRun terminal Audit fact: %w", eventErr)
		}
		auditDocument, err = json.Marshal(event)
		if err != nil {
			return devopsv1.PipelineRun{}, nil, nil, nil,
				fmt.Errorf("encode PipelineRun terminal Audit fact: %w", err)
		}
	}
	var reasonValue any
	if reason != "" {
		reasonValue = reason
	}
	return expected, runDocument, auditDocument, reasonValue, nil
}

func decodePipelineRun(document []byte) (devopsv1.PipelineRun, error) {
	var run devopsv1.PipelineRun
	if err := decodeDocument("PipelineRun", document, &run); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("validate stored PipelineRun: %w", err)
	}
	return run, nil
}

func validateDatabaseDeferral(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return errors.New("PipelineRun next observation time is invalid")
	}
	return nil
}

func mapRunLifecycleError(action string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX412":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrStaleLease)
		case "MX410":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrReconciliationExhausted)
		case "55000":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrInvalidTransition)
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}
