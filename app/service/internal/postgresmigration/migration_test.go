package postgresmigration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type executorFunc func(context.Context, string, ...any) (pgconn.CommandTag, error)

func (function executorFunc) Exec(
	ctx context.Context,
	statement string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	return function(ctx, statement, arguments...)
}

func TestUpClassifiesOnlyDeadlocksAsRetryable(t *testing.T) {
	t.Parallel()
	source := Source{Context: "paas", UpSQL: "SELECT 1", VerifySQL: "SELECT 1"}

	deadlock := executorFunc(func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "40P01"}
	})
	err := Up(context.Background(), deadlock, source)
	if !errors.Is(err, retryableApplyFailure) {
		t.Fatalf("classify deadlock: %v", err)
	}
	if err.Error() != "PostgreSQL migration apply failed" {
		t.Fatalf("normalized deadlock: %q", err)
	}

	constraint := executorFunc(func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
	})
	err = Up(context.Background(), constraint, source)
	if err == nil || errors.Is(err, retryableApplyFailure) {
		t.Fatalf("classify non-retryable failure: %v", err)
	}
}

func TestRetryMigrationApplyConvergesWithinBound(t *testing.T) {
	t.Parallel()
	attempts := 0
	err := retryMigrationApply(func() error {
		attempts++
		if attempts < maximumApplyAttempts {
			return retryableApplyFailure
		}
		return nil
	})
	if err != nil || attempts != maximumApplyAttempts {
		t.Fatalf("retry migration apply: attempts=%d err=%v", attempts, err)
	}
}

func TestRetryMigrationApplyStopsAtBound(t *testing.T) {
	t.Parallel()
	attempts := 0
	err := retryMigrationApply(func() error {
		attempts++
		return retryableApplyFailure
	})
	if !errors.Is(err, retryableApplyFailure) || attempts != maximumApplyAttempts {
		t.Fatalf("bound migration apply: attempts=%d err=%v", attempts, err)
	}
}

func TestRetryMigrationApplyDoesNotRetryPermanentFailure(t *testing.T) {
	t.Parallel()
	attempts := 0
	permanent := errors.New("permanent")
	err := retryMigrationApply(func() error {
		attempts++
		return permanent
	})
	if !errors.Is(err, permanent) || attempts != 1 {
		t.Fatalf("permanent migration apply: attempts=%d err=%v", attempts, err)
	}
}
