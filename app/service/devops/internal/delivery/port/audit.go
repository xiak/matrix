package port

import (
	"context"
	"errors"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

var (
	ErrAuditInvalid         = errors.New("Audit ingestion rejected the DevOps event")
	ErrAuditUnauthenticated = errors.New("Audit ingestion authentication failed")
	ErrAuditConflict        = errors.New("Audit ingestion replay conflicts")
	ErrAuditUnavailable     = errors.New("Audit ingestion is unavailable")
)

type AuditIngestor interface {
	Ready(context.Context) error
	Ingest(context.Context, auditv1.Event) error
}
