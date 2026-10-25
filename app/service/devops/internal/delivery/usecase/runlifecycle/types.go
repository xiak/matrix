// Package runlifecycle owns durable PipelineRun stage coordination. It stores
// one deterministic command intent before an adapter effect and requires a
// current lease fence for every result.
package runlifecycle

import (
	"errors"
	"strconv"
	"strings"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	MaximumReconciliationAttempts = uint64(10)
	MaximumActiveRuns             = uint64(2)
	maximumTaskAttempts           = uint64(100)
)

var (
	ErrStaleLease              = errors.New("PipelineRun task lease or fencing token is stale")
	ErrInvalidTransition       = errors.New("PipelineRun task transition is invalid")
	ErrReconciliationExhausted = errors.New("PipelineRun reconciliation attempts are exhausted")
)

type ClaimMode string

const (
	ClaimExecute ClaimMode = "EXECUTE"
	ClaimObserve ClaimMode = "OBSERVE"
)

// TaskIntent is the smallest durable effect identity. Stage-specific adapters
// will derive their closed command from this identity and the immutable run
// input; retries never substitute a new run or revision.
type TaskIntent struct {
	CommandID   string
	RunID       devopsv1.ResourceID
	InputDigest string
	Stage       devopsv1.PipelineRunStage
	Attempt     uint64
}

type Lease struct {
	TenantID               devopsv1.TenantID
	Run                    devopsv1.PipelineRun
	Intent                 TaskIntent
	Mode                   ClaimMode
	WorkerID               string
	FencingToken           uint64
	LeaseExpiresAt         time.Time
	ReconciliationAttempts uint64
}

type LeaseGuard struct {
	TenantID     devopsv1.TenantID
	RunID        devopsv1.ResourceID
	CommandID    string
	WorkerID     string
	FencingToken uint64
}

func (lease Lease) Guard() LeaseGuard {
	return LeaseGuard{
		TenantID:     lease.TenantID,
		RunID:        lease.Run.ID,
		CommandID:    lease.Intent.CommandID,
		WorkerID:     lease.WorkerID,
		FencingToken: lease.FencingToken,
	}
}

type Reconciliation struct {
	Lease         Lease
	NextAttemptAt time.Time
}

func TaskCommandID(
	runID devopsv1.ResourceID,
	stage devopsv1.PipelineRunStage,
	attempt uint64,
) string {
	return string(runID) + ":" + strings.ToLower(string(stage)) + ":" + strconv.FormatUint(attempt, 10)
}
