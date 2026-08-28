package platformcommand

import (
	"context"
	"errors"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

// NodeConnectionsPlan commits one private input and its exact predecessor.
// Only their digests enter the ordinary journal; staged bytes stay private.
type NodeConnectionsPlan struct {
	InstalledPlan
	CommandID      string
	InputDigest    string
	ExpectedDigest string
	Before         []byte
	After          []byte
}

func (NodeConnectionsPlan) String() string   { return "node controller replacement <redacted>" }
func (NodeConnectionsPlan) GoString() string { return "node controller replacement <redacted>" }
func (NodeConnectionsPlan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("node controller plan is private")
}
func (plan NodeConnectionsPlan) Clear() { clear(plan.Before); clear(plan.After) }

func (backend *Backend) configureNodes(ctx context.Context, request cli.Request) (result cli.Result, returnErr error) {
	if (request.Resume && (request.Configuration != "" || request.ExpectedConfigurationDigest != "")) ||
		(!request.Resume && (strings.TrimSpace(request.Configuration) == "" || strings.TrimSpace(request.Configuration) != request.Configuration ||
			paasv1.ValidateDigest("expectedConfigurationDigest", request.ExpectedConfigurationDigest) != nil)) {
		return cli.Result{}, fault(cli.FaultInvalidArgument, "NODE_CONNECTION_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.Result{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result, returnErr = cli.Result{}, fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := readPlatformJournal(session)
	if err != nil {
		return cli.Result{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.CurrentReleaseID == "" || (state.Last != nil && state.Last.Outcome == lifecycle.OutcomeManualIntervention) {
		return cli.Result{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	if state.Active != nil && state.Active.Command.Action != lifecycle.ActionConfigureNodes {
		return cli.Result{}, lifecycleFault(lifecycle.ErrCommandInProgress)
	}
	previous := state.Active
	if previous == nil && state.Last != nil && state.Last.Command.Action == lifecycle.ActionConfigureNodes {
		previous = state.Last
	}
	if request.Resume && previous == nil {
		return cli.Result{}, fault(cli.FaultPrecondition, "NODE_CONNECTION_NOT_PENDING")
	}
	installed := installedPlan(session.Root(), state)
	plan, err := backend.effects.PrepareNodeConnections(ctx, installed, request.Configuration, request.ExpectedConfigurationDigest, previous)
	if err != nil {
		if ctx.Err() != nil {
			return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.Result{}, effectFault(lifecycle.PhaseStaging, err)
	}
	defer plan.Clear()
	if plan.InstalledPlan != installed || paasv1.ValidateDigest("inputDigest", plan.InputDigest) != nil ||
		paasv1.ValidateDigest("expectedDigest", plan.ExpectedDigest) != nil {
		return cli.Result{}, fault(cli.FaultVerification, "NODE_CONNECTION_PLAN_INVALID")
	}
	if plan.InputDigest == plan.ExpectedDigest {
		if state.Active != nil {
			return cli.Result{}, fault(cli.FaultConflict, "NODE_CONNECTION_CONFLICT")
		}
		result := statusResult(state)
		result.ConfigurationDigest = plan.InputDigest
		return result, nil
	}
	if plan.CommandID == "" {
		plan.CommandID, err = randomIdentity(backend.entropy, "cmd")
		if err != nil {
			return cli.Result{}, fault(cli.FaultInternal, "COMMAND_ID_UNAVAILABLE")
		}
	}
	started, err := lifecycle.Start(state, lifecycle.Command{ID: plan.CommandID, Action: lifecycle.ActionConfigureNodes,
		InputDigest: plan.InputDigest, ExpectedConfigurationDigest: plan.ExpectedDigest, RequestedAt: canonicalNow(backend.now())})
	if err != nil {
		return cli.Result{}, lifecycleFault(err)
	}
	if started.Replay == lifecycle.ReplayCompleted {
		result, err := operationResult(started.Journal, started.Execution, false)
		result.ConfigurationDigest = plan.InputDigest
		return result, err
	}
	if started.Replay == lifecycle.ReplayNone {
		if err := session.Write(started.Journal); err != nil {
			return cli.Result{}, stateWriteFault(err)
		}
	}
	for {
		state, err := readPlatformJournal(session)
		if err != nil || state.Active == nil || state.Active.Command.ID != plan.CommandID ||
			state.Active.Command.Action != lifecycle.ActionConfigureNodes || state.Active.Command.InputDigest != plan.InputDigest ||
			state.Active.Command.ExpectedConfigurationDigest != plan.ExpectedDigest {
			return cli.Result{}, fault(cli.FaultVerification, "NODE_CONNECTION_STATE_INVALID")
		}
		execution := *state.Active
		if err := backend.effects.ApplyNodeConnectionsPhase(ctx, plan, execution.Phase); err != nil {
			// Replacing management credentials is one-way. Never restore old
			// trust on failure; retain this exact intent for bounded resume.
			if ctx.Err() != nil {
				return cli.Result{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
			}
			return cli.Result{}, effectFault(execution.Phase, err)
		}
		next, ok := lifecycle.NextPhase(state)
		if !ok {
			return cli.Result{}, fault(cli.FaultInternal, "NODE_CONNECTION_PHASE_INVALID")
		}
		advanced, err := lifecycle.Advance(state, plan.CommandID, next, nextJournalTime(backend.now(), execution.UpdatedAt))
		if err != nil || session.Write(advanced) != nil {
			return cli.Result{}, fault(cli.FaultInternal, "NODE_CONNECTION_STATE_COMMIT_FAILED")
		}
		if advanced.Active == nil {
			result, err := operationResult(advanced, *advanced.Last, true)
			result.ConfigurationDigest = plan.InputDigest
			return result, err
		}
	}
}
