package runnersandboxdocker

import (
	"context"
	"errors"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

var _ port.RunnerSandbox = (*Sandbox)(nil)

// Sandbox exposes the closed runner port while Client retains the private
// Docker Engine protocol and container-plan vocabulary.
type Sandbox struct {
	client *Client
}

func NewSandbox(client *Client) (*Sandbox, error) {
	if client == nil || client.httpClient == nil || client.storageFree == nil {
		return nil, ErrInvalid
	}
	return &Sandbox{client: client}, nil
}

func (sandbox *Sandbox) Create(ctx context.Context, reference port.RunnerStepReference) error {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return err
	}
	return sandbox.client.CreateStep(ctx, plan)
}

func (sandbox *Sandbox) Start(ctx context.Context, reference port.RunnerStepReference) error {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return err
	}
	return sandbox.client.StartStep(ctx, plan)
}

func (sandbox *Sandbox) Observe(
	ctx context.Context,
	reference port.RunnerStepReference,
) (port.RunnerSandboxState, error) {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return "", err
	}
	state, err := sandbox.client.ObserveStep(ctx, plan)
	if errors.Is(err, ErrStepNotFound) {
		return port.RunnerSandboxAbsent, nil
	}
	if err != nil {
		return "", err
	}
	return runnerState(state)
}

func (sandbox *Sandbox) Follow(
	ctx context.Context,
	reference port.RunnerStepReference,
	progress runnerlog.Progress,
) (port.RunnerSandboxResult, error) {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return port.RunnerSandboxResult{}, err
	}
	budget, err := ResumeLogBudget(progress)
	if err != nil {
		return port.RunnerSandboxResult{}, err
	}
	result, err := sandbox.client.FollowStep(ctx, plan, budget)
	if err != nil {
		return port.RunnerSandboxResult{}, err
	}
	next, err := budget.Progress()
	if err != nil {
		return port.RunnerSandboxResult{}, err
	}
	state, err := runnerState(result.State)
	if err != nil {
		return port.RunnerSandboxResult{}, err
	}
	return port.RunnerSandboxResult{
		State: state, Chunks: result.Chunks, LogProgress: next,
	}, nil
}

func (sandbox *Sandbox) Cancel(
	ctx context.Context,
	reference port.RunnerStepReference,
) (port.RunnerSandboxState, error) {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return "", err
	}
	state, err := sandbox.client.CancelStep(ctx, plan)
	if errors.Is(err, ErrStepNotFound) {
		return port.RunnerSandboxAbsent, nil
	}
	if err != nil {
		return "", err
	}
	return runnerState(state)
}

func (sandbox *Sandbox) Delete(ctx context.Context, reference port.RunnerStepReference) error {
	plan, err := sandbox.plan(reference)
	if err != nil {
		return err
	}
	return sandbox.client.DeleteStep(ctx, plan)
}

func (sandbox *Sandbox) plan(
	reference port.RunnerStepReference,
) (ContainerPlan, error) {
	if sandbox == nil || sandbox.client == nil {
		return ContainerPlan{}, ErrInvalid
	}
	return NewStepPlan(reference.EffectID, reference.Step, reference.SourceRoot)
}

func runnerState(value StepState) (port.RunnerSandboxState, error) {
	switch value {
	case StepCreated:
		return port.RunnerSandboxCreated, nil
	case StepRunning:
		return port.RunnerSandboxRunning, nil
	case StepPassed:
		return port.RunnerSandboxPassed, nil
	case StepFailed:
		return port.RunnerSandboxFailed, nil
	case StepCancelled:
		return port.RunnerSandboxCancelled, nil
	default:
		return "", ErrStepOutcomeUnknown
	}
}
