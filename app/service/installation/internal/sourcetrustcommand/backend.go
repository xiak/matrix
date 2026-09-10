// Package sourcetrustcommand owns the installation-operator workflow for
// applying and removing endpoint-scoped DevOps source-provider trust.
package sourcetrustcommand

import (
	"context"
	"errors"
	"path/filepath"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/installedrelease"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/release"
)

var (
	ErrEffectInput          = errors.New("source trust input is invalid")
	ErrEffectConflict       = errors.New("source trust filesystem ownership conflicts")
	ErrEffectVerification   = errors.New("source trust material verification failed")
	ErrEffectUnavailable    = errors.New("source trust filesystem is unavailable")
	ErrEffectOutcomeUnknown = errors.New("source trust mutation outcome is unknown")
)

type ResultState string

const (
	StateApplied   ResultState = "APPLIED"
	StateUnchanged ResultState = "UNCHANGED"
	StateRemoved   ResultState = "REMOVED"
)

type ApplyPlan struct {
	Root           string
	Scope          devopsv1.ResourceScope
	EndpointOrigin string
	FromFile       string
}

type RemovePlan struct {
	Root           string
	Scope          devopsv1.ResourceScope
	EndpointOrigin string
}

type Effects interface {
	ApplySourceTrust(context.Context, ApplyPlan) (ResultState, error)
	RemoveSourceTrust(context.Context, RemovePlan) (ResultState, error)
}

type Backend struct {
	effects Effects
}

func NewBackend(effects Effects) (*Backend, error) {
	if effects == nil {
		return nil, errors.New("source trust effects are required")
	}
	return &Backend{effects: effects}, nil
}

func (backend *Backend) RunSourceTrust(
	ctx context.Context,
	request cli.SourceTrustRequest,
) (result cli.SourceTrustResult, returnErr error) {
	if backend == nil || backend.effects == nil {
		return cli.SourceTrustResult{}, fault(cli.FaultInternal, "BACKEND_UNAVAILABLE")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return cli.SourceTrustResult{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	scope, err := validateRequest(request)
	if err != nil {
		return cli.SourceTrustResult{}, fault(cli.FaultInvalidArgument, "SOURCE_TRUST_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.SourceTrustResult{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.SourceTrustResult{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := session.Read()
	if err != nil {
		return cli.SourceTrustResult{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil {
		return cli.SourceTrustResult{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	}
	if state.CurrentReleaseID == "" {
		return cli.SourceTrustResult{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	bundle, err := installedrelease.AuthenticateCurrent(session.Root(), state)
	if err != nil {
		return cli.SourceTrustResult{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	if !bundle.Manifest.IncludesProduct(release.ProductDevOps) {
		return cli.SourceTrustResult{}, fault(cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	}

	var effectState ResultState
	switch request.Operation {
	case cli.SourceTrustApply:
		effectState, err = backend.effects.ApplySourceTrust(ctx, ApplyPlan{
			Root: session.Root(), Scope: scope, EndpointOrigin: request.EndpointOrigin,
			FromFile: request.FromFile,
		})
	case cli.SourceTrustRemove:
		effectState, err = backend.effects.RemoveSourceTrust(ctx, RemovePlan{
			Root: session.Root(), Scope: scope, EndpointOrigin: request.EndpointOrigin,
		})
	}
	if err != nil {
		if ctx.Err() != nil {
			return cli.SourceTrustResult{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.SourceTrustResult{}, effectFault(err)
	}
	if !validResultState(request.Operation, effectState) {
		return cli.SourceTrustResult{}, fault(cli.FaultInternal, "SOURCE_TRUST_RESULT_INVALID")
	}
	return cli.SourceTrustResult{
		State: string(effectState), TenantID: request.TenantID,
		EndpointOrigin: request.EndpointOrigin,
	}, nil
}

func validateRequest(request cli.SourceTrustRequest) (devopsv1.ResourceScope, error) {
	scope := devopsv1.ResourceScope{TenantID: devopsv1.TenantID(request.TenantID)}
	if request.Root == "" || devopsv1.ValidateResourceScope(scope) != nil ||
		devopsv1.ValidateEndpointOrigin(request.EndpointOrigin) != nil {
		return devopsv1.ResourceScope{}, errors.New("source trust request is invalid")
	}
	switch request.Operation {
	case cli.SourceTrustApply:
		if request.FromFile == "" || !filepath.IsAbs(request.FromFile) ||
			filepath.Clean(request.FromFile) != request.FromFile {
			return devopsv1.ResourceScope{}, errors.New("source trust input path is invalid")
		}
	case cli.SourceTrustRemove:
		if request.FromFile != "" {
			return devopsv1.ResourceScope{}, errors.New("source trust removal is invalid")
		}
	default:
		return devopsv1.ResourceScope{}, errors.New("source trust operation is invalid")
	}
	return scope, nil
}

func validResultState(operation cli.SourceTrustOperation, state ResultState) bool {
	switch operation {
	case cli.SourceTrustApply:
		return state == StateApplied || state == StateUnchanged
	case cli.SourceTrustRemove:
		return state == StateRemoved
	default:
		return false
	}
}

func acquireFault(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	case errors.Is(err, journal.ErrNotInitialized):
		return fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	case errors.Is(err, journal.ErrOwnershipConflict):
		return fault(cli.FaultConflict, "INSTALLATION_ROOT_CONFLICT")
	case errors.Is(err, journal.ErrIntegrity):
		return fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	default:
		return fault(cli.FaultPrecondition, "INSTALLATION_ROOT_INVALID")
	}
}

func effectFault(err error) error {
	switch {
	case errors.Is(err, ErrEffectInput):
		return fault(cli.FaultInvalidArgument, "SOURCE_TRUST_INPUT_INVALID")
	case errors.Is(err, ErrEffectConflict):
		return fault(cli.FaultConflict, "SOURCE_TRUST_OWNERSHIP_CONFLICT")
	case errors.Is(err, ErrEffectVerification):
		return fault(cli.FaultVerification, "SOURCE_TRUST_STATE_INVALID")
	case errors.Is(err, ErrEffectOutcomeUnknown):
		return fault(cli.FaultUnavailable, "SOURCE_TRUST_OUTCOME_UNKNOWN")
	case errors.Is(err, ErrEffectUnavailable):
		return fault(cli.FaultUnavailable, "SOURCE_TRUST_STORAGE_UNAVAILABLE")
	default:
		return fault(cli.FaultInternal, "SOURCE_TRUST_OPERATION_FAILED")
	}
}

func fault(class cli.FaultClass, code string) *cli.Fault {
	value, err := cli.NewFault(class, code)
	if err != nil {
		panic("static source trust fault is invalid")
	}
	return value
}
