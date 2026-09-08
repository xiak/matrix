// Package sourcecredentialcommand owns the installation-operator workflow for
// applying and retiring DevOps source credentials.
package sourcecredentialcommand

import (
	"context"
	"errors"
	"path/filepath"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/installedrelease"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/release"
)

var (
	ErrEffectInput          = errors.New("source credential input is invalid")
	ErrEffectNotFound       = errors.New("source credential material is absent")
	ErrEffectConflict       = errors.New("source credential filesystem ownership conflicts")
	ErrEffectVerification   = errors.New("source credential material verification failed")
	ErrEffectUnavailable    = errors.New("source credential filesystem is unavailable")
	ErrEffectOutcomeUnknown = errors.New("source credential replacement outcome is unknown")
)

type ResultState string

const (
	StateApplied         ResultState = "APPLIED"
	StateUnchanged       ResultState = "UNCHANGED"
	StatePreviousRetired ResultState = "PREVIOUS_RETIRED"
)

type ApplyPlan struct {
	Root      string
	Scope     devopsv1.ResourceScope
	Purpose   sourcecredential.Purpose
	Reference devopsv1.ResourceID
	FromFile  string
}

type RetirePreviousPlan struct {
	Root      string
	Scope     devopsv1.ResourceScope
	Reference devopsv1.ResourceID
}

type Effects interface {
	ApplySourceCredential(context.Context, ApplyPlan) (ResultState, error)
	RetirePreviousSourceCredential(context.Context, RetirePreviousPlan) (ResultState, error)
}

type Backend struct {
	effects Effects
}

func NewBackend(effects Effects) (*Backend, error) {
	if effects == nil {
		return nil, errors.New("source credential effects are required")
	}
	return &Backend{effects: effects}, nil
}

func (backend *Backend) RunSourceCredential(
	ctx context.Context,
	request cli.SourceCredentialRequest,
) (result cli.SourceCredentialResult, returnErr error) {
	if backend == nil || backend.effects == nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultInternal, "BACKEND_UNAVAILABLE")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	scope, reference, err := validateRequest(request)
	if err != nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultInvalidArgument, "SOURCE_CREDENTIAL_INPUT_INVALID")
	}
	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.SourceCredentialResult{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.SourceCredentialResult{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := session.Read()
	if err != nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	}
	if state.CurrentReleaseID == "" {
		return cli.SourceCredentialResult{}, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	bundle, err := installedrelease.AuthenticateCurrent(session.Root(), state)
	if err != nil {
		return cli.SourceCredentialResult{}, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	if !bundle.Manifest.IncludesProduct(release.ProductDevOps) {
		return cli.SourceCredentialResult{}, fault(cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	}

	var effectState ResultState
	switch request.Operation {
	case cli.SourceCredentialApply:
		effectState, err = backend.effects.ApplySourceCredential(ctx, ApplyPlan{
			Root: session.Root(), Scope: scope, Purpose: request.Purpose,
			Reference: reference, FromFile: request.FromFile,
		})
	case cli.SourceCredentialRetirePrevious:
		effectState, err = backend.effects.RetirePreviousSourceCredential(
			ctx,
			RetirePreviousPlan{
				Root: session.Root(), Scope: scope, Reference: reference,
			},
		)
	}
	if err != nil {
		if ctx.Err() != nil {
			return cli.SourceCredentialResult{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
		}
		return cli.SourceCredentialResult{}, effectFault(err)
	}
	if !validResultState(request.Operation, effectState) {
		return cli.SourceCredentialResult{}, fault(cli.FaultInternal, "SOURCE_CREDENTIAL_RESULT_INVALID")
	}
	return cli.SourceCredentialResult{
		State: string(effectState), Purpose: request.Purpose,
		TenantID: request.TenantID, Reference: request.Reference,
	}, nil
}

func validateRequest(
	request cli.SourceCredentialRequest,
) (devopsv1.ResourceScope, devopsv1.ResourceID, error) {
	scope := devopsv1.ResourceScope{TenantID: devopsv1.TenantID(request.TenantID)}
	reference := devopsv1.ResourceID(request.Reference)
	if request.Root == "" || errors.Join(
		sourcecredential.ValidatePurpose(request.Purpose),
		devopsv1.ValidateResourceScope(scope),
		devopsv1.ValidateID("sourceCredentialRef", request.Reference),
	) != nil {
		return devopsv1.ResourceScope{}, "", errors.New("source credential request is invalid")
	}
	switch request.Operation {
	case cli.SourceCredentialApply:
		if request.FromFile == "" || !filepath.IsAbs(request.FromFile) ||
			filepath.Clean(request.FromFile) != request.FromFile {
			return devopsv1.ResourceScope{}, "", errors.New("source credential input path is invalid")
		}
	case cli.SourceCredentialRetirePrevious:
		if request.Purpose != sourcecredential.PurposeWebhook || request.FromFile != "" {
			return devopsv1.ResourceScope{}, "", errors.New("source credential retirement is invalid")
		}
	default:
		return devopsv1.ResourceScope{}, "", errors.New("source credential operation is invalid")
	}
	return scope, reference, nil
}

func validResultState(operation cli.SourceCredentialOperation, state ResultState) bool {
	switch operation {
	case cli.SourceCredentialApply:
		return state == StateApplied || state == StateUnchanged
	case cli.SourceCredentialRetirePrevious:
		return state == StatePreviousRetired
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
		return fault(cli.FaultInvalidArgument, "SOURCE_CREDENTIAL_INPUT_INVALID")
	case errors.Is(err, ErrEffectNotFound):
		return fault(cli.FaultPrecondition, "SOURCE_CREDENTIAL_NOT_APPLIED")
	case errors.Is(err, ErrEffectConflict):
		return fault(cli.FaultConflict, "SOURCE_CREDENTIAL_OWNERSHIP_CONFLICT")
	case errors.Is(err, ErrEffectVerification):
		return fault(cli.FaultVerification, "SOURCE_CREDENTIAL_STATE_INVALID")
	case errors.Is(err, ErrEffectOutcomeUnknown):
		return fault(cli.FaultUnavailable, "SOURCE_CREDENTIAL_OUTCOME_UNKNOWN")
	case errors.Is(err, ErrEffectUnavailable):
		return fault(cli.FaultUnavailable, "SOURCE_CREDENTIAL_STORAGE_UNAVAILABLE")
	default:
		return fault(cli.FaultInternal, "SOURCE_CREDENTIAL_OPERATION_FAILED")
	}
}

func fault(class cli.FaultClass, code string) *cli.Fault {
	value, err := cli.NewFault(class, code)
	if err != nil {
		panic("static source credential fault is invalid")
	}
	return value
}
