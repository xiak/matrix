// Package runnernodecommand owns the operator workflows that transfer the
// authenticated runner release, create node-local CSRs, and sign those CSRs
// from an idle DevOps-selected Matrix installation.
package runnernodecommand

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/installedrelease"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/release"
)

var (
	ErrEffectInput          = errors.New("runner node effect input is invalid")
	ErrEffectConflict       = errors.New("runner node filesystem ownership conflicts")
	ErrEffectVerification   = errors.New("runner node material verification failed")
	ErrEffectUnavailable    = errors.New("runner node dependency is unavailable")
	ErrEffectOutcomeUnknown = errors.New("runner node operation outcome is unknown")
)

type CreateRequestPlan struct {
	Root           string
	Bundle         release.VerifiedBundle
	InstallationID string
	NodeID         string
	Slots          uint8
	GatewayOrigin  string
	AuthorityPins  runnerenrollment.AuthorityPins
}

type ExportReleasePlan struct {
	Root           string
	InstallationID string
	Bundle         release.VerifiedBundle
	TrustBytes     []byte
	Output         string
}

type EnrollPlan struct {
	Root           string
	InstallationID string
	Bundle         release.VerifiedBundle
	Request        runnerenrollment.Request
	Output         string
}

type Effects interface {
	AuthenticateRunnerRelease(context.Context, string, string) (release.VerifiedBundle, error)
	CreateRunnerRequest(context.Context, CreateRequestPlan) (runnerenrollment.Request, error)
	ExportRunnerRelease(context.Context, ExportReleasePlan) (runnerenrollment.AuthorityPins, error)
	ReadRunnerRequest(context.Context, string) (runnerenrollment.Request, error)
	EnrollRunner(context.Context, EnrollPlan) (runnerenrollment.SignedEnrollment, error)
}

type Backend struct {
	effects Effects
}

func NewBackend(effects Effects) (*Backend, error) {
	if effects == nil {
		return nil, errors.New("runner node effects are required")
	}
	return &Backend{effects: effects}, nil
}

func (backend *Backend) RunRunnerNode(
	ctx context.Context,
	request cli.RunnerNodeRequest,
) (result cli.RunnerNodeResult, returnErr error) {
	if backend == nil || backend.effects == nil {
		return cli.RunnerNodeResult{}, fault(cli.FaultInternal, "BACKEND_UNAVAILABLE")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return cli.RunnerNodeResult{}, fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	}
	if err := validateRequest(request); err != nil {
		return cli.RunnerNodeResult{}, fault(cli.FaultInvalidArgument, "RUNNER_NODE_INPUT_INVALID")
	}
	if request.Operation == cli.RunnerNodeCreateRequest {
		bundle, err := backend.effects.AuthenticateRunnerRelease(
			ctx, request.Release, request.TrustKey,
		)
		if err != nil {
			return cli.RunnerNodeResult{}, effectFault(err)
		}
		created, err := backend.effects.CreateRunnerRequest(ctx, CreateRequestPlan{
			Root: request.Root, Bundle: bundle, InstallationID: request.InstallationID,
			NodeID: request.NodeID, Slots: request.Slots, GatewayOrigin: request.GatewayOrigin,
			AuthorityPins: runnerenrollment.AuthorityPins{
				ServerCAFingerprint: request.ServerCAPin,
				RunnerCAFingerprint: request.RunnerCAPin,
			},
		})
		if err != nil {
			return cli.RunnerNodeResult{}, effectFault(err)
		}
		if created.ReleaseID != bundle.Manifest.Release.ID ||
			created.InstallationID != request.InstallationID || created.NodeID != request.NodeID ||
			created.GatewayOrigin != request.GatewayOrigin || len(created.Slots) != int(request.Slots) ||
			created.AuthorityPins.ServerCAFingerprint != request.ServerCAPin ||
			created.AuthorityPins.RunnerCAFingerprint != request.RunnerCAPin ||
			runnerenrollment.ValidateRequest(created) != nil {
			return cli.RunnerNodeResult{}, fault(cli.FaultInternal, "RUNNER_REQUEST_RESULT_INVALID")
		}
		digest, err := runnerenrollment.RequestDigest(created)
		if err != nil {
			return cli.RunnerNodeResult{}, fault(cli.FaultInternal, "RUNNER_REQUEST_RESULT_INVALID")
		}
		return cli.RunnerNodeResult{
			State: "REQUESTED", ReleaseID: created.ReleaseID,
			InstallationID: created.InstallationID, NodeID: created.NodeID,
			Slots: uint8(len(created.Slots)), RequestDigest: digest,
		}, nil
	}

	session, err := journal.AcquireExisting(ctx, request.Root)
	if err != nil {
		return cli.RunnerNodeResult{}, acquireFault(err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && returnErr == nil {
			result = cli.RunnerNodeResult{}
			returnErr = fault(cli.FaultInternal, "INSTALLATION_LOCK_RELEASE_FAILED")
		}
	}()
	state, err := session.Read()
	if err != nil {
		return cli.RunnerNodeResult{}, fault(cli.FaultVerification, "INSTALLATION_STATE_INVALID")
	}
	if state.Active != nil {
		return cli.RunnerNodeResult{}, fault(cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	}
	bundle, trustBytes, err := authenticateSelectedRelease(session.Root(), state)
	if err != nil {
		return cli.RunnerNodeResult{}, err
	}
	defer clear(trustBytes)

	switch request.Operation {
	case cli.RunnerNodeExportRelease:
		pins, exportErr := backend.effects.ExportRunnerRelease(ctx, ExportReleasePlan{
			Root: session.Root(), InstallationID: state.InstallationID,
			Bundle: bundle, TrustBytes: trustBytes, Output: request.Output,
		})
		if exportErr != nil {
			return cli.RunnerNodeResult{}, effectFault(exportErr)
		}
		if runnerenrollment.ValidateAuthorityPins(pins) != nil {
			return cli.RunnerNodeResult{}, fault(cli.FaultInternal, "RUNNER_EXPORT_RESULT_INVALID")
		}
		return cli.RunnerNodeResult{
			State: "EXPORTED", ReleaseID: bundle.Manifest.Release.ID,
			ServerCAPin: pins.ServerCAFingerprint, RunnerCAPin: pins.RunnerCAFingerprint,
		}, nil
	case cli.RunnerNodeEnroll:
		enrollmentRequest, readErr := backend.effects.ReadRunnerRequest(ctx, request.RequestFile)
		if readErr != nil {
			return cli.RunnerNodeResult{}, effectFault(readErr)
		}
		if runnerenrollment.ValidateRequest(enrollmentRequest) != nil ||
			enrollmentRequest.ReleaseID != bundle.Manifest.Release.ID ||
			enrollmentRequest.InstallationID != state.InstallationID {
			return cli.RunnerNodeResult{}, fault(cli.FaultPrecondition, "RUNNER_REQUEST_INSTALLATION_MISMATCH")
		}
		signed, enrollErr := backend.effects.EnrollRunner(ctx, EnrollPlan{
			Root: session.Root(), InstallationID: state.InstallationID,
			Bundle: bundle, Request: enrollmentRequest, Output: request.Output,
		})
		if enrollErr != nil {
			return cli.RunnerNodeResult{}, effectFault(enrollErr)
		}
		if runnerenrollment.ValidateEnrollmentAgainstRequest(signed, enrollmentRequest) != nil {
			return cli.RunnerNodeResult{}, fault(cli.FaultInternal, "RUNNER_ENROLLMENT_RESULT_INVALID")
		}
		digest, _ := runnerenrollment.RequestDigest(enrollmentRequest)
		return cli.RunnerNodeResult{
			State: "ENROLLED", ReleaseID: enrollmentRequest.ReleaseID,
			InstallationID: enrollmentRequest.InstallationID,
			NodeID:         enrollmentRequest.NodeID, Slots: uint8(len(enrollmentRequest.Slots)),
			RequestDigest: digest,
		}, nil
	default:
		return cli.RunnerNodeResult{}, fault(cli.FaultInvalidArgument, "RUNNER_NODE_INPUT_INVALID")
	}
}

func authenticateSelectedRelease(
	root string,
	state lifecycle.Journal,
) (release.VerifiedBundle, []byte, error) {
	if state.CurrentReleaseID == "" || state.CurrentReleaseDigest == "" {
		return release.VerifiedBundle{}, nil, fault(cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	}
	trustPath := filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust))
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != state.ReleaseTrust.KeyID ||
		trust.PublicKeyFingerprint != state.ReleaseTrust.Fingerprint {
		clear(trustBytes)
		return release.VerifiedBundle{}, nil, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	bundle, err := installedrelease.Authenticate(
		root, state.CurrentReleaseID, state.CurrentReleaseDigest, trustBytes,
	)
	if err != nil {
		clear(trustBytes)
		return release.VerifiedBundle{}, nil, fault(cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
	}
	if !bundle.Manifest.IncludesProduct(release.ProductDevOps) {
		clear(trustBytes)
		return release.VerifiedBundle{}, nil, fault(cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	}
	return bundle, trustBytes, nil
}

func validateRequest(request cli.RunnerNodeRequest) error {
	switch request.Operation {
	case cli.RunnerNodeExportRelease:
		if !cleanAbsolute(request.Root) || !cleanAbsolute(request.Output) ||
			request.Release != "" || request.TrustKey != "" || request.InstallationID != "" ||
			request.NodeID != "" || request.Slots != 0 || request.GatewayOrigin != "" ||
			request.ServerCAPin != "" || request.RunnerCAPin != "" || request.RequestFile != "" {
			return errors.New("runner release export input is invalid")
		}
	case cli.RunnerNodeCreateRequest:
		if !cleanAbsolute(request.Root) || !cleanAbsolute(request.Release) ||
			!cleanAbsolute(request.TrustKey) ||
			lifecycle.ValidateInstallationID(request.InstallationID) != nil ||
			runnerenrollment.ValidateNodeID(request.NodeID) != nil || request.Slots == 0 ||
			request.Slots > release.RunnerMaximumSlots ||
			runnerenrollment.ValidateGatewayOrigin(request.GatewayOrigin) != nil ||
			runnerenrollment.ValidateAuthorityPins(runnerenrollment.AuthorityPins{
				ServerCAFingerprint: request.ServerCAPin,
				RunnerCAFingerprint: request.RunnerCAPin,
			}) != nil ||
			request.RequestFile != "" || request.Output != "" {
			return errors.New("runner request input is invalid")
		}
	case cli.RunnerNodeEnroll:
		if !cleanAbsolute(request.Root) || !cleanAbsolute(request.RequestFile) ||
			!cleanAbsolute(request.Output) || request.Release != "" || request.TrustKey != "" ||
			request.InstallationID != "" || request.NodeID != "" || request.Slots != 0 ||
			request.GatewayOrigin != "" || request.ServerCAPin != "" || request.RunnerCAPin != "" {
			return errors.New("runner enrollment input is invalid")
		}
	default:
		return errors.New("runner node operation is invalid")
	}
	return nil
}

func cleanAbsolute(value string) bool {
	if value == "" || len(value) > 4096 || !filepath.IsAbs(value) ||
		filepath.Clean(value) != value {
		return false
	}
	volume := filepath.VolumeName(value)
	return value != volume+string(filepath.Separator)
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
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fault(cli.FaultInterrupted, "COMMAND_INTERRUPTED")
	case errors.Is(err, ErrEffectInput):
		return fault(cli.FaultInvalidArgument, "RUNNER_NODE_INPUT_INVALID")
	case errors.Is(err, ErrEffectConflict):
		return fault(cli.FaultConflict, "RUNNER_NODE_OWNERSHIP_CONFLICT")
	case errors.Is(err, ErrEffectVerification):
		return fault(cli.FaultVerification, "RUNNER_NODE_MATERIAL_INVALID")
	case errors.Is(err, ErrEffectOutcomeUnknown):
		return fault(cli.FaultUnavailable, "RUNNER_NODE_OUTCOME_UNKNOWN")
	case errors.Is(err, ErrEffectUnavailable):
		return fault(cli.FaultUnavailable, "RUNNER_NODE_DEPENDENCY_UNAVAILABLE")
	default:
		return fault(cli.FaultInternal, "RUNNER_NODE_OPERATION_FAILED")
	}
}

func fault(class cli.FaultClass, code string) *cli.Fault {
	value, err := cli.NewFault(class, code)
	if err != nil {
		panic("static runner node fault is invalid")
	}
	return value
}
