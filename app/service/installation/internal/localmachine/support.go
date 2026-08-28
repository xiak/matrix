package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const (
	nodeSupportKind         = "NodeSupportEvidence"
	maximumNodeSupportBytes = int64(64 * 1024)
	maximumNodeSupportTime  = 15 * time.Second
	nodeSupportVerified     = "VERIFIED"
	nodeSupportUnavailable  = "UNAVAILABLE"
)

// Only this closed projection reaches a support file. In particular, neither
// a Plan/Journal nor the collector's device and mount labels is serialized.
type nodeSupportBinding struct {
	Identity              nodev1.Identity   `json:"identity"`
	IdentityFingerprint   string            `json:"identityFingerprint"`
	ConfigurationDigest   string            `json:"configurationDigest"`
	ReleaseID             string            `json:"releaseId"`
	ReleaseDigest         string            `json:"releaseDigest"`
	PreviousReleaseID     string            `json:"previousReleaseId,omitempty"`
	PreviousReleaseDigest string            `json:"previousReleaseDigest,omitempty"`
	RuntimeRevision       uint64            `json:"runtimeRevision"`
	JournalVersion        uint64            `json:"journalVersion"`
	JournalDigest         string            `json:"journalDigest"`
	CorrelationID         string            `json:"correlationId"`
	Action                lifecycle.Action  `json:"action"`
	Phase                 lifecycle.Phase   `json:"phase"`
	Outcome               lifecycle.Outcome `json:"outcome"`
	FailureCode           string            `json:"failureCode,omitempty"`
	SystemReserve         paasv1.Capacity   `json:"systemReserve"`
}

type nodeSupportEvidence struct {
	APIVersion     string                  `json:"apiVersion"`
	Kind           string                  `json:"kind"`
	State          string                  `json:"state"`
	Binding        nodeSupportBinding      `json:"binding"`
	GeneratedAt    time.Time               `json:"generatedAt"`
	BootRegistered bool                    `json:"bootRegistered"`
	Components     []nodeSupportComponent  `json:"components"`
	Readiness      string                  `json:"readiness"`
	UsageState     paasv1.MeasurementState `json:"usageState"`
	Usage          *nodeSupportUsage       `json:"usage,omitempty"`
}

type nodeSupportComponent struct {
	Name  string      `json:"name"`
	State nativeState `json:"state"`
}

type nodeSupportUsage struct {
	ObservedAt       time.Time               `json:"observedAt"`
	ValidUntil       time.Time               `json:"validUntil"`
	CPU              paasv1.CPUUsage         `json:"cpu"`
	Memory           paasv1.MemoryUsage      `json:"memory"`
	FilesystemsState paasv1.MeasurementState `json:"filesystemsState"`
	Filesystems      []nodeSupportFilesystem `json:"filesystems,omitempty"`
}

type nodeSupportFilesystem struct {
	State paasv1.MeasurementState      `json:"state"`
	Value *paasv1.FilesystemUsageValue `json:"value,omitempty"`
}

func (effects *NodeEffects) WriteSupportEvidence(ctx context.Context, request nodecommand.SupportPlan) (created bool, err error) {
	if effects == nil || effects.supervisor == nil || effects.verifier == nil || ctx == nil {
		return false, nodecommand.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, maximumNodeSupportTime)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(nodecommand.ErrUnavailable, err)
	}
	binding, err := nodeSupportSnapshotBinding(request)
	if err != nil || authenticateNodeFiles(request.Installation) != nil {
		return false, nodecommand.ErrVerification
	}
	plan := request.Installation
	relative, err := supportOutputRelative(plan.Root, request.Output)
	if err != nil {
		return false, nodecommand.ErrConflict
	}
	if exists, err := managedFileExists(plan.Root, relative); err != nil {
		return false, nodecommand.ErrConflict
	} else if exists {
		content, err := readManagedFile(plan.Root, relative, maximumNodeSupportBytes)
		defer clear(content)
		if err != nil {
			return false, nodecommand.ErrConflict
		}
		_, err = verifyNodeSupportEvidence(content, request, binding)
		if err != nil {
			return false, nodecommand.ErrConflict
		}
		return false, nil
	}
	evidence := nodeSupportEvidence{
		APIVersion: supportAPIVersion, Kind: nodeSupportKind, State: supportStateNotReady,
		Binding: binding, GeneratedAt: request.GeneratedAt, Readiness: nodeSupportUnavailable,
		UsageState: paasv1.MeasurementUnavailable,
	}
	evidence.BootRegistered, err = effects.supervisor.InspectStartup(ctx, nativeNodeStartup(plan))
	if err != nil {
		return false, err
	}
	services := nativeNodeServices(plan)
	allRunning := true
	for index, service := range services {
		state, err := effects.supervisor.Inspect(ctx, service)
		if err != nil {
			return false, err
		}
		name := "NODE"
		if index == 0 {
			name = "COLLECTOR"
		}
		evidence.Components = append(evidence.Components, nodeSupportComponent{Name: name, State: state})
		allRunning = allRunning && state == nativeRunning
	}
	if evidence.BootRegistered && allRunning && effects.verifier.Verify(ctx, plan.Configuration, plan.Credentials) == nil {
		evidence.Readiness = nodeSupportVerified
		if request.Journal.Last.Outcome != lifecycle.OutcomeManualIntervention {
			evidence.State = supportStateReady
		}
	}
	if evidence.Components[0].State == nativeRunning {
		usage, err := effects.verifier.ObserveUsage(ctx, plan.Configuration, plan.Credentials)
		if err == nil {
			if paasv1.ValidateExecutionTargetUsage(usage) != nil {
				return false, nodecommand.ErrVerification
			}
			usage = usage.Snapshot(time.Now().UTC().Truncate(time.Microsecond))
			evidence.UsageState = paasv1.MeasurementAvailable
			if usage.CPU.State == paasv1.MeasurementStale && usage.Memory.State == paasv1.MeasurementStale && usage.FilesystemsState == paasv1.MeasurementStale {
				evidence.UsageState = paasv1.MeasurementStale
			}
			evidence.Usage = &nodeSupportUsage{ObservedAt: usage.ObservedAt, ValidUntil: usage.ValidUntil,
				CPU: usage.CPU, Memory: usage.Memory, FilesystemsState: usage.FilesystemsState}
			for _, filesystem := range usage.Filesystems {
				evidence.Usage.Filesystems = append(evidence.Usage.Filesystems, nodeSupportFilesystem{
					State: filesystem.State, Value: filesystem.Value,
				})
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(nodecommand.ErrUnavailable, err)
	}
	content, err := json.Marshal(evidence)
	if err != nil || int64(len(content)) >= maximumNodeSupportBytes {
		return false, nodecommand.ErrVerification
	}
	content = append(content, '\n')
	defer clear(content)
	if _, err := verifyNodeSupportEvidence(content, request, binding); err != nil {
		return false, nodecommand.ErrVerification
	}
	if err := writeManagedOnce(plan.Root, relative, content); err != nil {
		existing, readErr := readManagedFile(plan.Root, relative, maximumNodeSupportBytes)
		defer clear(existing)
		if _, verifyErr := verifyNodeSupportEvidence(existing, request, binding); readErr == nil && verifyErr == nil {
			return false, nodecommand.ErrOutcomeUnknown
		}
		return false, nodecommand.ErrConflict
	}
	return true, nil
}

func nodeSupportSnapshotBinding(request nodecommand.SupportPlan) (nodeSupportBinding, error) {
	plan, state := request.Installation, request.Journal
	if nodecommand.ValidatePlan(plan) != nil || plan.Previous != nil || plan.ReleaseSource != nil ||
		lifecycle.ValidateJournal(state) != nil || state.Node == nil || state.Active != nil || state.Last == nil ||
		state.InstallationID != plan.Configuration.Identity.InstallationID || *state.Node != plan.Binding ||
		state.CurrentReleaseID != plan.Bundle.Manifest.Release.ID || state.CurrentReleaseDigest != plan.Bundle.ManifestSHA256 ||
		state.ReleaseTrust != (lifecycle.ReleaseTrust{KeyID: plan.Trust.KeyID, Fingerprint: plan.Trust.PublicKeyFingerprint}) ||
		request.GeneratedAt.IsZero() || request.GeneratedAt.Location() != time.UTC ||
		request.GeneratedAt != request.GeneratedAt.Truncate(time.Microsecond) || request.GeneratedAt.Before(state.Last.UpdatedAt) {
		return nodeSupportBinding{}, nodecommand.ErrVerification
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nodeSupportBinding{}, nodecommand.ErrVerification
	}
	defer clear(encoded)
	return nodeSupportBinding{
		Identity: plan.Configuration.Identity, IdentityFingerprint: plan.Configuration.ExpectedFingerprint,
		ConfigurationDigest: plan.Binding.ConfigurationDigest,
		ReleaseID:           state.CurrentReleaseID, ReleaseDigest: state.CurrentReleaseDigest,
		PreviousReleaseID: state.PreviousRelease, PreviousReleaseDigest: state.PreviousReleaseDigest,
		RuntimeRevision: plan.Bundle.Manifest.Node.RuntimeRevision, JournalVersion: state.Version,
		JournalDigest: "sha256:" + sha256Hex(encoded), CorrelationID: state.Last.Command.ID,
		Action: state.Last.Command.Action, Phase: state.Last.Phase, Outcome: state.Last.Outcome,
		FailureCode: state.Last.FailureCode, SystemReserve: plan.Configuration.SystemReserve,
	}, nil
}

func verifyNodeSupportEvidence(content []byte, request nodecommand.SupportPlan, binding nodeSupportBinding) (nodeSupportEvidence, error) {
	invalid := nodecommand.ErrVerification
	var evidence nodeSupportEvidence
	if contractjson.DecodeObjectBytes(content, maximumNodeSupportBytes, &evidence) != nil ||
		evidence.APIVersion != supportAPIVersion || evidence.Kind != nodeSupportKind || evidence.Binding != binding ||
		evidence.GeneratedAt.IsZero() || evidence.GeneratedAt.Location() != time.UTC ||
		evidence.GeneratedAt != evidence.GeneratedAt.Truncate(time.Microsecond) ||
		evidence.GeneratedAt.After(request.GeneratedAt) || evidence.GeneratedAt.Before(request.Journal.Last.UpdatedAt) ||
		(evidence.State != supportStateReady && evidence.State != supportStateNotReady) ||
		(evidence.Readiness != nodeSupportVerified && evidence.Readiness != nodeSupportUnavailable) ||
		len(evidence.Components) != 2 {
		return nodeSupportEvidence{}, invalid
	}
	allRunning := true
	for index, name := range []string{"COLLECTOR", "NODE"} {
		component := evidence.Components[index]
		if component.Name != name || (component.State != nativeRunning && component.State != nativeStopped &&
			component.State != nativeMissing && component.State != nativeChanging) {
			return nodeSupportEvidence{}, invalid
		}
		allRunning = allRunning && component.State == nativeRunning
	}
	verified := evidence.Readiness == nodeSupportVerified
	if verified && (!evidence.BootRegistered || !allRunning) ||
		(evidence.State == supportStateReady) != (verified && binding.Outcome != lifecycle.OutcomeManualIntervention) {
		return nodeSupportEvidence{}, invalid
	}
	if (evidence.Usage == nil && evidence.UsageState != paasv1.MeasurementUnavailable) ||
		(evidence.Usage != nil && evidence.UsageState != paasv1.MeasurementAvailable && evidence.UsageState != paasv1.MeasurementStale) {
		return nodeSupportEvidence{}, invalid
	}
	if evidence.Usage != nil {
		usage := evidence.Usage
		if evidence.Components[0].State != nativeRunning || len(usage.Filesystems) > paasv1.MaximumObservedFilesystems ||
			usage.ObservedAt.After(evidence.GeneratedAt.Add(maximumNodeSupportTime)) ||
			usage.ValidUntil.Sub(usage.ObservedAt) > nodev1.MaximumObservationAge {
			return nodeSupportEvidence{}, invalid
		}
		// Reuse the public quantity/state invariants. Synthetic labels exist only
		// during validation and never enter the diagnostic document.
		quantities := paasv1.ExecutionTargetUsage{ObservedAt: usage.ObservedAt, ValidUntil: usage.ValidUntil,
			CPU: usage.CPU, Memory: usage.Memory, FilesystemsState: usage.FilesystemsState}
		for index, filesystem := range usage.Filesystems {
			quantities.Filesystems = append(quantities.Filesystems, paasv1.FilesystemUsage{
				Device: strconv.Itoa(index), MountPoint: "/", FilesystemType: "redacted",
				State: filesystem.State, Value: filesystem.Value,
			})
		}
		if paasv1.ValidateExecutionTargetUsage(quantities) != nil {
			return nodeSupportEvidence{}, invalid
		}
		if (evidence.UsageState == paasv1.MeasurementStale) != (usage.CPU.State == paasv1.MeasurementStale &&
			usage.Memory.State == paasv1.MeasurementStale && usage.FilesystemsState == paasv1.MeasurementStale) {
			return nodeSupportEvidence{}, invalid
		}
		if !usage.ValidUntil.After(evidence.GeneratedAt) && (usage.CPU.State != paasv1.MeasurementStale ||
			usage.Memory.State != paasv1.MeasurementStale || usage.FilesystemsState != paasv1.MeasurementStale) {
			return nodeSupportEvidence{}, invalid
		}
	}
	return evidence, nil
}

const (
	supportAPIVersion        = "installation.matrix.xiak.com/v2"
	supportKind              = "PlatformSupportEvidence"
	maximumSupportEvidence   = int64(256 * 1024)
	supportStateReady        = "READY"
	supportStateNotReady     = "NOT_READY"
	supportStateHealthy      = "HEALTHY"
	supportStateAbsent       = "ABSENT"
	supportStateImagePresent = "PRESENT"
)

var supportCommandIDPattern = regexp.MustCompile(`^cmd-[0-9a-f]{32}$`)

type supportEvidence struct {
	APIVersion            string                  `json:"apiVersion"`
	Kind                  string                  `json:"kind"`
	State                 string                  `json:"state"`
	ReleaseID             string                  `json:"releaseId"`
	ReleaseDigest         string                  `json:"releaseDigest"`
	PreviousReleaseID     string                  `json:"previousReleaseId,omitempty"`
	PreviousReleaseDigest string                  `json:"previousReleaseDigest,omitempty"`
	Database              release.DatabaseProfile `json:"database"`
	GeneratedAt           time.Time               `json:"generatedAt"`
	CorrelationID         string                  `json:"correlationId"`
	Components            []supportComponent      `json:"components"`
	Images                []supportImage          `json:"images"`
}

type supportComponent struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	ImageID string `json:"imageId"`
}

type supportImage struct {
	Component    string               `json:"component"`
	Purpose      release.ImagePurpose `json:"purpose"`
	State        string               `json:"state"`
	ImageID      string               `json:"imageId"`
	SourceDigest string               `json:"sourceDigest"`
}

func (effects *Effects) WriteSupportEvidence(
	ctx context.Context,
	request platformcommand.SupportPlan,
) error {
	if effects == nil || effects.runtime == nil || ctx == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("local-machine support evidence is unavailable"),
		)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !supportCommandIDPattern.MatchString(request.CorrelationID) ||
		request.GeneratedAt.IsZero() || request.GeneratedAt.Location() != time.UTC ||
		request.GeneratedAt != request.GeneratedAt.Truncate(time.Microsecond) {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("support evidence identity or time is invalid"),
		)
	}
	plan, err := authenticateInstalledPlan(request.InstalledPlan)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(plan.TrustBytes)
	installation, expectation, err := preparePlatformExpectation(
		ctx, effects.runtime, plan,
	)
	if err != nil {
		return err
	}
	relative, err := supportOutputRelative(plan.Root, request.Output)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists, err := managedFileExists(plan.Root, relative); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	} else if exists {
		content, err := readManagedFile(plan.Root, relative, maximumSupportEvidence)
		if err != nil || verifySupportEvidence(
			content, request, plan, expectation,
		) != nil {
			clear(content)
			return errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("support evidence destination conflicts"),
			)
		}
		clear(content)
		return nil
	}
	evidence, err := collectSupportEvidence(
		ctx, effects.runtime, request, plan, installation, expectation,
	)
	if err != nil {
		return err
	}
	content, err := json.Marshal(evidence)
	if err != nil || int64(len(content)) > maximumSupportEvidence-1 {
		clear(content)
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("support evidence exceeds its bound"),
		)
	}
	content = append(content, '\n')
	defer clear(content)
	if err := writeManagedOnce(plan.Root, relative, content); err != nil {
		existing, readErr := readManagedFile(
			plan.Root, relative, maximumSupportEvidence,
		)
		if readErr == nil && verifySupportEvidence(existing, request, plan, expectation) == nil {
			clear(existing)
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		clear(existing)
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func collectSupportEvidence(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	request platformcommand.SupportPlan,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
	expectation platformComposeExpectation,
) (supportEvidence, error) {
	images := make([]supportImage, 0, len(installation.bundle.Manifest.Images))
	allImagesPresent := true
	for _, image := range installation.bundle.Manifest.Images {
		present, err := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return supportEvidence{}, err
		}
		state := supportStateImagePresent
		if !present {
			state = supportStateAbsent
			allImagesPresent = false
		}
		images = append(images, supportImage{
			Component: image.Component, Purpose: image.Purpose, State: state,
			ImageID: image.ImageID, SourceDigest: image.SourceDigest,
		})
	}
	slices.SortFunc(images, func(left, right supportImage) int {
		return strings.Compare(left.Component, right.Component)
	})

	observation, exists, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return supportEvidence{}, err
	}
	ready, err := validatePlatformObservation(observation, exists, expectation)
	if err != nil {
		return supportEvidence{}, err
	}
	names := make([]string, 0, len(expectation.Services))
	for name := range expectation.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	components := make([]supportComponent, 0, len(names))
	for _, name := range names {
		expected := expectation.Services[name]
		state := supportStateAbsent
		if observed, found := observation.Containers[name]; found {
			state = supportStateNotReady
			if observed.Config.Labels["com.docker.compose.config-hash"] == expected.ConfigHash &&
				observed.State.Running && observed.State.Status == "running" &&
				observed.State.Health != nil && observed.State.Health.Status == "healthy" {
				state = supportStateHealthy
			}
		}
		components = append(components, supportComponent{
			Name: name, State: state, ImageID: expected.Image,
		})
	}
	state := supportStateNotReady
	if ready && allImagesPresent {
		state = supportStateReady
	}
	return supportEvidence{
		APIVersion: supportAPIVersion, Kind: supportKind, State: state,
		ReleaseID:             plan.Bundle.Manifest.Release.ID,
		ReleaseDigest:         plan.Bundle.ManifestSHA256,
		PreviousReleaseID:     request.PreviousID,
		PreviousReleaseDigest: request.PreviousDigest,
		Database:              installation.bundle.Manifest.Database,
		GeneratedAt:           request.GeneratedAt, CorrelationID: request.CorrelationID,
		Components: components, Images: images,
	}, nil
}

func supportOutputRelative(root, output string) (string, error) {
	if root == "" || output == "" || !filepath.IsAbs(output) ||
		filepath.Clean(output) != output {
		return "", errors.New("support output path is invalid")
	}
	relative, err := filepath.Rel(root, output)
	if err != nil || filepath.IsAbs(relative) || filepath.Dir(relative) !=
		filepath.FromSlash(layout.SupportDirectory) {
		return "", errors.New("support output is outside its owned directory")
	}
	name := filepath.Base(relative)
	if name == "." || name == ".." || len(name) > 128 || strings.HasPrefix(name, ".") ||
		!strings.EqualFold(filepath.Ext(name), ".json") {
		return "", errors.New("support output filename is invalid")
	}
	if _, err := managedPath(root, relative); err != nil {
		return "", err
	}
	return relative, nil
}

func verifySupportEvidence(
	content []byte,
	request platformcommand.SupportPlan,
	plan platformcommand.InstallPlan,
	expectation platformComposeExpectation,
) error {
	var evidence supportEvidence
	if contractjson.DecodeObjectBytes(content, maximumSupportEvidence, &evidence) != nil ||
		evidence.APIVersion != supportAPIVersion || evidence.Kind != supportKind ||
		(evidence.State != supportStateReady && evidence.State != supportStateNotReady) ||
		evidence.ReleaseID != plan.Bundle.Manifest.Release.ID ||
		evidence.ReleaseDigest != plan.Bundle.ManifestSHA256 ||
		evidence.PreviousReleaseID != request.PreviousID ||
		evidence.PreviousReleaseDigest != request.PreviousDigest ||
		evidence.Database != plan.Bundle.Manifest.Database ||
		evidence.GeneratedAt != request.GeneratedAt ||
		evidence.CorrelationID != request.CorrelationID ||
		len(evidence.Components) != len(expectation.Services) ||
		len(evidence.Images) != len(plan.Bundle.Manifest.Images) {
		return errors.New("support evidence identity is invalid")
	}
	componentNames := make([]string, 0, len(expectation.Services))
	for name := range expectation.Services {
		componentNames = append(componentNames, name)
	}
	slices.Sort(componentNames)
	allComponentsHealthy := true
	for index, name := range componentNames {
		component := evidence.Components[index]
		if component.Name != name || component.ImageID != expectation.Services[name].Image ||
			(component.State != supportStateHealthy && component.State != supportStateNotReady &&
				component.State != supportStateAbsent) {
			return errors.New("support component evidence is invalid")
		}
		if component.State != supportStateHealthy {
			allComponentsHealthy = false
		}
	}
	wantImages := make([]supportImage, 0, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		wantImages = append(wantImages, supportImage{
			Component: image.Component, Purpose: image.Purpose,
			ImageID: image.ImageID, SourceDigest: image.SourceDigest,
		})
	}
	slices.SortFunc(wantImages, func(left, right supportImage) int {
		return strings.Compare(left.Component, right.Component)
	})
	allImagesPresent := true
	for index, want := range wantImages {
		observed := evidence.Images[index]
		if observed.Component != want.Component || observed.Purpose != want.Purpose ||
			observed.ImageID != want.ImageID || observed.SourceDigest != want.SourceDigest ||
			(observed.State != supportStateImagePresent && observed.State != supportStateAbsent) {
			return errors.New("support image evidence is invalid")
		}
		if observed.State != supportStateImagePresent {
			allImagesPresent = false
		}
	}
	shouldBeReady := allComponentsHealthy && allImagesPresent
	if (evidence.State == supportStateReady) != shouldBeReady {
		return errors.New("support evidence state differs from its component evidence")
	}
	return nil
}
