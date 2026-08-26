package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const (
	supportAPIVersion        = "installation.matrix.xiak.com/v1"
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
	APIVersion            string             `json:"apiVersion"`
	Kind                  string             `json:"kind"`
	State                 string             `json:"state"`
	ReleaseID             string             `json:"releaseId"`
	ReleaseDigest         string             `json:"releaseDigest"`
	PreviousReleaseID     string             `json:"previousReleaseId,omitempty"`
	PreviousReleaseDigest string             `json:"previousReleaseDigest,omitempty"`
	DatabaseSchemaVersion uint64             `json:"databaseSchemaVersion"`
	GeneratedAt           time.Time          `json:"generatedAt"`
	CorrelationID         string             `json:"correlationId"`
	Components            []supportComponent `json:"components"`
	Images                []supportImage     `json:"images"`
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
		DatabaseSchemaVersion: installation.bundle.Manifest.Database.SchemaVersion,
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
		evidence.DatabaseSchemaVersion != plan.Bundle.Manifest.Database.SchemaVersion ||
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
