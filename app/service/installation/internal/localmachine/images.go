package localmachine

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func loadInstallImages(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	staged, err := verifiedStagedBundle(plan)
	if err != nil {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("staged release cannot be authenticated"),
		)
	}
	for _, image := range staged.Manifest.Images {
		_, present, err := inspectInstalledReleaseImage(ctx, runtimeBoundary, image)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		_, candidatePresent, err := inspectReleaseImageID(ctx, runtimeBoundary, image)
		if err != nil {
			return err
		}
		if !candidatePresent {
			archive, declaration, openErr := staged.OpenVerifiedPayload(image.ArchivePath)
			if openErr != nil || declaration.Path != image.ArchivePath {
				return errors.Join(
					platformcommand.ErrEffectVerification,
					errors.New("image archive cannot be authenticated"),
				)
			}
			_, started, loadErr := runtimeBoundary.Run(ctx, archive, "image", "load", "--quiet")
			closeErr := archive.Close()
			if loadErr != nil || closeErr != nil {
				if started {
					return errors.Join(platformcommand.ErrEffectOutcomeUnknown, loadErr, closeErr)
				}
				return errors.Join(platformcommand.ErrEffectUnavailable, loadErr, closeErr)
			}
			rechecked, _, recheckErr := staged.OpenVerifiedPayload(image.ArchivePath)
			if recheckErr != nil {
				return errors.Join(
					platformcommand.ErrEffectVerification,
					errors.New("staged release changed while loading images"),
				)
			}
			if closeErr := rechecked.Close(); closeErr != nil {
				return errors.Join(platformcommand.ErrEffectVerification, closeErr)
			}
		}
		if err := publishInstalledReleaseImage(ctx, runtimeBoundary, image); err != nil {
			return err
		}
		if _, present, err = inspectInstalledReleaseImage(ctx, runtimeBoundary, image); err != nil {
			return err
		} else if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("installed image reference is absent"),
			)
		}
	}
	return nil
}

func inspectInstalledReleaseImage(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	image release.Image,
) (string, bool, error) {
	reference := image.RuntimeReference()
	if image.LocalReference == "" {
		present, err := inspectExactImage(ctx, runtimeBoundary, reference)
		return reference, present, err
	}
	output, started, err := runtimeBoundary.Run(
		ctx, nil, "image", "inspect", "--format",
		"{{.Id}}|{{.Os}}|{{.Architecture}}", reference,
	)
	if err != nil {
		if !started {
			return "", false, errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		return "", false, nil
	}
	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 3 || !slices.Contains(image.RuntimeImageIDs(), parts[0]) ||
		parts[1] != image.OS || parts[2] != image.Architecture {
		return "", false, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("installed image reference resolves to unexpected content"),
		)
	}
	return parts[0], true, nil
}

func inspectReleaseImageID(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	image release.Image,
) (string, bool, error) {
	for _, imageID := range image.RuntimeImageIDs() {
		present, err := inspectExactImage(ctx, runtimeBoundary, imageID)
		if err != nil {
			return "", false, err
		}
		if present {
			return imageID, true, nil
		}
	}
	return "", false, nil
}

func publishInstalledReleaseImage(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	image release.Image,
) error {
	imageID, present, err := inspectReleaseImageID(ctx, runtimeBoundary, image)
	if err != nil {
		return err
	}
	if !present {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("loaded image identity is absent"),
		)
	}
	if image.LocalReference == "" {
		return nil
	}
	_, started, err := runtimeBoundary.Run(
		ctx, nil, "image", "tag", imageID, image.LocalReference,
	)
	if err != nil {
		if started {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
		}
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	observedID, present, err := inspectInstalledReleaseImage(ctx, runtimeBoundary, image)
	if err != nil {
		return err
	}
	if !present || observedID != imageID {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("installed image reference publication failed"),
		)
	}
	return nil
}
