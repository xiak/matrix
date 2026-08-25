package localmachine

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/internal/release"
)

func loadInstallImages(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	root, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	staged, err := release.VerifyDirectory(root, plan.TrustBytes)
	if err != nil || staged.ManifestSHA256 != plan.Bundle.ManifestSHA256 {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("staged release cannot be authenticated"),
		)
	}
	for _, image := range staged.Manifest.Images {
		present, err := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		archive, declaration, err := staged.OpenVerifiedPayload(image.ArchivePath)
		if err != nil || declaration.Path != image.ArchivePath {
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
		rechecked, _, err := staged.OpenVerifiedPayload(image.ArchivePath)
		if err != nil {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("staged release changed while loading images"),
			)
		}
		if err := rechecked.Close(); err != nil {
			return errors.Join(platformcommand.ErrEffectVerification, err)
		}
		present, err = inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return err
		}
		if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("loaded image identity is absent"),
			)
		}
	}
	return nil
}
