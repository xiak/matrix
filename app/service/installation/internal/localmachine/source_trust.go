package localmachine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/sourcetrustcommand"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

var _ sourcetrustcommand.Effects = (*Effects)(nil)

func (effects *Effects) ApplySourceTrust(
	ctx context.Context,
	plan sourcetrustcommand.ApplyPlan,
) (sourcetrustcommand.ResultState, error) {
	if effects == nil || ctx == nil {
		return "", sourcetrustcommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	content, err := processconfig.ReadFile(
		plan.FromFile, sourcetrust.MaximumBundleBytes, true,
	)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectInput, err)
	}
	defer clear(content)
	canonical, err := sourcetrust.Canonicalize(content, time.Now().UTC())
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectInput, err)
	}
	defer clear(canonical)
	directoryRelative, relative, err := sourceTrustPaths(plan.Scope, plan.EndpointOrigin)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectInput, err)
	}
	hasBundle, err := inspectSourceTrustDirectory(plan.Root, directoryRelative)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectConflict, err)
	}
	if !hasBundle {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := writeManagedOnce(plan.Root, relative, canonical); err != nil {
			return "", classifySourceTrustWriteError(err)
		}
		return sourcetrustcommand.StateApplied, nil
	}
	exists, err := managedFileExists(plan.Root, relative)
	if err != nil {
		return "", classifySourceTrustWriteError(err)
	}
	if !exists {
		return "", sourcetrustcommand.ErrEffectConflict
	}
	stored, err := readManagedFile(plan.Root, relative, sourcetrust.MaximumBundleBytes)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectConflict, err)
	}
	defer clear(stored)
	if _, err := sourcetrust.CertPool(stored, time.Time{}); err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectVerification, err)
	}
	if bytes.Equal(stored, canonical) {
		return sourcetrustcommand.StateUnchanged, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := replaceManagedExpected(plan.Root, relative, stored, canonical); err != nil {
		return "", classifySourceTrustWriteError(err)
	}
	return sourcetrustcommand.StateApplied, nil
}

func (effects *Effects) RemoveSourceTrust(
	ctx context.Context,
	plan sourcetrustcommand.RemovePlan,
) (sourcetrustcommand.ResultState, error) {
	if effects == nil || ctx == nil {
		return "", sourcetrustcommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	directoryRelative, fileRelative, err := sourceTrustPaths(plan.Scope, plan.EndpointOrigin)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectInput, err)
	}
	directory, err := managedPath(plan.Root, directoryRelative)
	if err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectInput, err)
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return sourcetrustcommand.StateRemoved, nil
	}
	if err != nil || info == nil || !info.IsDir() || managedPathIsLink(directory, info) ||
		verifyManagedPermissions(directory, true) != nil {
		return "", sourcetrustcommand.ErrEffectConflict
	}
	if _, err := validateManagedExistingPath(directory); err != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectConflict, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 1 || len(entries) == 1 &&
		(entries[0].Name() != sourcetrust.BundleFilename || entries[0].IsDir() ||
			entries[0].Type()&os.ModeSymlink != 0) {
		return "", sourcetrustcommand.ErrEffectConflict
	}
	if len(entries) == 1 {
		stored, err := readManagedFile(
			plan.Root, fileRelative, sourcetrust.MaximumBundleBytes,
		)
		if err != nil {
			return "", errors.Join(sourcetrustcommand.ErrEffectConflict, err)
		}
		defer clear(stored)
		if _, err := sourcetrust.CertPool(stored, time.Time{}); err != nil {
			return "", errors.Join(sourcetrustcommand.ErrEffectVerification, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(entries) == 1 {
		file, pathErr := managedPath(plan.Root, fileRelative)
		if pathErr != nil {
			return "", errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, pathErr)
		}
		if removeErr := os.Remove(file); removeErr != nil {
			return "", errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, removeErr)
		}
		if syncErr := syncManagedDirectory(directory); syncErr != nil {
			return "", errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, syncErr)
		}
	}
	if removeErr := os.Remove(directory); removeErr != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, removeErr)
	}
	if syncErr := syncManagedDirectory(filepath.Dir(directory)); syncErr != nil {
		return "", errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, syncErr)
	}
	return sourcetrustcommand.StateRemoved, nil
}

func sourceTrustPaths(
	scope devopsv1.ResourceScope,
	endpointOrigin string,
) (string, string, error) {
	directory, err := sourcetrust.DirectoryName(scope, endpointOrigin)
	if err != nil {
		return "", "", err
	}
	directoryRelative := filepath.Join(
		filepath.FromSlash(layout.DevOpsSourceTrustRoot), directory,
	)
	return directoryRelative, filepath.Join(directoryRelative, sourcetrust.BundleFilename), nil
}

func inspectSourceTrustDirectory(
	root string,
	directoryRelative string,
) (bool, error) {
	directory, err := managedPath(root, directoryRelative)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info == nil || !info.IsDir() || managedPathIsLink(directory, info) ||
		verifyManagedPermissions(directory, true) != nil {
		return false, errManagedConflict
	}
	if _, err := validateManagedExistingPath(directory); err != nil {
		return false, errManagedConflict
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 1 || len(entries) == 1 &&
		(entries[0].Name() != sourcetrust.BundleFilename || entries[0].IsDir() ||
			entries[0].Type()&os.ModeSymlink != 0) {
		return false, errManagedConflict
	}
	return len(entries) == 1, nil
}

func classifySourceTrustWriteError(err error) error {
	switch {
	case errors.Is(err, errManagedOutcomeUnknown):
		return errors.Join(sourcetrustcommand.ErrEffectOutcomeUnknown, err)
	case errors.Is(err, errManagedConflict):
		return errors.Join(sourcetrustcommand.ErrEffectConflict, err)
	default:
		return errors.Join(sourcetrustcommand.ErrEffectUnavailable, err)
	}
}
