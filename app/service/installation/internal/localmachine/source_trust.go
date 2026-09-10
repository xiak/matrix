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

type recoveredSourceTrustRecord struct {
	directory string
	files     []string
}

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

// resetRecoveredSourceTrust removes only structurally proved, installation-
// owned endpoint trust records while retaining the root directory. Keeping the
// root inode is required because the running source processes bind-mount it;
// replacing the directory would leave those mounts attached to stale state.
func resetRecoveredSourceTrust(root string) error {
	records, trustRoot, err := inspectRecoveredSourceTrust(root)
	if err != nil {
		return err
	}
	for _, record := range records {
		for _, relative := range record.files {
			path, pathErr := managedPath(root, relative)
			if pathErr != nil || os.Remove(path) != nil {
				return errors.Join(
					errManagedOutcomeUnknown,
					errors.New("recovered source trust cleanup outcome is unknown"),
				)
			}
		}
		directory, pathErr := managedPath(root, record.directory)
		if pathErr != nil || os.Remove(directory) != nil {
			return errors.Join(
				errManagedOutcomeUnknown,
				errors.New("recovered source trust cleanup outcome is unknown"),
			)
		}
	}
	if err := syncManagedDirectory(trustRoot); err != nil {
		return errors.Join(
			errManagedOutcomeUnknown,
			errors.New("recovered source trust cleanup outcome is unknown"),
		)
	}
	return nil
}

func inspectRecoveredSourceTrust(
	root string,
) ([]recoveredSourceTrustRecord, string, error) {
	rootRelative := filepath.FromSlash(layout.DevOpsSourceTrustRoot)
	trustRoot, err := managedPath(root, rootRelative)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(trustRoot)
	if errors.Is(err, os.ErrNotExist) {
		created, createErr := ensureManagedDirectory(root, rootRelative)
		return nil, created, createErr
	}
	if err != nil || info == nil || !info.IsDir() || managedPathIsLink(trustRoot, info) ||
		verifyManagedPermissions(trustRoot, true) != nil {
		return nil, "", errManagedConflict
	}
	if _, err := validateManagedExistingPath(trustRoot); err != nil {
		return nil, "", errManagedConflict
	}
	entries, err := os.ReadDir(trustRoot)
	if err != nil {
		return nil, "", errors.New("inspect recovered source trust failed")
	}
	records := make([]recoveredSourceTrustRecord, 0, len(entries))
	for _, entry := range entries {
		if !validSourceTrustDirectoryName(entry.Name()) || !entry.IsDir() ||
			entry.Type()&os.ModeSymlink != 0 {
			return nil, "", errManagedConflict
		}
		directoryRelative := filepath.Join(rootRelative, entry.Name())
		directory, pathErr := managedPath(root, directoryRelative)
		if pathErr != nil {
			return nil, "", errManagedConflict
		}
		directoryInfo, inspectErr := validateManagedExistingPath(directory)
		if inspectErr != nil || !directoryInfo.IsDir() ||
			verifyManagedPermissions(directory, true) != nil {
			return nil, "", errManagedConflict
		}
		children, readErr := os.ReadDir(directory)
		if readErr != nil || len(children) > 3 {
			return nil, "", errManagedConflict
		}
		record := recoveredSourceTrustRecord{directory: directoryRelative}
		for _, child := range children {
			if child.IsDir() || child.Type()&os.ModeSymlink != 0 ||
				!recoveredSourceTrustFilename(child.Name()) {
				return nil, "", errManagedConflict
			}
			fileRelative := filepath.Join(directoryRelative, child.Name())
			file, filePathErr := managedPath(root, fileRelative)
			if filePathErr != nil {
				return nil, "", errManagedConflict
			}
			fileInfo, inspectErr := validateManagedExistingPath(file)
			if inspectErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() < 0 ||
				fileInfo.Size() > sourcetrust.MaximumBundleBytes ||
				verifyManagedPermissions(file, false) != nil {
				return nil, "", errManagedConflict
			}
			if child.Name() == sourcetrust.BundleFilename {
				content, readErr := readManagedFile(
					root, fileRelative, sourcetrust.MaximumBundleBytes,
				)
				if readErr != nil {
					return nil, "", errManagedConflict
				}
				_, poolErr := sourcetrust.CertPool(content, time.Time{})
				clear(content)
				if poolErr != nil {
					return nil, "", errManagedConflict
				}
			}
			record.files = append(record.files, fileRelative)
		}
		records = append(records, record)
	}
	return records, trustRoot, nil
}

func validSourceTrustDirectoryName(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func recoveredSourceTrustFilename(value string) bool {
	switch value {
	case sourcetrust.BundleFilename,
		sourcetrust.BundleFilename + ".partial",
		sourcetrust.BundleFilename + ".replacement":
		return true
	default:
		return false
	}
}
