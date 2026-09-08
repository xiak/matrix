package localmachine

import (
	"context"
	"crypto/subtle"
	"errors"
	"path/filepath"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/sourcecredentialcommand"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

var _ sourcecredentialcommand.Effects = (*Effects)(nil)

func (effects *Effects) ApplySourceCredential(
	ctx context.Context,
	plan sourcecredentialcommand.ApplyPlan,
) (sourcecredentialcommand.ResultState, error) {
	if effects == nil || ctx == nil {
		return "", sourcecredentialcommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	maximum := int64(256)
	if plan.Purpose == sourcecredential.PurposeWebhook {
		maximum = 128
	}
	value, err := processconfig.ReadFile(plan.FromFile, maximum, true)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectInput, err)
	}
	defer clear(value)
	requested, err := sourcecredential.NewMaterial(plan.Purpose, value, nil)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectInput, err)
	}
	defer requested.Clear()
	requestedBytes, err := sourcecredential.Encode(plan.Purpose, requested)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectInput, err)
	}
	defer clear(requestedBytes)
	relative, err := sourceCredentialMaterialPath(
		plan.Purpose, plan.Scope, plan.Reference,
	)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectInput, err)
	}
	exists, err := managedFileExists(plan.Root, relative)
	if err != nil {
		return "", classifySourceCredentialWriteError(err)
	}
	if !exists {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := writeManagedOnce(plan.Root, relative, requestedBytes); err != nil {
			return "", classifySourceCredentialWriteError(err)
		}
		return sourcecredentialcommand.StateApplied, nil
	}

	storedBytes, err := readManagedFile(
		plan.Root, relative, sourcecredential.MaximumMaterialBytes,
	)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectConflict, err)
	}
	defer clear(storedBytes)
	stored, err := sourcecredential.Decode(plan.Purpose, storedBytes)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer stored.Clear()
	if len(stored.Current) == len(value) &&
		subtle.ConstantTimeCompare(stored.Current, value) == 1 {
		return sourcecredentialcommand.StateUnchanged, nil
	}
	var previous []byte
	if plan.Purpose == sourcecredential.PurposeWebhook {
		previous = stored.Current
	}
	next, err := sourcecredential.NewMaterial(plan.Purpose, value, previous)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer next.Clear()
	nextBytes, err := sourcecredential.Encode(plan.Purpose, next)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer clear(nextBytes)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := replaceManagedExpected(plan.Root, relative, storedBytes, nextBytes); err != nil {
		return "", classifySourceCredentialWriteError(err)
	}
	return sourcecredentialcommand.StateApplied, nil
}

func (effects *Effects) RetirePreviousSourceCredential(
	ctx context.Context,
	plan sourcecredentialcommand.RetirePreviousPlan,
) (sourcecredentialcommand.ResultState, error) {
	if effects == nil || ctx == nil {
		return "", sourcecredentialcommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	relative, err := sourceCredentialMaterialPath(
		sourcecredential.PurposeWebhook, plan.Scope, plan.Reference,
	)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectInput, err)
	}
	exists, err := managedFileExists(plan.Root, relative)
	if err != nil {
		return "", classifySourceCredentialWriteError(err)
	}
	if !exists {
		return "", sourcecredentialcommand.ErrEffectNotFound
	}
	storedBytes, err := readManagedFile(
		plan.Root, relative, sourcecredential.MaximumMaterialBytes,
	)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectConflict, err)
	}
	defer clear(storedBytes)
	stored, err := sourcecredential.Decode(sourcecredential.PurposeWebhook, storedBytes)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer stored.Clear()
	if len(stored.Previous) == 0 {
		return sourcecredentialcommand.StatePreviousRetired, nil
	}
	next, err := sourcecredential.NewMaterial(
		sourcecredential.PurposeWebhook, stored.Current, nil,
	)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer next.Clear()
	nextBytes, err := sourcecredential.Encode(sourcecredential.PurposeWebhook, next)
	if err != nil {
		return "", errors.Join(sourcecredentialcommand.ErrEffectVerification, err)
	}
	defer clear(nextBytes)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := replaceManagedExpected(plan.Root, relative, storedBytes, nextBytes); err != nil {
		return "", classifySourceCredentialWriteError(err)
	}
	return sourcecredentialcommand.StatePreviousRetired, nil
}

func sourceCredentialMaterialPath(
	purpose sourcecredential.Purpose,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (string, error) {
	root := ""
	switch purpose {
	case sourcecredential.PurposeWebhook:
		root = layout.DevOpsWebhookCredentialRoot
	case sourcecredential.PurposeFetch:
		root = layout.DevOpsFetchCredentialRoot
	case sourcecredential.PurposeReport:
		root = layout.DevOpsReportCredentialRoot
	default:
		return "", errors.New("source credential purpose is invalid")
	}
	directory, err := sourcecredential.DirectoryName(purpose, scope, reference)
	if err != nil {
		return "", err
	}
	return filepath.Join(
		filepath.FromSlash(root), directory, sourcecredential.MaterialFilename,
	), nil
}

func classifySourceCredentialWriteError(err error) error {
	switch {
	case errors.Is(err, errManagedOutcomeUnknown):
		return errors.Join(sourcecredentialcommand.ErrEffectOutcomeUnknown, err)
	case errors.Is(err, errManagedConflict):
		return errors.Join(sourcecredentialcommand.ErrEffectConflict, err)
	default:
		return errors.Join(sourcecredentialcommand.ErrEffectUnavailable, err)
	}
}
