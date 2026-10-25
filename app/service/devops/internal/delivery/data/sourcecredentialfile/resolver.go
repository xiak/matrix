// Package sourcecredentialfile resolves installation-owned source credential
// material from a read-only filesystem mount.
package sourcecredentialfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

type Resolver struct {
	purpose sourcecredential.Purpose
	root    string
}

var _ sourceingress.WebhookSecretResolver = (*Resolver)(nil)

var ErrMaterialNotFound = errors.New("source credential material is absent")

func NewResolver(purpose sourcecredential.Purpose, root string) (*Resolver, error) {
	if sourcecredential.ValidatePurpose(purpose) != nil || root == "" ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("source credential root is invalid")
	}
	evaluated, err := filepath.EvalSymlinks(root)
	info, statErr := os.Lstat(root)
	if err != nil || statErr != nil || evaluated != root || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || !privateDirectory(info) {
		return nil, errors.New("source credential root is unavailable")
	}
	return &Resolver{purpose: purpose, root: root}, nil
}

func (resolver *Resolver) Resolve(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (sourcecredential.Material, error) {
	if resolver == nil || resolver.root == "" ||
		sourcecredential.ValidatePurpose(resolver.purpose) != nil {
		return sourcecredential.Material{}, errors.New("source credential resolver is unavailable")
	}
	if ctx == nil {
		return sourcecredential.Material{}, errors.New("source credential context is nil")
	}
	if err := ctx.Err(); err != nil {
		return sourcecredential.Material{}, err
	}
	directory, err := sourcecredential.DirectoryName(resolver.purpose, scope, reference)
	if err != nil {
		return sourcecredential.Material{}, err
	}
	credentialRoot := filepath.Join(resolver.root, directory)
	info, err := os.Lstat(credentialRoot)
	if errors.Is(err, os.ErrNotExist) {
		return sourcecredential.Material{}, ErrMaterialNotFound
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!privateDirectory(info) {
		return sourcecredential.Material{}, errors.New("source credential directory is unsafe")
	}
	evaluated, err := filepath.EvalSymlinks(credentialRoot)
	if err != nil || evaluated != credentialRoot {
		return sourcecredential.Material{}, errors.New("source credential directory is unsafe")
	}
	materialPath := filepath.Join(credentialRoot, sourcecredential.MaterialFilename)
	if _, statErr := os.Lstat(materialPath); errors.Is(statErr, os.ErrNotExist) {
		return sourcecredential.Material{}, ErrMaterialNotFound
	} else if statErr != nil {
		return sourcecredential.Material{}, errors.New("source credential material is unavailable")
	}
	content, err := processconfig.ReadFile(
		materialPath, sourcecredential.MaximumMaterialBytes, true,
	)
	if err != nil {
		return sourcecredential.Material{}, errors.New("source credential material is unavailable")
	}
	defer clear(content)
	material, err := sourcecredential.Decode(resolver.purpose, content)
	if err != nil {
		return sourcecredential.Material{}, errors.New("source credential material is invalid")
	}
	if err := ctx.Err(); err != nil {
		material.Clear()
		return sourcecredential.Material{}, err
	}
	return material, nil
}

func (resolver *Resolver) ResolveWebhookSecrets(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (sourceingress.WebhookSecretSet, error) {
	if resolver == nil || resolver.purpose != sourcecredential.PurposeWebhook {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential resolver is unavailable")
	}
	material, err := resolver.Resolve(ctx, scope, reference)
	if errors.Is(err, ErrMaterialNotFound) {
		return sourceingress.WebhookSecretSet{}, sourceingress.ErrSecretNotFound
	}
	if err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	defer material.Clear()
	secretSet, err := sourceingress.NewWebhookSecretSet(material.Current, material.Previous)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential content is invalid")
	}
	return secretSet, nil
}

func privateDirectory(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
