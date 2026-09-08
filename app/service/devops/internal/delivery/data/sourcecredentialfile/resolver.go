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
	root string
}

var _ sourceingress.WebhookSecretResolver = (*Resolver)(nil)

func NewResolver(root string) (*Resolver, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("webhook credential root is invalid")
	}
	evaluated, err := filepath.EvalSymlinks(root)
	info, statErr := os.Lstat(root)
	if err != nil || statErr != nil || evaluated != root || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || !privateDirectory(info) {
		return nil, errors.New("webhook credential root is unavailable")
	}
	return &Resolver{root: root}, nil
}

func (resolver *Resolver) ResolveWebhookSecrets(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (sourceingress.WebhookSecretSet, error) {
	if resolver == nil || resolver.root == "" {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential resolver is unavailable")
	}
	if ctx == nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential context is nil")
	}
	if err := ctx.Err(); err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	directory, err := sourcecredential.DirectoryName(
		sourcecredential.PurposeWebhook, scope, reference,
	)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	credentialRoot := filepath.Join(resolver.root, directory)
	info, err := os.Lstat(credentialRoot)
	if errors.Is(err, os.ErrNotExist) {
		return sourceingress.WebhookSecretSet{}, sourceingress.ErrSecretNotFound
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!privateDirectory(info) {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential directory is unsafe")
	}
	evaluated, err := filepath.EvalSymlinks(credentialRoot)
	if err != nil || evaluated != credentialRoot {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential directory is unsafe")
	}
	materialPath := filepath.Join(credentialRoot, sourcecredential.MaterialFilename)
	if _, statErr := os.Lstat(materialPath); errors.Is(statErr, os.ErrNotExist) {
		return sourceingress.WebhookSecretSet{}, sourceingress.ErrSecretNotFound
	} else if statErr != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential material is unavailable")
	}
	content, err := processconfig.ReadFile(
		materialPath, sourcecredential.MaximumMaterialBytes, true,
	)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential material is unavailable")
	}
	defer clear(content)
	material, err := sourcecredential.Decode(sourcecredential.PurposeWebhook, content)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook credential material is invalid")
	}
	defer material.Clear()
	if err := ctx.Err(); err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
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
