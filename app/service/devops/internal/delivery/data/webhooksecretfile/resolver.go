// Package webhooksecretfile resolves installation-owned source webhook keys
// from a read-only filesystem mount without exposing tenant identifiers or
// secret references as host path components.
package webhooksecretfile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"runtime"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const maximumSecretBytes int64 = 128

type Resolver struct {
	root string
}

var _ sourceingress.WebhookSecretResolver = (*Resolver)(nil)

func NewResolver(root string) (*Resolver, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("webhook secret root is invalid")
	}
	evaluated, err := filepath.EvalSymlinks(root)
	info, statErr := os.Lstat(root)
	if err != nil || statErr != nil || evaluated != root || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || !privateDirectory(info) {
		return nil, errors.New("webhook secret root is unavailable")
	}
	return &Resolver{root: root}, nil
}

func (resolver *Resolver) ResolveWebhookSecrets(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (sourceingress.WebhookSecretSet, error) {
	if resolver == nil || resolver.root == "" {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook secret resolver is unavailable")
	}
	if ctx == nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook secret context is nil")
	}
	if err := ctx.Err(); err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	directory, err := DirectoryName(scope, reference)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	secretRoot := filepath.Join(resolver.root, directory)
	info, err := os.Lstat(secretRoot)
	if errors.Is(err, os.ErrNotExist) {
		return sourceingress.WebhookSecretSet{}, sourceingress.ErrSecretNotFound
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!privateDirectory(info) {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook secret directory is unsafe")
	}
	evaluated, err := filepath.EvalSymlinks(secretRoot)
	if err != nil || evaluated != secretRoot {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook secret directory is unsafe")
	}
	currentPath := filepath.Join(secretRoot, "current")
	if _, statErr := os.Lstat(currentPath); errors.Is(statErr, os.ErrNotExist) {
		return sourceingress.WebhookSecretSet{}, sourceingress.ErrSecretNotFound
	} else if statErr != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("current webhook secret is unavailable")
	}
	current, err := processconfig.ReadFile(currentPath, maximumSecretBytes, true)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("current webhook secret is unavailable")
	}
	defer clear(current)
	var previous []byte
	previousPath := filepath.Join(secretRoot, "previous")
	if _, statErr := os.Lstat(previousPath); statErr == nil {
		previous, err = processconfig.ReadFile(previousPath, maximumSecretBytes, true)
		if err != nil {
			return sourceingress.WebhookSecretSet{}, errors.New("previous webhook secret is unavailable")
		}
		defer clear(previous)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return sourceingress.WebhookSecretSet{}, errors.New("previous webhook secret is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return sourceingress.WebhookSecretSet{}, err
	}
	secretSet, err := sourceingress.NewWebhookSecretSet(current, previous)
	if err != nil {
		return sourceingress.WebhookSecretSet{}, errors.New("webhook secret content is invalid")
	}
	return secretSet, nil
}

// DirectoryName deterministically frames tenant and secret-reference identity
// into one portable path segment. The one-way name is configuration metadata,
// not a secret.
func DirectoryName(
	scope devopsv1.ResourceScope,
	reference devopsv1.ResourceID,
) (string, error) {
	if err := errors.Join(
		devopsv1.ValidateResourceScope(scope),
		devopsv1.ValidateID("webhookSecretRef", string(reference)),
	); err != nil {
		return "", errors.New("webhook secret identity is invalid")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix-devops-webhook-secret-directory-v1"))
	writeFramed(digest, string(scope.TenantID))
	writeFramed(digest, string(reference))
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeFramed(writer hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

func privateDirectory(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
