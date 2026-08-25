package compose

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const maxSecretBytes = 1024 * 1024

// SecretResolver resolves one immutable provider-neutral reference. Returned
// bytes are consumed directly by the executor and must never be logged or
// persisted outside the dedicated restrictive secret file.
type SecretResolver interface {
	ResolveSecret(context.Context, paasv1.SecretVersionReference) ([]byte, error)
}

// FileSecretResolver is the default Phase 1 resolver. Provisioning places an
// exact version at <root>/<secretId>/<version>; both identifiers have already
// passed the public ID grammar and are never interpreted as paths.
type FileSecretResolver struct {
	root string
}

func NewFileSecretResolver(root string) (*FileSecretResolver, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) ||
		filepath.Clean(root) != root || isVolumeRoot(root) {
		return nil, errors.New("secret root is invalid or cannot be secured")
	}
	info, err := validateExistingPath(root, true)
	if err != nil || !info.IsDir() {
		return nil, errors.New("secret root is invalid or cannot be secured")
	}
	if runtime.GOOS == "windows" {
		if err := securePermissions(root, true); err != nil {
			return nil, errors.New("secret root is invalid or cannot be secured")
		}
	}
	if err := verifySecurePermissions(root, true); err != nil {
		return nil, errors.New("secret root permissions are unsafe")
	}
	return &FileSecretResolver{root: root}, nil
}

func (resolver *FileSecretResolver) ResolveSecret(
	ctx context.Context,
	reference paasv1.SecretVersionReference,
) ([]byte, error) {
	if resolver == nil || resolver.root == "" {
		return nil, errors.New("file secret resolver is not configured")
	}
	if ctx == nil {
		return nil, errors.New("secret resolution context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := errors.Join(
		paasv1.ValidateID("secretId", string(reference.SecretID)),
		paasv1.ValidateID("secret version", reference.Version),
	); err != nil {
		return nil, errors.New("secret version reference is invalid")
	}
	directory, err := safeJoin(resolver.root, string(reference.SecretID))
	if err != nil {
		return nil, errors.New("secret version path is invalid")
	}
	path, err := safeJoin(resolver.root, string(reference.SecretID), reference.Version)
	if err != nil {
		return nil, errors.New("secret version path is invalid")
	}
	if _, err := validateExistingPath(directory, true); err != nil {
		return nil, errors.New("secret version is unavailable")
	}
	if runtime.GOOS == "windows" {
		if err := securePermissions(directory, true); err != nil {
			return nil, errors.New("secret version permissions cannot be enforced")
		}
	}
	if err := verifySecurePermissions(directory, true); err != nil {
		return nil, errors.New("secret version permissions are unsafe")
	}
	info, err := validateExistingPath(path, false)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("secret version is unavailable")
	}
	if runtime.GOOS == "windows" {
		if err := securePermissions(path, false); err != nil {
			return nil, errors.New("secret version permissions cannot be enforced")
		}
	}
	if err := verifySecurePermissions(path, false); err != nil {
		return nil, errors.New("secret version permissions are unsafe")
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return nil, errors.New("secret version cannot be opened safely")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil {
		return nil, errors.New("secret version cannot be read")
	}
	if len(content) > maxSecretBytes {
		wipe(content)
		return nil, errors.New("secret version exceeds the 1 MiB limit")
	}
	if err := ctx.Err(); err != nil {
		wipe(content)
		return nil, err
	}
	return content, nil
}
