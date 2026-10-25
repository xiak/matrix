// Package sourcetrustfile resolves installation-owned, endpoint-scoped source
// trust from a read-only filesystem mount.
package sourcetrustfile

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

type Resolver struct {
	root string
	now  func() time.Time
}

func NewResolver(root string) (*Resolver, error) {
	return newResolver(root, time.Now)
}

func newResolver(root string, now func() time.Time) (*Resolver, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || now == nil {
		return nil, errors.New("source trust root is invalid")
	}
	evaluated, err := filepath.EvalSymlinks(root)
	info, statErr := os.Lstat(root)
	if err != nil || statErr != nil || evaluated != root || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || !privateDirectory(info) {
		return nil, errors.New("source trust root is unavailable")
	}
	return &Resolver{root: root, now: now}, nil
}

// Resolve returns nil,false for the deliberate system-root fallback. A present
// but unsafe or invalid record always fails rather than falling back.
func (resolver *Resolver) Resolve(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	endpointOrigin string,
) (*x509.CertPool, bool, error) {
	if resolver == nil || resolver.root == "" || resolver.now == nil || ctx == nil {
		return nil, false, errors.New("source trust resolver is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	directory, err := sourcetrust.DirectoryName(scope, endpointOrigin)
	if err != nil {
		return nil, false, errors.New("source trust identity is invalid")
	}
	trustDirectory := filepath.Join(resolver.root, directory)
	info, err := os.Lstat(trustDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!privateDirectory(info) {
		return nil, false, errors.New("source trust directory is unsafe")
	}
	evaluated, err := filepath.EvalSymlinks(trustDirectory)
	if err != nil || evaluated != trustDirectory {
		return nil, false, errors.New("source trust directory is unsafe")
	}
	entries, err := os.ReadDir(trustDirectory)
	if err != nil || len(entries) != 1 || entries[0].Name() != sourcetrust.BundleFilename ||
		entries[0].IsDir() || entries[0].Type()&os.ModeSymlink != 0 {
		return nil, false, errors.New("source trust directory shape is invalid")
	}
	content, err := processconfig.ReadFile(
		filepath.Join(trustDirectory, sourcetrust.BundleFilename),
		sourcetrust.MaximumBundleBytes,
		true,
	)
	if err != nil {
		return nil, false, errors.New("source trust bundle is unavailable")
	}
	defer clear(content)
	observedAt := resolver.now().UTC()
	pool, err := sourcetrust.CertPool(content, observedAt)
	if err != nil {
		return nil, false, errors.New("source trust bundle is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return pool, true, nil
}

func privateDirectory(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
