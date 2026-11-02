package compose

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type projectLock struct {
	file *os.File
}

// AcquireProjectLock serializes exact local project effects across processes.
// Its protected lock outlives runtime/data removal; closing releases the lease.
func AcquireProjectLock(ctx context.Context, root, project string) (io.Closer, error) {
	identity, identityErr := hex.DecodeString(strings.TrimPrefix(project, "matrix-"))
	if !strings.HasPrefix(project, "matrix-") || identityErr != nil || len(identity) != 12 ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root {
		return nil, errors.New("project lock identity is invalid")
	}
	if ctx == nil {
		return nil, errors.New("project lock context is required")
	}
	locks, err := ensureManagedDirectory(root, ".locks")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(locks, project+".lock")
	if err := validateManagedTarget(root, path); err != nil {
		return nil, err
	}
	file, err := openLockFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	if err := securePermissions(path, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := verifySecurePermissions(path, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := acquireOSFileLock(ctx, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &projectLock{file: file}, nil
}

func (lock *projectLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := errors.Join(releaseOSFileLock(lock.file), lock.file.Close())
	lock.file = nil
	return err
}
