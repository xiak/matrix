package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

type projectLock struct {
	file *os.File
}

func acquireProjectLock(ctx context.Context, root, project string) (*projectLock, error) {
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
