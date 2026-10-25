package runnerworkspacefile

import (
	"errors"
	"os"
	"sync"
)

type ownership struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func acquireOwnership(rootPath string) (*ownership, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	defer root.Close()
	file, err := root.OpenFile(
		ownershipLockName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600,
	)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = root.OpenFile(ownershipLockName, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	opened, statErr := file.Stat()
	current, currentErr := root.Lstat(ownershipLockName)
	if statErr != nil || currentErr != nil || !validOwnershipFile(opened) ||
		!validOwnershipFile(current) || !os.SameFile(opened, current) {
		return nil, errors.Join(ErrUnavailable, statErr, currentErr)
	}
	if created {
		if err := file.Sync(); err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		if err := syncDirectory(root, "."); err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
	}
	if err := lockOwnershipFile(file); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	closeOnError = false
	return &ownership{file: file}, nil
}

func (owner *ownership) Close() error {
	if owner == nil {
		return nil
	}
	owner.closeOnce.Do(func() {
		if owner.file == nil {
			return
		}
		owner.closeErr = errors.Join(
			unlockOwnershipFile(owner.file), owner.file.Close(),
		)
		owner.file = nil
	})
	return owner.closeErr
}

func validOwnershipFile(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().IsRegular() && privateMode(info.Mode(), 0o600) && info.Size() == 0
}
