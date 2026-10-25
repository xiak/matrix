package executorspoolfile

import (
	"errors"
	"os"
	"sync"
)

// Ownership holds the operating-system lock that makes one spool directory a
// single gateway process authority. The durable lock file is empty; ownership
// itself is released by the operating system when the process or handle exits.
type Ownership struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func AcquireOwnership(rootPath string) (*Ownership, error) {
	cleaned, err := validateRoot(rootPath)
	if err != nil {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(cleaned)
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
	opened, err := file.Stat()
	current, currentErr := root.Lstat(ownershipLockName)
	if err != nil || currentErr != nil || !validOwnershipFile(opened) ||
		!validOwnershipFile(current) || !os.SameFile(opened, current) {
		return nil, errors.Join(ErrUnavailable, err, currentErr)
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
	return &Ownership{file: file}, nil
}

func (ownership *Ownership) Close() error {
	if ownership == nil {
		return nil
	}
	ownership.closeOnce.Do(func() {
		if ownership.file == nil {
			return
		}
		ownership.closeErr = errors.Join(
			unlockOwnershipFile(ownership.file), ownership.file.Close(),
		)
		ownership.file = nil
	})
	return ownership.closeErr
}
