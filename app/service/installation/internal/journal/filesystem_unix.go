//go:build !windows

package journal

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func pathComponentIsLink(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func securePermissions(path string, directory bool) error {
	mode := os.FileMode(managedFileMode)
	if directory {
		mode = managedDirectoryMode
	}
	return os.Chmod(path, mode)
}

func verifySecurePermissions(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("group or other access is permitted")
	}
	if directory {
		if !info.IsDir() || info.Mode().Perm()&0o500 != 0o500 {
			return errors.New("directory owner access is insufficient")
		}
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o400 == 0 {
		return errors.New("file owner access is insufficient")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func durableReplace(temporary, target, parent string) error {
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func openRegularNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, errors.New("opened path is not a regular file")
	}
	return file, nil
}

func openLockFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, managedFileMode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, errors.New("lock path is not a regular file")
	}
	return file, nil
}

func acquireOSFileLock(ctx context.Context, file *os.File) error {
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseOSFileLock(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
