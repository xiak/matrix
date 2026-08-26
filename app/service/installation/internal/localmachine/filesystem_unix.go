//go:build !windows

package localmachine

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func managedPathIsLink(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func protectManagedPath(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

func protectPostgresDataRoot(path string) error {
	return os.Chmod(path, 0o711)
}

func verifyPostgresDataRoot(path string) error {
	info, err := os.Lstat(path)
	if err != nil || managedPathIsLink(path, info) || !info.IsDir() || info.Mode().Perm() != 0o711 {
		return errors.New("PostgreSQL data root permissions are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(unix.Geteuid()) {
		return errors.New("PostgreSQL data root owner is unsafe")
	}
	return nil
}

func verifyManagedPermissions(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || managedPathIsLink(path, info) || directory != info.IsDir() {
		return errors.New("managed path type is unsafe")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o600 != 0o600 ||
		(directory && info.Mode().Perm()&0o100 == 0) {
		return errors.New("managed path permissions are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(unix.Geteuid()) {
		return errors.New("managed path owner is unsafe")
	}
	return nil
}

func syncManagedDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func durableReplaceManaged(temporary, target, parent string) error {
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncManagedDirectory(parent)
}

func openManagedRegularNoFollow(path string) (*os.File, error) {
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
		return nil, errors.New("opened managed path is not regular")
	}
	return file, nil
}
