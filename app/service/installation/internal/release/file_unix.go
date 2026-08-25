//go:build !windows

package release

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func syncReleaseDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ownerOnlyMode(mode os.FileMode, directory bool) bool {
	if directory != mode.IsDir() || mode&os.ModeSymlink != 0 || mode.Perm()&0o077 != 0 {
		return false
	}
	return !directory || mode.Perm()&0o100 != 0
}

func pathComponentIsLink(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
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
		return nil, errors.New("opened release path is not a regular file")
	}
	return file, nil
}

func executableModeMatches(mode os.FileMode, expected bool) bool {
	return mode.Perm()&0o111 != 0 == expected
}
