//go:build !windows

package localcontainer

import (
	"errors"
	"os"
	"syscall"
)

func credentialFileGroupID(path string) (uint32, bool, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, false, errors.New("local managed-service credential group is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false, errors.New("local managed-service credential group is unavailable")
	}
	return uint32(stat.Gid), true, nil
}
