//go:build !windows

package localmachine

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// validateRunnerNodeRoot accepts the private request state before installation
// and the search-only root required by the per-slot service accounts afterward.
// Every secret below it remains root-owned and private.
func validateRunnerNodeRoot(root string) error {
	info, err := validateManagedExistingPath(root)
	if err != nil || !info.IsDir() || managedPathIsLink(root, info) ||
		(info.Mode().Perm() != 0o700 && info.Mode().Perm() != 0o711) {
		return errors.New("runner node root is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(unix.Geteuid()) {
		return errors.New("runner node root owner is unsafe")
	}
	return nil
}

func validRunnerInstalledOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
