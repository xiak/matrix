//go:build windows

package runnerworkspacefile

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockOwnershipFile(file *os.File) error {
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&windows.Overlapped{},
	)
}

func unlockOwnershipFile(file *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{},
	)
}
