//go:build linux

package runnerworkspacefile

import (
	"os"
	"syscall"
)

func lockOwnershipFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockOwnershipFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
