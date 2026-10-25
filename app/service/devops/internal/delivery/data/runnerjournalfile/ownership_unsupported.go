//go:build !linux && !windows

package runnerjournalfile

import (
	"errors"
	"os"
)

func lockOwnershipFile(*os.File) error {
	return errors.New("runner journal ownership is unsupported on this platform")
}

func unlockOwnershipFile(*os.File) error {
	return nil
}
