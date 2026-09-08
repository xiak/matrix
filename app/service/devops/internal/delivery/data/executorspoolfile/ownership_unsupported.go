//go:build !linux && !windows

package executorspoolfile

import (
	"errors"
	"os"
)

func lockOwnershipFile(*os.File) error {
	return errors.New("executor spool ownership is unsupported on this platform")
}

func unlockOwnershipFile(*os.File) error {
	return nil
}
