//go:build !linux && !windows

package runnerworkspacefile

import (
	"errors"
	"os"
)

func lockOwnershipFile(*os.File) error {
	return errors.New("runner workspace ownership is unsupported")
}

func unlockOwnershipFile(*os.File) error {
	return nil
}
