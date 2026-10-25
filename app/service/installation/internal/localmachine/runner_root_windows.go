//go:build windows

package localmachine

import "os"

func validateRunnerNodeRoot(root string) error {
	return validateManagedRoot(root)
}

func validRunnerInstalledOwner(os.FileInfo) bool { return true }
