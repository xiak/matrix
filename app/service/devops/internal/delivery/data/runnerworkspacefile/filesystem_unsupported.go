//go:build !linux

package runnerworkspacefile

import "os"

func sameFilesystem(os.FileInfo, os.FileInfo) bool {
	return true
}
