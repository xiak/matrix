//go:build linux

package localmachine

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

func readDockerHostStorage(path string) (uint64, uint64, error) {
	if path == "" {
		return 0, 0, errors.New("Docker host storage path is required")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil || filesystem.Bsize <= 0 {
		return 0, 0, errors.New("Docker host storage is unavailable")
	}
	blockSize := uint64(filesystem.Bsize)
	if filesystem.Blocks > math.MaxUint64/blockSize ||
		filesystem.Bavail > math.MaxUint64/blockSize {
		return 0, 0, errors.New("Docker host storage capacity overflows")
	}
	return filesystem.Blocks * blockSize, filesystem.Bavail * blockSize, nil
}
