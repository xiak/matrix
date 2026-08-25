//go:build darwin

package localmachine

import (
	"errors"
	"math"
	"strings"

	"golang.org/x/sys/unix"
)

func readLocalMetrics(storagePath string) (localMetrics, error) {
	machineID, err := unix.Sysctl("kern.uuid")
	if err != nil || strings.TrimSpace(machineID) == "" {
		return localMetrics{}, errors.New("stable Darwin machine ID is unavailable")
	}
	totalMemory, err := unix.SysctlUint64("hw.memsize")
	if err != nil || totalMemory == 0 {
		return localMetrics{}, errors.New("Darwin memory capacity is unavailable")
	}
	availableMemory, err := unix.SysctlUint64("hw.usermem")
	if err != nil || availableMemory == 0 || availableMemory > totalMemory {
		availableMemory = totalMemory
	}
	if storagePath == "" {
		storagePath = "/"
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(storagePath, &filesystem); err != nil {
		return localMetrics{}, err
	}
	blockSize := uint64(filesystem.Bsize)
	if blockSize == 0 ||
		filesystem.Blocks > math.MaxUint64/blockSize ||
		filesystem.Bavail > math.MaxUint64/blockSize {
		return localMetrics{}, errors.New("filesystem capacity is invalid")
	}
	return localMetrics{
		machineID:             strings.TrimSpace(machineID),
		memoryTotalBytes:      totalMemory,
		memoryAvailableBytes:  availableMemory,
		storageTotalBytes:     filesystem.Blocks * blockSize,
		storageAvailableBytes: filesystem.Bavail * blockSize,
	}, nil
}
