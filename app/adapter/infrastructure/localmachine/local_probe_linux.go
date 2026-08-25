//go:build linux

package localmachine

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func readLocalMetrics(storagePath string) (localMetrics, error) {
	machineID, err := readLinuxMachineID()
	if err != nil {
		return localMetrics{}, err
	}
	totalMemory, availableMemory, err := readLinuxMemory()
	if err != nil {
		return localMetrics{}, err
	}
	if storagePath == "" {
		storagePath = "/"
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(storagePath, &filesystem); err != nil {
		return localMetrics{}, err
	}
	if filesystem.Bsize <= 0 {
		return localMetrics{}, errors.New("filesystem block size is invalid")
	}
	blockSize := uint64(filesystem.Bsize)
	if filesystem.Blocks > math.MaxUint64/blockSize ||
		filesystem.Bavail > math.MaxUint64/blockSize {
		return localMetrics{}, errors.New("filesystem capacity overflows bytes")
	}
	return localMetrics{
		machineID:             machineID,
		memoryTotalBytes:      totalMemory,
		memoryAvailableBytes:  availableMemory,
		storageTotalBytes:     filesystem.Blocks * blockSize,
		storageAvailableBytes: filesystem.Bavail * blockSize,
	}, nil
}

func readLinuxMachineID() (string, error) {
	for _, name := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		source, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(source))
		if value != "" {
			return value, nil
		}
	}
	return "", errors.New("stable Linux machine ID is unavailable")
}

func readLinuxMemory() (uint64, uint64, error) {
	source, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer source.Close()
	var total uint64
	var available uint64
	scanner := bufio.NewScanner(source)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		var target *uint64
		switch fields[0] {
		case "MemTotal:":
			target = &total
		case "MemAvailable:":
			target = &available
		default:
			continue
		}
		kibibytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || kibibytes > math.MaxUint64/1024 {
			return 0, 0, fmt.Errorf("%s is invalid", fields[0])
		}
		*target = kibibytes * 1024
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if total == 0 || available > total {
		return 0, 0, errors.New("/proc/meminfo capacity is invalid")
	}
	return total, available, nil
}
