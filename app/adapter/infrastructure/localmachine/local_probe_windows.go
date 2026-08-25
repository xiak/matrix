//go:build windows

package localmachine

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").
	NewProc("GlobalMemoryStatusEx")

type memoryStatusEx struct {
	length            uint32
	memoryLoad        uint32
	totalPhysical     uint64
	availablePhysical uint64
	totalPageFile     uint64
	availablePageFile uint64
	totalVirtual      uint64
	availableVirtual  uint64
	availableExtended uint64
}

func readLocalMetrics(storagePath string) (localMetrics, error) {
	machineID, err := readWindowsMachineID()
	if err != nil {
		return localMetrics{}, err
	}
	memory, err := readWindowsMemory()
	if err != nil {
		return localMetrics{}, err
	}
	if storagePath == "" {
		storagePath, err = os.Getwd()
		if err != nil {
			return localMetrics{}, err
		}
	}
	pathPointer, err := windows.UTF16PtrFromString(storagePath)
	if err != nil {
		return localMetrics{}, err
	}
	var available uint64
	var total uint64
	var totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(
		pathPointer,
		&available,
		&total,
		&totalFree,
	); err != nil {
		return localMetrics{}, err
	}
	return localMetrics{
		machineID:             machineID,
		memoryTotalBytes:      memory.totalPhysical,
		memoryAvailableBytes:  memory.availablePhysical,
		storageTotalBytes:     total,
		storageAvailableBytes: available,
	}, nil
}

func readWindowsMachineID() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		key, err = registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Cryptography`,
			registry.QUERY_VALUE,
		)
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("Windows MachineGuid is empty")
	}
	return value, nil
}

func readWindowsMemory() (memoryStatusEx, error) {
	var status memoryStatusEx
	status.length = uint32(unsafe.Sizeof(status))
	result, _, callErr := globalMemoryStatusEx.Call(
		uintptr(unsafe.Pointer(&status)),
	)
	if result == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = errors.New("GlobalMemoryStatusEx returned false")
		}
		return memoryStatusEx{}, callErr
	}
	return status, nil
}
