//go:build windows

package localmachine

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func managedPathIsLink(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(name)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func protectManagedPath(string, bool) error { return nil }

func protectPostgresDataRoot(string) error { return nil }

func verifyPostgresDataRoot(path string) error {
	return verifyManagedPermissions(path, true)
}

func verifyManagedPermissions(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || managedPathIsLink(path, info) || directory != info.IsDir() {
		return errors.New("managed path type is unsafe")
	}
	return nil
}

func verifyNodeExecutableOwner(path string) error { return verifyManagedPermissions(path, false) }

func syncManagedDirectory(string) error { return nil }

func durableReplaceManaged(temporary, target, _ string) error {
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func openManagedRegularNoFollow(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return nil, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		windows.CloseHandle(handle)
		return nil, errors.New("opened managed path is not regular")
	}
	return os.NewFile(uintptr(handle), path), nil
}
