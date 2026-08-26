//go:build windows

package release

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func syncReleaseDirectory(string) error { return nil }

func ownerOnlyMode(mode os.FileMode, directory bool) bool {
	return directory == mode.IsDir() && mode&os.ModeSymlink == 0
}

func pathComponentIsLink(path string, info os.FileInfo) bool {
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

func openRegularNoFollow(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
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
		return nil, errors.New("opened release path is not a regular file")
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Windows has no portable executable permission bit. Executable identity is
// still content-addressed and is enforced when the bundle is installed on the
// supported Linux target.
func executableModeMatches(_ os.FileMode, _ bool) bool {
	return true
}
