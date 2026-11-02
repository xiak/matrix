package localcontainer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// WriteImmutable compares existing content without overwriting it. The parent is the exact
// protected project directory already checked by localcontainer.
func WriteImmutable(path string, content []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(content) > 64*1024 ||
		(mode != 0o600 && mode != 0o640) {
		return errors.New("managed-service protected configuration is invalid")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) || info.Size() > 64*1024 {
			return errors.New("managed-service configuration file conflicts")
		}
		existing, readErr := os.ReadFile(path)
		defer clear(existing)
		if readErr != nil || !bytes.Equal(existing, content) {
			return errors.New("managed-service immutable configuration changed")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("managed-service configuration is unavailable")
	}
	// Publish only complete, synced content. A crash while preparing a file
	// must not leave a partial named configuration that prevents equal replay.
	file, err := os.CreateTemp(filepath.Dir(path), ".matrix-configuration-")
	if err != nil {
		return errors.New("managed-service configuration cannot be created")
	}
	defer os.Remove(file.Name())
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("managed-service configuration cannot be committed")
	}
	if err := os.Link(file.Name(), path); errors.Is(err, os.ErrExist) {
		return WriteImmutable(path, content, mode)
	} else if err != nil {
		return errors.New("managed-service configuration cannot be published")
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return errors.New("managed-service configuration directory is unavailable")
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return errors.New("managed-service configuration durability is unconfirmed")
		}
	}
	return nil
}

// ReadProtectedSecret admits only a bounded regular secret file. The caller
// resolves its path from the protected installation and clears the returned bytes.
func ReadProtectedSecret(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("managed-service credential reference is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640) || info.Size() < 32 || info.Size() > 256 {
		return nil, errors.New("managed-service credential is unavailable")
	}
	value, err := os.ReadFile(path)
	if err != nil || len(value) < 32 || len(value) > 256 {
		clear(value)
		return nil, errors.New("managed-service credential cannot be read")
	}
	for _, b := range value {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			clear(value)
			return nil, errors.New("managed-service credential format is invalid")
		}
	}
	return value, nil
}
