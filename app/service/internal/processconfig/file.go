package processconfig

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unicode"
	"unicode/utf8"
)

func ReadFile(path string, maximumBytes int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || maximumBytes < 1 || maximumBytes > 16*1024*1024 {
		return nil, errors.New("process input file configuration is invalid")
	}
	return readExactFile(path, maximumBytes, func(info os.FileInfo) bool {
		return acceptableFile(info, maximumBytes, secret)
	})
}

// ReadSystemdCredential reads one immutable credential from the directory
// supplied to a service through CREDENTIALS_DIRECTORY. Unlike a normal secret,
// systemd may expose the file as root-owned 0440 through an isolated id-mapped
// mount so that the configured non-root service can read it.
func ReadSystemdCredential(
	directory string,
	name string,
	maximumBytes int64,
	secret bool,
) ([]byte, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		directory == filepath.VolumeName(directory)+string(filepath.Separator) ||
		name == "" || len(name) > 255 || filepath.Base(name) != name ||
		filepath.Clean(name) != name || maximumBytes < 1 || maximumBytes > 16*1024*1024 {
		return nil, errors.New("systemd credential configuration is invalid")
	}
	beforeDirectory, err := os.Lstat(directory)
	if err != nil || !acceptableCredentialDirectory(beforeDirectory) {
		return nil, errors.New("systemd credential directory is unavailable")
	}
	target := filepath.Join(directory, name)
	value, err := readExactFile(target, maximumBytes, func(info os.FileInfo) bool {
		return acceptableSystemdCredential(info, maximumBytes, secret)
	})
	if err != nil {
		return nil, err
	}
	afterDirectory, err := os.Lstat(directory)
	if err != nil || !os.SameFile(beforeDirectory, afterDirectory) ||
		beforeDirectory.Mode() != afterDirectory.Mode() {
		clear(value)
		return nil, errors.New("systemd credential directory changed while reading")
	}
	return value, nil
}

func readExactFile(
	path string,
	maximumBytes int64,
	acceptable func(os.FileInfo) bool,
) ([]byte, error) {
	if acceptable == nil {
		return nil, errors.New("process input file policy is unavailable")
	}
	before, err := os.Lstat(path)
	if err != nil || !acceptable(before) {
		return nil, errors.New("process input file is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("process input file is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) ||
		!acceptable(opened) {
		return nil, errors.New("process input file changed while opening")
	}
	value, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || int64(len(value)) > maximumBytes || int64(len(value)) != opened.Size() {
		clear(value)
		return nil, errors.New("process input file cannot be read exactly")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() ||
		opened.ModTime() != after.ModTime() {
		clear(value)
		return nil, errors.New("process input file changed while reading")
	}
	return value, nil
}

func ReadText(path string, maximumBytes int64, secret bool) (string, error) {
	value, err := ReadFile(path, maximumBytes, secret)
	if err != nil {
		return "", err
	}
	defer clear(value)
	if len(value) == 0 || !utf8.Valid(value) {
		return "", errors.New("process text input is invalid")
	}
	for remaining := value; len(remaining) > 0; {
		character, size := utf8.DecodeRune(remaining)
		if unicode.IsControl(character) {
			return "", errors.New("process text input is invalid")
		}
		remaining = remaining[size:]
	}
	return string(value), nil
}

func acceptableFile(info os.FileInfo, maximumBytes int64, secret bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumBytes {
		return false
	}
	return !secret || runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
}

func acceptableCredentialDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm() == 0o500 || info.Mode().Perm() == 0o550
}

func acceptableSystemdCredential(info os.FileInfo, maximumBytes int64, secret bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumBytes {
		return false
	}
	if !secret || runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm() == 0o400 || info.Mode().Perm() == 0o440
}
