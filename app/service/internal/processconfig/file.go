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
	before, err := os.Lstat(path)
	if err != nil || !acceptableFile(before, maximumBytes, secret) {
		return nil, errors.New("process input file is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("process input file is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) ||
		!acceptableFile(opened, maximumBytes, secret) {
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
