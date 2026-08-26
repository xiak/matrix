package compose

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	managedDirectoryMode = 0o700
	managedFileMode      = 0o600
	maxManagedStateBytes = 4 * 1024 * 1024
)

func prepareManagedRoot(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		isVolumeRoot(root) {
		return "", errors.New("binding root must be a clean absolute path")
	}
	info, err := validateExistingPath(root, true)
	if err != nil {
		return "", fmt.Errorf("binding root is unsafe: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("binding root is not a directory")
	}
	if err := securePermissions(root, true); err != nil {
		return "", fmt.Errorf("binding root permissions cannot be enforced: %w", err)
	}
	if err := verifySecurePermissions(root, true); err != nil {
		return "", fmt.Errorf("binding root permissions are unsafe: %w", err)
	}
	return root, nil
}

func isVolumeRoot(target string) bool {
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(target) == filepath.Clean(root)
}

func validateExistingPath(target string, wantDirectory bool) (os.FileInfo, error) {
	components, err := absolutePathComponents(target)
	if err != nil {
		return nil, err
	}
	var final os.FileInfo
	for index, component := range components {
		info, statErr := os.Lstat(component)
		if statErr != nil {
			return nil, statErr
		}
		if pathComponentIsLink(component, info) {
			return nil, fmt.Errorf("path component %q is a symbolic link or reparse point", component)
		}
		if index < len(components)-1 && !info.IsDir() {
			return nil, fmt.Errorf("path component %q is not a directory", component)
		}
		final = info
	}
	if final == nil {
		return nil, errors.New("absolute path has no components")
	}
	if wantDirectory && !final.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	return final, nil
}

func absolutePathComponents(target string) ([]string, error) {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, errors.New("path must be clean and absolute")
	}
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	remainder := strings.TrimPrefix(target, root)
	components := []string{root}
	current := root
	for _, name := range strings.FieldsFunc(remainder, func(value rune) bool {
		return value == '/' || value == '\\'
	}) {
		current = filepath.Join(current, name)
		components = append(components, current)
	}
	return components, nil
}

func safeJoin(root string, relative ...string) (string, error) {
	joined := filepath.Join(append([]string{root}, relative...)...)
	joined = filepath.Clean(joined)
	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("managed path escapes the binding root")
	}
	return joined, nil
}

func ensureManagedDirectory(root string, relative ...string) (string, error) {
	current := root
	for _, name := range relative {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || filepath.VolumeName(name) != "" {
			return "", errors.New("managed directory name is invalid")
		}
		next, err := safeJoin(root, append(pathRelativeParts(root, current), name)...)
		if err != nil {
			return "", err
		}
		info, statErr := os.Lstat(next)
		switch {
		case statErr == nil:
			if pathComponentIsLink(next, info) || !info.IsDir() {
				return "", fmt.Errorf("managed directory %q is unsafe", next)
			}
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(next, managedDirectoryMode); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			info, statErr = os.Lstat(next)
			if statErr != nil || pathComponentIsLink(next, info) || !info.IsDir() {
				return "", fmt.Errorf("managed directory %q was replaced", next)
			}
		default:
			return "", statErr
		}
		if err := securePermissions(next, true); err != nil {
			return "", err
		}
		if err := verifySecurePermissions(next, true); err != nil {
			return "", err
		}
		current = next
	}
	return current, nil
}

func pathRelativeParts(root, target string) []string {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." {
		return nil
	}
	return strings.Split(rel, string(filepath.Separator))
}

func writeManagedJSON(root, target string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode managed state failed")
	}
	if len(encoded) > maxManagedStateBytes {
		return errors.New("managed state exceeds the size limit")
	}
	return writeManagedFile(root, target, encoded)
}

func writeManagedFile(root, target string, content []byte) (returnErr error) {
	if len(content) > maxManagedStateBytes {
		return errors.New("managed file exceeds the size limit")
	}
	if err := validateManagedTarget(root, target); err != nil {
		return err
	}
	parent := filepath.Dir(target)
	if _, err := validateExistingPath(parent, true); err != nil {
		return fmt.Errorf("managed parent is unsafe: %w", err)
	}
	if err := verifySecurePermissions(parent, true); err != nil {
		return fmt.Errorf("managed parent permissions are unsafe: %w", err)
	}
	if info, err := os.Lstat(target); err == nil {
		if pathComponentIsLink(target, info) || !info.Mode().IsRegular() {
			return errors.New("managed target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temporary, err := temporaryPath(parent)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, managedFileMode)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if returnErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err := securePermissions(temporary, false); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		file = nil
		return err
	}
	file = nil
	if err := validateManagedTarget(root, target); err != nil {
		return err
	}
	if err := durableReplace(temporary, target, parent); err != nil {
		return err
	}
	if err := verifySecurePermissions(target, false); err != nil {
		return err
	}
	return nil
}

func temporaryPath(parent string) (string, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return "", errors.New("generate temporary file identity failed")
	}
	return filepath.Join(parent, ".matrix-tmp-"+hex.EncodeToString(identity[:])), nil
}

func validateManagedTarget(root, target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("managed target must be a clean absolute path")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("managed target escapes the binding root")
	}
	return nil
}

func readManagedFile(root, target string, maximum int64) ([]byte, error) {
	if err := validateManagedTarget(root, target); err != nil {
		return nil, err
	}
	info, err := validateExistingPath(target, false)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("managed state is not a regular file")
	}
	if err := verifySecurePermissions(target, false); err != nil {
		return nil, err
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("managed state exceeds the size limit")
	}
	return content, nil
}

func decodeManagedJSON(root, target string, value any) error {
	content, err := readManagedFile(root, target, maxManagedStateBytes)
	if err != nil {
		return err
	}
	return decodeStrictJSON(content, value)
}

func decodeStrictJSON(content []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("managed state is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("managed state has trailing content")
	}
	return nil
}

func inspectManagedRoot(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) ||
		filepath.Clean(root) != root || isVolumeRoot(root) {
		return "", errors.New("binding root is invalid")
	}
	info, err := validateExistingPath(root, true)
	if err != nil || !info.IsDir() || verifySecurePermissions(root, true) != nil {
		return "", errors.New("binding root is unsafe")
	}
	return root, nil
}

func removeManagedFile(root, target string) error {
	if err := validateManagedTarget(root, target); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if pathComponentIsLink(target, info) || !info.Mode().IsRegular() {
		return errors.New("managed removal target is unsafe")
	}
	return os.Remove(target)
}

func wipe(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
