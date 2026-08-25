package journal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	managedDirectoryMode = 0o700
	managedFileMode      = 0o600
)

func isVolumeRoot(target string) bool {
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(target) == filepath.Clean(root)
}

func validateExistingPath(target string) (os.FileInfo, error) {
	components, err := absolutePathComponents(target)
	if err != nil {
		return nil, err
	}
	var final os.FileInfo
	for index, component := range components {
		info, err := os.Lstat(component)
		if err != nil {
			return nil, err
		}
		if pathComponentIsLink(component, info) {
			return nil, errors.New("installation path contains a link or reparse point")
		}
		if index < len(components)-1 && !info.IsDir() {
			return nil, errors.New("installation path parent is not a directory")
		}
		final = info
	}
	if final == nil {
		return nil, errors.New("installation path has no components")
	}
	return final, nil
}

func absolutePathComponents(target string) ([]string, error) {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, errors.New("installation path must be clean and absolute")
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

func validateManagedTarget(root, target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("managed installation target must be clean and absolute")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("managed installation target escapes its root")
	}
	return nil
}

func readManagedFile(root, target string, maximum int64) ([]byte, error) {
	if err := validateManagedTarget(root, target); err != nil {
		return nil, err
	}
	info, err := validateExistingPath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum ||
		verifySecurePermissions(target, false) != nil {
		return nil, errors.New("managed installation file is unsafe")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, errors.New("open managed installation file failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, errors.New("managed installation file exceeds its bound")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("managed installation file changed while opened")
	}
	return content, nil
}

func readExactRegularFile(target string, size int) ([]byte, error) {
	info, err := validateExistingPath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(size) ||
		verifySecurePermissions(target, false) != nil {
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, int64(size)+1))
	if err != nil || len(content) != size {
		return nil, ErrIntegrity
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, ErrIntegrity
	}
	return content, nil
}

func writeNewManagedFile(target, parent string, content []byte) (returnErr error) {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, managedFileMode)
	if err != nil {
		return errors.New("create managed installation file failed")
	}
	defer func() {
		if file != nil {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if returnErr != nil {
			_ = os.Remove(target)
		}
	}()
	if err := securePermissions(target, false); err != nil {
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
	return syncDirectory(parent)
}

func writeManagedFile(root, target string, content []byte) (returnErr error) {
	if len(content) == 0 || len(content) > maximumJournalBytes {
		return errors.New("managed installation content is outside its bound")
	}
	if err := validateManagedTarget(root, target); err != nil {
		return err
	}
	parent := filepath.Dir(target)
	parentInfo, err := validateExistingPath(parent)
	if err != nil || !parentInfo.IsDir() || verifySecurePermissions(parent, true) != nil {
		return errors.New("managed installation parent is unsafe")
	}
	if info, err := os.Lstat(target); err == nil {
		if pathComponentIsLink(target, info) || !info.Mode().IsRegular() ||
			verifySecurePermissions(target, false) != nil {
			return errors.New("managed installation target is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect managed installation target failed")
	}
	temporary, err := temporaryPath(parent)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, managedFileMode)
	if err != nil {
		return errors.New("create managed installation temporary file failed")
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
	return verifySecurePermissions(target, false)
}

func temporaryPath(parent string) (string, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return "", errors.New("generate managed installation temporary identity failed")
	}
	return filepath.Join(parent, ".matrix-tmp-"+hex.EncodeToString(identity[:])), nil
}
