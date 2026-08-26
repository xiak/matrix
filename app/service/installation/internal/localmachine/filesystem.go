package localmachine

import (
	"crypto/subtle"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
)

const maximumManagedFileBytes = 4 * 1024 * 1024

var errManagedConflict = errors.New("installation-owned file conflicts with expected content")

func managedFileExists(root, relative string) (bool, error) {
	target, err := managedPath(root, relative)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || managedPathIsLink(target, info) || !info.Mode().IsRegular() ||
		verifyManagedPermissions(target, false) != nil {
		return false, errManagedConflict
	}
	return true, nil
}

func ensureManagedDirectory(root, relative string) (string, error) {
	if relative == "." {
		if err := validateManagedRoot(root); err != nil {
			return "", err
		}
		return root, nil
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return "", err
	}
	if err := validateManagedRoot(root); err != nil {
		return "", err
	}
	current := root
	contained, err := filepath.Rel(root, target)
	if err != nil {
		return "", errors.New("resolve installation-owned directory failed")
	}
	for _, component := range strings.Split(contained, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(current, 0o700); err != nil ||
				protectManagedPath(current, true) != nil ||
				syncManagedDirectory(filepath.Dir(current)) != nil {
				return "", errors.New("create installation-owned directory failed")
			}
		case statErr != nil, managedPathIsLink(current, info), !info.IsDir(),
			verifyManagedPermissions(current, true) != nil:
			return "", errManagedConflict
		}
	}
	return target, nil
}

// ensurePostgresDataRoot keeps every parent private while allowing the fixed
// PostgreSQL UID to traverse the bind-mount root after the official entrypoint
// drops privileges. The directory cannot be listed by another UID, and its
// provider-owned children are never treated as Matrix-managed files.
func ensurePostgresDataRoot(root string) (string, error) {
	if _, err := ensureManagedDirectory(root, "data"); err != nil {
		return "", err
	}
	target, err := managedPath(root, filepath.FromSlash(layout.PostgresData))
	if err != nil {
		return "", err
	}
	info, statErr := os.Lstat(target)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		if err := os.Mkdir(target, 0o700); err != nil ||
			protectPostgresDataRoot(target) != nil ||
			syncManagedDirectory(target) != nil ||
			syncManagedDirectory(filepath.Dir(target)) != nil {
			return "", errors.New("create PostgreSQL data root failed")
		}
	case statErr != nil, managedPathIsLink(target, info), !info.IsDir(),
		verifyPostgresDataRoot(target) != nil:
		return "", errManagedConflict
	}
	if err := verifyPostgresDataRoot(target); err != nil {
		return "", errManagedConflict
	}
	return target, nil
}

func writeManagedOnce(root, relative string, content []byte) error {
	if len(content) == 0 || len(content) > maximumManagedFileBytes {
		return errors.New("installation-owned content exceeds its bound")
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(root, filepath.Dir(relative)); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil {
		if managedPathIsLink(target, info) || !info.Mode().IsRegular() ||
			verifyManagedPermissions(target, false) != nil {
			return errManagedConflict
		}
		existing, readErr := readManagedFile(root, relative, int64(len(content)))
		if readErr != nil || subtle.ConstantTimeCompare(existing, content) != 1 {
			return errManagedConflict
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errManagedConflict
	}

	partial := target + ".partial"
	if info, statErr := os.Lstat(partial); statErr == nil {
		if managedPathIsLink(partial, info) || !info.Mode().IsRegular() ||
			verifyManagedPermissions(partial, false) != nil || os.Remove(partial) != nil {
			return errManagedConflict
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errManagedConflict
	}
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create installation-owned file failed")
	}
	removePartial := true
	defer func() {
		_ = file.Close()
		if removePartial {
			_ = os.Remove(partial)
		}
	}()
	if err := protectManagedPath(partial, false); err != nil {
		return errors.New("protect installation-owned file failed")
	}
	if _, err := file.Write(content); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("write installation-owned file failed")
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
		return errManagedConflict
	}
	if err := os.Rename(partial, target); err != nil ||
		syncManagedDirectory(filepath.Dir(target)) != nil {
		return errors.New("publish installation-owned file failed")
	}
	removePartial = false
	return verifyManagedPermissions(target, false)
}

// ensureManagedMutableFile creates a private provider-owned runtime file once.
// Replays prove its type, owner, mode, containment, and size without comparing
// content because the fixed provider is expected to rewrite it in place.
func ensureManagedMutableFile(root, relative string, initial []byte) error {
	if len(initial) == 0 || len(initial) > maximumManagedFileBytes {
		return errors.New("installation-owned mutable content exceeds its bound")
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(root, filepath.Dir(relative)); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return writeManagedOnce(root, relative, initial)
	}
	if err != nil || managedPathIsLink(target, info) || !info.Mode().IsRegular() ||
		info.Size() < 0 || info.Size() > maximumManagedFileBytes ||
		verifyManagedPermissions(target, false) != nil {
		return errManagedConflict
	}
	if _, err := readManagedFile(root, relative, maximumManagedFileBytes); err != nil {
		return errManagedConflict
	}
	return nil
}

func readManagedFile(root, relative string, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum > maximumManagedFileBytes {
		return nil, errors.New("installation-owned read bound is invalid")
	}
	target, err := managedPath(root, relative)
	if err != nil {
		return nil, err
	}
	info, err := validateManagedExistingPath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum ||
		verifyManagedPermissions(target, false) != nil {
		return nil, errors.New("installation-owned file is unsafe")
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return nil, errors.New("open installation-owned file failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, errors.New("read installation-owned file failed")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("installation-owned file changed while opened")
	}
	return content, nil
}

func removeManagedTree(root, relative string) error {
	target, err := managedPath(root, relative)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("inspect installation-owned cleanup target failed")
	}
	paths := make([]string, 0)
	err = filepath.WalkDir(target, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		contained, err := filepath.Rel(target, path)
		if err != nil || contained == ".." || filepath.IsAbs(contained) ||
			strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
			return errManagedConflict
		}
		info, err := os.Lstat(path)
		if err != nil || managedPathIsLink(path, info) ||
			verifyManagedPermissions(path, info.IsDir()) != nil {
			return errManagedConflict
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return errManagedConflict
	}
	slices.Reverse(paths)
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			return errors.New("remove installation-owned object failed")
		}
	}
	return syncManagedDirectory(filepath.Dir(target))
}

func managedPath(root, relative string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		relative == "." || strings.ContainsRune(relative, 0) {
		return "", errors.New("installation-owned path is invalid")
	}
	target := filepath.Clean(filepath.Join(root, relative))
	contained, err := filepath.Rel(root, target)
	if err != nil || contained == "." || contained == ".." || filepath.IsAbs(contained) ||
		strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", errors.New("installation-owned path escapes its root")
	}
	return target, nil
}

func validateManagedRoot(root string) error {
	info, err := validateManagedExistingPath(root)
	if err != nil || !info.IsDir() || verifyManagedPermissions(root, true) != nil {
		return errors.New("installation root is unsafe")
	}
	return nil
}

func validateManagedExistingPath(target string) (os.FileInfo, error) {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, errors.New("managed path must be clean and absolute")
	}
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	remainder := strings.TrimPrefix(target, root)
	current := root
	var final os.FileInfo
	for _, component := range strings.FieldsFunc(remainder, func(value rune) bool {
		return value == '/' || value == '\\'
	}) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || managedPathIsLink(current, info) {
			return nil, errors.New("managed path contains an unsafe component")
		}
		final = info
	}
	if final == nil {
		return nil, errors.New("managed path has no components")
	}
	return final, nil
}
