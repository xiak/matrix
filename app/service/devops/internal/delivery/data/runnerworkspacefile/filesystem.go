package runnerworkspacefile

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func recoverStaging(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	entries, readErr := directory.ReadDir(maximumWorkspaceEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumWorkspaceEntries {
		return errors.Join(ErrUnavailable, closeErr)
	}
	changed := false
	for _, entry := range entries {
		switch {
		case entry.Name() == ownershipLockName:
			info, infoErr := entry.Info()
			if infoErr != nil || !validOwnershipFile(info) {
				return errors.Join(ErrUnavailable, infoErr)
			}
		case entry.Name() == rootIdentityTemporary:
			info, infoErr := entry.Info()
			if infoErr != nil || entry.Type()&os.ModeSymlink != 0 ||
				!info.Mode().IsRegular() || !privateMode(info.Mode(), 0o600) {
				return errors.Join(ErrUnavailable, infoErr)
			}
			if err := root.Remove(entry.Name()); err != nil {
				return errors.Join(ErrUnavailable, err)
			}
			changed = true
		case validStagingName(entry.Name()):
			info, infoErr := entry.Info()
			if infoErr != nil || entry.Type()&os.ModeSymlink != 0 || !info.IsDir() ||
				!privateMode(info.Mode(), 0o700) {
				return errors.Join(ErrUnavailable, infoErr)
			}
			if err := discardStaging(root, entry.Name()); err != nil {
				return err
			}
			changed = true
		}
	}
	if changed {
		if err := syncDirectory(root, "."); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
	}
	return nil
}

func discardStaging(root *os.Root, name string) error {
	if root == nil || !validStagingName(name) {
		return ErrInvalid
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return errors.Join(ErrUnavailable, err)
	}
	directories := make([]string, 0, 16)
	err = walkRoot(root, name, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrUnavailable
		}
		if err := root.Chmod(path, 0o600); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.Count(directories[left], "/") < strings.Count(directories[right], "/")
	})
	for _, directory := range directories {
		if err := root.Chmod(directory, 0o700); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
	}
	if err := root.RemoveAll(name); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if err := syncDirectory(root, "."); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func listWorkspaceKeys(root *os.Root) ([]string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	entries, readErr := directory.ReadDir(maximumWorkspaceEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(ErrUnavailable, readErr, closeErr)
	}
	if closeErr != nil || len(entries) > maximumWorkspaceEntries {
		return nil, errors.Join(ErrUnavailable, closeErr)
	}
	keys := make([]string, 0, len(entries))
	foundLock := false
	foundIdentity := false
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrUnavailable, infoErr)
		}
		switch entry.Name() {
		case ownershipLockName:
			if foundLock || !validOwnershipFile(info) {
				return nil, ErrUnavailable
			}
			foundLock = true
		case rootIdentityName:
			if foundIdentity || !info.Mode().IsRegular() ||
				!privateMode(info.Mode(), 0o600) || info.Size() <= 0 ||
				info.Size() > maximumManifestBytes {
				return nil, ErrUnavailable
			}
			foundIdentity = true
		default:
			if !validWorkspaceKey(entry.Name()) || !info.IsDir() ||
				!privateMode(info.Mode(), 0o700) {
				return nil, ErrUnavailable
			}
			keys = append(keys, entry.Name())
		}
	}
	if !foundLock || !foundIdentity || len(keys) > maximumWorkspaces {
		return nil, ErrUnavailable
	}
	sort.Strings(keys)
	return keys, nil
}

func readManifest(root *os.Root, key string) (manifest, error) {
	if !validWorkspaceKey(key) || validateWorkspaceShape(root, key) != nil {
		return manifest{}, ErrUnavailable
	}
	content, err := readPrivateFile(root, key+"/"+manifestName, maximumManifestBytes)
	if err != nil {
		return manifest{}, err
	}
	return decodeManifest(content)
}

func validateWorkspaceShape(root *os.Root, key string) error {
	if !validWorkspaceKey(key) && !validStagingName(key) {
		return ErrUnavailable
	}
	info, err := root.Lstat(key)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return errors.Join(ErrUnavailable, err)
	}
	directory, err := root.Open(key)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	entries, readErr := directory.ReadDir(maximumWorkspaceChildren)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	if closeErr != nil || len(entries) != 2 {
		return errors.Join(ErrUnavailable, closeErr)
	}
	foundManifest := false
	foundSource := false
	for _, entry := range entries {
		entryInfo, infoErr := entry.Info()
		if infoErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.Join(ErrUnavailable, infoErr)
		}
		switch entry.Name() {
		case manifestName:
			if !entryInfo.Mode().IsRegular() || !privateMode(entryInfo.Mode(), 0o600) ||
				entryInfo.Size() <= 0 || entryInfo.Size() > maximumManifestBytes {
				return ErrUnavailable
			}
			foundManifest = true
		case sourceDirectoryName:
			if !entryInfo.IsDir() || !privateMode(entryInfo.Mode(), 0o555) {
				return ErrUnavailable
			}
			foundSource = true
		default:
			return ErrUnavailable
		}
	}
	if !foundManifest || !foundSource {
		return ErrUnavailable
	}
	return nil
}

func scanPublishedTree(
	ctx context.Context,
	root *os.Root,
	key string,
) (treeEvidence, error) {
	if err := validateWorkspaceShape(root, key); err != nil {
		return treeEvidence{}, err
	}
	return scanTree(ctx, root, key+"/"+sourceDirectoryName)
}

func scanTree(
	ctx context.Context,
	root *os.Root,
	sourceRoot string,
) (treeEvidence, error) {
	if ctx == nil || root == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return treeEvidence{}, ctx.Err()
		}
		return treeEvidence{}, ErrInvalid
	}
	rootInfo, err := root.Lstat(sourceRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() ||
		!privateMode(rootInfo.Mode(), 0o555) {
		return treeEvidence{}, errors.Join(ErrUnavailable, err)
	}
	digest := startTreeDigest()
	actualDirectories := make(map[string]struct{})
	expectedDirectories := make(map[string]struct{})
	var evidence treeEvidence
	type publishedFile struct {
		name       string
		relative   string
		info       os.FileInfo
		executable bool
	}
	files := make([]publishedFile, 0, 64)
	err = walkRoot(root, sourceRoot, func(name string, info os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !sameFilesystem(rootInfo, info) {
			return ErrUnavailable
		}
		if name == sourceRoot {
			return nil
		}
		relative := strings.TrimPrefix(name, sourceRoot+"/")
		if relative == name || relative == "" {
			return ErrUnavailable
		}
		if info.IsDir() {
			if !privateMode(info.Mode(), 0o555) ||
				len(actualDirectories) >= int(sourcearchive.MaximumPathCount) {
				return ErrUnavailable
			}
			actualDirectories[relative] = struct{}{}
			return nil
		}
		if !info.Mode().IsRegular() || sourcearchive.ValidatePath(relative) != nil ||
			(!privateMode(info.Mode(), 0o444) && !privateMode(info.Mode(), 0o555)) ||
			evidence.PathCount >= sourcearchive.MaximumPathCount || info.Size() < 0 ||
			info.Size() > sourcearchive.MaximumExpandedBytes-evidence.ExpandedBytes {
			return ErrUnavailable
		}
		if err := addParentDirectories(expectedDirectories, relative); err != nil {
			return err
		}
		files = append(files, publishedFile{
			name: name, relative: relative, info: info,
			executable: info.Mode().Perm()&0o111 != 0,
		})
		evidence.PathCount++
		evidence.ExpandedBytes += info.Size()
		return nil
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return treeEvidence{}, ctxErr
	}
	if err != nil || !equalStringSets(actualDirectories, expectedDirectories) {
		return treeEvidence{}, errors.Join(ErrUnavailable, err)
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].relative < files[right].relative
	})
	for _, published := range files {
		if err := ctx.Err(); err != nil {
			return treeEvidence{}, err
		}
		writeTreeHeader(
			digest, published.relative, published.executable, published.info.Size(),
		)
		file, err := root.Open(published.name)
		if err != nil {
			return treeEvidence{}, errors.Join(ErrUnavailable, err)
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(published.info, opened) ||
			!opened.Mode().IsRegular() || opened.Size() != published.info.Size() {
			_ = file.Close()
			return treeEvidence{}, errors.Join(ErrUnavailable, statErr)
		}
		copied, copyErr := io.Copy(digest, &contextReader{ctx: ctx, reader: file})
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || afterErr != nil || closeErr != nil || copied != published.info.Size() ||
			!os.SameFile(opened, after) || after.Size() != opened.Size() ||
			after.ModTime() != opened.ModTime() || after.Mode() != opened.Mode() {
			return treeEvidence{}, errors.Join(ErrUnavailable, copyErr, afterErr, closeErr)
		}
	}
	evidence.DirectoryCount = uint64(len(actualDirectories))
	evidence.TreeDigest = finishTreeDigest(digest)
	return evidence, nil
}

func walkRoot(
	root *os.Root,
	start string,
	visit func(string, os.FileInfo) error,
) error {
	if root == nil || visit == nil {
		return ErrInvalid
	}
	return fs.WalkDir(root.FS(), start, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.Join(ErrUnavailable, walkErr)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrUnavailable, err)
		}
		return visit(name, info)
	})
}

func equalStringSets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, found := right[value]; !found {
			return false
		}
	}
	return true
}

func readPrivateFile(root *os.Root, name string, maximum int) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!privateMode(info.Mode(), 0o600) || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, errors.Join(ErrUnavailable, err)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		_ = file.Close()
		return nil, errors.Join(ErrUnavailable, statErr)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	after, afterErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || closeErr != nil || int64(len(content)) != info.Size() ||
		!os.SameFile(opened, after) || after.Size() != opened.Size() ||
		after.ModTime() != opened.ModTime() || after.Mode() != opened.Mode() {
		return nil, errors.Join(ErrUnavailable, readErr, afterErr, closeErr)
	}
	return content, nil
}

func writePrivateFile(root *os.Root, name string, content []byte) error {
	if len(content) == 0 || len(content) > maximumManifestBytes {
		return ErrUnavailable
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func syncDirectory(root *os.Root, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func syncFile(root *os.Root, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
