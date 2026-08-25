package release

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	ManifestFilename  = "release.json"
	SignatureFilename = "release.sig"
)

// VerifiedBundle is returned only after the detached signature and every
// declared regular-file payload have been verified from one confined bundle
// directory. Root is retained for later provider effects; it is never part of
// operator-facing evidence.
type VerifiedBundle struct {
	Root           string
	Manifest       Manifest
	ManifestSHA256 string
}

// OpenVerifiedPayload returns one authenticated payload on the same open file
// description that was hashed. Callers can pass it directly to a fixed
// provider command without trusting a path lookup or archive filename.
func (bundle VerifiedBundle) OpenVerifiedPayload(relative string) (*os.File, File, error) {
	var declaration *File
	for index := range bundle.Manifest.Files {
		if bundle.Manifest.Files[index].Path == relative {
			declaration = &bundle.Manifest.Files[index]
			break
		}
	}
	if declaration == nil {
		return nil, File{}, errors.New("release payload is not declared")
	}
	target, err := confinedBundlePath(bundle.Root, declaration.Path)
	if err != nil {
		return nil, File{}, err
	}
	info, err := validateBundlePath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 ||
		uint64(info.Size()) != declaration.Size ||
		!executableModeMatches(info.Mode(), declaration.Executable) {
		return nil, File{}, errors.New("release payload is unsafe")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, File{}, errors.New("open release payload failed")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(declaration.Size)+1))
	openedInfo, statErr := file.Stat()
	expected, digestErr := hex.DecodeString(strings.TrimPrefix(declaration.SHA256, "sha256:"))
	if err != nil || written != int64(declaration.Size) || statErr != nil ||
		!openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) ||
		uint64(openedInfo.Size()) != declaration.Size || digestErr != nil ||
		len(expected) != sha256.Size ||
		subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		_ = file.Close()
		return nil, File{}, errors.New("release payload verification failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, File{}, errors.New("rewind verified release payload failed")
	}
	return file, *declaration, nil
}

// VerifyDirectory verifies a fully extracted offline bundle without following
// a symbolic link or reparse point. Archives are extracted by a separately
// bounded release-builder path; installation consumes this regular-file-only
// representation.
func VerifyDirectory(root string, trustBytes []byte) (VerifiedBundle, error) {
	cleanRoot, err := validateBundleRoot(root)
	if err != nil {
		return VerifiedBundle{}, err
	}
	manifestBytes, _, err := readBundleFile(cleanRoot, ManifestFilename, maximumManifestBytes)
	if err != nil {
		return VerifiedBundle{}, errors.New("read release manifest failed")
	}
	signature, _, err := readBundleFile(cleanRoot, SignatureFilename, ed25519SignatureBytes)
	if err != nil || len(signature) != ed25519SignatureBytes {
		return VerifiedBundle{}, errors.New("read release signature failed")
	}
	manifest, err := Verify(manifestBytes, signature, trustBytes)
	if err != nil {
		return VerifiedBundle{}, err
	}
	if err := verifyDirectoryInventory(cleanRoot, manifest.Files); err != nil {
		return VerifiedBundle{}, err
	}
	digest := sha256.Sum256(manifestBytes)
	return VerifiedBundle{
		Root:           cleanRoot,
		Manifest:       manifest,
		ManifestSHA256: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

func validateBundleRoot(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		isFilesystemRoot(root) {
		return "", errors.New("release bundle root must be a clean absolute non-volume-root path")
	}
	info, err := validateBundlePath(root)
	if err != nil || !info.IsDir() {
		return "", errors.New("release bundle root is unsafe")
	}
	return root, nil
}

func isFilesystemRoot(target string) bool {
	volume := filepath.VolumeName(target)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(target) == filepath.Clean(root)
}

func verifyDirectoryInventory(root string, files []File) error {
	expectedFiles := map[string]*File{
		ManifestFilename:  nil,
		SignatureFilename: nil,
	}
	expectedDirectories := make(map[string]struct{})
	for index := range files {
		file := &files[index]
		expectedFiles[file.Path] = file
		for directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path))); directory != "."; directory = filepath.ToSlash(filepath.Dir(filepath.FromSlash(directory))) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expectedFiles))
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk release bundle failed")
		}
		if current == root {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil || relative == "." || filepath.IsAbs(relative) ||
			relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("release bundle entry escapes its root")
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(current)
		if err != nil || pathComponentIsLink(current, info) {
			return fmt.Errorf("release bundle entry %q is unsafe", relative)
		}
		if info.IsDir() {
			if _, found := expectedDirectories[relative]; !found {
				return fmt.Errorf("release bundle directory %q is undeclared", relative)
			}
			return nil
		}
		declaration, found := expectedFiles[relative]
		if !found || !info.Mode().IsRegular() {
			return fmt.Errorf("release bundle file %q is undeclared or non-regular", relative)
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("release bundle file %q is duplicated", relative)
		}
		seen[relative] = struct{}{}
		if declaration != nil {
			if err := verifyPayload(root, *declaration); err != nil {
				return fmt.Errorf("verify release payload %q failed: %w", relative, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expectedFiles) {
		return errors.New("release bundle payload inventory is incomplete")
	}
	return nil
}

func verifyPayload(root string, declaration File) error {
	target, err := confinedBundlePath(root, declaration.Path)
	if err != nil {
		return err
	}
	info, err := validateBundlePath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != declaration.Size {
		return errors.New("payload length differs from its manifest")
	}
	if !executableModeMatches(info.Mode(), declaration.Executable) {
		return errors.New("payload executable mode differs from its manifest")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return errors.New("open release payload failed")
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(declaration.Size)+1))
	if err != nil || written != int64(declaration.Size) {
		return errors.New("payload length differs from its manifest")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) ||
		uint64(openedInfo.Size()) != declaration.Size {
		return errors.New("release payload changed while it was opened")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(declaration.SHA256, "sha256:"))
	if err != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("payload digest differs from its manifest")
	}
	return nil
}

func readBundleFile(root, relative string, maximum uint64) ([]byte, os.FileInfo, error) {
	if maximum == 0 || maximum > maximumPayloadBytes {
		return nil, nil, errors.New("release file size limit is invalid")
	}
	target, err := confinedBundlePath(root, relative)
	if err != nil {
		return nil, nil, err
	}
	info, err := validateBundlePath(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > maximum {
		return nil, nil, errors.New("release file is unsafe or exceeds its size limit")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, nil, errors.New("open release file failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || uint64(len(content)) > maximum {
		return nil, nil, errors.New("read release file failed or exceeded its size limit")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, nil, errors.New("release file changed while it was opened")
	}
	return content, openedInfo, nil
}

func confinedBundlePath(root, relative string) (string, error) {
	if relative == ManifestFilename || relative == SignatureFilename {
		// The two authenticated metadata files are fixed names rather than
		// manifest payload paths.
	} else if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	target := filepath.Clean(filepath.Join(root, filepath.FromSlash(relative)))
	contained, err := filepath.Rel(root, target)
	if err != nil || contained == "." || contained == ".." || filepath.IsAbs(contained) ||
		strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", errors.New("release file escapes its bundle root")
	}
	return target, nil
}

func validateBundlePath(target string) (os.FileInfo, error) {
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
			return nil, errors.New("release path contains a symbolic link or reparse point")
		}
		if index < len(components)-1 && !info.IsDir() {
			return nil, errors.New("release path parent is not a directory")
		}
		final = info
	}
	if final == nil {
		return nil, errors.New("release path has no components")
	}
	return final, nil
}

func absolutePathComponents(target string) ([]string, error) {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, errors.New("release path must be clean and absolute")
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
