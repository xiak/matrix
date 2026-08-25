package release

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrStageConflict = errors.New("staged release content conflicts with authenticated input")

// StageDirectory copies authenticated release bytes into one protected,
// installation-owned directory. It streams image archives, verifies every
// copied byte before publication, and resumes only exact partial staging.
func StageDirectory(
	bundle VerifiedBundle,
	trustBytes []byte,
	destination string,
) (VerifiedBundle, error) {
	verified, err := VerifyDirectory(bundle.Root, trustBytes)
	if err != nil || verified.ManifestSHA256 != bundle.ManifestSHA256 ||
		verified.Manifest.Release.ID != bundle.Manifest.Release.ID {
		return VerifiedBundle{}, errors.New("release bundle changed before staging")
	}
	if destination == "" || len(destination) > 4096 || !filepath.IsAbs(destination) ||
		filepath.Clean(destination) != destination || isFilesystemRoot(destination) {
		return VerifiedBundle{}, errors.New("staged release destination is invalid")
	}
	parent := filepath.Dir(destination)
	parentInfo, err := validateBundlePath(parent)
	if err != nil || !parentInfo.IsDir() || !ownerOnlyMode(parentInfo.Mode(), true) {
		return VerifiedBundle{}, errors.New("staged release parent is unsafe")
	}

	if info, statErr := os.Lstat(destination); statErr == nil {
		if pathComponentIsLink(destination, info) || !info.IsDir() ||
			!ownerOnlyMode(info.Mode(), true) {
			return VerifiedBundle{}, ErrStageConflict
		}
		staged, verifyErr := VerifyDirectory(destination, trustBytes)
		if verifyErr != nil || staged.ManifestSHA256 != verified.ManifestSHA256 {
			return VerifiedBundle{}, ErrStageConflict
		}
		return staged, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return VerifiedBundle{}, errors.New("inspect staged release destination failed")
	}

	staging := destination + ".staging"
	if info, statErr := os.Lstat(staging); errors.Is(statErr, os.ErrNotExist) {
		if err := os.Mkdir(staging, 0o700); err != nil {
			return VerifiedBundle{}, errors.New("create staged release directory failed")
		}
		if err := os.Chmod(staging, 0o700); err != nil || syncReleaseDirectory(parent) != nil {
			return VerifiedBundle{}, errors.New("protect staged release directory failed")
		}
	} else if statErr != nil || pathComponentIsLink(staging, info) || !info.IsDir() ||
		!ownerOnlyMode(info.Mode(), true) {
		return VerifiedBundle{}, ErrStageConflict
	}

	for _, declaration := range verified.Manifest.Files {
		if err := ensureStageParents(staging, declaration.Path); err != nil {
			return VerifiedBundle{}, err
		}
		if err := copyStagedPayload(verified.Root, staging, declaration); err != nil {
			return VerifiedBundle{}, err
		}
	}
	for _, metadata := range []struct {
		name    string
		maximum uint64
	}{
		{name: ManifestFilename, maximum: maximumManifestBytes},
		{name: SignatureFilename, maximum: ed25519SignatureBytes},
	} {
		content, _, err := readBundleFile(verified.Root, metadata.name, metadata.maximum)
		if err != nil {
			return VerifiedBundle{}, errors.New("read authenticated release metadata failed")
		}
		if err := writeExactStageFile(staging, metadata.name, content, 0o600); err != nil {
			return VerifiedBundle{}, err
		}
	}

	staged, err := VerifyDirectory(staging, trustBytes)
	if err != nil || staged.ManifestSHA256 != verified.ManifestSHA256 {
		return VerifiedBundle{}, ErrStageConflict
	}
	if err := os.Rename(staging, destination); err != nil {
		return VerifiedBundle{}, errors.New("publish staged release failed")
	}
	if err := syncReleaseDirectory(parent); err != nil {
		return VerifiedBundle{}, errors.New("publish staged release durability failed")
	}
	staged.Root = destination
	return staged, nil
}

func ensureStageParents(root, relative string) error {
	directory := filepath.Dir(filepath.Join(root, filepath.FromSlash(relative)))
	relativeDirectory, err := filepath.Rel(root, directory)
	if err != nil || relativeDirectory == ".." || filepath.IsAbs(relativeDirectory) ||
		strings.HasPrefix(relativeDirectory, ".."+string(filepath.Separator)) {
		return ErrStageConflict
	}
	current := root
	if relativeDirectory == "." {
		return nil
	}
	for _, component := range strings.Split(relativeDirectory, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(current, 0o700); err != nil || os.Chmod(current, 0o700) != nil ||
				syncReleaseDirectory(filepath.Dir(current)) != nil {
				return errors.New("create staged release parent failed")
			}
		case statErr != nil, pathComponentIsLink(current, info), !info.IsDir(),
			!ownerOnlyMode(info.Mode(), true):
			return ErrStageConflict
		}
	}
	return nil
}

func copyStagedPayload(sourceRoot, stagingRoot string, declaration File) error {
	target := filepath.Join(stagingRoot, filepath.FromSlash(declaration.Path))
	if info, err := os.Lstat(target); err == nil {
		if pathComponentIsLink(target, info) || !info.Mode().IsRegular() ||
			!ownerOnlyMode(info.Mode(), false) || verifyPayload(stagingRoot, declaration) != nil {
			return ErrStageConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStageConflict
	}

	source, err := confinedBundlePath(sourceRoot, declaration.Path)
	if err != nil {
		return err
	}
	sourceInfo, err := validateBundlePath(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() < 0 ||
		uint64(sourceInfo.Size()) != declaration.Size ||
		!executableModeMatches(sourceInfo.Mode(), declaration.Executable) {
		return errors.New("release payload changed before staging")
	}
	input, err := openRegularNoFollow(source)
	if err != nil {
		return errors.New("open release payload for staging failed")
	}
	defer input.Close()

	partial := target + ".partial"
	if info, statErr := os.Lstat(partial); statErr == nil {
		if pathComponentIsLink(partial, info) || !info.Mode().IsRegular() ||
			!ownerOnlyMode(info.Mode(), false) || os.Remove(partial) != nil {
			return ErrStageConflict
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrStageConflict
	}
	mode := os.FileMode(0o600)
	if declaration.Executable {
		mode = 0o700
	}
	output, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("create staged release payload failed")
	}
	removePartial := true
	defer func() {
		_ = output.Close()
		if removePartial {
			_ = os.Remove(partial)
		}
	}()
	if err := os.Chmod(partial, mode); err != nil {
		return errors.New("protect staged release payload failed")
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(input, int64(declaration.Size)+1))
	if err != nil || written != int64(declaration.Size) {
		return errors.New("copy staged release payload failed")
	}
	openedInfo, err := input.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(sourceInfo, openedInfo) ||
		uint64(openedInfo.Size()) != declaration.Size {
		return errors.New("release payload changed while staging")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(declaration.SHA256, "sha256:"))
	if err != nil || len(expected) != sha256.Size ||
		subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("staged release payload digest differs")
	}
	if err := output.Sync(); err != nil || output.Close() != nil {
		return errors.New("flush staged release payload failed")
	}
	if err := os.Rename(partial, target); err != nil ||
		syncReleaseDirectory(filepath.Dir(target)) != nil {
		return errors.New("publish staged release payload failed")
	}
	removePartial = false
	return nil
}

func writeExactStageFile(root, relative string, content []byte, mode os.FileMode) error {
	target := filepath.Join(root, relative)
	if info, err := os.Lstat(target); err == nil {
		if pathComponentIsLink(target, info) || !info.Mode().IsRegular() ||
			!ownerOnlyMode(info.Mode(), false) {
			return ErrStageConflict
		}
		existing, _, readErr := readBundleFile(root, relative, uint64(len(content)))
		if readErr != nil || subtle.ConstantTimeCompare(existing, content) != 1 {
			return ErrStageConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStageConflict
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("create staged release metadata failed")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(target)
		}
	}()
	if err := os.Chmod(target, mode); err != nil {
		return errors.New("protect staged release metadata failed")
	}
	if _, err := file.Write(content); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("write staged release metadata failed")
	}
	if err := syncReleaseDirectory(filepath.Dir(target)); err != nil {
		return errors.New("flush staged release metadata failed")
	}
	remove = false
	return nil
}
