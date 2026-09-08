package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RunnerGVisorChecksumContent is the exact upstream-style checksum document
// carried beside the fixed gVisor archive. It is a fresh slice so callers
// cannot alter the static release contract.
func RunnerGVisorChecksumContent() []byte {
	return []byte(strings.TrimPrefix(RunnerGVisorArchiveSHA256, "sha256:") +
		"  " + filepath.Base(filepath.FromSlash(RunnerGVisorArchivePath)) + "\n")
}

// VerifyRunnerDirectory authenticates the independently transferable subset
// of one DevOps-selected Matrix release. The signed outer manifest remains the
// authority; unrelated platform images are deliberately absent from this
// dedicated-node bundle.
func VerifyRunnerDirectory(root string, trustBytes []byte) (VerifiedBundle, error) {
	return verifyRunnerDirectory(
		root, trustBytes, RunnerGVisorArchiveSHA256, RunnerGVisorChecksumContent(),
	)
}

func verifyRunnerDirectory(
	root string,
	trustBytes []byte,
	gvisorDigest string,
	gvisorChecksum []byte,
) (VerifiedBundle, error) {
	if !digestPattern.MatchString(gvisorDigest) || len(gvisorChecksum) == 0 ||
		len(gvisorChecksum) > maximumManifestBytes {
		return VerifiedBundle{}, errors.New("runner release verification profile is invalid")
	}
	cleanRoot, err := validateBundleRoot(root)
	if err != nil {
		return VerifiedBundle{}, err
	}
	manifestBytes, _, err := readBundleFile(cleanRoot, ManifestFilename, maximumManifestBytes)
	if err != nil {
		return VerifiedBundle{}, errors.New("read runner release manifest failed")
	}
	signature, _, err := readBundleFile(cleanRoot, SignatureFilename, ed25519SignatureBytes)
	if err != nil || len(signature) != ed25519SignatureBytes {
		return VerifiedBundle{}, errors.New("read runner release signature failed")
	}
	manifest, err := Verify(manifestBytes, signature, trustBytes)
	if err != nil || !manifest.IncludesProduct(ProductDevOps) {
		return VerifiedBundle{}, errors.New("runner release is not an authenticated DevOps release")
	}
	declarations := make(map[string]File, len(manifest.Files))
	for _, declaration := range manifest.Files {
		declarations[declaration.Path] = declaration
	}
	for _, required := range RunnerReleasePayloadPaths() {
		if _, found := declarations[required]; !found {
			return VerifiedBundle{}, errors.New("runner release payload declaration is incomplete")
		}
	}
	if declarations[RunnerGVisorArchivePath].SHA256 != gvisorDigest {
		return VerifiedBundle{}, errors.New("runner release gVisor archive is not pinned")
	}
	if err := verifySelectedDirectoryInventory(
		cleanRoot, RunnerReleasePayloadPaths(),
	); err != nil {
		return VerifiedBundle{}, err
	}
	bundle := VerifiedBundle{Root: cleanRoot, Manifest: manifest}
	digest := sha256.Sum256(manifestBytes)
	bundle.ManifestSHA256 = "sha256:" + hex.EncodeToString(digest[:])
	for _, required := range RunnerReleasePayloadPaths() {
		payload, _, openErr := bundle.OpenVerifiedPayload(required)
		if openErr != nil {
			return VerifiedBundle{}, errors.New("runner release payload verification failed")
		}
		if closeErr := payload.Close(); closeErr != nil {
			return VerifiedBundle{}, errors.New("close verified runner release payload failed")
		}
	}
	checksum, _, err := bundle.OpenVerifiedPayload(RunnerGVisorChecksumPath)
	if err != nil {
		return VerifiedBundle{}, errors.New("open runner gVisor checksum failed")
	}
	content, readErr := io.ReadAll(io.LimitReader(checksum, int64(maximumManifestBytes)+1))
	closeErr := checksum.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(content, gvisorChecksum) {
		return VerifiedBundle{}, errors.New("runner gVisor checksum is invalid")
	}
	return bundle, nil
}

func verifySelectedDirectoryInventory(root string, selected []string) error {
	expectedFiles := map[string]*File{
		ManifestFilename:  nil,
		SignatureFilename: nil,
	}
	expectedDirectories := make(map[string]struct{})
	for _, relative := range selected {
		expectedFiles[relative] = nil
		for directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(relative))); directory != "."; directory = filepath.ToSlash(filepath.Dir(filepath.FromSlash(directory))) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expectedFiles))
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk runner release failed")
		}
		if current == root {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("runner release entry escapes its root")
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(current)
		if err != nil || pathComponentIsLink(current, info) {
			return fmt.Errorf("runner release entry %q is unsafe", relative)
		}
		if info.IsDir() {
			if _, found := expectedDirectories[relative]; !found {
				return fmt.Errorf("runner release directory %q is undeclared", relative)
			}
			return nil
		}
		if _, found := expectedFiles[relative]; !found || !info.Mode().IsRegular() {
			return fmt.Errorf("runner release file %q is undeclared or non-regular", relative)
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("runner release file %q is duplicated", relative)
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expectedFiles) {
		return errors.New("runner release payload inventory is incomplete")
	}
	return nil
}
