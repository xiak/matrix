package localmachine

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/klauspost/compress/zstd"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	runnerInstalledDirectory = "installed"
	runnerEnrollmentFilename = "enrollment.json"
	maximumGVisorMemory      = 512 * 1024 * 1024
)

type fixedGVisorEntry struct {
	path      string
	size      int64
	directory bool
}

var fixedGVisorArchiveEntries = []fixedGVisorEntry{
	{path: "containerd-shim-runsc-v1", size: 43_446_810},
	{path: "runsc", size: 109_183_255},
	{path: "gvisor-bin", directory: true},
	{path: "gvisor-bin/checkpointgofer", size: 68_978_374},
	{path: "gvisor-bin/gvisor-sentry-prewarmer", size: 1_416},
	{path: "gvisor-bin/gvisor_sentry", size: 51_707_039},
	{path: "gvisor-bin/runsc-metric-server", size: 52_807_462},
}

func (effects *Effects) InstallRunnerNode(
	ctx context.Context,
	plan runnernodecommand.InstallPlan,
) (runnernodecommand.InstallationEvidence, error) {
	if effects == nil || effects.runnerSystem == nil || ctx == nil {
		return runnernodecommand.InstallationEvidence{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runnernodecommand.InstallationEvidence{}, err
	}
	if runnerenrollment.ValidateRequest(plan.Request) != nil ||
		runnerenrollment.ValidateEnrollmentAgainstRequest(plan.Enrollment, plan.Request) != nil ||
		plan.Request.ReleaseID != plan.Bundle.Manifest.Release.ID ||
		!plan.Bundle.Manifest.IncludesProduct(release.ProductDevOps) {
		return runnernodecommand.InstallationEvidence{}, runnernodecommand.ErrEffectInput
	}
	stored, err := readExistingRunnerRequest(plan.Root)
	if err != nil || !equalRunnerRequests(stored, plan.Request) ||
		validateStoredRunnerKeys(plan.Root, plan.Request) != nil {
		return runnernodecommand.InstallationEvidence{}, errors.Join(
			runnernodecommand.ErrEffectVerification, err,
		)
	}
	systemPlan, err := newRunnerSystemPlan(plan.Root, plan.Request)
	if err != nil {
		return runnernodecommand.InstallationEvidence{}, errors.Join(
			runnernodecommand.ErrEffectVerification, err,
		)
	}
	if err := effects.runnerSystem.Preflight(ctx, systemPlan); err != nil {
		return runnernodecommand.InstallationEvidence{}, err
	}
	if err := validatePinnedRunnerBundle(plan.Bundle); err != nil {
		return runnernodecommand.InstallationEvidence{}, errors.Join(
			runnernodecommand.ErrEffectVerification, err,
		)
	}

	installed := filepath.Join(plan.Root, runnerInstalledDirectory)
	if _, statErr := os.Lstat(installed); errors.Is(statErr, os.ErrNotExist) {
		if err := publishPrivateDirectory(installed, func(staging string) error {
			return populateRunnerInstallation(staging, plan.Bundle, plan.Enrollment)
		}); err != nil {
			return runnernodecommand.InstallationEvidence{}, err
		}
	} else if statErr != nil {
		return runnernodecommand.InstallationEvidence{}, errors.Join(
			runnernodecommand.ErrEffectConflict, statErr,
		)
	}
	if err := verifyRunnerInstallation(installed, plan.Bundle, plan.Enrollment); err != nil {
		return runnernodecommand.InstallationEvidence{}, errors.Join(
			runnernodecommand.ErrEffectVerification, err,
		)
	}
	if err := effects.runnerSystem.Converge(ctx, systemPlan); err != nil {
		return runnernodecommand.InstallationEvidence{}, err
	}
	digest, err := runnerenrollment.RequestDigest(plan.Request)
	if err != nil {
		return runnernodecommand.InstallationEvidence{}, runnernodecommand.ErrEffectVerification
	}
	return runnernodecommand.InstallationEvidence{
		ReleaseID: plan.Request.ReleaseID, InstallationID: plan.Request.InstallationID,
		NodeID: plan.Request.NodeID, Slots: uint8(len(plan.Request.Slots)), RequestDigest: digest,
	}, nil
}

func equalRunnerRequests(left, right runnerenrollment.Request) bool {
	leftBytes, leftErr := runnerenrollment.EncodeRequest(left)
	rightBytes, rightErr := runnerenrollment.EncodeRequest(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func validatePinnedRunnerBundle(bundle release.VerifiedBundle) error {
	declarations := make(map[string]release.File, len(bundle.Manifest.Files))
	for _, declaration := range bundle.Manifest.Files {
		declarations[declaration.Path] = declaration
	}
	for _, path := range release.RunnerPayloadPaths() {
		if _, found := declarations[path]; !found {
			return errors.New("runner release declaration is incomplete")
		}
	}
	if declarations[release.RunnerGVisorArchivePath].SHA256 != release.RunnerGVisorArchiveSHA256 {
		return errors.New("runner gVisor release is not pinned")
	}
	for _, path := range release.RunnerPayloadPaths() {
		payload, _, err := bundle.OpenVerifiedPayload(path)
		if err != nil {
			return err
		}
		if closeErr := payload.Close(); closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func populateRunnerInstallation(
	root string,
	bundle release.VerifiedBundle,
	enrollment runnerenrollment.SignedEnrollment,
) error {
	encoded, err := runnerenrollment.EncodeSignedEnrollment(enrollment)
	if err != nil {
		return runnernodecommand.ErrEffectVerification
	}
	defer clear(encoded)
	if err := writePrivateFile(filepath.Join(root, runnerEnrollmentFilename), encoded, false); err != nil {
		return err
	}
	for _, relative := range release.RunnerPayloadPaths() {
		if err := copyVerifiedRunnerPayload(bundle, relative, root); err != nil {
			return err
		}
	}
	if err := writePrivateFile(
		filepath.Join(root, "pki", "server-ca.pem"), enrollment.Document.ServerCA, false,
	); err != nil {
		return err
	}
	if err := writePrivateFile(
		filepath.Join(root, "pki", "runner-ca.pem"), enrollment.Document.RunnerCA, false,
	); err != nil {
		return err
	}
	for _, slot := range enrollment.Document.Slots {
		if err := writePrivateFile(filepath.Join(
			root, "pki", "slots", strconv.Itoa(int(slot.Index)), "client.crt",
		), slot.Certificate, false); err != nil {
			return err
		}
	}
	archive := filepath.Join(root, filepath.FromSlash(release.RunnerGVisorArchivePath))
	if err := extractFixedGVisorArchive(archive, filepath.Join(root, "gvisor")); err != nil {
		return errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	return applyRunnerInstalledModes(root)
}

func verifyRunnerInstallation(
	root string,
	bundle release.VerifiedBundle,
	enrollment runnerenrollment.SignedEnrollment,
) error {
	if err := verifyRunnerInstalledInventory(root, len(enrollment.Document.Slots)); err != nil {
		return err
	}
	encoded, err := runnerenrollment.EncodeSignedEnrollment(enrollment)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := compareInstalledBytes(
		filepath.Join(root, runnerEnrollmentFilename), encoded, maximumEnrollment,
	); err != nil {
		return err
	}
	for _, relative := range release.RunnerPayloadPaths() {
		if err := compareInstalledPayload(bundle, relative, filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			return err
		}
	}
	if err := compareInstalledBytes(
		filepath.Join(root, "pki", "server-ca.pem"), enrollment.Document.ServerCA, maximumEnrollment,
	); err != nil {
		return err
	}
	if err := compareInstalledBytes(
		filepath.Join(root, "pki", "runner-ca.pem"), enrollment.Document.RunnerCA, maximumEnrollment,
	); err != nil {
		return err
	}
	for _, slot := range enrollment.Document.Slots {
		if err := compareInstalledBytes(filepath.Join(
			root, "pki", "slots", strconv.Itoa(int(slot.Index)), "client.crt",
		), slot.Certificate, maximumEnrollment); err != nil {
			return err
		}
	}
	archive := filepath.Join(root, filepath.FromSlash(release.RunnerGVisorArchivePath))
	return verifyFixedGVisorExtraction(archive, filepath.Join(root, "gvisor"))
}

func compareInstalledPayload(bundle release.VerifiedBundle, relative, target string) error {
	source, declaration, err := bundle.OpenVerifiedPayload(relative)
	if err != nil {
		return err
	}
	defer source.Close()
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return err
	}
	defer file.Close()
	sourceHash := sha256.New()
	targetHash := sha256.New()
	sourceSize, sourceErr := io.Copy(sourceHash, io.LimitReader(source, int64(declaration.Size)+1))
	targetSize, targetErr := io.Copy(targetHash, io.LimitReader(file, int64(declaration.Size)+1))
	if sourceErr != nil || targetErr != nil || sourceSize != int64(declaration.Size) ||
		targetSize != int64(declaration.Size) || !bytes.Equal(sourceHash.Sum(nil), targetHash.Sum(nil)) {
		return errors.New("installed runner payload differs")
	}
	return nil
}

func compareInstalledBytes(path string, expected []byte, maximum int64) error {
	content, err := processconfig.ReadFile(path, maximum, false)
	if err != nil {
		return err
	}
	defer clear(content)
	if !bytes.Equal(content, expected) {
		return errors.New("installed runner material differs")
	}
	return nil
}

func extractFixedGVisorArchive(archive, target string) error {
	return extractGVisorArchive(archive, target, fixedGVisorArchiveEntries)
}

func extractGVisorArchive(archive, target string, entries []fixedGVisorEntry) error {
	if err := makePrivateDirectory(target); err != nil {
		return err
	}
	return walkGVisorArchive(archive, entries, func(entry fixedGVisorEntry, content io.Reader) error {
		path := filepath.Join(target, filepath.FromSlash(entry.path))
		if entry.directory {
			return makePrivateDirectory(path)
		}
		if err := makePrivateDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(file, content)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != entry.size {
			return errors.New("extract gVisor executable failed")
		}
		return nil
	})
}

func verifyFixedGVisorExtraction(archive, target string) error {
	return verifyGVisorExtraction(archive, target, fixedGVisorArchiveEntries)
}

func verifyGVisorExtraction(archive, target string, entries []fixedGVisorEntry) error {
	return walkGVisorArchive(archive, entries, func(entry fixedGVisorEntry, content io.Reader) error {
		path := filepath.Join(target, filepath.FromSlash(entry.path))
		if entry.directory {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || managedPathIsLink(path, info) {
				return errors.New("installed gVisor directory is invalid")
			}
			return nil
		}
		file, err := openManagedRegularNoFollow(path)
		if err != nil {
			return err
		}
		defer file.Close()
		archiveHash := sha256.New()
		installedHash := sha256.New()
		archiveSize, archiveErr := io.Copy(archiveHash, content)
		installedSize, installedErr := io.Copy(installedHash, io.LimitReader(file, entry.size+1))
		if archiveErr != nil || installedErr != nil || archiveSize != entry.size ||
			installedSize != entry.size || !bytes.Equal(archiveHash.Sum(nil), installedHash.Sum(nil)) {
			return errors.New("installed gVisor executable differs")
		}
		return nil
	})
}

func walkFixedGVisorArchive(
	archive string,
	visit func(fixedGVisorEntry, io.Reader) error,
) error {
	return walkGVisorArchive(archive, fixedGVisorArchiveEntries, visit)
}

func walkGVisorArchive(
	archive string,
	entries []fixedGVisorEntry,
	visit func(fixedGVisorEntry, io.Reader) error,
) error {
	before, err := os.Lstat(archive)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		visit == nil || validateGVisorEntryProfile(entries) != nil {
		return errors.New("gVisor archive is unsafe")
	}
	file, err := openManagedRegularNoFollow(archive)
	if err != nil {
		return errors.New("open gVisor archive failed")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || before.Size() != opened.Size() ||
		before.ModTime() != opened.ModTime() {
		return errors.New("gVisor archive changed while opening")
	}
	decoder, err := zstd.NewReader(
		file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maximumGVisorMemory),
	)
	if err != nil {
		return errors.New("open gVisor zstd stream failed")
	}
	defer decoder.Close()
	reader := tar.NewReader(decoder)
	seen := make(map[string]struct{}, len(entries))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return errors.New("read gVisor archive failed")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir && len(name) > 0 && name[len(name)-1] == '/' {
			name = name[:len(name)-1]
		}
		entry, found := gVisorEntryByPath(entries, name)
		if !found {
			return errors.New("gVisor archive contains an unexpected entry")
		}
		if _, duplicate := seen[name]; duplicate || header.Mode != 0o755 ||
			(entry.directory && (header.Typeflag != tar.TypeDir || header.Size != 0)) ||
			(!entry.directory && header.Typeflag != tar.TypeReg) || header.Size != entry.size {
			return errors.New("gVisor archive entry is invalid")
		}
		seen[name] = struct{}{}
		limited := &io.LimitedReader{R: reader, N: entry.size}
		if err := visit(entry, limited); err != nil || limited.N != 0 {
			return errors.Join(errors.New("consume gVisor archive entry failed"), err)
		}
	}
	if len(seen) != len(entries) {
		return errors.New("gVisor archive is incomplete")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() ||
		opened.ModTime() != after.ModTime() {
		return errors.New("gVisor archive changed while reading")
	}
	return nil
}

func gVisorEntryByPath(entries []fixedGVisorEntry, path string) (fixedGVisorEntry, bool) {
	for _, entry := range entries {
		if entry.path == path {
			return entry, true
		}
	}
	return fixedGVisorEntry{}, false
}

func validateGVisorEntryProfile(entries []fixedGVisorEntry) error {
	if len(entries) == 0 || len(entries) > 32 {
		return errors.New("gVisor archive profile is invalid")
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.path)))
		if entry.path == "" || clean != entry.path || entry.path == "." ||
			entry.path[0] == '/' || entry.size < 0 || (entry.directory && entry.size != 0) ||
			(!entry.directory && entry.size == 0) {
			return errors.New("gVisor archive profile entry is invalid")
		}
		if _, duplicate := seen[entry.path]; duplicate {
			return errors.New("gVisor archive profile entry is duplicated")
		}
		seen[entry.path] = struct{}{}
	}
	return nil
}

func applyRunnerInstalledModes(root string) error {
	directories := []struct {
		path string
		mode os.FileMode
	}{
		{path: root, mode: 0o711},
		{path: filepath.Join(root, "runner"), mode: 0o555},
		{path: filepath.Join(root, "runner", "linux-amd64"), mode: 0o555},
		{path: filepath.Join(root, "runner", "linux-amd64", "bin"), mode: 0o555},
		{path: filepath.Join(root, "gvisor"), mode: 0o555},
		{path: filepath.Join(root, "gvisor", "gvisor-bin"), mode: 0o555},
	}
	for _, directory := range directories {
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
		}
	}
	if err := os.Chmod(
		filepath.Join(root, filepath.FromSlash(release.RunnerBinaryPath)), 0o555,
	); err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	for _, entry := range fixedGVisorArchiveEntries {
		if entry.directory {
			continue
		}
		if err := os.Chmod(filepath.Join(root, "gvisor", filepath.FromSlash(entry.path)), 0o555); err != nil {
			return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
		}
	}
	return nil
}

func verifyRunnerInstalledInventory(root string, slotCount int) error {
	files := map[string]os.FileMode{
		runnerEnrollmentFilename:                               0o600,
		filepath.FromSlash(release.RunnerBinaryPath):           0o555,
		filepath.FromSlash(release.RunnerToolchainArchivePath): 0o600,
		filepath.FromSlash(release.RunnerGVisorArchivePath):    0o600,
		filepath.FromSlash(release.RunnerGVisorChecksumPath):   0o600,
		filepath.Join("pki", "server-ca.pem"):                  0o600,
		filepath.Join("pki", "runner-ca.pem"):                  0o600,
	}
	directories := map[string]os.FileMode{".": 0o711}
	for relative := range files {
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			if _, found := directories[parent]; !found {
				directories[parent] = 0o700
			}
		}
	}
	for _, relative := range []string{"runner", filepath.Join("runner", "linux-amd64"), filepath.Join("runner", "linux-amd64", "bin")} {
		directories[relative] = 0o555
	}
	for _, entry := range fixedGVisorArchiveEntries {
		relative := filepath.Join("gvisor", filepath.FromSlash(entry.path))
		if entry.directory {
			directories[relative] = 0o555
		} else {
			files[relative] = 0o555
		}
	}
	directories["gvisor"] = 0o555
	for index := 1; index <= slotCount; index++ {
		relative := filepath.Join("pki", "slots", strconv.Itoa(index), "client.crt")
		files[relative] = 0o600
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			if _, found := directories[parent]; !found {
				directories[parent] = 0o700
			}
		}
	}
	seenFiles := make(map[string]struct{}, len(files))
	seenDirectories := make(map[string]struct{}, len(directories))
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || managedPathIsLink(path, info) ||
			!validRunnerInstalledOwner(info) {
			return errors.New("installed runner inventory is unsafe")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			mode, found := directories[relative]
			if !found || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
				return errors.New("installed runner directory is unexpected")
			}
			seenDirectories[relative] = struct{}{}
			return nil
		}
		mode, found := files[relative]
		if !found || !info.Mode().IsRegular() ||
			(runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
			return errors.New("installed runner file is unexpected")
		}
		seenFiles[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seenFiles) != len(files) || len(seenDirectories) != len(directories) {
		return errors.Join(errors.New("installed runner inventory is incomplete"), err)
	}
	return nil
}
