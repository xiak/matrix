package localmachine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func collectorDeclaration(plan nodecommand.Plan) (release.File, error) {
	for _, file := range plan.Bundle.Manifest.Files {
		if file.Path == "bin/node-exporter" && file.Executable && file.Size > 0 && file.Size <= 64*1024*1024 {
			return file, nil
		}
	}
	return release.File{}, nodecommand.ErrVerification
}

// The signed release stays owner-only. Only this reverified executable copy
// is made readable/executable in a private service mount namespace; its parent
// remains private and no credential directory is made traversable.
func materializeCollector(plan nodecommand.Plan) error {
	bundle, err := authenticateNodeRelease(plan)
	if err != nil {
		return err
	}
	declaration, err := collectorDeclaration(plan)
	if err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(plan.Root, filepath.Dir(filepath.FromSlash(layout.CollectorExecutable))); err != nil {
		return errors.Join(nodecommand.ErrConflict, err)
	}
	target, err := managedPath(plan.Root, filepath.FromSlash(layout.CollectorExecutable))
	if err != nil {
		return nodecommand.ErrConflict
	}
	if _, err := os.Lstat(target); err == nil {
		return verifyMaterializedCollector(plan)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nodecommand.ErrConflict
	}
	input, err := openManagedRegularNoFollow(filepath.Join(bundle.Root, "bin", "node-exporter"))
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer input.Close()
	partial := target + ".partial"
	if info, err := os.Lstat(partial); err == nil {
		if managedPathIsLink(partial, info) || !info.Mode().IsRegular() || verifyNodeExecutableOwner(partial) != nil || os.Remove(partial) != nil {
			return nodecommand.ErrConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nodecommand.ErrConflict
	}
	output, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nodecommand.ErrConflict
	}
	published := false
	defer func() {
		_ = output.Close()
		if !published {
			_ = os.Remove(partial)
		}
	}()
	if err := protectManagedPath(partial, false); err != nil {
		return nodecommand.ErrConflict
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(input, int64(declaration.Size)+1))
	if err != nil || uint64(written) != declaration.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != declaration.SHA256 {
		return nodecommand.ErrVerification
	}
	if output.Chmod(0o555) != nil || output.Sync() != nil || output.Close() != nil {
		return nodecommand.ErrUnavailable
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return nodecommand.ErrConflict
	}
	if os.Rename(partial, target) != nil {
		return nodecommand.ErrUnavailable
	}
	published = true
	if syncManagedDirectory(filepath.Dir(target)) != nil {
		return nodecommand.ErrOutcomeUnknown
	}
	return verifyMaterializedCollector(plan)
}

func verifyMaterializedCollector(plan nodecommand.Plan) error {
	declaration, err := collectorDeclaration(plan)
	if err != nil {
		return err
	}
	target, err := managedPath(plan.Root, filepath.FromSlash(layout.CollectorExecutable))
	if err != nil {
		return nodecommand.ErrVerification
	}
	info, err := validateManagedExistingPath(target)
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != declaration.Size ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o555) ||
		verifyNodeExecutableOwner(target) != nil {
		return nodecommand.ErrConflict
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return nodecommand.ErrConflict
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(declaration.Size)+1))
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(info, opened) || uint64(written) != declaration.Size ||
		"sha256:"+hex.EncodeToString(hasher.Sum(nil)) != declaration.SHA256 {
		return nodecommand.ErrVerification
	}
	return nil
}
