package localmachine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func nodeCredentialFiles(plan nodecommand.Plan) []nodeFile {
	return []nodeFile{
		{layout.NodeCertificate, plan.Credentials.Certificate}, {layout.NodePrivateKey, plan.Credentials.PrivateKey},
		{layout.NodeTrust, plan.Credentials.Trust}, {layout.CollectorCertificate, plan.Credentials.CollectorCertificate},
		{layout.CollectorPrivateKey, plan.Credentials.CollectorPrivateKey},
	}
}

// The bounded private snapshot is one atomic file, not a second configuration
// authority. Its five values authenticate against the journal's commitment.
func encodeNodeCredentials(material nodecommand.Credentials) ([]byte, error) {
	return json.Marshal([5][]byte{material.Certificate, material.PrivateKey, material.Trust,
		material.CollectorCertificate, material.CollectorPrivateKey})
}

func decodeNodeCredentials(source []byte) (nodecommand.Credentials, error) {
	var values [][]byte
	err := json.Unmarshal(source, &values)
	valid := err == nil && len(values) == 5
	for index, value := range values {
		maximum := 64 * 1024
		if index == 2 {
			maximum = 256 * 1024
		}
		valid = valid && len(value) > 0 && len(value) <= maximum
	}
	if !valid {
		for _, value := range values {
			clear(value)
		}
		return nodecommand.Credentials{}, nodecommand.ErrVerification
	}
	return nodecommand.Credentials{Certificate: values[0], PrivateKey: values[1], Trust: values[2],
		CollectorCertificate: values[3], CollectorPrivateKey: values[4]}, nil
}

func (effects *NodeEffects) preflightNodeRotation(ctx context.Context, plan nodecommand.Plan) error {
	if err := authenticateNodeFiles(*plan.Previous); err != nil {
		return err
	}
	if err := effects.supervisor.Preflight(ctx, plan.Bundle.Manifest.Host.MinimumSystemd); err != nil {
		return err
	}
	if _, err := effects.supervisor.InspectStartup(ctx, nativeNodeStartup(plan)); err != nil {
		return err
	}
	for _, service := range nativeNodeServices(plan) {
		if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
			return err
		}
	}
	// Only bounded credential snapshots and replacement files are staged. A
	// renewal does not need another release's disk budget or a Docker mutation.
	required := uint64(128 * 1024)
	for _, candidate := range []nodecommand.Plan{*plan.Previous, plan} {
		for _, file := range nodeCredentialFiles(candidate) {
			required += 2 * uint64(len(file.content))
		}
	}
	available, err := availableFilesystemBytes(plan.Root)
	if err != nil || available < required {
		return nodecommand.ErrPrecondition
	}
	return nil
}

func stageNodeCredentials(plan nodecommand.Plan) error {
	if plan.Previous == nil || nodecommand.ValidatePlan(plan) != nil {
		return nodecommand.ErrVerification
	}
	if err := authenticateNodeFiles(*plan.Previous); err != nil {
		return err
	}
	for _, candidate := range []nodecommand.Plan{*plan.Previous, plan} {
		content, err := encodeNodeCredentials(candidate.Credentials)
		if err != nil {
			return nodecommand.ErrVerification
		}
		err = writeManagedOnce(plan.Root, filepath.FromSlash(layout.NodeCredentialSnapshot(candidate.Binding.ConfigurationDigest)), content)
		clear(content)
		if err != nil {
			return errors.Join(nodecommand.ErrConflict, err)
		}
	}
	return nil
}

func (effects *NodeEffects) replaceNodeCredentials(ctx context.Context, plan nodecommand.Plan) error {
	if plan.Previous == nil || nodecommand.ValidatePlan(plan) != nil {
		return nodecommand.ErrVerification
	}
	if _, err := authenticateNodeRelease(plan); err != nil {
		return err
	}
	before, err := nodeFiles(*plan.Previous)
	if err != nil {
		return nodecommand.ErrVerification
	}
	after, err := nodeFiles(plan)
	if err != nil || len(before) != len(after) {
		return nodecommand.ErrVerification
	}
	// Recovery may observe a mix of the two sealed sets. Prove every byte and
	// every service owner before stopping anything or replacing the first file.
	for index, file := range after {
		if file.name != before[index].name {
			return nodecommand.ErrVerification
		}
		actual, err := readManagedFile(plan.Root, filepath.FromSlash(file.name),
			int64(max(len(file.content), len(before[index].content))))
		valid := err == nil && (bytes.Equal(actual, file.content) || bytes.Equal(actual, before[index].content))
		clear(actual)
		if !valid {
			return nodecommand.ErrConflict
		}
	}
	if err := verifyMaterializedCollector(plan); err != nil {
		return err
	}
	if _, err := effects.supervisor.InspectStartup(ctx, nativeNodeStartup(plan)); err != nil {
		return err
	}
	services := nativeNodeServices(plan)
	for _, service := range services {
		if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
			return err
		}
	}
	for index := len(services) - 1; index >= 0; index-- {
		if err := effects.supervisor.Stop(ctx, services[index]); err != nil {
			return err
		}
	}
	for index, file := range after {
		if err := replaceManagedExpected(plan.Root, filepath.FromSlash(file.name), before[index].content, file.content); err != nil {
			if errors.Is(err, errManagedOutcomeUnknown) {
				return errors.Join(nodecommand.ErrOutcomeUnknown, err)
			}
			return errors.Join(nodecommand.ErrConflict, err)
		}
	}
	return authenticateNodeFiles(plan)
}

// FinalizeRotation runs only after the new commitment is durable. Each unlink
// is exact, authenticated and replayable; no directory tree or operator input
// is deleted. A later rotation must finish this cleanup before staging more keys.
func (effects *NodeEffects) FinalizeRotation(ctx context.Context, plan nodecommand.Plan, command lifecycle.Command) error {
	plan.Previous, plan.RevokePreviousCredentials = nil, false
	if effects == nil || ctx == nil || command.Action != lifecycle.ActionRotateCredentials ||
		command.InputDigest != plan.Binding.ConfigurationDigest || command.ExpectedConfigurationDigest == command.InputDigest {
		return nodecommand.ErrVerification
	}
	// Validate the receipt's digest syntax before constructing a managed path.
	for _, digest := range []string{command.ExpectedConfigurationDigest, command.InputDigest} {
		if paasv1.ValidateDigest("configurationDigest", digest) != nil {
			return nodecommand.ErrVerification
		}
	}
	if err := authenticateNodeFiles(plan); err != nil {
		return err
	}
	for _, digest := range []string{command.ExpectedConfigurationDigest, command.InputDigest} {
		if ctx.Err() != nil {
			return nodecommand.ErrOutcomeUnknown
		}
		relative := filepath.FromSlash(layout.NodeCredentialSnapshot(digest))
		path, err := managedPath(plan.Root, relative)
		if err != nil {
			return nodecommand.ErrConflict
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nodecommand.ErrConflict
		}
		_, material, err := effects.ReadRotation(plan.Root, digest)
		if err != nil {
			return err
		}
		expected, err := encodeNodeCredentials(material)
		material.Clear()
		if err != nil {
			return nodecommand.ErrVerification
		}
		actual, err := readManagedFile(plan.Root, relative, int64(len(expected)))
		equal := err == nil && bytes.Equal(actual, expected)
		clear(actual)
		clear(expected)
		if !equal {
			return nodecommand.ErrConflict
		}
		if os.Remove(path) != nil || syncManagedDirectory(filepath.Dir(path)) != nil {
			return nodecommand.ErrOutcomeUnknown
		}
	}
	return nil
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
