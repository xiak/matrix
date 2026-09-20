package localmachine

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const (
	totpBackupCustodyEntrypoint = "/matrix/bin/matrix-iam-backup-custody"
	totpBackupCustodyDSNTarget  = "/run/matrix/iam-backup-custody-dsn"
)

type backupCustodyResult struct {
	started bool
	err     error
}

type backupCustodyProcess struct {
	input    *io.PipeWriter
	output   *boundedLeaseOutput
	done     <-chan backupCustodyResult
	cancel   context.CancelFunc
	lease    []byte
	finished bool
}

type boundedLeaseOutput struct {
	mu        sync.Mutex
	content   []byte
	ready     chan struct{}
	readyOnce sync.Once
	exceeded  bool
}

func newBoundedLeaseOutput() *boundedLeaseOutput {
	return &boundedLeaseOutput{ready: make(chan struct{})}
}

func (output *boundedLeaseOutput) Write(content []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	maximum := int(installationv1.MaximumTOTPBackupCustodyBytes) + 1
	if output.exceeded || len(output.content)+len(content) > maximum {
		output.exceeded = true
		output.readyOnce.Do(func() { close(output.ready) })
		return 0, errors.New("backup custody output exceeds its bound")
	}
	output.content = append(output.content, content...)
	if bytes.Contains(output.content, []byte{'\n'}) || len(output.content) == maximum {
		if len(output.content) == maximum && output.content[maximum-1] != '\n' {
			output.exceeded = true
		}
		output.readyOnce.Do(func() { close(output.ready) })
	}
	return len(content), nil
}

func (output *boundedLeaseOutput) snapshot() ([]byte, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.content...), output.exceeded
}

func startTOTPBackupCustody(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	streaming streamingDockerRuntime,
	plan platformcommand.InstallPlan,
	installation verifiedInstallation,
	backupID string,
) (*backupCustodyProcess, installationv1.TOTPBackupSnapshotLease, error) {
	if ctx == nil || runtimeBoundary == nil || streaming == nil ||
		!backupIDPattern.MatchString(backupID) {
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("TOTP backup custody is unavailable"),
		)
	}
	imageID := ""
	for _, image := range installation.bundle.Manifest.Images {
		if image.Component != "iam" {
			continue
		}
		if imageID != "" {
			return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("TOTP backup custody image identity is ambiguous"),
			)
		}
		imageID = image.ImageID
	}
	if imageID == "" {
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody image is unavailable"),
		)
	}
	present, err := inspectExactImage(ctx, runtimeBoundary, imageID)
	if err != nil {
		return nil, installationv1.TOTPBackupSnapshotLease{}, err
	}
	if !present {
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody image is unavailable"),
		)
	}
	networkID, err := controlNetworkID(
		ctx, runtimeBoundary, installation.topology.ProjectName,
		plan.InstallationID, installation.bundle.Manifest.Release.ID,
	)
	if err != nil {
		return nil, installationv1.TOTPBackupSnapshotLease{}, err
	}
	dsnSource, err := managedPath(plan.Root, filepath.FromSlash(layout.IAMBackupCustody))
	if err != nil || strings.ContainsRune(dsnSource, ',') {
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody credential path is invalid"),
		)
	}
	dsn, err := readManagedFile(
		plan.Root, filepath.FromSlash(layout.IAMBackupCustody), maximumCredentialFile,
	)
	defer clear(dsn)
	if err != nil || validateDatabaseDSN(string(dsn), "matrix_iam_backup_custody_login") != nil {
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody credential is unavailable"),
		)
	}
	arguments := []string{
		"run", "--rm", "--pull", "never", "--interactive",
		"--name", installation.topology.ProjectName + "-iam-backup-custody-" + strings.TrimPrefix(backupID, "backup-"),
		"--network", networkID,
		"--user", "0:0", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--cpus", "1", "--memory", "256m", "--memory-swap", "256m",
		"--pids-limit", "64", "--ipc", "private", "--cgroupns", "private",
		"--log-driver", "none",
		"--label", "com.xiak.matrix.managed=true",
		"--label", "com.xiak.matrix.installation=" + plan.InstallationID,
		"--label", "com.xiak.matrix.release=" + installation.bundle.Manifest.Release.ID,
		"--label", "com.xiak.matrix.role=iam-backup-custody",
		"--label", "com.xiak.matrix.backup=" + backupID,
		"--mount", "type=bind,src=" + dsnSource + ",dst=" + totpBackupCustodyDSNTarget + ",readonly",
		"--env", installationv1.TOTPBackupCustodyDatabaseDSNFileEnvironment + "=" + totpBackupCustodyDSNTarget,
		"--entrypoint", totpBackupCustodyEntrypoint,
		imageID, installationv1.TOTPBackupCustodySnapshotCommand,
	}
	processContext, cancel := context.WithTimeout(
		ctx, time.Duration(installationv1.TOTPBackupSnapshotLeaseMaximumSeconds)*time.Second,
	)
	inputReader, inputWriter := io.Pipe()
	output := newBoundedLeaseOutput()
	done := make(chan backupCustodyResult, 1)
	go func() {
		started, runErr := streaming.RunTo(processContext, inputReader, output, arguments...)
		_ = inputReader.Close()
		done <- backupCustodyResult{started: started, err: runErr}
	}()
	process := &backupCustodyProcess{
		input: inputWriter, output: output, done: done, cancel: cancel,
	}
	select {
	case <-output.ready:
	case result := <-done:
		process.finished = true
		process.cancel()
		_ = process.input.Close()
		if !result.started {
			return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
				platformcommand.ErrEffectUnavailable,
				errors.New("TOTP backup custody process did not start"),
			)
		}
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody process exited before exporting a snapshot"),
		)
	case <-processContext.Done():
		process.abort()
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("TOTP backup custody snapshot export timed out"),
		)
	}
	line, exceeded := output.snapshot()
	if exceeded || len(line) < 2 || int64(len(line)) > installationv1.MaximumTOTPBackupCustodyBytes+1 ||
		line[len(line)-1] != '\n' || bytes.Count(line, []byte{'\n'}) != 1 {
		process.abort()
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody process emitted an invalid lease frame"),
		)
	}
	lease, err := installationv1.DecodeTOTPBackupSnapshotLease(bytes.NewReader(line[:len(line)-1]))
	if err != nil {
		process.abort()
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody process emitted an invalid lease"),
		)
	}
	sealedInstallationID, bootstrapDigest, err := sealedIAMBootstrapScope(plan.Root, plan.InstallationID)
	if err != nil || lease.Custody.InstallationID != sealedInstallationID ||
		lease.Custody.BootstrapDigest != bootstrapDigest {
		process.abort()
		return nil, installationv1.TOTPBackupSnapshotLease{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody scope differs from the sealed installation"),
		)
	}
	process.lease = append([]byte(nil), line...)
	return process, lease, nil
}

func (process *backupCustodyProcess) release() error {
	if process == nil || process.finished {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody process is not active"),
		)
	}
	written, writeErr := io.WriteString(process.input, installationv1.TOTPBackupCustodyReleaseFrame)
	closeErr := process.input.Close()
	result := <-process.done
	process.finished = true
	process.cancel()
	content, exceeded := process.output.snapshot()
	if writeErr != nil || written != len(installationv1.TOTPBackupCustodyReleaseFrame) || closeErr != nil ||
		!result.started || result.err != nil || exceeded || !bytes.Equal(content, process.lease) {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("TOTP backup custody process did not close cleanly"),
		)
	}
	return nil
}

func (process *backupCustodyProcess) abort() {
	if process == nil || process.finished {
		return
	}
	_ = process.input.Close()
	process.cancel()
	<-process.done
	process.finished = true
}

func validateBackupTOTPBackupCustody(value *backupTOTPBackupCustody) error {
	if value == nil || installationv1.ValidateTOTPBackupCustody(value.Custody) != nil ||
		iamv1.ValidateDigest("custodyDigest", value.CustodyDigest) != nil {
		return errors.New("backup TOTP custody is invalid")
	}
	digest, err := installationv1.TOTPBackupCustodyDigest(value.Custody)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(value.CustodyDigest)) != 1 {
		return errors.New("backup TOTP custody digest is invalid")
	}
	return nil
}

func verifyBackupTOTPBackupCustody(
	root, installationID string,
	manifest backupManifest,
) error {
	if manifest.APIVersion != backupAPIVersion {
		if manifest.TOTPBackupCustody != nil {
			return errors.New("legacy backup contains TOTP custody")
		}
		return nil
	}
	if err := validateBackupTOTPBackupCustody(manifest.TOTPBackupCustody); err != nil {
		return err
	}
	keyring, err := readTOTPKeyring(root, installationID)
	if err != nil {
		return err
	}
	defer func() { keyring = iamv1.TOTPKeyring{} }()
	custody := manifest.TOTPBackupCustody.Custody
	if keyring.Scope.InstallationID != custody.InstallationID ||
		keyring.Scope.BootstrapDigest != custody.BootstrapDigest ||
		keyring.KeysetRevision < custody.KeysetRevision {
		return errors.New("backup TOTP custody differs from the installation keyring")
	}
	keys := make(map[string]iamv1.TOTPWrappingKey, len(keyring.Keys))
	for _, key := range keyring.Keys {
		keys[key.KeyID] = key
	}
	for _, required := range custody.RequiredKeys {
		key, found := keys[required.KeyID]
		if !found || key.FormatVersion != required.FormatVersion {
			return errors.New("backup TOTP custody requires an unavailable wrapping key")
		}
		commitment, err := iamv1.TOTPKeyMaterialCommitment(keyring, required.KeyID)
		if err != nil || subtle.ConstantTimeCompare([]byte(commitment), []byte(required.Commitment)) != 1 {
			return errors.New("backup TOTP custody wrapping key commitment differs")
		}
	}
	return nil
}
