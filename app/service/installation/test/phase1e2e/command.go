package phase1e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	maximumCommandOutput                  = 1024 * 1024
	credentialRecoveryInterruptionTimeout = 2 * time.Minute
)

type commandOutput struct {
	stdout []byte
	stderr []byte
	exit   int
}

type boundedBuffer struct {
	content   bytes.Buffer
	remaining int
	overflow  bool
}

func newBoundedBuffer(maximum int) *boundedBuffer {
	return &boundedBuffer{remaining: maximum}
}

func (value *boundedBuffer) Write(content []byte) (int, error) {
	original := len(content)
	if original > value.remaining {
		content = content[:value.remaining]
		value.overflow = true
	}
	written, err := value.content.Write(content)
	value.remaining -= written
	if err != nil {
		return written, err
	}
	return original, nil
}

func runProcess(ctx context.Context, executable string, arguments ...string) (commandOutput, error) {
	return runProcessWithEnvironment(ctx, nil, executable, arguments...)
}

func runProcessWithEnvironment(ctx context.Context, environment []string, executable string, arguments ...string) (commandOutput, error) {
	stdout := newBoundedBuffer(maximumCommandOutput)
	stderr := newBoundedBuffer(maximumCommandOutput)
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	if environment != nil {
		command.Env = environment
	}
	err := command.Run()
	result := commandOutput{
		stdout: append([]byte(nil), stdout.content.Bytes()...),
		stderr: append([]byte(nil), stderr.content.Bytes()...),
	}
	if stdout.overflow || stderr.overflow {
		return commandOutput{}, errors.New("command output exceeded acceptance bound")
	}
	if err == nil {
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.exit = exit.ExitCode()
		return result, nil
	}
	return commandOutput{}, err
}

type mxEnvelope struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Action     string   `json:"action"`
	Status     string   `json:"status"`
	Result     mxResult `json:"result"`
}

type mxResult struct {
	State               string `json:"state"`
	ReleaseID           string `json:"releaseId,omitempty"`
	PreviousID          string `json:"previousId,omitempty"`
	BackupID            string `json:"backupId,omitempty"`
	Changed             bool   `json:"changed"`
	CorrelationID       string `json:"correlationId,omitempty"`
	ConfigurationDigest string `json:"configurationDigest,omitempty"`
}

type mxFailure struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Error      struct {
		Class   string `json:"class"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func mxPath(bundle release.VerifiedBundle) string {
	return filepath.Join(bundle.Root, filepath.FromSlash("bin/mx"))
}

func runMX(
	ctx context.Context,
	bundle release.VerifiedBundle,
	action string,
	arguments []string,
	forbidden [][]byte,
) (mxResult, error) {
	args := []string{"--format", "json", "platform", action}
	args = append(args, arguments...)
	output, err := runProcess(ctx, mxPath(bundle), args...)
	if err != nil || containsAny(output.stdout, forbidden) || containsAny(output.stderr, forbidden) {
		return mxResult{}, fail("mx-" + action)
	}
	if output.exit != 0 || len(output.stderr) != 0 {
		if code, ok := classifyMXFailure(output, action); ok {
			return mxResult{}, fail("mx-" + action + "-" + code)
		}
		return mxResult{}, fail("mx-" + action)
	}
	var envelope mxEnvelope
	if decodeOne(output.stdout, &envelope) != nil ||
		envelope.APIVersion != "cli.matrix.xiak.com/v1" ||
		envelope.Kind != "PlatformCommandResult" || envelope.Action != strings.ToUpper(strings.ReplaceAll(action, "-", "_")) ||
		envelope.Status != "SUCCEEDED" || envelope.Result.State != "READY" {
		return mxResult{}, fail("mx-" + action + "-result")
	}
	return envelope.Result, nil
}

func classifyMXFailure(output commandOutput, action string) (string, bool) {
	if output.exit == 0 || len(output.stdout) != 0 || len(output.stderr) == 0 {
		return "", false
	}
	var envelope mxFailure
	if decodeOne(output.stderr, &envelope) != nil ||
		envelope.APIVersion != "cli.matrix.xiak.com/v1" ||
		envelope.Kind != "PlatformCommandFailure" ||
		envelope.Action != strings.ToUpper(strings.ReplaceAll(action, "-", "_")) ||
		envelope.Status != "FAILED" || !validMXFailureCode(envelope.Error.Code) {
		return "", false
	}
	wantExit, wantMessage, ok := mxFailureContract(envelope.Error.Class)
	if !ok || output.exit != wantExit || envelope.Error.Message != wantMessage {
		return "", false
	}
	return envelope.Error.Code, true
}

func completedMXFailureCode(
	waitErr error,
	stdout, stderr *boundedBuffer,
	action string,
	forbidden [][]byte,
) (string, bool) {
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || stdout == nil || stderr == nil ||
		stdout.overflow || stderr.overflow ||
		containsAny(stdout.content.Bytes(), forbidden) || containsAny(stderr.content.Bytes(), forbidden) {
		return "", false
	}
	return classifyMXFailure(commandOutput{
		stdout: stdout.content.Bytes(), stderr: stderr.content.Bytes(), exit: exit.ExitCode(),
	}, action)
}

func mxFailureContract(class string) (int, string, bool) {
	switch class {
	case "INVALID_ARGUMENT":
		return 2, "Command input is invalid", true
	case "PRECONDITION_FAILED":
		return 3, "Platform preconditions are not satisfied", true
	case "CONFLICT":
		return 4, "Platform state conflicts with this command", true
	case "VERIFICATION_FAILED":
		return 5, "Platform verification failed", true
	case "UNAVAILABLE":
		return 6, "A required platform dependency is unavailable", true
	case "INTERNAL":
		return 70, "Matrix could not complete the command", true
	case "INTERRUPTED":
		return 130, "Command was interrupted", true
	default:
		return 0, "", false
	}
}

func validMXFailureCode(value string) bool {
	if len(value) < 3 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func startMX(
	ctx context.Context,
	bundle release.VerifiedBundle,
	action string,
	arguments []string,
	environment ...string,
) (*exec.Cmd, *boundedBuffer, *boundedBuffer, error) {
	args := []string{"--format", "json", "platform", action}
	args = append(args, arguments...)
	stdout := newBoundedBuffer(maximumCommandOutput)
	stderr := newBoundedBuffer(maximumCommandOutput)
	command := exec.CommandContext(ctx, mxPath(bundle), args...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = append(os.Environ(), environment...)
	if err := command.Start(); err != nil {
		return nil, nil, nil, err
	}
	return command, stdout, stderr, nil
}

// The proxy forwards the real signed invocation to the real engine unchanged.
// It only withholds the provider process exit after a successful apply, so the
// installer can be killed while its durable journal still records an unknown
// outcome. No production hook, forged receipt or database mutation is involved.
func (value *gate) interruptCredentialRecovery(ctx context.Context, inputPath, commandID, installationID string, forbidden [][]byte) (mxResult, error) {
	realDocker, err := exec.LookPath("docker")
	if err != nil || !filepath.IsAbs(realDocker) {
		return mxResult{}, fail("credential-recovery-provider-path")
	}
	directory, err := os.MkdirTemp(value.config.root, ".recovery-interruption-")
	if err != nil {
		return mxResult{}, fail("credential-recovery-interruption-fixture")
	}
	defer os.RemoveAll(directory)
	for _, path := range []string{realDocker, directory} {
		if strings.ContainsAny(path, " \t\r\n'\"$\\") || strings.ContainsRune(path, 96) {
			return mxResult{}, fail("credential-recovery-provider-path")
		}
	}
	marker, fifo := filepath.Join(directory, "committed"), filepath.Join(directory, "release")
	output, err := runProcess(ctx, "mkfifo", "-m", "600", fifo)
	if err != nil || output.exit != 0 {
		return mxResult{}, fail("credential-recovery-interruption-fixture")
	}
	releasePipe, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		return mxResult{}, fail("credential-recovery-interruption-fixture")
	}
	defer releasePipe.Close()
	script := fmt.Sprintf(`#!/bin/sh
set -u
umask 077
if [ "$#" -eq 4 ] && [ "$1" = container ] && [ "$2" = start ] && [ "$3" = --attach ]; then
  actual=$(%q container inspect --format '{{index .Config.Labels "com.xiak.matrix.command"}} {{index .Config.Labels "com.xiak.matrix.installation"}} {{index .Config.Labels "com.xiak.matrix.role"}}' "$4") || exit "$?"
  if [ "$actual" = %q ]; then
    status=0
    %q "$@" || status=$?
    if [ "$status" -eq 0 ]; then
      printf complete > %q
      mv %q %q
      IFS= read -r released < %q || :
    fi
    exit "$status"
  fi
fi
exec %q "$@"
`, realDocker, commandID+" "+installationID+" iam-local-recovery-apply", realDocker, marker+".pending", marker+".pending", marker, fifo, realDocker)
	if os.WriteFile(filepath.Join(directory, "docker"), []byte(script), 0o700) != nil {
		return mxResult{}, fail("credential-recovery-interruption-fixture")
	}
	// A fresh intent performs an eligibility inspection, an exact receipt
	// inspection and the apply. Each purpose-only provider call is independently
	// bounded to 30 seconds, so the crash injector must not cancel the parent
	// before those fail-closed boundaries can complete on a constrained host.
	interruption, cancel := context.WithTimeout(ctx, credentialRecoveryInterruptionTimeout)
	defer cancel()
	command, stdout, stderr, err := startMX(interruption, value.releases.a, "recover-credentials",
		[]string{"--root", value.config.root, "--recovery-input", inputPath}, "PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil {
		return mxResult{}, fail("credential-recovery-interruption-start")
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			_, _ = releasePipe.Write([]byte("continue\n"))
			<-waited
		}
	}()
	for {
		select {
		case <-waited:
			finished = true
			return mxResult{}, fail("credential-recovery-ended-before-crash")
		default:
		}
		content, readErr := os.ReadFile(marker)
		if readErr == nil {
			if string(content) != "complete" {
				return mxResult{}, fail("credential-recovery-interruption-marker")
			}
			break
		}
		if !errors.Is(readErr, os.ErrNotExist) || !waitPoll(interruption, 50*time.Millisecond) {
			return mxResult{}, fail("credential-recovery-interruption-boundary")
		}
	}
	if command.Process.Kill() != nil {
		return mxResult{}, fail("credential-recovery-installer-kill")
	}
	_, _ = releasePipe.Write([]byte("continue\n"))
	waitErr := <-waited
	finished = true
	if waitErr == nil || stdout.overflow || stderr.overflow || stdout.content.Len() != 0 ||
		containsAny(stdout.content.Bytes(), forbidden) || containsAny(stderr.content.Bytes(), forbidden) {
		return mxResult{}, fail("credential-recovery-interrupted-output")
	}
	pending, err := readJournal(ctx, value.config.root)
	if err != nil || pending.Active == nil || pending.Active.Command.ID != commandID ||
		pending.Active.Command.Action != lifecycle.ActionRecoverCredentials ||
		pending.Active.Phase != lifecycle.PhaseRecoveringCredentials || pending.Active.Command.InputDigest == "" {
		return mxResult{}, fail("credential-recovery-interrupted-intent")
	}
	if os.Remove(inputPath) != nil {
		return mxResult{}, fail("credential-recovery-operator-input-removal")
	}
	return runMX(ctx, value.releases.a, "recover-credentials", []string{"--root", value.config.root, "--resume"}, forbidden)
}

// The wrapper passes the real snapshot-bound pg_dump through unchanged, then
// withholds only its process exit. Killing mx at that point leaves its durable
// backup intent and unpublished partial artifact, without a production hook
// or a fabricated database result. The same signed command must take a new
// lease on replay and publish exactly the original backup identity.
func (value *gate) interruptBackupDump(ctx context.Context, forbidden [][]byte) (mxResult, error) {
	realDocker, err := exec.LookPath("docker")
	if err != nil || !filepath.IsAbs(realDocker) {
		return mxResult{}, fail("backup-interruption-provider-path")
	}
	before, err := readJournal(ctx, value.config.root)
	if err != nil || before.Active != nil || before.InstallationID == "" ||
		before.CurrentReleaseID != value.releases.b.Manifest.Release.ID {
		return mxResult{}, fail("backup-interruption-preflight")
	}
	directory, err := os.MkdirTemp(value.config.root, ".backup-interruption-")
	if err != nil {
		return mxResult{}, fail("backup-interruption-fixture")
	}
	defer os.RemoveAll(directory)
	for _, path := range []string{realDocker, directory} {
		if strings.ContainsAny(path, " \t\r\n'\"$\\") || strings.ContainsRune(path, 96) {
			return mxResult{}, fail("backup-interruption-provider-path")
		}
	}
	marker, fifo := filepath.Join(directory, "dump-completed"), filepath.Join(directory, "release")
	output, err := runProcess(ctx, "mkfifo", "-m", "600", fifo)
	if err != nil || output.exit != 0 {
		return mxResult{}, fail("backup-interruption-fixture")
	}
	releasePipe, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		return mxResult{}, fail("backup-interruption-fixture")
	}
	defer releasePipe.Close()
	script := fmt.Sprintf(`#!/bin/sh
set -u
umask 077
if [ "$#" -ge 6 ] && [ "$1" = exec ] && [ "$2" = --user ] && [ "$3" = postgres ] && [ "$5" = pg_dump ]; then
  snapshot=0
  for argument in "$@"; do
    case "$argument" in --snapshot=*) snapshot=1 ;; esac
  done
  if [ "$snapshot" -eq 1 ]; then
    actual=$(%q container inspect --format '{{index .Config.Labels "com.xiak.matrix.installation"}} {{index .Config.Labels "com.xiak.matrix.release"}} {{index .Config.Labels "com.xiak.matrix.role"}}' "$4") || exit "$?"
    if [ "$actual" = %q ]; then
      status=0
      %q "$@" || status=$?
      if [ "$status" -eq 0 ]; then
        printf complete > %q
        mv %q %q
        IFS= read -r released < %q || :
      fi
      exit "$status"
    fi
  fi
fi
exec %q "$@"
`, realDocker, before.InstallationID+" "+before.CurrentReleaseID+" postgres", realDocker,
		marker+".pending", marker+".pending", marker, fifo, realDocker)
	if os.WriteFile(filepath.Join(directory, "docker"), []byte(script), 0o700) != nil {
		return mxResult{}, fail("backup-interruption-fixture")
	}
	interruption, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	command, stdout, stderr, err := startMX(interruption, value.releases.b, "backup",
		[]string{"--root", value.config.root}, "PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil {
		return mxResult{}, fail("backup-interruption-start")
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			_, _ = releasePipe.Write([]byte("continue\n"))
			<-waited
		}
	}()
	for {
		select {
		case <-waited:
			finished = true
			return mxResult{}, fail("backup-ended-before-interruption")
		default:
		}
		content, readErr := os.ReadFile(marker)
		if readErr == nil {
			if string(content) != "complete" {
				return mxResult{}, fail("backup-interruption-marker")
			}
			break
		}
		if !errors.Is(readErr, os.ErrNotExist) || !waitPoll(interruption, 50*time.Millisecond) {
			return mxResult{}, fail("backup-interruption-boundary")
		}
	}
	if command.Process.Kill() != nil {
		return mxResult{}, fail("backup-installer-kill")
	}
	_, _ = releasePipe.Write([]byte("continue\n"))
	waitErr := <-waited
	finished = true
	return value.resumeInterruptedBackup(ctx, before, stdout, stderr, waitErr, forbidden)
}

// The real IAM custody process exports a database snapshot, but the proxy
// withholds that one lease frame before mx can start pg_dump. Killing mx at
// this boundary tests an orphaned snapshot lease and a durable BACKING_UP
// intent without fabricating a custody response or changing production code.
func (value *gate) interruptBackupSnapshotExport(ctx context.Context, forbidden [][]byte) (mxResult, error) {
	realDocker, err := exec.LookPath("docker")
	if err != nil || !filepath.IsAbs(realDocker) {
		return mxResult{}, fail("snapshot-interruption-provider-path")
	}
	before, err := readJournal(ctx, value.config.root)
	if err != nil || before.Active != nil || before.InstallationID == "" ||
		before.CurrentReleaseID != value.releases.b.Manifest.Release.ID {
		return mxResult{}, fail("snapshot-interruption-preflight")
	}
	directory, err := os.MkdirTemp(value.config.root, ".snapshot-interruption-")
	if err != nil {
		return mxResult{}, fail("snapshot-interruption-fixture")
	}
	defer os.RemoveAll(directory)
	for _, path := range []string{realDocker, directory} {
		if strings.ContainsAny(path, " \t\r\n'\"$\\") || strings.ContainsRune(path, 96) {
			return mxResult{}, fail("snapshot-interruption-provider-path")
		}
	}
	marker, fifo := filepath.Join(directory, "snapshot-exported"), filepath.Join(directory, "release")
	output, err := runProcess(ctx, "mkfifo", "-m", "600", fifo)
	if err != nil || output.exit != 0 {
		return mxResult{}, fail("snapshot-interruption-fixture")
	}
	releasePipe, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		return mxResult{}, fail("snapshot-interruption-fixture")
	}
	defer releasePipe.Close()
	script := fmt.Sprintf(`#!/bin/sh
set -u
umask 077
if [ "$#" -ge 4 ] && [ "$1" = run ]; then
  role=0
  installation=0
  release=0
  for argument in "$@"; do
    case "$argument" in
      %q) role=1 ;;
      %q) installation=1 ;;
      %q) release=1 ;;
    esac
  done
  if [ "$role" -eq 1 ] && [ "$installation" -eq 1 ] && [ "$release" -eq 1 ]; then
    %q "$@" | {
      IFS= read -r lease || exit 1
      printf exported > %q
      mv %q %q
      IFS= read -r released < %q || :
      printf '%%s\n' "$lease"
      cat
    }
    exit "$?"
  fi
fi
exec %q "$@"
`, "com.xiak.matrix.role=iam-backup-custody",
		"com.xiak.matrix.installation="+before.InstallationID,
		"com.xiak.matrix.release="+before.CurrentReleaseID,
		realDocker, marker+".pending", marker+".pending", marker, fifo, realDocker)
	if os.WriteFile(filepath.Join(directory, "docker"), []byte(script), 0o700) != nil {
		return mxResult{}, fail("snapshot-interruption-fixture")
	}
	interruption, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	command, stdout, stderr, err := startMX(interruption, value.releases.b, "backup",
		[]string{"--root", value.config.root}, "PATH="+directory+":"+os.Getenv("PATH"))
	if err != nil {
		return mxResult{}, fail("snapshot-interruption-start")
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			_, _ = releasePipe.Write([]byte("continue\n"))
			<-waited
		}
	}()
	for {
		select {
		case <-waited:
			finished = true
			return mxResult{}, fail("snapshot-ended-before-interruption")
		default:
		}
		content, readErr := os.ReadFile(marker)
		if readErr == nil {
			if string(content) != "exported" {
				return mxResult{}, fail("snapshot-interruption-marker")
			}
			break
		}
		if !errors.Is(readErr, os.ErrNotExist) || !waitPoll(interruption, 50*time.Millisecond) {
			return mxResult{}, fail("snapshot-interruption-boundary")
		}
	}
	if command.Process.Kill() != nil {
		return mxResult{}, fail("snapshot-installer-kill")
	}
	_, _ = releasePipe.Write([]byte("continue\n"))
	waitErr := <-waited
	finished = true
	return value.resumeInterruptedBackup(ctx, before, stdout, stderr, waitErr, forbidden)
}

func (value *gate) resumeInterruptedBackup(
	ctx context.Context,
	before lifecycle.Journal,
	stdout, stderr *boundedBuffer,
	waitErr error,
	forbidden [][]byte,
) (mxResult, error) {
	if waitErr == nil || stdout.overflow || stderr.overflow || stdout.content.Len() != 0 ||
		containsAny(stdout.content.Bytes(), forbidden) || containsAny(stderr.content.Bytes(), forbidden) {
		return mxResult{}, fail("backup-interrupted-output")
	}
	pending, err := readJournal(ctx, value.config.root)
	if err != nil || pending.Active == nil || pending.Active.Command.Action != lifecycle.ActionBackup ||
		pending.Active.Phase != lifecycle.PhaseBackingUp || pending.Active.Command.ID == "" ||
		pending.Active.Command.BackupID == "" || pending.CurrentReleaseID != before.CurrentReleaseID {
		return mxResult{}, fail("backup-interrupted-intent")
	}
	backupID := pending.Active.Command.BackupID
	backupRoot := filepath.Join(value.config.root, filepath.FromSlash(layout.BackupDirectory))
	if _, err := os.Lstat(filepath.Join(backupRoot, backupID)); !errors.Is(err, os.ErrNotExist) {
		return mxResult{}, fail("backup-interruption-published-partial")
	}
	if info, err := os.Lstat(filepath.Join(backupRoot, "."+backupID+".partial")); err != nil || !info.IsDir() {
		return mxResult{}, fail("backup-interruption-missing-partial")
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		ids, err := dockerLines(ctx, "container", "ls", "--all", "--quiet",
			"--filter", "label=com.xiak.matrix.installation="+before.InstallationID,
			"--filter", "label=com.xiak.matrix.role=iam-backup-custody",
			"--filter", "label=com.xiak.matrix.backup="+backupID)
		if err != nil {
			return mxResult{}, fail("backup-interruption-custody-observation")
		}
		if len(ids) == 0 {
			break
		}
		if time.Now().After(deadline) || !waitPoll(ctx, 50*time.Millisecond) {
			return mxResult{}, fail("backup-interruption-orphaned-custody")
		}
	}
	result, err := runMX(ctx, value.releases.b, "backup", []string{"--root", value.config.root}, forbidden)
	if err != nil || result.BackupID != backupID || result.CorrelationID != pending.Active.Command.ID || !result.Changed {
		return mxResult{}, fail("backup-interruption-resume")
	}
	if _, err := os.Lstat(filepath.Join(backupRoot, "."+backupID+".partial")); !errors.Is(err, os.ErrNotExist) {
		return mxResult{}, fail("backup-interruption-retained-partial")
	}
	return result, nil
}

func validateExpectedMXFailure(
	waitErr error,
	stdout, stderr *boundedBuffer,
	action string,
	forbidden [][]byte,
	wantExit int,
	wantClass, wantCode string,
) error {
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.ExitCode() != wantExit || stdout.overflow || stderr.overflow ||
		stdout.content.Len() != 0 || containsAny(stderr.content.Bytes(), forbidden) {
		return fail("failed-" + action + "-exit")
	}
	var envelope mxFailure
	if decodeOne(stderr.content.Bytes(), &envelope) != nil ||
		envelope.APIVersion != "cli.matrix.xiak.com/v1" ||
		envelope.Kind != "PlatformCommandFailure" || envelope.Action != strings.ToUpper(strings.ReplaceAll(action, "-", "_")) ||
		envelope.Status != "FAILED" || envelope.Error.Class != wantClass ||
		envelope.Error.Code != wantCode || strings.Contains(strings.ToLower(envelope.Error.Message), "docker") ||
		strings.Contains(strings.ToLower(envelope.Error.Message), "postgres") {
		return fail("failed-" + action + "-result")
	}
	return nil
}

func decodeOne(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func containsAny(content []byte, values [][]byte) bool {
	for _, value := range values {
		if len(value) != 0 && bytes.Contains(content, value) {
			return true
		}
	}
	return false
}

func docker(ctx context.Context, arguments ...string) ([]byte, error) {
	// The acceptance driver and mx must inspect and mutate the same local
	// engine. Inherited Docker contexts can otherwise target a remote host.
	output, err := runProcessWithEnvironment(ctx, dockerAcceptanceEnvironment(os.Environ()),
		"docker", dockerAcceptanceArguments(arguments...)...)
	if err != nil || output.exit != 0 || len(output.stderr) != 0 {
		return nil, errors.New("Docker acceptance command failed")
	}
	return output.stdout, nil
}

func dockerAcceptanceArguments(arguments ...string) []string {
	return append([]string{"--host", "unix:///var/run/docker.sock"}, arguments...)
}

func dockerAcceptanceEnvironment(source []string) []string {
	result := make([]string, 0, len(source))
	for _, value := range source {
		name, _, valid := strings.Cut(value, "=")
		if valid && strings.HasPrefix(strings.ToUpper(name), "DOCKER_") {
			continue
		}
		result = append(result, value)
	}
	return result
}

func dockerLines(ctx context.Context, arguments ...string) ([]string, error) {
	content, err := docker(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, nil
	}
	lines := strings.Split(trimmed, "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
		if lines[index] == "" || strings.ContainsAny(lines[index], "\r\t ") {
			return nil, errors.New("Docker returned an invalid identity list")
		}
	}
	return lines, nil
}

func readJournal(ctx context.Context, root string) (lifecycle.Journal, error) {
	session, err := journal.AcquireExisting(ctx, root)
	if err != nil {
		return lifecycle.Journal{}, err
	}
	value, readErr := session.Read()
	closeErr := session.Close()
	if readErr != nil {
		return lifecycle.Journal{}, readErr
	}
	if closeErr != nil {
		return lifecycle.Journal{}, closeErr
	}
	return value, nil
}

func assertNoExternalRoute() error {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return fail("external-network-route")
	}
	for index, line := range strings.Split(string(content), "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "00000000" {
			flags, parseErr := strconv.ParseUint(fields[3], 16, 32)
			if parseErr == nil && flags&1 != 0 {
				return fail("external-network-route")
			}
		}
	}
	return assertNoExternalConnectivity()
}

func assertNoExternalConnectivity() error {
	connection, dialErr := net.DialTimeout("tcp", "1.1.1.1:443", 300*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	if dialErr == nil {
		return fail("external-network-connectivity")
	}
	return nil
}

func assertEmptyDocker(ctx context.Context) error {
	checks := [][]string{
		{"container", "ls", "--all", "--quiet"},
		{"image", "ls", "--all", "--quiet"},
		{"volume", "ls", "--quiet"},
		{"network", "ls", "--quiet", "--filter", "label=com.xiak.matrix.managed=true"},
	}
	for _, arguments := range checks {
		lines, err := dockerLines(ctx, arguments...)
		if err != nil || len(lines) != 0 {
			return fail("clean-docker-namespace")
		}
	}
	return nil
}

type containerInspection struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	RestartCount uint64 `json:"RestartCount"`
	Config       struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		PortBindings map[string][]json.RawMessage `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]json.RawMessage `json:"Ports"`
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func inspectContainers(ctx context.Context, ids []string) ([]containerInspection, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	arguments := append([]string{"container", "inspect"}, ids...)
	content, err := docker(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	var inspections []containerInspection
	if json.Unmarshal(content, &inspections) != nil || len(inspections) != len(ids) {
		return nil, errors.New("Docker container inspection is invalid")
	}
	return inspections, nil
}

func expectedPlatformServices(
	manifest release.Manifest,
	root, installationID, northboundOrigin string,
) (topology.Result, map[string]struct{}, error) {
	compiled, err := topology.CompileInstalled(manifest, topology.Options{
		InstallationID:   installationID,
		Root:             filepath.ToSlash(root),
		Listener:         "0.0.0.0",
		Port:             8080,
		NorthboundOrigin: northboundOrigin,
	})
	if err != nil {
		return topology.Result{}, nil, err
	}
	var document map[string]json.RawMessage
	if decodeOne(compiled.ComposeJSON, &document) != nil {
		return topology.Result{}, nil, errors.New("compiled platform topology is invalid")
	}
	var declared map[string]json.RawMessage
	if json.Unmarshal(document["services"], &declared) != nil || len(declared) == 0 {
		return topology.Result{}, nil, errors.New("compiled platform service inventory is invalid")
	}
	services := make(map[string]struct{}, len(declared))
	for service := range declared {
		services[service] = struct{}{}
	}
	return compiled, services, nil
}

func expectedPlatformPortBindings(composeJSON []byte) (map[string][]string, error) {
	var document struct {
		Services map[string]struct {
			Ports []string `json:"ports"`
		} `json:"services"`
	}
	if json.Unmarshal(composeJSON, &document) != nil || len(document.Services) == 0 {
		return nil, errors.New("compiled platform edge inventory is invalid")
	}
	result := make(map[string][]string, len(document.Services))
	published := 0
	for service, configuration := range document.Services {
		bindings := make([]string, 0, len(configuration.Ports))
		for _, value := range configuration.Ports {
			separator := strings.LastIndexByte(value, ':')
			if separator <= 0 || separator == len(value)-1 {
				return nil, errors.New("compiled platform edge binding is invalid")
			}
			host, hostPort, err := net.SplitHostPort(value[:separator])
			if err != nil {
				return nil, errors.New("compiled platform edge binding is invalid")
			}
			binding, err := canonicalPlatformPortBinding(value[separator+1:], host, hostPort)
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, binding)
			published++
		}
		slices.Sort(bindings)
		result[service] = bindings
	}
	if published == 0 {
		return nil, errors.New("compiled platform edge inventory is empty")
	}
	return result, nil
}

func canonicalPlatformPortBinding(containerPort, host, hostPort string) (string, error) {
	port, protocol, found := strings.Cut(containerPort, "/")
	hostNumber, hostErr := strconv.ParseUint(hostPort, 10, 16)
	containerNumber, containerErr := strconv.ParseUint(port, 10, 16)
	if !found || protocol != "tcp" || net.ParseIP(host) == nil || hostErr != nil ||
		containerErr != nil || hostNumber == 0 || containerNumber == 0 ||
		strconv.FormatUint(hostNumber, 10) != hostPort || strconv.FormatUint(containerNumber, 10) != port {
		return "", errors.New("platform edge binding is invalid")
	}
	return host + "|" + hostPort + "|" + containerPort, nil
}

func matchesPlatformPortBindings(expected []string, actual map[string][]json.RawMessage) bool {
	observed := make([]string, 0, len(expected))
	for containerPort, values := range actual {
		for _, value := range values {
			var binding struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			}
			if decodeOne(value, &binding) != nil {
				return false
			}
			canonical, err := canonicalPlatformPortBinding(
				containerPort, binding.HostIP, binding.HostPort,
			)
			if err != nil {
				return false
			}
			observed = append(observed, canonical)
		}
	}
	slices.Sort(observed)
	return slices.Equal(expected, observed)
}

func assertPlatform(
	ctx context.Context,
	root string,
	manifest release.Manifest,
	wantPrevious string,
) (lifecycle.Journal, error) {
	state, err := readJournal(ctx, root)
	if err != nil || state.CurrentReleaseID != manifest.Release.ID ||
		state.PreviousRelease != wantPrevious || state.Active != nil {
		return lifecycle.Journal{}, fail("platform-journal")
	}
	compiled, expected, err := expectedPlatformServices(manifest, root, state.InstallationID, state.NorthboundOrigin)
	if err != nil {
		return lifecycle.Journal{}, fail("platform-topology-contract")
	}
	expectedPorts, err := expectedPlatformPortBindings(compiled.ComposeJSON)
	if err != nil {
		return lifecycle.Journal{}, fail("platform-topology-contract")
	}
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.managed=true",
		"--filter", "label=com.xiak.matrix.installation="+state.InstallationID,
	)
	if err != nil || len(ids) != len(expected) {
		return lifecycle.Journal{}, fail("platform-container-inventory")
	}
	inspections, err := inspectContainers(ctx, ids)
	if err != nil {
		return lifecycle.Journal{}, fail("platform-container-inspection")
	}
	seen := make(map[string]struct{}, len(inspections))
	for _, inspection := range inspections {
		role := inspection.Config.Labels["com.xiak.matrix.role"]
		if _, ok := expected[role]; !ok || inspection.Config.Labels["com.xiak.matrix.release"] != manifest.Release.ID ||
			inspection.Config.Labels["com.xiak.matrix.installation"] != state.InstallationID ||
			!inspection.State.Running || inspection.State.Status != "running" ||
			inspection.State.Health == nil || inspection.State.Health.Status != "healthy" {
			return lifecycle.Journal{}, fail("platform-container-state")
		}
		if _, duplicate := seen[role]; duplicate {
			return lifecycle.Journal{}, fail("platform-container-identity")
		}
		seen[role] = struct{}{}
		if !matchesPlatformPortBindings(expectedPorts[role], inspection.HostConfig.PortBindings) {
			stage := "platform-port-boundary"
			if role == "apisix" {
				stage = "platform-edge-boundary"
			}
			return lifecycle.Journal{}, fail(stage)
		}
	}
	return state, nil
}

func assertNoPlatformReleaseContainers(ctx context.Context, releaseID string) error {
	ids, err := dockerLines(
		ctx, "container", "ls", "--all", "--quiet",
		"--filter", "label=com.xiak.matrix.managed=true",
		"--filter", "label=com.xiak.matrix.release="+releaseID,
	)
	if err != nil || len(ids) != 0 {
		return fail("superseded-platform-containers")
	}
	return nil
}

func formatResourceVersion(value uint64) string {
	return fmt.Sprintf("\"%d\"", value)
}
