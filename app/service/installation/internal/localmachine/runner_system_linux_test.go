//go:build linux

package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const runnerSystemTestDockerGID = 3999

type fakeRunnerHost struct {
	mutex         sync.Mutex
	accounts      map[string]runnerSystemAccount
	active        map[string]bool
	enabled       map[string]bool
	calls         [][]string
	loaded        bool
	tagged        bool
	loadCount     int
	useraddCount  int
	loadFails     bool
	dockerVersion string
	runscPath     string
	toolchainArch string
}

func newFakeRunnerHost() *fakeRunnerHost {
	return &fakeRunnerHost{
		accounts: make(map[string]runnerSystemAccount), active: make(map[string]bool),
		enabled:       make(map[string]bool),
		dockerVersion: "29.6.2|1.55|1.40|linux|amd64",
		toolchainArch: "amd64",
	}
}

func (host *fakeRunnerHost) locate(name string) (string, error) {
	return "/usr/bin/" + name, nil
}

func (host *fakeRunnerHost) run(
	ctx context.Context,
	program string,
	arguments ...string,
) (runnerHostCommandOutcome, error) {
	if err := ctx.Err(); err != nil {
		return runnerHostCommandOutcome{}, err
	}
	host.mutex.Lock()
	defer host.mutex.Unlock()
	call := append([]string{path.Base(program)}, arguments...)
	host.calls = append(host.calls, call)
	switch path.Base(program) {
	case "getent":
		return host.getent(arguments)
	case "id":
		account := host.accounts[arguments[len(arguments)-1]]
		return successfulRunnerHostOutput(strconv.FormatUint(uint64(account.GID), 10) + " " +
			strconv.Itoa(runnerSystemTestDockerGID) + "\n"), nil
	case "useradd":
		name := arguments[len(arguments)-1]
		index, err := strconv.Atoi(strings.TrimPrefix(name, "matrix-devops-"))
		if err != nil || index < 1 || index > 4 {
			return runnerHostCommandOutcome{exitCode: 1}, nil
		}
		host.useraddCount++
		host.accounts[name] = runnerSystemAccount{
			Name: name, UID: uint32(2000 + index), GID: uint32(3000 + index),
		}
		return runnerHostCommandOutcome{}, nil
	case "systemctl":
		return host.systemctl(arguments), nil
	case "nft", "systemd-analyze":
		return runnerHostCommandOutcome{}, nil
	case "docker":
		return host.docker(arguments)
	default:
		return runnerHostCommandOutcome{}, errors.New("unexpected runner host executable")
	}
}

func (host *fakeRunnerHost) getent(arguments []string) (runnerHostCommandOutcome, error) {
	if len(arguments) != 2 {
		return runnerHostCommandOutcome{exitCode: 1}, nil
	}
	if arguments[0] == "group" && arguments[1] == "docker" {
		return successfulRunnerHostOutput("docker:x:" + strconv.Itoa(runnerSystemTestDockerGID) + ":\n"), nil
	}
	account, found := host.accounts[arguments[1]]
	if !found {
		return runnerHostCommandOutcome{exitCode: 2}, nil
	}
	if arguments[0] == "passwd" {
		return successfulRunnerHostOutput(
			account.Name + ":x:" + strconv.FormatUint(uint64(account.UID), 10) + ":" +
				strconv.FormatUint(uint64(account.GID), 10) + ":Matrix DevOps runner:/nonexistent:/usr/bin/nologin\n",
		), nil
	}
	if arguments[0] == "group" {
		return successfulRunnerHostOutput(
			account.Name + ":x:" + strconv.FormatUint(uint64(account.GID), 10) + ":\n",
		), nil
	}
	return runnerHostCommandOutcome{exitCode: 1}, nil
}

func (host *fakeRunnerHost) systemctl(arguments []string) runnerHostCommandOutcome {
	if len(arguments) == 0 {
		return runnerHostCommandOutcome{exitCode: 1}
	}
	switch arguments[0] {
	case "is-active":
		if host.active[arguments[len(arguments)-1]] {
			return runnerHostCommandOutcome{}
		}
		return runnerHostCommandOutcome{exitCode: 3}
	case "start":
		for _, unit := range arguments[1:] {
			host.active[unit] = true
		}
	case "restart":
		host.active[arguments[len(arguments)-1]] = true
	case "stop":
		host.active[arguments[len(arguments)-1]] = false
	case "disable":
		unit := arguments[len(arguments)-1]
		host.active[unit] = false
		host.enabled[unit] = false
	case "enable":
		for _, unit := range arguments[1:] {
			host.enabled[unit] = true
		}
	case "daemon-reload":
	default:
		return runnerHostCommandOutcome{exitCode: 1}
	}
	return runnerHostCommandOutcome{}
}

func (host *fakeRunnerHost) docker(arguments []string) (runnerHostCommandOutcome, error) {
	if len(arguments) >= 1 && arguments[0] == "version" {
		if arguments[len(arguments)-1] == "{{.Server.Version}}" {
			version, _, _ := strings.Cut(host.dockerVersion, "|")
			return successfulRunnerHostOutput(version + "\n"), nil
		}
		return successfulRunnerHostOutput(host.dockerVersion + "\n"), nil
	}
	if len(arguments) >= 1 && arguments[0] == "info" {
		return successfulRunnerHostOutput("{\"runsc\":{\"path\":\"" +
			host.runscPath + "\"}}\n"), nil
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "load" {
		host.loaded = true
		host.loadCount++
		if host.loadFails {
			return runnerHostCommandOutcome{exitCode: 1}, nil
		}
		return runnerHostCommandOutcome{}, nil
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "tag" {
		if !host.loaded {
			return runnerHostCommandOutcome{exitCode: 1}, nil
		}
		host.tagged = true
		return runnerHostCommandOutcome{}, nil
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "remove" {
		reference := arguments[len(arguments)-1]
		if reference == release.RunnerToolchainLocalReference {
			host.tagged = false
		} else {
			host.loaded = false
		}
		return runnerHostCommandOutcome{}, nil
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "inspect" {
		reference := arguments[len(arguments)-1]
		if reference == release.RunnerToolchainLocalReference && host.tagged {
			content, _ := json.Marshal(runnerToolchainInspection{
				ID:          release.RunnerToolchainSourceDigest,
				RepoTags:    []string{release.RunnerToolchainLocalReference},
				RepoDigests: []string{release.RunnerToolchainLocalDigestReference},
				OS:          "linux", Architecture: host.toolchainArch,
			})
			return successfulRunnerHostOutput(string(content) + "\n"), nil
		}
		if reference == release.RunnerToolchainSourceDigest && host.loaded {
			content, _ := json.Marshal(runnerToolchainInspection{
				ID: release.RunnerToolchainSourceDigest, OS: "linux", Architecture: host.toolchainArch,
			})
			return successfulRunnerHostOutput(string(content) + "\n"), nil
		}
		return runnerHostCommandOutcome{exitCode: 1}, nil
	}
	return runnerHostCommandOutcome{}, errors.New("unexpected Docker invocation")
}

func successfulRunnerHostOutput(value string) runnerHostCommandOutcome {
	return runnerHostCommandOutcome{output: []byte(value)}
}

func TestLinuxRunnerSystemConvergesAndReplaysExactHostState(t *testing.T) {
	system, host, plan, paths, closeSocket := linuxRunnerSystemFixture(t, 2)
	defer closeSocket()
	if err := system.Converge(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	assertRunnerSystemFilesAndOwnership(t, plan, paths)
	if host.useraddCount != 2 || host.loadCount != 1 || !host.tagged {
		t.Fatalf("first convergence did not provision exact state: %#v", host)
	}
	assertRunnerActivationOrder(t, host.calls)
	firstCallCount := len(host.calls)
	if err := system.Converge(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if host.useraddCount != 2 || host.loadCount != 1 || len(host.calls) <= firstCallCount {
		t.Fatalf("replay repeated material effects: users=%d loads=%d", host.useraddCount, host.loadCount)
	}
	for _, unit := range runnerSlotUnits(2) {
		if !host.active[unit] || !host.enabled[unit] {
			t.Fatalf("runner unit %s is not enabled and active after replay", unit)
		}
	}
}

func TestLinuxRunnerSystemPreflightRejectsNonRootBeforeHostCommands(t *testing.T) {
	system, host, plan, _, closeSocket := linuxRunnerSystemFixture(t, 1)
	defer closeSocket()
	system.euid = func() int { return 1000 }
	if err := system.Preflight(context.Background(), plan); !errors.Is(
		err, runnernodecommand.ErrEffectUnavailable,
	) {
		t.Fatalf("non-root preflight failure=%v, want unavailable", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("non-root preflight invoked host commands: %#v", host.calls)
	}
}

func TestLinuxRunnerSystemPreflightRejectsUnsearchableServiceAncestorBeforeHostCommands(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o750} {
		t.Run(mode.String(), func(t *testing.T) {
			system, host, plan, _, closeSocket := linuxRunnerSystemFixture(t, 1)
			defer closeSocket()
			if err := os.Chmod(path.Dir(plan.Root), mode); err != nil {
				t.Fatal(err)
			}
			if err := system.Preflight(context.Background(), plan); !errors.Is(
				err, runnernodecommand.ErrEffectConflict,
			) {
				t.Fatalf("unsearchable ancestor failure=%v, want conflict", err)
			}
			if len(host.calls) != 0 {
				t.Fatalf("unsearchable ancestor reached host commands: %#v", host.calls)
			}
		})
	}
}

func TestLinuxRunnerSystemPreflightRejectsSharedDockerConfiguration(t *testing.T) {
	system, host, plan, paths, closeSocket := linuxRunnerSystemFixture(t, 1)
	defer closeSocket()
	if err := os.WriteFile(paths.DockerConfig, []byte("{\"log-driver\":\"json-file\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := system.Preflight(context.Background(), plan); !errors.Is(
		err, runnernodecommand.ErrEffectConflict,
	) {
		t.Fatalf("shared Docker preflight failure=%v, want conflict", err)
	}
	if host.useraddCount != 0 || host.loadCount != 0 {
		t.Fatal("preflight performed mutating host commands")
	}
}

func TestLinuxRunnerSystemStopsEverySlotWhenReadinessFails(t *testing.T) {
	system, host, plan, _, closeSocket := linuxRunnerSystemFixture(t, 2)
	defer closeSocket()
	system.readiness = func(context.Context, []runnerSystemSlot) error {
		return errors.New("not ready")
	}
	err := system.Converge(context.Background(), plan)
	if !errors.Is(err, runnernodecommand.ErrEffectUnavailable) {
		t.Fatalf("failure=%v, want unavailable", err)
	}
	for _, unit := range runnerSlotUnits(2) {
		if host.active[unit] || host.enabled[unit] {
			t.Fatalf("failed convergence left %s enabled or active", unit)
		}
	}
	if !host.active[runnerFirewallUnit] {
		t.Fatal("failed convergence removed the fail-closed firewall")
	}
}

func TestLinuxRunnerSystemDisablesManagedFailedUnit(t *testing.T) {
	system, host, _, paths, closeSocket := linuxRunnerSystemFixture(t, 1)
	defer closeSocket()
	unit := runnerSlotUnit(1)
	if err := os.WriteFile(
		path.Join(paths.SystemdRoot, unit), []byte(runnerManagedHeader+"[Unit]\n"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	host.enabled[unit] = true
	if err := system.deactivateRunnerUnits(context.Background(), "/usr/bin/systemctl"); err != nil {
		t.Fatal(err)
	}
	if host.enabled[unit] || host.active[unit] {
		t.Fatalf("failed managed unit remained enabled or active: %#v", host)
	}
}

func TestLinuxRunnerSystemRejectsSharedDockerConfiguration(t *testing.T) {
	system, host, plan, paths, closeSocket := linuxRunnerSystemFixture(t, 1)
	defer closeSocket()
	if err := os.WriteFile(paths.DockerConfig, []byte("{\"log-driver\":\"json-file\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := system.Converge(context.Background(), plan)
	if !errors.Is(err, runnernodecommand.ErrEffectConflict) {
		t.Fatalf("shared Docker config failure=%v, want conflict", err)
	}
	if host.loadCount != 0 || host.active[runnerFirewallUnit] {
		t.Fatal("conflicting Docker ownership reached runtime activation")
	}
}

func TestRunnerDockerConfigRollsBackWhenDaemonProfileFails(t *testing.T) {
	base := runnerHostTestRoot(t)
	paths := runnerHostTestPaths(base)
	if err := os.MkdirAll(path.Dir(paths.DockerConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	host := newFakeRunnerHost()
	host.dockerVersion = "30.0.0|1.55|1.40|linux|amd64"
	host.runscPath = "/opt/runsc"
	system := &linuxRunnerNodeSystem{run: host.run, paths: paths}
	desired := []byte("{\"runtimes\":{\"runsc\":{\"path\":\"/opt/runsc\"}}}\n")
	err := system.convergeDocker(
		context.Background(), runnerHostTools{Docker: "/usr/bin/docker", Systemctl: "/usr/bin/systemctl"},
		runnerSystemFileSnapshot{}, desired, runnerSystemTestDockerGID, "/opt/runsc",
	)
	if !errors.Is(err, runnernodecommand.ErrEffectUnavailable) {
		t.Fatalf("Docker failure=%v, want unavailable", err)
	}
	if _, statErr := os.Lstat(paths.DockerConfig); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed Docker config was not rolled back: %v", statErr)
	}
}

func TestRunnerDockerConfigRollsBackWhenRunscRuntimeDoesNotMatch(t *testing.T) {
	base := runnerHostTestRoot(t)
	paths := runnerHostTestPaths(base)
	if err := os.MkdirAll(path.Dir(paths.DockerConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	host := newFakeRunnerHost()
	host.runscPath = "/opt/other-runsc"
	system := &linuxRunnerNodeSystem{run: host.run, paths: paths}
	desired := []byte("{\"runtimes\":{\"runsc\":{\"path\":\"/opt/runsc\"}}}\n")
	err := system.convergeDocker(
		context.Background(), runnerHostTools{Docker: "/usr/bin/docker", Systemctl: "/usr/bin/systemctl"},
		runnerSystemFileSnapshot{}, desired, runnerSystemTestDockerGID, "/opt/runsc",
	)
	if !errors.Is(err, runnernodecommand.ErrEffectUnavailable) {
		t.Fatalf("runsc mismatch failure=%v, want unavailable", err)
	}
	if _, statErr := os.Lstat(paths.DockerConfig); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runsc mismatch Docker config was not rolled back: %v", statErr)
	}
}

func TestRunnerToolchainCleansPartialLoadAndInvalidMetadata(t *testing.T) {
	for _, test := range []struct {
		name       string
		configure  func(*fakeRunnerHost)
		wantEffect error
	}{
		{
			name: "partial load failure",
			configure: func(host *fakeRunnerHost) {
				host.loadFails = true
			},
			wantEffect: runnernodecommand.ErrEffectUnavailable,
		},
		{
			name: "invalid loaded platform",
			configure: func(host *fakeRunnerHost) {
				host.toolchainArch = "arm64"
			},
			wantEffect: runnernodecommand.ErrEffectVerification,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := newFakeRunnerHost()
			test.configure(host)
			system := &linuxRunnerNodeSystem{run: host.run}
			err := system.convergeToolchain(
				context.Background(), "/usr/bin/docker", "/media/toolchain.tar",
			)
			if !errors.Is(err, test.wantEffect) {
				t.Fatalf("toolchain failure=%v, want %v", err, test.wantEffect)
			}
			if host.loaded || host.tagged || host.loadCount != 1 {
				t.Fatalf("failed toolchain convergence was not cleaned: %#v", host)
			}
		})
	}
}

func TestLinuxRunnerSystemRejectsForeignManagedPath(t *testing.T) {
	system, host, plan, paths, closeSocket := linuxRunnerSystemFixture(t, 1)
	defer closeSocket()
	target := path.Join(paths.SystemdRoot, runnerSlotUnit(1))
	if err := os.WriteFile(target, []byte("[Unit]\nDescription=foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := system.Converge(context.Background(), plan)
	if !errors.Is(err, runnernodecommand.ErrEffectConflict) {
		t.Fatalf("foreign managed path failure=%v, want conflict", err)
	}
	if host.loadCount != 0 || host.active[runnerFirewallUnit] {
		t.Fatal("foreign managed path reached runtime activation")
	}
}

func TestRunnerHostCommandUsesClosedEnvironmentAndPreservesExitStatus(t *testing.T) {
	t.Setenv("MATRIX_RUNNER_SECRET", "must-not-leak")
	environmentTool := "/usr/bin/env"
	if _, err := os.Stat(environmentTool); err != nil {
		environmentTool = "/bin/env"
	}
	outcome, err := defaultRunnerHostCommand(context.Background(), environmentTool)
	if err != nil || outcome.exitCode != 0 {
		t.Fatalf("read closed environment: outcome=%#v err=%v", outcome, err)
	}
	if strings.Contains(string(outcome.output), "MATRIX_RUNNER_SECRET=") {
		t.Fatal("runner host command inherited the parent environment")
	}
	for _, expected := range runnerHostEnvironment() {
		if !strings.Contains("\n"+string(outcome.output), "\n"+expected+"\n") {
			t.Fatalf("runner host command environment is missing %q", expected)
		}
	}

	shell := "/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		t.Skip("POSIX shell is unavailable")
	}
	outcome, err = defaultRunnerHostCommand(
		context.Background(), shell, "-c", "printf controlled-output; exit 7",
	)
	if err != nil || outcome.exitCode != 7 || string(outcome.output) != "controlled-output" {
		t.Fatalf("exit status was not preserved: outcome=%#v err=%v", outcome, err)
	}
}

func TestRunnerHostLockRejectsConcurrentConvergence(t *testing.T) {
	base := runnerHostTestRoot(t)
	lockPath := path.Join(base, "runner-install.lock")
	first, err := acquireRunnerHostLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRunnerHostLock(first)
	if _, err := acquireRunnerHostLock(lockPath); !errors.Is(err, runnernodecommand.ErrEffectConflict) {
		t.Fatalf("concurrent host lock failure=%v, want conflict", err)
	}
}

func TestRunnerInstalledInventoryOwnerMustRemainRoot(t *testing.T) {
	root := runnerHostTestRoot(t)
	target := path.Join(root, "runner-binary")
	if err := os.WriteFile(target, []byte("runner"), 0o555); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(target)
	if err != nil || !validRunnerInstalledOwner(info) {
		t.Fatalf("root-owned runner material was rejected: %v", err)
	}
	if err := os.Chown(target, 1234, 1234); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(target)
	if err != nil || validRunnerInstalledOwner(info) {
		t.Fatalf("non-root runner material was accepted: %v", err)
	}
}

func TestRunnerHostDirectoryRejectsWritableAncestorWithoutStickyBit(t *testing.T) {
	root := runnerHostTestRoot(t)
	ancestor := path.Join(root, "ancestor")
	target := path.Join(ancestor, "target")
	if err := os.MkdirAll(target, 0o755); err != nil || os.Chmod(ancestor, 0o777) != nil {
		t.Fatal("prepare writable ancestor fixture failed")
	}
	if err := validateRunnerHostDirectory(target); !errors.Is(
		err, runnernodecommand.ErrEffectConflict,
	) {
		t.Fatalf("writable ancestor failure=%v, want conflict", err)
	}
	if err := os.Chmod(ancestor, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := validateRunnerHostDirectory(target); err != nil {
		t.Fatalf("sticky root-owned ancestor was rejected: %v", err)
	}
}

func linuxRunnerSystemFixture(
	t *testing.T,
	slots int,
) (*linuxRunnerNodeSystem, *fakeRunnerHost, runnerSystemPlan, runnerHostPaths, func()) {
	t.Helper()
	base := runnerHostTestRoot(t)
	paths := runnerHostTestPaths(base)
	for _, directory := range []string{
		path.Dir(paths.DockerConfig), paths.SystemdRoot, paths.ValidationRoot,
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil || os.Chmod(directory, 0o755) != nil {
			t.Fatal("create runner host fixture directory failed")
		}
	}
	listener, err := net.Listen("unix", paths.DockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.DockerSocket, 0o660); err != nil ||
		os.Chown(paths.DockerSocket, 0, runnerSystemTestDockerGID) != nil {
		_ = listener.Close()
		t.Fatal("prepare Docker socket fixture failed")
	}
	plan := linuxRunnerTestPlan(path.Join(base, "runner"), slots)
	for _, directory := range []string{
		plan.Root, path.Join(plan.Root, "data"), path.Join(plan.Root, "data", "slots"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil || os.Chmod(directory, 0o700) != nil {
			t.Fatal("create runner root fixture failed")
		}
	}
	for _, slot := range plan.Slots {
		for _, directory := range []string{slot.StorageRoot, slot.JournalRoot, slot.WorkspaceRoot} {
			if err := os.MkdirAll(directory, 0o700); err != nil || os.Chmod(directory, 0o700) != nil {
				t.Fatal("create runner slot fixture failed")
			}
		}
	}
	host := newFakeRunnerHost()
	host.runscPath = plan.RunscBinary
	system := &linuxRunnerNodeSystem{
		run: host.run, locate: host.locate, euid: func() int { return 0 }, arch: "amd64",
		paths: paths, readiness: func(context.Context, []runnerSystemSlot) error { return nil },
	}
	return system, host, plan, paths, func() { _ = listener.Close() }
}

func runnerHostTestRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("runner host integration requires root")
	}
	root, err := os.MkdirTemp(os.TempDir(), "matrix-runner-host-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func runnerHostTestPaths(base string) runnerHostPaths {
	return runnerHostPaths{
		DockerConfig:   path.Join(base, "etc", "docker", "daemon.json"),
		DockerSocket:   path.Join(base, "run", "docker.sock"),
		SystemdRoot:    path.Join(base, "etc", "systemd", "system"),
		FirewallRoot:   path.Join(base, "etc", "matrix-devops"),
		FirewallRules:  path.Join(base, "etc", "matrix-devops", "runner-egress.nft"),
		LockFile:       path.Join(base, "run", "runner-install.lock"),
		ValidationRoot: path.Join(base, "run"),
	}
}

func linuxRunnerTestPlan(root string, slots int) runnerSystemPlan {
	const (
		installationID = "mxi-11111111111111111111111111111111"
		namespace      = "spiffe://matrix.xiak.com/installations/11111111111111111111111111111111/devops/runners"
	)
	installed := path.Join(root, "installed")
	plan := runnerSystemPlan{
		Root: root, ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa", InstallationID: installationID,
		NodeID: "runner-one", GatewayOrigin: "https://192.0.2.10:8444",
		GatewayAddress: "192.0.2.10", GatewayServerName: "devops-executor-gateway",
		RunnerNamespace:  namespace,
		RunnerBinary:     path.Join(installed, release.RunnerBinaryPath),
		RunscBinary:      path.Join(installed, "gvisor", "runsc"),
		ToolchainArchive: path.Join(installed, release.RunnerToolchainArchivePath),
		ServerCA:         path.Join(installed, "pki", "server-ca.pem"), Slots: make([]runnerSystemSlot, slots),
	}
	for index := range plan.Slots {
		slot := index + 1
		slotName := strconv.Itoa(slot)
		storage := path.Join(root, "data", "slots", slotName)
		plan.Slots[index] = runnerSystemSlot{
			Index: uint8(slot), Identity: namespace + "/nodes/runner-one/slots/" + slotName,
			Listen:      "127.0.0.1:" + strconv.Itoa(runnerReadyPortBase+slot),
			ClientKey:   path.Join(root, "secrets", "slots", slotName, "client.key"),
			ClientCert:  path.Join(installed, "pki", "slots", slotName, "client.crt"),
			StorageRoot: storage, JournalRoot: path.Join(storage, "journal"),
			WorkspaceRoot: path.Join(storage, "workspace"),
		}
	}
	return plan
}

func assertRunnerSystemFilesAndOwnership(
	t *testing.T,
	plan runnerSystemPlan,
	paths runnerHostPaths,
) {
	t.Helper()
	for _, target := range []string{
		paths.FirewallRules, path.Join(paths.SystemdRoot, runnerFirewallUnit),
		path.Join(paths.SystemdRoot, runnerSlotUnit(1)), path.Join(paths.SystemdRoot, runnerSlotUnit(2)),
	} {
		content, err := os.ReadFile(target)
		if err != nil || !strings.HasPrefix(string(content), runnerManagedHeader) {
			t.Fatalf("managed host file %s is invalid: %v", target, err)
		}
	}
	for index, slot := range plan.Slots {
		for _, target := range []string{slot.StorageRoot, slot.JournalRoot, slot.WorkspaceRoot} {
			info, err := os.Lstat(target)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("slot path %s mode is invalid: %v", target, err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != uint32(2001+index) || stat.Gid != uint32(3001+index) {
				t.Fatalf("slot path %s owner=%d:%d", target, stat.Uid, stat.Gid)
			}
		}
	}
	for _, target := range []string{plan.Root, path.Join(plan.Root, "data"), path.Join(plan.Root, "data", "slots")} {
		info, err := os.Lstat(target)
		if err != nil || info.Mode().Perm() != 0o711 {
			t.Fatalf("runner traversal path %s is invalid: %v", target, err)
		}
	}
}

func assertRunnerActivationOrder(t *testing.T, calls [][]string) {
	t.Helper()
	find := func(prefix ...string) int {
		for index, call := range calls {
			if len(call) >= len(prefix) && strings.Join(call[:len(prefix)], "\x00") == strings.Join(prefix, "\x00") {
				return index
			}
		}
		return -1
	}
	firewall := find("systemctl", "restart", runnerFirewallUnit)
	docker := find("systemctl", "restart", "docker.service")
	load := find("docker", "image", "load")
	start := find("systemctl", "start", runnerSlotUnit(1), runnerSlotUnit(2))
	if firewall < 0 || docker <= firewall || load <= docker || start <= load {
		t.Fatalf("runner activation order is unsafe: %#v", calls)
	}
}
