//go:build linux

package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"golang.org/x/sys/unix"
)

const (
	maximumRunnerHostCommandOutput = 1024 * 1024
	maximumRunnerSystemFile        = 1024 * 1024
	runnerReadinessTimeout         = 45 * time.Second
	runnerReadinessPollInterval    = 250 * time.Millisecond
)

type runnerHostCommandOutcome struct {
	output   []byte
	exitCode int
}

type runnerHostCommand func(
	context.Context,
	string,
	...string,
) (runnerHostCommandOutcome, error)

type runnerExecutableLocator func(string) (string, error)

type runnerHostPaths struct {
	DockerConfig   string
	DockerSocket   string
	SystemdRoot    string
	FirewallRoot   string
	FirewallRules  string
	LockFile       string
	ValidationRoot string
}

type runnerHostTools struct {
	Docker         string
	Getent         string
	ID             string
	Nft            string
	Nologin        string
	Systemctl      string
	SystemdAnalyze string
	Useradd        string
}

type linuxRunnerNodeSystem struct {
	run       runnerHostCommand
	locate    runnerExecutableLocator
	euid      func() int
	arch      string
	paths     runnerHostPaths
	readiness func(context.Context, []runnerSystemSlot) error
}

func newRunnerNodeSystem() runnerNodeSystem {
	return &linuxRunnerNodeSystem{
		run: defaultRunnerHostCommand, locate: locateRunnerHostExecutable,
		euid: os.Geteuid, arch: runtime.GOARCH,
		paths: runnerHostPaths{
			DockerConfig: "/etc/docker/daemon.json", DockerSocket: runnerDockerSocket,
			SystemdRoot: "/etc/systemd/system", FirewallRoot: "/etc/matrix-devops",
			FirewallRules: "/etc/matrix-devops/runner-egress.nft",
			LockFile:      "/run/matrix-devops-runner-install.lock", ValidationRoot: "/run",
		},
		readiness: waitForRunnerReadiness,
	}
}

func (system *linuxRunnerNodeSystem) Preflight(
	ctx context.Context,
	plan runnerSystemPlan,
) (returnErr error) {
	if err := system.validateHost(ctx, plan); err != nil {
		return err
	}
	lock, err := acquireRunnerHostLock(system.paths.LockFile)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := releaseRunnerHostLock(lock); closeErr != nil && returnErr == nil {
			returnErr = runnernodecommand.ErrEffectOutcomeUnknown
		}
	}()
	tools, err := system.resolveTools()
	if err != nil {
		return err
	}
	dockerGroup, err := system.lookupGroup(ctx, tools.Getent, "docker")
	if err != nil || dockerGroup.GID == 0 {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	if _, _, _, err = selectRunnerDockerConfig(system.paths.DockerConfig, plan.RunscBinary); err != nil {
		return err
	}
	return validateRunnerOwnedProfilePaths(system.paths)
}

func (system *linuxRunnerNodeSystem) Converge(
	ctx context.Context,
	plan runnerSystemPlan,
) (returnErr error) {
	if err := system.validateHost(ctx, plan); err != nil {
		return err
	}
	lock, err := acquireRunnerHostLock(system.paths.LockFile)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := releaseRunnerHostLock(lock); closeErr != nil && returnErr == nil {
			returnErr = runnernodecommand.ErrEffectOutcomeUnknown
		}
	}()
	if err := validateRunnerOwnedProfilePaths(system.paths); err != nil {
		return err
	}

	tools, err := system.resolveTools()
	if err != nil {
		return err
	}
	if err := system.deactivateRunnerUnits(ctx, tools.Systemctl); err != nil {
		return err
	}
	dockerGroup, err := system.lookupGroup(ctx, tools.Getent, "docker")
	if err != nil || dockerGroup.GID == 0 {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	accounts, err := system.ensureRunnerAccounts(ctx, plan, tools, dockerGroup.GID)
	if err != nil {
		return err
	}
	if err := prepareRunnerStorage(plan, accounts); err != nil {
		return err
	}
	if err := ensureRunnerHostDirectory(path.Dir(system.paths.DockerConfig), 0o755); err != nil {
		return err
	}

	dockerSnapshot, _, desiredDocker, err := selectRunnerDockerConfig(
		system.paths.DockerConfig, plan.RunscBinary,
	)
	if err != nil {
		return err
	}
	profiles, err := renderRunnerHostProfiles(plan, accounts, tools, system.paths)
	if err != nil {
		return errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	if err := system.validateProfiles(ctx, tools, profiles); err != nil {
		return err
	}
	if err := system.publishProfiles(ctx, tools, profiles, len(plan.Slots)); err != nil {
		return err
	}
	if err := system.activateFirewall(ctx, tools.Systemctl); err != nil {
		return err
	}
	if err := system.convergeDocker(
		ctx, tools, dockerSnapshot, desiredDocker, dockerGroup.GID, plan.RunscBinary,
	); err != nil {
		return err
	}
	if err := system.convergeToolchain(ctx, tools.Docker, plan.ToolchainArchive); err != nil {
		return err
	}

	runnerUnitsMayBeActive := true
	defer func() {
		if returnErr == nil || !runnerUnitsMayBeActive {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if cleanupErr := system.deactivateRunnerUnits(cleanupContext, tools.Systemctl); cleanupErr != nil {
			returnErr = errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, returnErr)
		}
	}()
	units := runnerSlotUnits(len(plan.Slots))
	if err := system.runSuccessful(ctx, tools.Systemctl, append([]string{"enable"}, units...)...); err != nil {
		return err
	}
	if err := system.runSuccessful(ctx, tools.Systemctl, append([]string{"start"}, units...)...); err != nil {
		return err
	}
	for _, unit := range units {
		if err := system.runSuccessful(ctx, tools.Systemctl, "is-active", "--quiet", unit); err != nil {
			return err
		}
	}
	readyContext, cancelReady := context.WithTimeout(ctx, runnerReadinessTimeout)
	defer cancelReady()
	if err := system.readiness(readyContext, plan.Slots); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return runnernodecommand.ErrEffectUnavailable
	}
	runnerUnitsMayBeActive = false
	return nil
}

func (system *linuxRunnerNodeSystem) validateHost(
	ctx context.Context,
	plan runnerSystemPlan,
) error {
	if system == nil || system.run == nil || system.locate == nil || system.euid == nil ||
		system.readiness == nil || ctx == nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateRunnerSystemPlan(plan) != nil {
		return runnernodecommand.ErrEffectInput
	}
	if system.arch != "amd64" || system.euid() != 0 || validateRunnerHostPaths(system.paths) != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	if err := validateRunnerNodeRoot(plan.Root); err != nil {
		return errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	return nil
}

func (system *linuxRunnerNodeSystem) resolveTools() (runnerHostTools, error) {
	tools := runnerHostTools{}
	targets := []struct {
		name   string
		target *string
	}{
		{name: "docker", target: &tools.Docker},
		{name: "getent", target: &tools.Getent},
		{name: "id", target: &tools.ID},
		{name: "nft", target: &tools.Nft},
		{name: "nologin", target: &tools.Nologin},
		{name: "systemctl", target: &tools.Systemctl},
		{name: "systemd-analyze", target: &tools.SystemdAnalyze},
		{name: "useradd", target: &tools.Useradd},
	}
	for _, target := range targets {
		resolved, err := system.locate(target.name)
		if err != nil || !validRunnerUnixPath(resolved) {
			return runnerHostTools{}, errors.Join(runnernodecommand.ErrEffectUnavailable, err)
		}
		*target.target = resolved
	}
	return tools, nil
}

func defaultRunnerHostCommand(
	ctx context.Context,
	program string,
	arguments ...string,
) (runnerHostCommandOutcome, error) {
	if ctx == nil || !validRunnerUnixPath(program) {
		return runnerHostCommandOutcome{}, runnernodecommand.ErrEffectInput
	}
	if err := ctx.Err(); err != nil {
		return runnerHostCommandOutcome{}, err
	}
	var output boundedOutput
	output.maximum = maximumRunnerHostCommandOutput
	command := exec.CommandContext(ctx, program, arguments...)
	command.Dir = "/"
	command.Env = runnerHostEnvironment()
	command.Stdin = nil
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return runnerHostCommandOutcome{}, ctxErr
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && !output.exceeded {
			return runnerHostCommandOutcome{
				output: append([]byte(nil), output.Bytes()...), exitCode: exitError.ExitCode(),
			}, nil
		}
		return runnerHostCommandOutcome{}, runnernodecommand.ErrEffectUnavailable
	}
	if output.exceeded {
		return runnerHostCommandOutcome{}, runnernodecommand.ErrEffectUnavailable
	}
	return runnerHostCommandOutcome{
		output: append([]byte(nil), output.Bytes()...), exitCode: 0,
	}, nil
}

func runnerHostEnvironment() []string {
	return []string{
		"ALL_PROXY=", "DOCKER_CONFIG=/var/empty/matrix-devops", "DOCKER_CONTEXT=",
		"DOCKER_HOST=unix:///var/run/docker.sock", "DOCKER_TLS_VERIFY=", "HOME=/var/empty",
		"HTTPS_PROXY=", "HTTP_PROXY=", "LANG=C", "LC_ALL=C", "NO_PROXY=", "PAGER=cat",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat",
		"TERM=dumb", "TZ=UTC", "XDG_CONFIG_HOME=/var/empty", "all_proxy=", "http_proxy=",
		"https_proxy=", "no_proxy=",
	}
}

func locateRunnerHostExecutable(name string) (string, error) {
	candidates := map[string][]string{
		"docker":          {"/usr/bin/docker", "/usr/local/bin/docker"},
		"getent":          {"/usr/bin/getent", "/bin/getent"},
		"id":              {"/usr/bin/id", "/bin/id"},
		"nft":             {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"},
		"nologin":         {"/usr/sbin/nologin", "/sbin/nologin"},
		"systemctl":       {"/usr/bin/systemctl", "/bin/systemctl"},
		"systemd-analyze": {"/usr/bin/systemd-analyze", "/bin/systemd-analyze"},
		"useradd":         {"/usr/sbin/useradd", "/sbin/useradd"},
	}
	for _, candidate := range candidates[name] {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || !validRunnerUnixPath(resolved) {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
			info.Mode().Perm()&0o022 != 0 ||
			validateRunnerHostDirectory(path.Dir(resolved)) != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && stat.Uid == 0 {
			return resolved, nil
		}
	}
	return "", errors.New("runner host executable is unavailable")
}

func (system *linuxRunnerNodeSystem) runSuccessful(
	ctx context.Context,
	program string,
	arguments ...string,
) error {
	outcome, err := system.run(ctx, program, arguments...)
	if err != nil {
		return err
	}
	if outcome.exitCode != 0 {
		return runnernodecommand.ErrEffectUnavailable
	}
	return nil
}

func runnerSlotUnits(count int) []string {
	units := make([]string, count)
	for index := range units {
		units[index] = runnerSlotUnit(uint8(index + 1))
	}
	return units
}

func (system *linuxRunnerNodeSystem) deactivateRunnerUnits(ctx context.Context, systemctl string) error {
	for index := uint8(1); index <= release.RunnerMaximumSlots; index++ {
		unit := runnerSlotUnit(index)
		outcome, err := system.run(ctx, systemctl, "is-active", "--quiet", unit)
		if err != nil {
			return err
		}
		switch outcome.exitCode {
		case 0:
			if err := system.runSuccessful(ctx, systemctl, "stop", unit); err != nil {
				return err
			}
		case 3, 4:
			continue
		default:
			return runnernodecommand.ErrEffectUnavailable
		}
		managed, err := runnerOwnedSystemFileExists(path.Join(system.paths.SystemdRoot, unit))
		if err != nil {
			return err
		}
		if managed {
			if err := system.runSuccessful(ctx, systemctl, "disable", "--now", unit); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRunnerOwnedProfilePaths(paths runnerHostPaths) error {
	targets := []string{
		paths.FirewallRules,
		path.Join(paths.SystemdRoot, runnerFirewallUnit),
	}
	for index := uint8(1); index <= release.RunnerMaximumSlots; index++ {
		targets = append(targets, path.Join(paths.SystemdRoot, runnerSlotUnit(index)))
	}
	for _, target := range targets {
		if _, err := runnerOwnedSystemFileExists(target); err != nil {
			return err
		}
	}
	return nil
}

type runnerHostGroup struct {
	Name string
	GID  uint32
}

func (system *linuxRunnerNodeSystem) lookupGroup(
	ctx context.Context,
	getent string,
	name string,
) (runnerHostGroup, error) {
	outcome, err := system.run(ctx, getent, "group", name)
	if err != nil || outcome.exitCode != 0 {
		return runnerHostGroup{}, errors.New("runner host group is unavailable")
	}
	line, ok := oneRunnerHostLine(outcome.output)
	fields := strings.Split(line, ":")
	if !ok || len(fields) != 4 || fields[0] != name || fields[1] == "" {
		return runnerHostGroup{}, errors.New("runner host group is invalid")
	}
	gid, ok := canonicalRunnerHostID(fields[2])
	if !ok || gid == 0 {
		return runnerHostGroup{}, errors.New("runner host group identity is invalid")
	}
	return runnerHostGroup{Name: name, GID: gid}, nil
}

func (system *linuxRunnerNodeSystem) ensureRunnerAccounts(
	ctx context.Context,
	plan runnerSystemPlan,
	tools runnerHostTools,
	dockerGID uint32,
) ([]runnerSystemAccount, error) {
	accounts := make([]runnerSystemAccount, len(plan.Slots))
	seenUIDs := make(map[uint32]struct{}, len(accounts))
	seenGIDs := make(map[uint32]struct{}, len(accounts))
	for index, slot := range plan.Slots {
		name := runnerAccountName(slot.Index)
		account, found, err := system.lookupRunnerAccount(ctx, tools, name, dockerGID)
		if err != nil {
			return nil, err
		}
		if !found {
			if err := system.runSuccessful(
				ctx, tools.Useradd, "--system", "--user-group", "--no-create-home",
				"--home-dir", "/nonexistent", "--shell", tools.Nologin,
				"--groups", "docker", "--comment", "Matrix DevOps runner slot "+strconv.Itoa(int(slot.Index)),
				name,
			); err != nil {
				return nil, err
			}
			account, found, err = system.lookupRunnerAccount(ctx, tools, name, dockerGID)
			if err != nil || !found {
				return nil, errors.Join(runnernodecommand.ErrEffectUnavailable, err)
			}
		}
		account.Index = slot.Index
		if account.Name != name || account.UID == 0 || account.GID == 0 ||
			account.GID == dockerGID {
			return nil, runnernodecommand.ErrEffectConflict
		}
		if _, duplicate := seenUIDs[account.UID]; duplicate {
			return nil, runnernodecommand.ErrEffectConflict
		}
		if _, duplicate := seenGIDs[account.GID]; duplicate {
			return nil, runnernodecommand.ErrEffectConflict
		}
		seenUIDs[account.UID] = struct{}{}
		seenGIDs[account.GID] = struct{}{}
		accounts[index] = account
	}
	return accounts, nil
}

func (system *linuxRunnerNodeSystem) lookupRunnerAccount(
	ctx context.Context,
	tools runnerHostTools,
	name string,
	dockerGID uint32,
) (runnerSystemAccount, bool, error) {
	outcome, err := system.run(ctx, tools.Getent, "passwd", name)
	if err != nil {
		return runnerSystemAccount{}, false, err
	}
	if outcome.exitCode == 2 {
		return runnerSystemAccount{}, false, nil
	}
	line, ok := oneRunnerHostLine(outcome.output)
	fields := strings.Split(line, ":")
	if outcome.exitCode != 0 || !ok || len(fields) != 7 || fields[0] != name ||
		fields[1] == "" || fields[5] != "/nonexistent" || fields[6] != tools.Nologin {
		return runnerSystemAccount{}, false, runnernodecommand.ErrEffectConflict
	}
	uid, uidOK := canonicalRunnerHostID(fields[2])
	gid, gidOK := canonicalRunnerHostID(fields[3])
	if !uidOK || !gidOK || uid == 0 || gid == 0 {
		return runnerSystemAccount{}, false, runnernodecommand.ErrEffectConflict
	}
	primary, err := system.lookupGroup(ctx, tools.Getent, name)
	if err != nil || primary.GID != gid {
		return runnerSystemAccount{}, false, runnernodecommand.ErrEffectConflict
	}
	groupOutcome, err := system.run(ctx, tools.ID, "-G", name)
	if err != nil || groupOutcome.exitCode != 0 || !exactRunnerGroups(
		groupOutcome.output, gid, dockerGID,
	) {
		return runnerSystemAccount{}, false, runnernodecommand.ErrEffectConflict
	}
	return runnerSystemAccount{Name: name, UID: uid, GID: gid}, true, nil
}

func oneRunnerHostLine(content []byte) (string, bool) {
	if len(content) == 0 || len(content) > 4096 || bytes.IndexByte(content, 0) >= 0 {
		return "", false
	}
	line := strings.TrimSuffix(string(content), "\n")
	return line, line != "" && !strings.ContainsAny(line, "\r\n")
}

func canonicalRunnerHostID(value string) (uint32, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err == nil && parsed > 0
}

func exactRunnerGroups(content []byte, primary, docker uint32) bool {
	line, ok := oneRunnerHostLine(content)
	if !ok || primary == docker {
		return false
	}
	values := strings.Fields(line)
	if len(values) != 2 {
		return false
	}
	seen := map[uint32]struct{}{}
	for _, value := range values {
		id, valid := canonicalRunnerHostID(value)
		if !valid {
			return false
		}
		seen[id] = struct{}{}
	}
	_, primaryFound := seen[primary]
	_, dockerFound := seen[docker]
	return len(seen) == 2 && primaryFound && dockerFound
}

func prepareRunnerStorage(plan runnerSystemPlan, accounts []runnerSystemAccount) error {
	if len(accounts) != len(plan.Slots) {
		return runnernodecommand.ErrEffectInput
	}
	for _, directory := range []string{
		plan.Root, path.Join(plan.Root, "data"), path.Join(plan.Root, "data", "slots"),
	} {
		if err := constrainRunnerDirectory(directory, 0, 0, []os.FileMode{0o700, 0o711}, 0o711); err != nil {
			return err
		}
	}
	for index, slot := range plan.Slots {
		account := accounts[index]
		for _, directory := range []string{slot.StorageRoot, slot.JournalRoot, slot.WorkspaceRoot} {
			if err := constrainRunnerDirectory(
				directory, account.UID, account.GID, []os.FileMode{0o700}, 0o700,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func constrainRunnerDirectory(
	target string,
	uid uint32,
	gid uint32,
	acceptedModes []os.FileMode,
	wantMode os.FileMode,
) error {
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!slices.Contains(acceptedModes, info.Mode().Perm()) {
		return errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uid) || (stat.Gid != 0 && stat.Gid != gid) {
		return runnernodecommand.ErrEffectConflict
	}
	if err := os.Chown(target, int(uid), int(gid)); err != nil || os.Chmod(target, wantMode) != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	verified, err := os.Lstat(target)
	if err != nil || verified == nil || !verified.IsDir() || verified.Mode()&os.ModeSymlink != 0 ||
		verified.Mode().Perm() != wantMode {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	verifiedStat, verifiedOK := verified.Sys().(*syscall.Stat_t)
	if !verifiedOK || verifiedStat.Uid != uid || verifiedStat.Gid != gid {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	return nil
}

type runnerSystemFileSnapshot struct {
	exists  bool
	content []byte
	mode    os.FileMode
}

func equalRunnerSystemFileSnapshots(left, right runnerSystemFileSnapshot) bool {
	return left.exists == right.exists && left.mode == right.mode &&
		bytes.Equal(left.content, right.content)
}

type runnerHostProfiles struct {
	firewallRules  []byte
	firewallUnit   []byte
	runnerUnits    map[string][]byte
	validationRoot string
}

func selectRunnerDockerConfig(
	target string,
	runscPath string,
) (runnerSystemFileSnapshot, bool, []byte, error) {
	snapshot, err := readRunnerSystemFile(target, maximumRunnerSystemFile, 0o644, true)
	if err != nil {
		return runnerSystemFileSnapshot{}, false, nil, err
	}
	defaultConfig, err := renderRunnerDockerConfig(runscPath, false)
	if err != nil {
		return runnerSystemFileSnapshot{}, false, nil, err
	}
	classicConfig, err := renderRunnerDockerConfig(runscPath, true)
	if err != nil {
		return runnerSystemFileSnapshot{}, false, nil, err
	}
	if !snapshot.exists {
		return snapshot, false, defaultConfig, nil
	}
	switch {
	case bytes.Equal(snapshot.content, defaultConfig):
		return snapshot, false, defaultConfig, nil
	case isRunnerClassicDockerBase(snapshot.content), bytes.Equal(snapshot.content, classicConfig):
		return snapshot, true, classicConfig, nil
	default:
		return runnerSystemFileSnapshot{}, false, nil, runnernodecommand.ErrEffectConflict
	}
}

func renderRunnerHostProfiles(
	plan runnerSystemPlan,
	accounts []runnerSystemAccount,
	tools runnerHostTools,
	paths runnerHostPaths,
) (runnerHostProfiles, error) {
	rules, err := renderRunnerFirewall(plan, accounts)
	if err != nil {
		return runnerHostProfiles{}, err
	}
	firewall, err := renderRunnerFirewallService(tools.Nft, paths.FirewallRules)
	if err != nil {
		return runnerHostProfiles{}, err
	}
	units := make(map[string][]byte, len(plan.Slots))
	for index, slot := range plan.Slots {
		content, err := renderRunnerService(plan, slot, accounts[index])
		if err != nil {
			return runnerHostProfiles{}, err
		}
		units[runnerSlotUnit(slot.Index)] = content
	}
	return runnerHostProfiles{
		firewallRules: rules, firewallUnit: firewall, runnerUnits: units,
		validationRoot: paths.ValidationRoot,
	}, nil
}

func (system *linuxRunnerNodeSystem) validateProfiles(
	ctx context.Context,
	tools runnerHostTools,
	profiles runnerHostProfiles,
) error {
	staging, err := os.MkdirTemp(profiles.validationRoot, ".matrix-runner-profile-")
	if err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	created := make([]string, 0, len(profiles.runnerUnits)+2)
	cleaned := false
	cleanup := func() error {
		var result error
		for index := len(created) - 1; index >= 0; index-- {
			result = errors.Join(result, os.Remove(created[index]))
		}
		result = errors.Join(result, os.Remove(staging))
		return result
	}
	defer func() {
		if !cleaned {
			_ = cleanup()
		}
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	rulesPath := path.Join(staging, "runner-egress.nft")
	if err := writeRunnerValidationFile(rulesPath, profiles.firewallRules); err != nil {
		return err
	}
	created = append(created, rulesPath)
	unitPaths := make([]string, 0, len(profiles.runnerUnits)+1)
	firewallPath := path.Join(staging, runnerFirewallUnit)
	if err := writeRunnerValidationFile(firewallPath, profiles.firewallUnit); err != nil {
		return err
	}
	created = append(created, firewallPath)
	unitPaths = append(unitPaths, firewallPath)
	unitNames := make([]string, 0, len(profiles.runnerUnits))
	for name := range profiles.runnerUnits {
		unitNames = append(unitNames, name)
	}
	slices.Sort(unitNames)
	for _, name := range unitNames {
		target := path.Join(staging, name)
		if err := writeRunnerValidationFile(target, profiles.runnerUnits[name]); err != nil {
			return err
		}
		created = append(created, target)
		unitPaths = append(unitPaths, target)
	}
	if err := system.runSuccessful(ctx, tools.Nft, "--check", "--file", rulesPath); err != nil {
		return err
	}
	if err := system.runSuccessful(
		ctx, tools.SystemdAnalyze, append([]string{"verify"}, unitPaths...)...,
	); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	cleaned = true
	return nil
}

func writeRunnerValidationFile(target string, content []byte) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	writeErr := writeAll(file, content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	return nil
}

func (system *linuxRunnerNodeSystem) publishProfiles(
	ctx context.Context,
	tools runnerHostTools,
	profiles runnerHostProfiles,
	slotCount int,
) error {
	if err := ensureRunnerHostDirectory(system.paths.FirewallRoot, 0o755); err != nil {
		return err
	}
	if err := writeRunnerOwnedSystemFile(
		system.paths.FirewallRules, profiles.firewallRules, 0o644,
	); err != nil {
		return err
	}
	if err := writeRunnerOwnedSystemFile(
		path.Join(system.paths.SystemdRoot, runnerFirewallUnit), profiles.firewallUnit, 0o644,
	); err != nil {
		return err
	}
	unitNames := make([]string, 0, len(profiles.runnerUnits))
	for name := range profiles.runnerUnits {
		unitNames = append(unitNames, name)
	}
	sort.Strings(unitNames)
	for _, name := range unitNames {
		content := profiles.runnerUnits[name]
		if err := writeRunnerOwnedSystemFile(
			path.Join(system.paths.SystemdRoot, name), content, 0o644,
		); err != nil {
			return err
		}
	}
	for index := slotCount + 1; index <= int(release.RunnerMaximumSlots); index++ {
		name := runnerSlotUnit(uint8(index))
		target := path.Join(system.paths.SystemdRoot, name)
		exists, err := runnerOwnedSystemFileExists(target)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := system.runSuccessful(ctx, tools.Systemctl, "disable", "--now", name); err != nil {
			return err
		}
		if err := os.Remove(target); err != nil || syncRunnerHostDirectory(system.paths.SystemdRoot) != nil {
			return runnernodecommand.ErrEffectOutcomeUnknown
		}
	}
	return system.runSuccessful(ctx, tools.Systemctl, "daemon-reload")
}

func (system *linuxRunnerNodeSystem) activateFirewall(
	ctx context.Context,
	systemctl string,
) error {
	if err := system.runSuccessful(ctx, systemctl, "enable", runnerFirewallUnit); err != nil {
		return err
	}
	if err := system.runSuccessful(ctx, systemctl, "restart", runnerFirewallUnit); err != nil {
		return err
	}
	return system.runSuccessful(ctx, systemctl, "is-active", "--quiet", runnerFirewallUnit)
}

func (system *linuxRunnerNodeSystem) convergeDocker(
	ctx context.Context,
	tools runnerHostTools,
	snapshot runnerSystemFileSnapshot,
	desired []byte,
	dockerGID uint32,
	runscPath string,
) error {
	changed := !snapshot.exists || !bytes.Equal(snapshot.content, desired)
	if changed {
		current, err := readRunnerSystemFile(
			system.paths.DockerConfig, maximumRunnerSystemFile, 0o644, true,
		)
		if err != nil || !equalRunnerSystemFileSnapshots(current, snapshot) {
			return runnernodecommand.ErrEffectOutcomeUnknown
		}
		if err := writeUnownedSystemFile(system.paths.DockerConfig, desired, 0o644); err != nil {
			return err
		}
	}
	failure := func() error {
		if !changed {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return runnernodecommand.ErrEffectUnavailable
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := restoreRunnerSystemFile(system.paths.DockerConfig, snapshot, desired); err != nil {
			return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, err)
		}
		if err := system.runSuccessful(
			cleanupContext, tools.Systemctl, "restart", "docker.service",
		); err != nil {
			return runnernodecommand.ErrEffectOutcomeUnknown
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return runnernodecommand.ErrEffectUnavailable
	}
	if err := system.runSuccessful(ctx, tools.Systemctl, "enable", "docker.service"); err != nil {
		return failure()
	}
	if err := system.runSuccessful(ctx, tools.Systemctl, "restart", "docker.service"); err != nil {
		return failure()
	}
	if err := system.runSuccessful(ctx, tools.Systemctl, "is-active", "--quiet", "docker.service"); err != nil {
		return failure()
	}
	if err := system.validateDockerDaemon(ctx, tools.Docker, runscPath); err != nil {
		return failure()
	}
	if err := validateRunnerDockerSocket(system.paths.DockerSocket, dockerGID); err != nil {
		return failure()
	}
	return nil
}

func (system *linuxRunnerNodeSystem) validateDockerDaemon(
	ctx context.Context,
	docker string,
	runscPath string,
) error {
	outcome, err := system.run(
		ctx, docker, "version", "--format",
		"{{.Server.Version}}|{{.Server.APIVersion}}|{{.Server.MinAPIVersion}}|{{.Server.Os}}|{{.Server.Arch}}",
	)
	if err != nil || outcome.exitCode != 0 {
		return runnernodecommand.ErrEffectUnavailable
	}
	line, ok := oneRunnerHostLine(outcome.output)
	fields := strings.Split(line, "|")
	if !ok || len(fields) != 5 || !runnerDocker29(fields[0]) ||
		!runnerEngineAPISupported(fields[2], fields[1], "1.46") ||
		fields[3] != "linux" || fields[4] != "amd64" {
		return runnernodecommand.ErrEffectUnavailable
	}
	runtimeOutcome, err := system.run(ctx, docker, "info", "--format", "{{json .Runtimes}}")
	if err != nil || runtimeOutcome.exitCode != 0 {
		return runnernodecommand.ErrEffectUnavailable
	}
	var runtimes map[string]struct {
		Path string `json:"path"`
	}
	decoder := json.NewDecoder(bytes.NewReader(runtimeOutcome.output))
	if err := decoder.Decode(&runtimes); err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		runtimes[release.RunnerRuntimeName].Path != runscPath {
		return runnernodecommand.ErrEffectUnavailable
	}
	return nil
}

func (system *linuxRunnerNodeSystem) convergeToolchain(
	ctx context.Context,
	docker string,
	archive string,
) error {
	if image, found, err := system.inspectRunnerToolchain(
		ctx, docker, release.RunnerToolchainLocalReference,
	); err != nil {
		return err
	} else if found {
		if validRunnerToolchainInspection(image) {
			return nil
		}
		return runnernodecommand.ErrEffectConflict
	}
	for _, candidate := range []string{
		release.RunnerToolchainSourceDigest, release.RunnerToolchainArchiveConfigDigest,
	} {
		if _, found, err := system.inspectRunnerToolchain(ctx, docker, candidate); err != nil {
			return err
		} else if found {
			return runnernodecommand.ErrEffectConflict
		}
	}
	cleanupReferences := []string{
		release.RunnerToolchainLocalReference,
		release.RunnerToolchainSourceDigest,
		release.RunnerToolchainArchiveConfigDigest,
	}
	if err := system.runSuccessful(ctx, docker, "image", "load", "--input", archive); err != nil {
		return system.cleanupLoadedToolchain(ctx, docker, cleanupReferences, err)
	}
	loadedID := ""
	for _, candidate := range []string{
		release.RunnerToolchainSourceDigest, release.RunnerToolchainArchiveConfigDigest,
	} {
		image, found, err := system.inspectRunnerToolchain(ctx, docker, candidate)
		if err != nil {
			return system.cleanupLoadedToolchain(ctx, docker, cleanupReferences, err)
		}
		if found && image.ID == candidate {
			if loadedID != "" {
				return system.cleanupLoadedToolchain(
					ctx, docker, cleanupReferences, runnernodecommand.ErrEffectVerification,
				)
			}
			loadedID = candidate
		}
	}
	if loadedID == "" {
		return system.cleanupLoadedToolchain(
			ctx, docker, cleanupReferences, runnernodecommand.ErrEffectVerification,
		)
	}
	if err := system.runSuccessful(
		ctx, docker, "image", "tag", loadedID, release.RunnerToolchainLocalReference,
	); err != nil {
		return system.cleanupLoadedToolchain(ctx, docker, cleanupReferences, err)
	}
	image, found, err := system.inspectRunnerToolchain(
		ctx, docker, release.RunnerToolchainLocalReference,
	)
	if err != nil || !found || !validRunnerToolchainInspection(image) {
		cause := err
		if cause == nil {
			cause = runnernodecommand.ErrEffectVerification
		}
		return system.cleanupLoadedToolchain(ctx, docker, cleanupReferences, cause)
	}
	return nil
}

type runnerToolchainInspection struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	RepoDigests  []string `json:"RepoDigests"`
	OS           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
}

func (system *linuxRunnerNodeSystem) inspectRunnerToolchain(
	ctx context.Context,
	docker string,
	reference string,
) (runnerToolchainInspection, bool, error) {
	outcome, err := system.run(ctx, docker, "image", "inspect", "--format", "{{json .}}", reference)
	if err != nil {
		return runnerToolchainInspection{}, false, err
	}
	if outcome.exitCode != 0 {
		if outcome.exitCode != 1 {
			return runnerToolchainInspection{}, false, runnernodecommand.ErrEffectUnavailable
		}
		version, versionErr := system.run(ctx, docker, "version", "--format", "{{.Server.Version}}")
		line, validVersion := oneRunnerHostLine(version.output)
		if versionErr != nil || version.exitCode != 0 || !validVersion || !runnerDocker29(line) {
			return runnerToolchainInspection{}, false, runnernodecommand.ErrEffectUnavailable
		}
		return runnerToolchainInspection{}, false, nil
	}
	if len(outcome.output) == 0 || len(outcome.output) > maximumRunnerHostCommandOutput {
		return runnerToolchainInspection{}, false, runnernodecommand.ErrEffectVerification
	}
	var image runnerToolchainInspection
	decoder := json.NewDecoder(bytes.NewReader(outcome.output))
	if err := decoder.Decode(&image); err != nil {
		return runnerToolchainInspection{}, false, runnernodecommand.ErrEffectVerification
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return runnerToolchainInspection{}, false, runnernodecommand.ErrEffectVerification
	}
	return image, true, nil
}

func validRunnerToolchainInspection(image runnerToolchainInspection) bool {
	if image.OS != "linux" || image.Architecture != "amd64" ||
		!slices.Equal(image.RepoTags, []string{release.RunnerToolchainLocalReference}) {
		return false
	}
	switch image.ID {
	case release.RunnerToolchainSourceDigest:
		return slices.Equal(image.RepoDigests, []string{release.RunnerToolchainLocalDigestReference})
	case release.RunnerToolchainArchiveConfigDigest:
		return len(image.RepoDigests) == 0
	default:
		return false
	}
}

func (system *linuxRunnerNodeSystem) cleanupLoadedToolchain(
	ctx context.Context,
	docker string,
	references []string,
	cause error,
) error {
	if cause == nil {
		cause = runnernodecommand.ErrEffectVerification
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if _, duplicate := seen[reference]; duplicate {
			continue
		}
		seen[reference] = struct{}{}
		_, found, err := system.inspectRunnerToolchain(cleanupContext, docker, reference)
		if err != nil {
			return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, cause)
		}
		if !found {
			continue
		}
		outcome, err := system.run(cleanupContext, docker, "image", "remove", "--force", reference)
		if err != nil || outcome.exitCode != 0 {
			return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, cause, err)
		}
		if _, found, err := system.inspectRunnerToolchain(
			cleanupContext, docker, reference,
		); err != nil || found {
			return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, cause, err)
		}
	}
	return cause
}

func validateRunnerHostPaths(paths runnerHostPaths) error {
	for _, candidate := range []string{
		paths.DockerConfig, paths.DockerSocket, paths.SystemdRoot, paths.FirewallRoot,
		paths.FirewallRules, paths.LockFile, paths.ValidationRoot,
	} {
		if !validRunnerUnixPath(candidate) {
			return errors.New("runner host path is invalid")
		}
	}
	if path.Dir(paths.FirewallRules) != paths.FirewallRoot ||
		path.Dir(paths.LockFile) != paths.ValidationRoot || path.Dir(paths.DockerConfig) == "/" ||
		paths.SystemdRoot == paths.FirewallRoot || paths.SystemdRoot == paths.ValidationRoot ||
		paths.FirewallRoot == paths.ValidationRoot {
		return errors.New("runner host path ownership is invalid")
	}
	return nil
}

func validateRunnerDockerSocket(target string, dockerGID uint32) error {
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm() != 0o660 {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != dockerGID {
		return runnernodecommand.ErrEffectUnavailable
	}
	return nil
}

func readRunnerSystemFile(
	target string,
	maximum int64,
	wantMode os.FileMode,
	allowMissing bool,
) (runnerSystemFileSnapshot, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return runnerSystemFileSnapshot{}, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != wantMode || info.Size() <= 0 || info.Size() > maximum {
		return runnerSystemFileSnapshot{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return runnerSystemFileSnapshot{}, runnernodecommand.ErrEffectConflict
	}
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		return runnerSystemFileSnapshot{}, runnernodecommand.ErrEffectConflict
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !sameRunnerSystemFile(info, openedInfo) {
		_ = file.Close()
		return runnerSystemFileSnapshot{}, runnernodecommand.ErrEffectConflict
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	afterInfo, afterStatErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || afterStatErr != nil || closeErr != nil ||
		!sameRunnerSystemFile(openedInfo, afterInfo) || len(content) == 0 ||
		int64(len(content)) > maximum || int64(len(content)) != afterInfo.Size() {
		return runnerSystemFileSnapshot{}, runnernodecommand.ErrEffectUnavailable
	}
	return runnerSystemFileSnapshot{exists: true, content: content, mode: info.Mode().Perm()}, nil
}

func sameRunnerSystemFile(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() ||
		left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid &&
		leftStat.Mode == rightStat.Mode && leftStat.Size == rightStat.Size &&
		leftStat.Mtim == rightStat.Mtim && leftStat.Ctim == rightStat.Ctim
}

func ensureRunnerHostDirectory(target string, mode os.FileMode) error {
	if !validRunnerUnixPath(target) || (mode != 0o700 && mode != 0o755) {
		return runnernodecommand.ErrEffectInput
	}
	if err := validateRunnerHostDirectory(path.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(target, mode); err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	info, err := validateManagedExistingPath(target)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
		return errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return runnernodecommand.ErrEffectConflict
	}
	return nil
}

func writeRunnerOwnedSystemFile(target string, content []byte, mode os.FileMode) error {
	if existing, err := readRunnerSystemFile(target, maximumRunnerSystemFile, mode, true); err != nil {
		return err
	} else if existing.exists {
		if bytes.Equal(existing.content, content) {
			return nil
		}
		if !bytes.HasPrefix(existing.content, []byte(runnerManagedHeader)) {
			return runnernodecommand.ErrEffectConflict
		}
	}
	return atomicWriteRunnerSystemFile(target, content, mode)
}

func writeUnownedSystemFile(target string, content []byte, mode os.FileMode) error {
	return atomicWriteRunnerSystemFile(target, content, mode)
}

func atomicWriteRunnerSystemFile(target string, content []byte, mode os.FileMode) error {
	if !validRunnerUnixPath(target) || len(content) == 0 || len(content) > maximumRunnerSystemFile ||
		mode != 0o644 {
		return runnernodecommand.ErrEffectInput
	}
	parent := path.Dir(target)
	if err := validateRunnerHostDirectory(parent); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".matrix-runner-system-")
	if err != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	temporaryPath := temporary.Name()
	succeeded := false
	defer func() {
		_ = temporary.Close()
		if !succeeded {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil || temporary.Chown(0, 0) != nil ||
		writeAll(temporary, content) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	if err := os.Rename(temporaryPath, target); err != nil || syncRunnerHostDirectory(parent) != nil {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	succeeded = true
	return nil
}

func validateRunnerHostDirectory(target string) error {
	info, err := validateManagedExistingPath(target)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return runnernodecommand.ErrEffectConflict
	}
	return validateRunnerHostAncestorChain(path.Dir(target))
}

func validateRunnerHostAncestorChain(target string) error {
	for current := target; ; current = path.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(runnernodecommand.ErrEffectConflict, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		writableWithoutSticky := info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0
		if !ok || stat.Uid != 0 || writableWithoutSticky {
			return runnernodecommand.ErrEffectConflict
		}
		if current == "/" {
			return nil
		}
	}
}

func runnerOwnedSystemFileExists(target string) (bool, error) {
	snapshot, err := readRunnerSystemFile(target, maximumRunnerSystemFile, 0o644, true)
	if err != nil || !snapshot.exists {
		return false, err
	}
	if !bytes.HasPrefix(snapshot.content, []byte(runnerManagedHeader)) {
		return false, runnernodecommand.ErrEffectConflict
	}
	return true, nil
}

func restoreRunnerSystemFile(
	target string,
	snapshot runnerSystemFileSnapshot,
	current []byte,
) error {
	installed, err := readRunnerSystemFile(target, maximumRunnerSystemFile, 0o644, false)
	if err != nil || !bytes.Equal(installed.content, current) {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	if snapshot.exists {
		return atomicWriteRunnerSystemFile(target, snapshot.content, snapshot.mode)
	}
	if err := os.Remove(target); err != nil || syncRunnerHostDirectory(path.Dir(target)) != nil {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	return nil
}

func acquireRunnerHostLock(target string) (*os.File, error) {
	if !validRunnerUnixPath(target) || validateRunnerHostDirectory(path.Dir(target)) != nil {
		return nil, runnernodecommand.ErrEffectUnavailable
	}
	fd, err := unix.Open(target, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, runnernodecommand.ErrEffectUnavailable
	}
	file := os.NewFile(uintptr(fd), target)
	info, statErr := file.Stat()
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if statErr != nil || !statOK || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		stat.Uid != 0 {
		_ = file.Close()
		return nil, runnernodecommand.ErrEffectConflict
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, runnernodecommand.ErrEffectConflict
		}
		return nil, runnernodecommand.ErrEffectUnavailable
	}
	return file, nil
}

func releaseRunnerHostLock(file *os.File) error {
	if file == nil {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil || closeErr != nil {
		return runnernodecommand.ErrEffectOutcomeUnknown
	}
	return nil
}

func syncRunnerHostDirectory(target string) error {
	directory, err := os.Open(target)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func runnerDocker29(value string) bool {
	core := value
	if index := strings.IndexAny(core, "-+"); index >= 0 {
		if index == len(core)-1 {
			return false
		}
		for _, character := range core[index+1:] {
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') && character != '.' && character != '-' {
				return false
			}
		}
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 || parts[0] != "29" {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func runnerEngineAPISupported(minimum, maximum, selected string) bool {
	minimumMajor, minimumMinor, minimumOK := runnerAPIVersion(minimum)
	maximumMajor, maximumMinor, maximumOK := runnerAPIVersion(maximum)
	selectedMajor, selectedMinor, selectedOK := runnerAPIVersion(selected)
	if !minimumOK || !maximumOK || !selectedOK {
		return false
	}
	selectedValue := selectedMajor*1000 + selectedMinor
	return selectedValue >= minimumMajor*1000+minimumMinor &&
		selectedValue <= maximumMajor*1000+maximumMinor
}

func runnerAPIVersion(value string) (int, int, bool) {
	majorText, minorText, found := strings.Cut(value, ".")
	if !found || majorText == "" || minorText == "" || strings.Contains(minorText, ".") ||
		(len(majorText) > 1 && majorText[0] == '0') ||
		(len(minorText) > 1 && minorText[0] == '0') {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	return major, minor, majorErr == nil && minorErr == nil && major >= 0 && minor >= 0
}

func waitForRunnerReadiness(ctx context.Context, slots []runnerSystemSlot) error {
	if ctx == nil || len(slots) == 0 {
		return runnernodecommand.ErrEffectInput
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext,
			DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
			ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 4096,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("runner readiness redirect is forbidden")
		},
	}
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(runnerReadinessPollInterval)
	defer ticker.Stop()
	for {
		ready := true
		for _, slot := range slots {
			if !runnerSlotReady(ctx, client, slot) {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runnerSlotReady(ctx context.Context, client *http.Client, slot runnerSystemSlot) bool {
	if ctx == nil || client == nil || slot.Listen != net.JoinHostPort(
		"127.0.0.1", strconv.Itoa(runnerReadyPortBase+int(slot.Index)),
	) {
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+slot.Listen+"/ready", nil)
	if err != nil {
		return false
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return false
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
	closeErr := response.Body.Close()
	return readErr == nil && closeErr == nil && len(body) <= 256 &&
		response.StatusCode == http.StatusOK &&
		response.Header.Get("Cache-Control") == "no-store" &&
		response.Header.Get("Content-Type") == "application/json" &&
		response.Header.Get("X-Content-Type-Options") == "nosniff" &&
		bytes.Equal(body, []byte("{\"apiVersion\":\"process.matrix.xiak.com/v1\",\"kind\":\"ProcessReadiness\",\"state\":\"READY\"}\n"))
}
