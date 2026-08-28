//go:build linux

package localmachine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	systemd "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
)

type localNodeSupervisor struct{}

// Use the system manager's local private socket, never an inherited user bus,
// remote address or shell. Only exact startup registration changes reload the
// manager's unit definitions; they never restart the manager or another service.
func nodeSystemdConnection(ctx context.Context) (*systemd.Conn, context.Context, context.CancelFunc, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	if os.Geteuid() != 0 {
		cancel()
		return nil, bounded, cancel, nodecommand.ErrPrecondition
	}
	connection, err := systemd.NewSystemdConnectionContext(bounded)
	if err != nil {
		cancel()
		return nil, bounded, cancel, errors.Join(nodecommand.ErrUnavailable, err)
	}
	return connection, bounded, cancel, nil
}

func (localNodeSupervisor) Preflight(ctx context.Context, minimum uint64) error {
	connection, _, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	defer connection.Close()
	encoded, err := connection.GetManagerProperty("Version")
	value, decodeErr := strconv.Unquote(encoded)
	if err != nil || decodeErr != nil {
		return nodecommand.ErrUnavailable
	}
	major := strings.FieldsFunc(value, func(r rune) bool { return r < '0' || r > '9' })
	if len(major) == 0 {
		return nodecommand.ErrPrecondition
	}
	version, err := strconv.ParseUint(major[0], 10, 32)
	if err != nil || version < minimum {
		return nodecommand.ErrPrecondition
	}
	return nil
}

func (localNodeSupervisor) InspectStartup(ctx context.Context, startup nativeStartup) (bool, error) {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	defer connection.Close()
	return inspectNativeStartup(bounded, connection, startup)
}

func (localNodeSupervisor) RegisterStartup(ctx context.Context, startup nativeStartup) error {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	defer connection.Close()
	registered, err := inspectNativeStartup(bounded, connection, startup)
	if err != nil || registered {
		return err
	}
	if _, err := os.Lstat(startup.unitFile); err != nil {
		return nodecommand.ErrVerification
	}
	// No force/overwrite and no generic enable operation that may follow
	// operator-created aliases. An interrupted pair is completed on replay.
	for _, path := range nativeStartupLinks(startup) {
		if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
		if err := verifyNativeRegistrationDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Symlink(startup.unitFile, path); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
		if linked, err := verifyNativeStartupLink(path, startup.unitFile); err != nil || !linked {
			return nodecommand.ErrConflict
		}
		if err := syncManagedDirectory(filepath.Dir(path)); err != nil {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
	}
	// Restoring only a missing enablement link need not reload already loaded
	// definitions. A first registration or interrupted load still reconciles.
	registered, err = inspectNativeStartup(bounded, connection, startup)
	if err != nil || registered {
		return err
	}
	if err := connection.ReloadContext(bounded); err != nil {
		return errors.Join(nodecommand.ErrOutcomeUnknown, err)
	}
	registered, err = inspectNativeStartup(bounded, connection, startup)
	if err != nil {
		return err
	}
	if !registered {
		return nodecommand.ErrOutcomeUnknown
	}
	return nil
}

func (localNodeSupervisor) UnregisterStartup(ctx context.Context, startup nativeStartup) error {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return errors.Join(nodecommand.ErrOutcomeUnknown, err)
	}
	defer cancel()
	defer connection.Close()
	if _, err := inspectNativeStartup(bounded, connection, startup); err != nil {
		return err
	}
	changed := false
	links := nativeStartupLinks(startup)
	for index := len(links) - 1; index >= 0; index-- {
		linked, err := verifyNativeStartupLink(links[index], startup.unitFile)
		if err != nil {
			return err
		}
		if !linked {
			continue
		}
		if err := os.Remove(links[index]); err != nil {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
		if err := syncManagedDirectory(filepath.Dir(links[index])); err != nil {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
		changed = true
	}
	if changed {
		if err := connection.ReloadContext(bounded); err != nil {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
	}
	// Do not stop the bootstrap unit: this may be its own rollback invocation.
	// Source, release, credentials and receipts remain available for recovery.
	return nil
}

func nativeStartupLinks(startup nativeStartup) [2]string {
	return [2]string{filepath.Join("/etc/systemd/system", startup.service.name),
		filepath.Join("/etc/systemd/system/multi-user.target.wants", startup.service.name)}
}

func verifyNativeRegistrationDirectory(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && current == path {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return nodecommand.ErrConflict
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nodecommand.ErrConflict
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func verifyNativeStartupLink(path, destination string) (bool, error) {
	if err := verifyNativeRegistrationDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false, nodecommand.ErrConflict
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	target, err := os.Readlink(path)
	if !ok || stat.Uid != 0 || err != nil || target != destination {
		return false, nodecommand.ErrConflict
	}
	return true, nil
}

func inspectNativeStartup(ctx context.Context, connection *systemd.Conn, startup nativeStartup) (bool, error) {
	relative, err := filepath.Rel(startup.root, startup.unitFile)
	if err != nil {
		return false, nodecommand.ErrConflict
	}
	exists, err := managedFileExists(startup.root, relative)
	if err != nil {
		return false, nodecommand.ErrConflict
	}
	if exists {
		expected := nativeStartupUnit(startup)
		actual, err := readManagedFile(startup.root, relative, int64(len(expected)))
		if err != nil || !bytes.Equal(actual, expected) {
			return false, nodecommand.ErrConflict
		}
	}
	links := nativeStartupLinks(startup)
	linked := 0
	for _, path := range links {
		present, err := verifyNativeStartupLink(path, startup.unitFile)
		if err != nil || (present && !exists) {
			return false, nodecommand.ErrConflict
		}
		if present {
			linked++
		}
	}
	// Inspect the manager's real search paths before reloading. A pending
	// mask, drop-in, generated unit or dependency must not become ours simply
	// because the currently loaded unit still looks correct.
	encoded, err := connection.GetManagerProperty("UnitPath")
	if err != nil {
		return false, nodecommand.ErrUnavailable
	}
	variant, err := dbus.ParseVariant(encoded, dbus.SignatureOf([]string{}))
	if err != nil {
		return false, nodecommand.ErrUnavailable
	}
	var searchPaths []string
	if dbus.Store([]any{variant.Value()}, &searchPaths) != nil || len(searchPaths) == 0 || len(searchPaths) > 64 {
		return false, nodecommand.ErrPrecondition
	}
	dropins := []string{"service.d", startup.service.name + ".d"}
	for prefix := strings.TrimSuffix(startup.service.name, ".service"); strings.Contains(prefix, "-"); {
		index := strings.LastIndex(prefix, "-")
		dropins = append(dropins, prefix[:index+1]+".service.d")
		prefix = prefix[:index]
	}
	for _, directory := range searchPaths {
		if !filepath.IsAbs(directory) {
			return false, nodecommand.ErrPrecondition
		}
		path := filepath.Join(directory, startup.service.name)
		if path != links[0] {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return false, nodecommand.ErrConflict
			}
		}
		for _, suffix := range append(slices.Clone(dropins), startup.service.name+".wants", startup.service.name+".requires") {
			entries, err := os.ReadDir(filepath.Join(directory, suffix))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, nodecommand.ErrConflict
			}
			for _, entry := range entries {
				if !strings.HasSuffix(suffix, ".d") || strings.HasSuffix(entry.Name(), ".conf") {
					return false, nodecommand.ErrConflict
				}
			}
		}
	}
	properties, err := connection.GetAllPropertiesContext(ctx, startup.service.name)
	if nativeUnitMissing(err) || (err == nil && properties["LoadState"] == "not-found") {
		return false, nil
	}
	if err != nil {
		return false, errors.Join(nodecommand.ErrUnavailable, err)
	}
	// systemd reports the registered unit-file path, not the symlink's target.
	// Both that exact link and its protected source were authenticated above.
	if properties["FragmentPath"] != links[0] || verifyNativeServiceProperties(properties, startup.service, false) != nil {
		return false, nodecommand.ErrConflict
	}
	var names []string
	if dbus.Store([]any{properties["Names"]}, &names) != nil || !slices.Equal(names, []string{startup.service.name}) {
		return false, nodecommand.ErrConflict
	}
	return linked == len(links) && properties["NeedDaemonReload"] == false && properties["UnitFileState"] == "enabled", nil
}

func (localNodeSupervisor) Inspect(ctx context.Context, service nativeService) (nativeState, error) {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	defer connection.Close()
	return inspectNativeService(bounded, connection, service)
}

func (localNodeSupervisor) Start(ctx context.Context, service nativeService) error {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	defer connection.Close()
	state, err := inspectNativeService(bounded, connection, service)
	if err != nil {
		return err
	}
	if state == nativeRunning {
		return nil
	}
	if state == nativeChanging {
		return awaitNativeService(bounded, connection, service, true)
	}
	// systemd may chown and later remove a RuntimeDirectory. A stopped or
	// missing unit cannot claim a pre-existing directory merely by name.
	for _, directory := range service.runtimeDirectories {
		if _, err := os.Lstat(filepath.Join("/run", directory)); err == nil {
			return nodecommand.ErrConflict
		} else if !errors.Is(err, os.ErrNotExist) {
			return nodecommand.ErrUnavailable
		}
	}
	completed := make(chan string, 1)
	if state == nativeMissing {
		if service.collector {
			// DynamicUser must not silently reuse an existing static account.
			if _, err := user.Lookup(service.user); err == nil {
				return nodecommand.ErrConflict
			} else {
				var unknown user.UnknownUserError
				if !errors.As(err, &unknown) {
					return nodecommand.ErrUnavailable
				}
			}
			if _, err := user.LookupGroup(service.user); err == nil {
				return nodecommand.ErrConflict
			} else {
				var unknown user.UnknownGroupError
				if !errors.As(err, &unknown) {
					return nodecommand.ErrUnavailable
				}
			}
		}
		_, err = connection.StartTransientUnitContext(bounded, service.name, "fail", nativeServiceProperties(service), completed)
	} else {
		if err := connection.ResetFailedUnitContext(bounded, service.name); err != nil {
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
		_, err = connection.StartUnitContext(bounded, service.name, "fail", completed)
	}
	if err != nil {
		// A reply can be lost after systemd accepted the job. Never discard the
		// journal intent or replace a conflicting unit on an ambiguous result.
		if actual, inspectErr := inspectNativeService(bounded, connection, service); inspectErr == nil && actual == nativeRunning {
			return nil
		}
		return errors.Join(nodecommand.ErrOutcomeUnknown, err)
	}
	select {
	case <-bounded.Done():
		return nodecommand.ErrOutcomeUnknown
	case result := <-completed:
		if result != "done" {
			return nodecommand.ErrVerification
		}
	}
	return awaitNativeService(bounded, connection, service, true)
}

func (localNodeSupervisor) Stop(ctx context.Context, service nativeService) error {
	connection, bounded, cancel, err := nodeSystemdConnection(ctx)
	if err != nil {
		return errors.Join(nodecommand.ErrOutcomeUnknown, err)
	}
	defer cancel()
	defer connection.Close()
	state, err := inspectNativeService(bounded, connection, service)
	if err != nil {
		return err
	}
	if state == nativeMissing {
		return nil
	}
	completed := make(chan string, 1)
	_, err = connection.StopUnitContext(bounded, service.name, "fail", completed)
	if err != nil {
		return errors.Join(nodecommand.ErrOutcomeUnknown, err)
	}
	select {
	case <-bounded.Done():
		return nodecommand.ErrOutcomeUnknown
	case result := <-completed:
		if result != "done" {
			return nodecommand.ErrOutcomeUnknown
		}
	}
	if err := awaitNativeService(bounded, connection, service, false); err != nil {
		return err
	}
	// Reset only this already-authenticated failed transient unit so it can be
	// garbage-collected; never reset global systemd state.
	if err := connection.ResetFailedUnitContext(bounded, service.name); err != nil && !nativeUnitMissing(err) {
		return nodecommand.ErrOutcomeUnknown
	}
	return nil
}

func awaitNativeService(ctx context.Context, connection *systemd.Conn, service nativeService, running bool) error {
	for {
		state, err := inspectNativeService(ctx, connection, service)
		if err != nil {
			return err
		}
		if running && state == nativeRunning {
			return nil
		}
		if !running && (state == nativeMissing || state == nativeStopped) {
			return nil
		}
		if running && state == nativeStopped {
			return nodecommand.ErrVerification
		}
		select {
		case <-ctx.Done():
			return nodecommand.ErrOutcomeUnknown
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func nativeUnitMissing(err error) bool {
	var pointer *dbus.Error
	if errors.As(err, &pointer) {
		return pointer.Name == "org.freedesktop.systemd1.NoSuchUnit" || pointer.Name == "org.freedesktop.DBus.Error.UnknownObject"
	}
	var value dbus.Error
	return errors.As(err, &value) && (value.Name == "org.freedesktop.systemd1.NoSuchUnit" || value.Name == "org.freedesktop.DBus.Error.UnknownObject")
}

func inspectNativeService(ctx context.Context, connection *systemd.Conn, service nativeService) (nativeState, error) {
	properties, err := connection.GetAllPropertiesContext(ctx, service.name)
	if nativeUnitMissing(err) {
		return nativeMissing, nil
	}
	if err != nil {
		return "", errors.Join(nodecommand.ErrUnavailable, err)
	}
	if properties["LoadState"] == "not-found" {
		return nativeMissing, nil
	}
	if err := verifyNativeServiceProperties(properties, service, true); err != nil {
		return "", err
	}
	switch properties["ActiveState"] {
	case "active":
		pid, ok := properties["MainPID"].(uint32)
		if !ok || pid == 0 {
			return nativeChanging, nil
		}
		info, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10))
		if err != nil {
			return nativeChanging, nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (service.collector && stat.Uid == 0) || (!service.collector && stat.Uid != 0) {
			return "", nodecommand.ErrConflict
		}
		return nativeRunning, nil
	case "inactive", "failed":
		return nativeStopped, nil
	case "activating", "deactivating", "reloading":
		return nativeChanging, nil
	default:
		return "", nodecommand.ErrConflict
	}
}

func nativeServiceProperties(service nativeService) []systemd.Property {
	policy := service.policy
	properties := []systemd.Property{
		systemd.PropDescription(service.description), systemd.PropType(policy.Type),
		systemd.PropExecStart(append([]string{service.executable}, service.arguments...), false),
	}
	for _, property := range []struct {
		name  string
		value any
	}{
		{"User", service.user}, {"Group", service.user}, {"DynamicUser", policy.DynamicUser},
		{"Slice", "system.slice"}, {"WorkingDirectory", "/"},
		{"Environment", service.environment}, {"LoadCredential", service.credentials},
		{"BindReadOnlyPaths", service.binds}, {"ReadWritePaths", service.writePaths},
		{"RuntimeDirectory", service.runtimeDirectories}, {"RuntimeDirectoryMode", policy.RuntimeDirectoryMode},
		{"RuntimeDirectoryPreserve", policy.RuntimeDirectoryPreserve},
		{"Restart", policy.Restart}, {"RestartUSec", policy.RestartMicros},
		{"RemainAfterExit", policy.RemainAfterExit},
		{"TimeoutStartUSec", policy.TimeoutStartMicros}, {"TimeoutStopUSec", policy.TimeoutStopMicros},
		{"MemoryMax", policy.MemoryMax}, {"TasksMax", policy.TasksMax}, {"CPUQuotaPerSecUSec", policy.CPUQuotaPerSecond},
		{"NoNewPrivileges", policy.NoNewPrivileges}, {"ProtectSystem", policy.ProtectSystem}, {"ProtectHome", policy.ProtectHome},
		{"PrivateDevices", policy.PrivateDevices}, {"PrivateTmp", true},
		{"ProtectKernelTunables", true}, {"ProtectKernelModules", true}, {"ProtectControlGroups", true},
		{"RestrictSUIDSGID", true}, {"LockPersonality", true}, {"RestrictRealtime", true},
		{"CapabilityBoundingSet", uint64(0)}, {"AmbientCapabilities", uint64(0)},
		{"UMask", uint32(0o077)}, {"StandardOutput", "null"}, {"StandardError", "null"}, {"KillMode", "control-group"},
	} {
		properties = append(properties, systemd.Property{Name: property.name, Value: dbus.MakeVariant(property.value)})
	}
	if service.collector {
		properties = append(properties, systemd.Property{Name: "InaccessiblePaths", Value: dbus.MakeVariant([]string{"-/run/docker.sock", "-/run/containerd"})})
	}
	return properties
}

type nativeExec struct {
	Path           string
	Arguments      []string
	IgnoreFailure  bool
	StartRealtime  uint64
	StartMonotonic uint64
	ExitRealtime   uint64
	ExitMonotonic  uint64
	PID            uint32
	Code           int32
	Status         int32
}

// Check the effective service, not just its convenient name/description. A
// same-name unit with extra hooks, credentials, environment files or writable
// mounts cannot become an owned unit that Matrix may start or stop.
func verifyNativeServiceProperties(actual map[string]any, service nativeService, transient bool) error {
	if actual["LoadState"] != "loaded" || actual["Transient"] != transient {
		return nodecommand.ErrConflict
	}
	for _, property := range nativeServiceProperties(service) {
		value, exists := actual[property.Name]
		if !exists {
			return nodecommand.ErrConflict
		}
		switch property.Name {
		case "ExecStart":
			var commands []nativeExec
			if dbus.Store([]any{value}, &commands) != nil || len(commands) != 1 || commands[0].Path != service.executable || commands[0].IgnoreFailure ||
				!slices.Equal(commands[0].Arguments, append([]string{service.executable}, service.arguments...)) {
				return nodecommand.ErrConflict
			}
		case "LoadCredential":
			var credentials []nativeCredential
			if dbus.Store([]any{value}, &credentials) != nil || len(credentials) != len(service.credentials) {
				return nodecommand.ErrConflict
			}
			for _, expected := range service.credentials {
				if !slices.Contains(credentials, expected) {
					return nodecommand.ErrConflict
				}
			}
		case "BindReadOnlyPaths":
			var binds []nativeBind
			if dbus.Store([]any{value}, &binds) != nil || len(binds) != len(service.binds) {
				return nodecommand.ErrConflict
			}
			for _, expected := range service.binds {
				if !slices.Contains(binds, expected) {
					return nodecommand.ErrConflict
				}
			}
		case "Environment", "ReadWritePaths", "InaccessiblePaths", "RuntimeDirectory":
			var values []string
			if dbus.Store([]any{value}, &values) != nil {
				return nodecommand.ErrConflict
			}
			expected := property.Value.Value().([]string)
			if len(values) != len(expected) {
				return nodecommand.ErrConflict
			}
			for _, item := range expected {
				if !slices.Contains(values, item) {
					return nodecommand.ErrConflict
				}
			}
		default:
			if !reflect.DeepEqual(value, property.Value.Value()) {
				return nodecommand.ErrConflict
			}
		}
	}
	empty := []string{"ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition",
		"EnvironmentFiles", "SupplementaryGroups", "BindPaths", "TemporaryFileSystem", "SetCredential"}
	if !transient {
		empty = append(empty, "DropInPaths")
	}
	for _, name := range empty {
		value, exists := actual[name]
		if !exists {
			return nodecommand.ErrConflict
		}
		sequence := reflect.ValueOf(value)
		if sequence.Kind() != reflect.Slice || sequence.Len() != 0 {
			return nodecommand.ErrConflict
		}
	}
	// These credential sources were added after the minimum supported systemd.
	// If implemented by this host, none may introduce unsealed material.
	for _, name := range []string{"ImportCredential", "SetCredentialEncrypted", "LoadCredentialEncrypted"} {
		if value, exists := actual[name]; exists {
			sequence := reflect.ValueOf(value)
			if sequence.Kind() != reflect.Slice || sequence.Len() != 0 {
				return nodecommand.ErrConflict
			}
		}
	}
	if actual["RootDirectory"] != "" || actual["RootImage"] != "" {
		return nodecommand.ErrConflict
	}
	return nil
}
