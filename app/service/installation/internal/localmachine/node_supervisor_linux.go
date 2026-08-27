//go:build linux

package localmachine

import (
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
// remote address, shell, unit-file directory, or daemon reload.
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
	if err := verifyNativeServiceProperties(properties, service); err != nil {
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
		systemd.PropDescription(service.description), systemd.PropType("exec"),
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
		{"TimeoutStartUSec", uint64(30000000)}, {"TimeoutStopUSec", policy.TimeoutStopMicros},
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
func verifyNativeServiceProperties(actual map[string]any, service nativeService) error {
	if actual["LoadState"] != "loaded" || actual["Transient"] != true {
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
	for _, name := range []string{"ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
		"EnvironmentFiles", "SupplementaryGroups", "BindPaths", "TemporaryFileSystem", "SetCredential"} {
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
