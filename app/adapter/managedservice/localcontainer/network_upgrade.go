package localcontainer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"time"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

var errNetworkUpgrade = errors.New("local managed-service network upgrade requires operator recovery")

// NetworkUpgrade describes one product's authenticated direct-port predecessor.
// Only trusted product composition supplies these fixed mounts and ingress.
type NetworkUpgrade struct {
	Root                string
	ServiceName         string
	EndpointServiceName string
	OfferingID          string
	TargetPort          int
	Mounts              map[string]string // container target -> protected project file (data is writable)
	Endpoint            func(int, map[string]string) map[string]any
	Runtime             composeadapter.Runtime
}

// UpgradeNetwork runs during exclusive worker startup before any work is claimed.
// Running products are recreated in place; stopped products stay stopped. Data,
// credentials and published endpoint identity are never discarded on failure.
func UpgradeNetwork(ctx context.Context, config NetworkUpgrade) error {
	if ctx == nil || config.Runtime == nil || config.Endpoint == nil ||
		!serviceNamePattern.MatchString(config.ServiceName) || !serviceNamePattern.MatchString(config.EndpointServiceName) ||
		config.ServiceName == config.EndpointServiceName || managedservicev1.ValidateID("offeringId", config.OfferingID) != nil ||
		config.TargetPort < 1 || config.TargetPort > 65535 || len(config.Mounts) < 2 || len(config.Mounts) > 5 ||
		!filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || filepath.Dir(config.Root) == config.Root {
		return errNetworkUpgrade
	}
	dataMounts := 0
	for target, file := range config.Mounts {
		if target == "" || target[0] != '/' || !fileNamePattern.MatchString(file) {
			return errNetworkUpgrade
		}
		if file == "data" {
			dataMounts++
		}
	}
	rootInfo, err := os.Lstat(config.Root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || dataMounts != 1 {
		return errNetworkUpgrade
	}
	entries, err := os.ReadDir(config.Root)
	if err != nil || len(entries) > 1000 {
		return errNetworkUpgrade
	}
	for _, entry := range entries {
		if !entry.IsDir() || !regexp.MustCompile(`^matrix-[0-9a-f]{24}$`).MatchString(entry.Name()) {
			return errNetworkUpgrade
		}
		directory := filepath.Join(config.Root, entry.Name())
		info, err := os.Lstat(directory)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (os.PathSeparator == '/' && info.Mode().Perm() != 0o700) {
			return errNetworkUpgrade
		}
		project := composeadapter.RuntimeProject{Name: entry.Name(), Directory: directory,
			EffectDocument: filepath.Join(directory, "compose.json"), ObservationDocument: filepath.Join(directory, "observe.json"), TimeoutSeconds: 120}
		if _, err := os.Lstat(project.EffectDocument); errors.Is(err, os.ErrNotExist) {
			// A new provisioning attempt may have crashed before writing a
			// document. The authoritative queue still owns that attempt.
			continue
		}
		step, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = upgradeProjectNetwork(step, project, config)
		cancel()
		if err != nil {
			return errNetworkUpgrade
		}
	}
	return nil
}

func upgradeProjectNetwork(ctx context.Context, project composeadapter.RuntimeProject, config NetworkUpgrade) error {
	var document map[string]json.RawMessage
	content, err := readNetworkUpgradeFile(project.EffectDocument)
	if err != nil || json.Unmarshal(content, &document) != nil {
		return errNetworkUpgrade
	}
	var name string
	var services map[string]map[string]json.RawMessage
	if json.Unmarshal(document["name"], &name) != nil || name != project.Name ||
		json.Unmarshal(document["services"], &services) != nil || len(services) < 1 || len(services) > 2 || services[config.ServiceName] == nil {
		return errNetworkUpgrade
	}
	if len(services) == 2 && services[config.EndpointServiceName] == nil {
		return errNetworkUpgrade
	}
	backend := services[config.ServiceName]
	var labels map[string]string
	var mounts []struct {
		Type, Source, Target string
		ReadOnly             bool `json:"read_only"`
	}
	if json.Unmarshal(backend["labels"], &labels) != nil || labels["com.xiak.matrix.managed"] != "true" ||
		labels["com.xiak.matrix.managedservice.offering"] != config.OfferingID ||
		labels["com.xiak.matrix.managedservice.region"] != "local-primary" ||
		managedservicev1.ValidateID("installationId", labels["com.xiak.matrix.managedservice.installation"]) != nil ||
		json.Unmarshal(backend["volumes"], &mounts) != nil || len(mounts) != len(config.Mounts) {
		return errNetworkUpgrade
	}
	wantMounts := make(map[string]string, len(config.Mounts))
	for target, file := range config.Mounts {
		wantMounts[target] = file
	}
	for _, mount := range mounts {
		file, found := wantMounts[mount.Target]
		if !found || mount.Type != "bind" || mount.Source != filepath.Join(project.Directory, file) || (mount.ReadOnly != (file != "data")) {
			return errNetworkUpgrade
		}
		info, err := os.Lstat(mount.Source)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errNetworkUpgrade
		}
		delete(wantMounts, mount.Target)
	}
	portBytes, err := readNetworkUpgradeFile(filepath.Join(project.Directory, "published-port"))
	if err != nil {
		return errNetworkUpgrade
	}
	port, err := strconv.Atoi(string(portBytes))
	if err != nil || port < 20000 || port > 39999 {
		return errNetworkUpgrade
	}
	var oldPorts []string
	if raw, exists := backend["ports"]; exists {
		if json.Unmarshal(raw, &oldPorts) != nil || !reflect.DeepEqual(oldPorts, []string{fmt.Sprintf("127.0.0.1:%d:%d/tcp", port, config.TargetPort)}) {
			return errNetworkUpgrade
		}
	}
	// Observe using a validated document, including recovery after a crash
	// between the two atomic document replacements below.
	observation, err := readNetworkUpgradeFile(project.ObservationDocument)
	var observedDocument map[string]json.RawMessage
	var observedName string
	if err != nil || json.Unmarshal(observation, &observedDocument) != nil || json.Unmarshal(observedDocument["name"], &observedName) != nil || observedName != name {
		return errNetworkUpgrade
	}
	containers, err := config.Runtime.Observe(ctx, project)
	if err != nil {
		return errNetworkUpgrade
	}
	seen := map[string]bool{}
	running, directRuntime := false, false
	for _, container := range containers {
		if seen[container.Service] || container.OneOff || container.Project != project.Name ||
			(container.Service != config.ServiceName && container.Service != config.EndpointServiceName) {
			return errNetworkUpgrade
		}
		for _, key := range []string{"com.xiak.matrix.managed", "com.xiak.matrix.managedservice.installation", "com.xiak.matrix.managedservice.offering", "com.xiak.matrix.managedservice.region"} {
			if container.Labels[key] != labels[key] {
				return errNetworkUpgrade
			}
		}
		seen[container.Service] = true
		running = running || container.State == "running" || container.State == "restarting"
		directRuntime = directRuntime || (container.Service == config.ServiceName && container.PublishedPorts != 0)
	}
	ready := len(containers) == 2 && seen[config.ServiceName] && seen[config.EndpointServiceName]
	for _, container := range containers {
		wantPorts := uint32(0)
		if container.Service == config.EndpointServiceName {
			wantPorts = 1
		}
		ready = ready && container.State == "running" && container.Health == "healthy" && container.PublishedPorts == wantPorts
	}
	if len(services) == 2 && len(oldPorts) == 0 && !directRuntime && (!running || ready) {
		return nil
	}
	delete(backend, "ports")
	backend["networks"], _ = json.Marshal([]string{"private"})
	endpointLabels := map[string]string{}
	for _, key := range []string{"com.xiak.matrix.managed", "com.xiak.matrix.managedservice.installation", "com.xiak.matrix.managedservice.offering", "com.xiak.matrix.managedservice.region"} {
		endpointLabels[key] = labels[key]
	}
	encodedEndpoint, _ := json.Marshal(config.Endpoint(port, endpointLabels))
	var endpoint map[string]json.RawMessage
	_ = json.Unmarshal(encodedEndpoint, &endpoint)
	services[config.EndpointServiceName] = endpoint
	document["services"], _ = json.Marshal(services)
	document["networks"], _ = json.Marshal(PrivateNetworks())
	updated, err := json.Marshal(document)
	if err != nil {
		return errNetworkUpgrade
	}
	for _, file := range []string{project.EffectDocument, project.ObservationDocument} {
		if err := replaceNetworkUpgradeFile(file, updated); err != nil {
			return errNetworkUpgrade
		}
	}
	if running {
		if err := config.Runtime.Apply(ctx, project); err != nil {
			return errNetworkUpgrade
		}
		current, err := config.Runtime.Observe(ctx, project)
		if err != nil || len(current) != 2 {
			return errNetworkUpgrade
		}
		seen = map[string]bool{}
		for _, container := range current {
			if seen[container.Service] || container.OneOff || container.Project != project.Name ||
				(container.Service != config.ServiceName && container.Service != config.EndpointServiceName) {
				return errNetworkUpgrade
			}
			for key, value := range endpointLabels {
				if container.Labels[key] != value {
					return errNetworkUpgrade
				}
			}
			seen[container.Service] = true
			wantPorts := uint32(0)
			if container.Service == config.EndpointServiceName {
				wantPorts = 1
			}
			if container.State != "running" || container.Health != "healthy" || container.PublishedPorts != wantPorts {
				return errNetworkUpgrade
			}
		}
	} else if len(containers) > 0 {
		if err := config.Runtime.Stop(ctx, project); err != nil {
			return errNetworkUpgrade
		}
		remaining, err := config.Runtime.Observe(ctx, project)
		if err != nil || len(remaining) != 0 {
			return errNetworkUpgrade
		}
	}
	return nil
}

func readNetworkUpgradeFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 65536 ||
		(os.PathSeparator == '/' && info.Mode().Perm() != 0o600) {
		return nil, errNetworkUpgrade
	}
	return os.ReadFile(path)
}

func replaceNetworkUpgradeFile(path string, content []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".matrix-network-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
