package localmysql

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

var errNetworkUpgrade = errors.New("local MySQL network upgrade requires operator recovery")

// UpgradeNetwork runs once during exclusive local-worker startup, before it
// claims work. It migrates the protected deployment documents of installed
// releases; it is not a tenant API or a readiness probe. Running instances are
// recreated in place. Stopped instances stay stopped: obsolete containers and
// networks are removed, while the new documents, data and credentials remain.
// Failure never triggers data purge or an unsafe direct-port fallback.
func (provisioner *Provisioner) UpgradeNetwork(ctx context.Context) error {
	if provisioner == nil || ctx == nil || provisioner.runtime == nil {
		return errNetworkUpgrade
	}
	entries, err := os.ReadDir(provisioner.root)
	if err != nil || len(entries) > 1000 {
		return errNetworkUpgrade
	}
	for _, entry := range entries {
		if !entry.IsDir() || !regexp.MustCompile(`^matrix-[0-9a-f]{24}$`).MatchString(entry.Name()) {
			return errNetworkUpgrade
		}
		directory := filepath.Join(provisioner.root, entry.Name())
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
		err = provisioner.upgradeProjectNetwork(step, project)
		cancel()
		if err != nil {
			return errNetworkUpgrade
		}
	}
	return nil
}

func (provisioner *Provisioner) upgradeProjectNetwork(ctx context.Context, project composeadapter.RuntimeProject) error {
	var document map[string]json.RawMessage
	content, err := readNetworkUpgradeFile(project.EffectDocument)
	if err != nil || json.Unmarshal(content, &document) != nil {
		return errNetworkUpgrade
	}
	var name string
	var services map[string]map[string]json.RawMessage
	if json.Unmarshal(document["name"], &name) != nil || name != project.Name ||
		json.Unmarshal(document["services"], &services) != nil || len(services) < 1 || len(services) > 2 || services[mysqlServiceName] == nil {
		return errNetworkUpgrade
	}
	if len(services) == 2 && services[endpointServiceName] == nil {
		return errNetworkUpgrade
	}
	backend := services[mysqlServiceName]
	var labels map[string]string
	var mounts []struct {
		Type, Source, Target string
		ReadOnly             bool `json:"read_only"`
	}
	if json.Unmarshal(backend["labels"], &labels) != nil || labels["com.xiak.matrix.managed"] != "true" ||
		labels["com.xiak.matrix.managedservice.offering"] != managedservicev1.MySQLOfferingID ||
		labels["com.xiak.matrix.managedservice.region"] != "local-primary" ||
		managedservicev1.ValidateID("installationId", labels["com.xiak.matrix.managedservice.installation"]) != nil ||
		json.Unmarshal(backend["volumes"], &mounts) != nil || len(mounts) != 3 {
		return errNetworkUpgrade
	}
	wantMounts := map[string]string{"/var/lib/mysql": "data", "/run/secrets/mysql-password": "mysql-password", "/run/secrets/mysql-root-password": "mysql-root-password"}
	for _, mount := range mounts {
		file, found := wantMounts[mount.Target]
		if !found || mount.Type != "bind" || mount.Source != filepath.Join(project.Directory, file) || (file != "data" && !mount.ReadOnly) {
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
		if json.Unmarshal(raw, &oldPorts) != nil || !reflect.DeepEqual(oldPorts, []string{fmt.Sprintf("127.0.0.1:%d:3306/tcp", port)}) {
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
	containers, err := provisioner.runtime.Observe(ctx, project)
	if err != nil {
		return errNetworkUpgrade
	}
	seen := map[string]bool{}
	running, directRuntime := false, false
	for _, container := range containers {
		if seen[container.Service] || container.OneOff || container.Project != project.Name ||
			(container.Service != mysqlServiceName && container.Service != endpointServiceName) {
			return errNetworkUpgrade
		}
		for _, key := range []string{"com.xiak.matrix.managed", "com.xiak.matrix.managedservice.installation", "com.xiak.matrix.managedservice.offering", "com.xiak.matrix.managedservice.region"} {
			if container.Labels[key] != labels[key] {
				return errNetworkUpgrade
			}
		}
		seen[container.Service] = true
		running = running || container.State == "running" || container.State == "restarting"
		directRuntime = directRuntime || (container.Service == mysqlServiceName && container.PublishedPorts != 0)
	}
	ready := len(containers) == 2 && seen[mysqlServiceName] && seen[endpointServiceName]
	for _, container := range containers {
		wantPorts := uint32(0)
		if container.Service == endpointServiceName {
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
	encodedEndpoint, _ := json.Marshal(endpointService(provisioner.endpointImageID, port, endpointLabels))
	var endpoint map[string]json.RawMessage
	_ = json.Unmarshal(encodedEndpoint, &endpoint)
	services[endpointServiceName] = endpoint
	document["services"], _ = json.Marshal(services)
	document["networks"], _ = json.Marshal(privateNetworks())
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
		if err := provisioner.runtime.Apply(ctx, project); err != nil {
			return errNetworkUpgrade
		}
		current, err := provisioner.runtime.Observe(ctx, project)
		if err != nil || len(current) != 2 {
			return errNetworkUpgrade
		}
		seen = map[string]bool{}
		for _, container := range current {
			if seen[container.Service] || container.OneOff || container.Project != project.Name ||
				(container.Service != mysqlServiceName && container.Service != endpointServiceName) {
				return errNetworkUpgrade
			}
			for key, value := range endpointLabels {
				if container.Labels[key] != value {
					return errNetworkUpgrade
				}
			}
			seen[container.Service] = true
			wantPorts := uint32(0)
			if container.Service == endpointServiceName {
				wantPorts = 1
			}
			if container.State != "running" || container.Health != "healthy" || container.PublishedPorts != wantPorts {
				return errNetworkUpgrade
			}
		}
	} else if len(containers) > 0 {
		if err := provisioner.runtime.Stop(ctx, project); err != nil {
			return errNetworkUpgrade
		}
		remaining, err := provisioner.runtime.Observe(ctx, project)
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
	file, err := os.CreateTemp(filepath.Dir(path), ".mysql-network-")
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
