package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

// NodeVerifier is the narrow TLS composition port. Only cmd/mx constructs the
// concrete node adapter; native effects never import another adapter package.
type NodeVerifier interface {
	Validate(nodeconfig.Configuration, nodecommand.Credentials) error
	ValidateRotation(nodeconfig.Configuration, nodecommand.Credentials, nodecommand.Credentials, bool) error
	Verify(context.Context, nodeconfig.Configuration, nodecommand.Credentials) error
}

type NodeEffects struct {
	supervisor nodeSupervisor
	docker     dockerRuntime
	verifier   NodeVerifier
}

func NewNodeEffects(verifier NodeVerifier) *NodeEffects {
	return &NodeEffects{supervisor: localNodeSupervisor{}, docker: localDockerRuntime{}, verifier: verifier}
}

func (effects *NodeEffects) ValidateEnrollment(plan nodecommand.Plan) error {
	if effects == nil || effects.verifier == nil || nodecommand.ValidatePlan(plan) != nil {
		return nodecommand.ErrVerification
	}
	if runtime.GOOS == "linux" && nodeconfig.ValidateNativeRoot(plan.Root) != nil {
		return nodecommand.ErrPrecondition
	}
	if plan.Previous != nil {
		return effects.verifier.ValidateRotation(plan.Configuration, plan.Previous.Credentials, plan.Credentials, plan.RevokePreviousCredentials)
	}
	return effects.verifier.Validate(plan.Configuration, plan.Credentials)
}

func (effects *NodeEffects) ReadInstallation(root string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	return readNodeCredentials(root)
}

func (effects *NodeEffects) ReadRotation(root, digest string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	if paasv1.ValidateDigest("configurationDigest", digest) != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
	}
	config, err := readNodeConfiguration(root)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, err
	}
	source, err := readManagedFile(root, filepath.FromSlash(layout.NodeCredentialSnapshot(digest)), 1024*1024)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
	}
	defer clear(source)
	material, err := decodeNodeCredentials(source)
	binding, bindingErr := nodecommand.Binding(config, material)
	if err != nil || bindingErr != nil || binding.ConfigurationDigest != digest {
		material.Clear()
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
	}
	return config, material, nil
}

func readNodeConfiguration(root string) (nodeconfig.Configuration, error) {
	source, err := readManagedFile(root, filepath.FromSlash(layout.NodeConfiguration), nodeconfig.MaximumBytes)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.ErrVerification
	}
	defer clear(source)
	config, err := nodeconfig.DecodeConfiguration(source)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.ErrVerification
	}
	return config, nil
}

func readNodeCredentials(root string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	config, err := readNodeConfiguration(root)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, err
	}
	var material nodecommand.Credentials
	for _, file := range []struct {
		name    string
		maximum int64
		target  *[]byte
	}{
		{layout.NodeCertificate, 64 * 1024, &material.Certificate},
		{layout.NodePrivateKey, 64 * 1024, &material.PrivateKey},
		{layout.NodeTrust, 256 * 1024, &material.Trust},
		{layout.CollectorCertificate, 64 * 1024, &material.CollectorCertificate},
		{layout.CollectorPrivateKey, 64 * 1024, &material.CollectorPrivateKey},
	} {
		*file.target, err = readManagedFile(root, filepath.FromSlash(file.name), file.maximum)
		if err != nil {
			material.Clear()
			return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
		}
	}
	return config, material, nil
}

func (effects *NodeEffects) ApplyPhase(ctx context.Context, plan nodecommand.Plan, phase lifecycle.Phase) error {
	if effects == nil || effects.supervisor == nil || effects.docker == nil || effects.verifier == nil || ctx == nil {
		return nodecommand.ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if effects.ValidateEnrollment(plan) != nil {
		return nodecommand.ErrVerification
	}
	if plan.Previous != nil {
		switch phase {
		case lifecycle.PhasePreflight:
			return effects.preflightNodeRotation(ctx, plan)
		case lifecycle.PhaseStaging:
			return stageNodeCredentials(plan)
		case lifecycle.PhaseConfiguring:
			return effects.replaceNodeCredentials(ctx, plan)
		}
	}
	if plan.ReleaseSource != nil {
		switch phase {
		case lifecycle.PhasePreflight:
			if err := authenticateNodeFiles(*plan.ReleaseSource); err != nil {
				return err
			}
			return effects.preflightNodeWithSpace(ctx, *plan.ReleaseSource, 128*1024)
		case lifecycle.PhaseConfiguring, lifecycle.PhaseRollingBack:
			return effects.replaceNodeRelease(ctx, plan)
		}
	}
	switch phase {
	case lifecycle.PhasePreflight:
		return effects.preflightNode(ctx, plan)
	case lifecycle.PhaseStaging:
		if _, err := ensureManagedDirectory(plan.Root, "releases"); err != nil {
			return errors.Join(nodecommand.ErrConflict, err)
		}
		_, err := release.StageDirectory(plan.Bundle, plan.TrustBytes,
			filepath.Join(plan.Root, filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID))))
		if err != nil {
			return errors.Join(nodecommand.ErrVerification, err)
		}
		return nil
	case lifecycle.PhaseConfiguring:
		return configureNode(plan)
	case lifecycle.PhaseStarting:
		if err := authenticateNodeFiles(plan); err != nil {
			return err
		}
		services := nativeNodeServices(plan)
		startup := nativeNodeStartup(plan)
		// Prove every service and the boot registration before any mutation.
		if _, err := effects.supervisor.InspectStartup(ctx, startup); err != nil {
			return err
		}
		for _, service := range services {
			if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
				return err
			}
		}
		if err := effects.supervisor.RegisterStartup(ctx, startup); err != nil {
			return err
		}
		for _, service := range services {
			if err := effects.supervisor.Start(ctx, service); err != nil {
				return err
			}
		}
		return nil
	case lifecycle.PhaseVerifying, lifecycle.PhaseCommitting:
		return effects.verifyNode(ctx, plan)
	default:
		return nodecommand.ErrVerification
	}
}

// StageRelease authenticates the installed source before caching an immutable
// candidate. It must not activate units, credentials or a different boot entry.
func (effects *NodeEffects) StageRelease(ctx context.Context, plan nodecommand.Plan) error {
	if ctx == nil || effects == nil || effects.supervisor == nil || effects.docker == nil {
		return nodecommand.ErrUnavailable
	}
	if plan.ReleaseSource == nil || effects.ValidateEnrollment(plan) != nil {
		return nodecommand.ErrVerification
	}
	if err := authenticateNodeFiles(*plan.ReleaseSource); err != nil {
		return err
	}
	minimum := max(plan.Bundle.Manifest.MinimumFreeBytes, uint64(128*1024))
	destination := filepath.Join(plan.Root, filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)))
	if _, err := os.Lstat(destination); err == nil {
		if _, err := authenticateNodeRelease(plan); err != nil {
			return err
		}
		// A retained predecessor is already on disk. Reserve only bounded
		// journal/boot writes, not another complete release's staging budget.
		minimum = 128 * 1024
	} else if !errors.Is(err, os.ErrNotExist) {
		return nodecommand.ErrConflict
	}
	if err := effects.preflightNodeWithSpace(ctx, *plan.ReleaseSource, minimum); err != nil {
		return err
	}
	registered, err := effects.supervisor.InspectStartup(ctx, nativeNodeStartup(*plan.ReleaseSource))
	if err != nil || !registered {
		if err != nil {
			return err
		}
		return nodecommand.ErrPrecondition
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err := ensureManagedDirectory(plan.Root, "releases"); err != nil {
		return nodecommand.ErrConflict
	}
	if _, err := release.StageDirectory(plan.Bundle, plan.TrustBytes, destination); err != nil {
		if errors.Is(err, release.ErrStageConflict) {
			return nodecommand.ErrConflict
		}
		return nodecommand.ErrVerification
	}
	return ctx.Err()
}

func (effects *NodeEffects) preflightNode(ctx context.Context, plan nodecommand.Plan) error {
	return effects.preflightNodeWithSpace(ctx, plan, plan.Bundle.Manifest.MinimumFreeBytes)
}

func (effects *NodeEffects) preflightNodeWithSpace(ctx context.Context, plan nodecommand.Plan, minimum uint64) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || validateManagedRoot(plan.Root) != nil {
		return nodecommand.ErrPrecondition
	}
	for _, hidden := range []string{"/root", "/home", "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"} {
		if plan.Root == hidden || strings.HasPrefix(plan.Root, hidden+"/") {
			return nodecommand.ErrPrecondition
		}
	}
	if err := effects.supervisor.Preflight(ctx, plan.Bundle.Manifest.Host.MinimumSystemd); err != nil {
		return err
	}
	if _, err := effects.supervisor.InspectStartup(ctx, nativeNodeStartup(plan)); err != nil {
		return err
	}
	available, err := availableFilesystemBytes(plan.Root)
	if err != nil {
		return errors.Join(nodecommand.ErrUnavailable, err)
	}
	if available < minimum {
		return nodecommand.ErrPrecondition
	}
	output, _, err := effects.docker.Run(ctx, nil, "version", "--format", "{{json .Server}}")
	if err != nil {
		return errors.Join(nodecommand.ErrUnavailable, err)
	}
	var server dockerServerVersion
	if json.Unmarshal(output, &server) != nil || server.OS != "linux" || server.Architecture != "amd64" ||
		compareProviderVersion(server.Version, plan.Bundle.Manifest.Host.MinimumDocker) < 0 {
		return nodecommand.ErrPrecondition
	}
	output, _, err = effects.docker.Run(ctx, nil, "compose", "version", "--short")
	if err != nil {
		return errors.Join(nodecommand.ErrUnavailable, err)
	}
	if compareProviderVersion(strings.TrimSpace(string(output)), plan.Bundle.Manifest.Host.MinimumCompose) < 0 {
		return nodecommand.ErrPrecondition
	}
	for _, service := range nativeNodeServices(plan) {
		state, err := effects.supervisor.Inspect(ctx, service)
		if err != nil {
			return err
		}
		if state == nativeMissing {
			listener, err := net.Listen("tcp", service.listenAddress)
			if err != nil {
				return nodecommand.ErrConflict
			}
			if listener.Close() != nil {
				return nodecommand.ErrUnavailable
			}
		}
	}
	return nil
}

func (effects *NodeEffects) Observe(ctx context.Context, plan nodecommand.Plan) (bool, error) {
	if effects == nil || effects.supervisor == nil || effects.verifier == nil || ctx == nil {
		return false, nodecommand.ErrUnavailable
	}
	if err := authenticateNodeFiles(plan); err != nil {
		return false, err
	}
	return effects.observeNodeServices(ctx, plan)
}

func (effects *NodeEffects) observeNodeServices(ctx context.Context, plan nodecommand.Plan) (bool, error) {
	registered, err := effects.supervisor.InspectStartup(ctx, nativeNodeStartup(plan))
	if err != nil || !registered {
		return false, err
	}
	for _, service := range nativeNodeServices(plan) {
		state, err := effects.supervisor.Inspect(ctx, service)
		if err != nil {
			return false, err
		}
		if state != nativeRunning {
			return false, nil
		}
	}
	if err := effects.verifier.Verify(ctx, plan.Configuration, plan.Credentials); err != nil {
		return false, nil
	}
	return true, nil
}

func (effects *NodeEffects) verifyNode(ctx context.Context, plan nodecommand.Plan) error {
	if err := authenticateNodeFiles(plan); err != nil {
		return err
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		ready, err := effects.observeNodeServices(deadline, plan)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-deadline.Done():
			return nodecommand.ErrVerification
		case <-time.After(time.Second):
		}
	}
}

// Rollback stops only exact installation-owned native services. It retains
// staged bytes, credentials, receipts and every Docker workload for replay.
func (effects *NodeEffects) Rollback(ctx context.Context, plan nodecommand.Plan) error {
	if plan.Previous != nil {
		return nodecommand.ErrVerification
	}
	if effects == nil || effects.supervisor == nil || ctx == nil {
		return nodecommand.ErrUnavailable
	}
	if plan.ReleaseSource != nil {
		// A failed candidate is not a failed enrollment: restore and verify the
		// authenticated source, retaining the latest credential commitment.
		restored, candidate := *plan.ReleaseSource, plan
		candidate.ReleaseSource = nil
		restored.ReleaseSource = &candidate
		if err := effects.replaceNodeRelease(ctx, restored); err != nil {
			return err
		}
		restored.ReleaseSource = nil
		if err := effects.ApplyPhase(ctx, restored, lifecycle.PhaseStarting); err != nil {
			return err
		}
		return effects.verifyNode(ctx, restored)
	}
	services := nativeNodeServices(plan)
	startup := nativeNodeStartup(plan)
	if _, err := effects.supervisor.InspectStartup(ctx, startup); err != nil {
		return err
	}
	for _, service := range services {
		if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
			if errors.Is(err, nodecommand.ErrConflict) {
				return err
			}
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
	}
	if err := effects.supervisor.UnregisterStartup(ctx, startup); err != nil {
		return err
	}
	for index := len(services) - 1; index >= 0; index-- {
		if err := effects.supervisor.Stop(ctx, services[index]); err != nil {
			return err
		}
	}
	return nil
}

func (effects *NodeEffects) replaceNodeRelease(ctx context.Context, plan nodecommand.Plan) error {
	if plan.ReleaseSource == nil || nodecommand.ValidatePlan(plan) != nil {
		return nodecommand.ErrVerification
	}
	source := *plan.ReleaseSource
	for _, candidate := range []nodecommand.Plan{source, plan} {
		if _, err := authenticateNodeRelease(candidate); err != nil {
			return err
		}
	}
	if err := authenticateNodeFileTransition(source, plan); err != nil {
		return err
	}
	// The shared collector copy may be either authenticated payload after an
	// interrupted transition. Never stop a process to overwrite unknown bytes.
	stopServices := verifyMaterializedCollector(plan) != nil
	if stopServices {
		if err := verifyMaterializedCollector(source); err != nil {
			return err
		}
	}
	before, after := nativeNodeServices(source), nativeNodeServices(plan)
	owned := make([]nativeService, len(after))
	for index, service := range after {
		if service.name != before[index].name {
			return nodecommand.ErrVerification
		}
		_, err := effects.supervisor.Inspect(ctx, service)
		if errors.Is(err, nodecommand.ErrConflict) {
			if _, err = effects.supervisor.Inspect(ctx, before[index]); err != nil {
				return err
			}
			owned[index], stopServices = before[index], true
		} else if err != nil {
			return err
		} else {
			owned[index] = service
		}
	}
	// This first mutation proves the closed old/new disk and loaded boot unit,
	// including links, masks and drop-ins. The registration links never vanish.
	if err := effects.supervisor.ReplaceStartup(ctx, nativeNodeStartup(source), nativeNodeStartup(plan)); err != nil {
		return err
	}
	if stopServices {
		for index := len(owned) - 1; index >= 0; index-- {
			if err := effects.supervisor.Stop(ctx, owned[index]); err != nil {
				return err
			}
		}
	}
	if err := materializeCollector(plan, &source); err != nil {
		return err
	}
	return authenticateNodeFiles(plan)
}

func configureNode(plan nodecommand.Plan) error {
	if _, err := authenticateNodeRelease(plan); err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(plan.Root, filepath.FromSlash(layout.ExecutorRoot)); err != nil {
		return errors.Join(nodecommand.ErrConflict, err)
	}
	if err := materializeCollector(plan, nil); err != nil {
		return err
	}
	files, err := nodeFiles(plan)
	if err != nil {
		return nodecommand.ErrVerification
	}
	for _, file := range files {
		if err := writeManagedOnce(plan.Root, filepath.FromSlash(file.name), file.content); err != nil {
			return errors.Join(nodecommand.ErrConflict, err)
		}
	}
	return authenticateNodeFiles(plan)
}

type nodeFile struct {
	name    string
	content []byte
}

func nodeFiles(plan nodecommand.Plan) ([]nodeFile, error) {
	configuration, err := json.Marshal(plan.Configuration)
	if err != nil {
		return nil, err
	}
	collector := nativeNodeServices(plan)[0]
	startup := nativeNodeStartup(plan)
	credentialRoot := "/run/credentials/" + collector.name
	uri, err := nodev1.NodeURI(plan.Configuration.Identity)
	if err != nil {
		return nil, err
	}
	collectorConfiguration := []byte(fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\n  client_ca_file: %q\n  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans:\n    - %q\n  min_version: TLS13\nhttp_server_config:\n  http2: false\n",
		credentialRoot+"/collector.pem", credentialRoot+"/collector-key.pem", credentialRoot+"/trust.pem", uri))
	return append([]nodeFile{
		{layout.ReleaseTrust, plan.TrustBytes}, {layout.NodeConfiguration, configuration},
		{layout.NodeDockerConfiguration, []byte("{}\n")},
		{filepath.ToSlash(filepath.Join(layout.NodeStartupDirectory, startup.service.name)), nativeStartupUnit(startup)},
		{layout.CollectorConfiguration, collectorConfiguration},
	}, nodeCredentialFiles(plan)...), nil
}

func authenticateNodeRelease(plan nodecommand.Plan) (release.VerifiedBundle, error) {
	if nodecommand.ValidatePlan(plan) != nil {
		return release.VerifiedBundle{}, nodecommand.ErrVerification
	}
	bundle, err := release.VerifyDirectory(filepath.Join(plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID))), plan.TrustBytes)
	if err != nil || bundle.ManifestSHA256 != plan.Bundle.ManifestSHA256 || nodecommand.ValidateRelease(bundle) != nil {
		return release.VerifiedBundle{}, nodecommand.ErrVerification
	}
	return bundle, nil
}

func authenticateNodeFiles(plan nodecommand.Plan) error {
	if _, err := authenticateNodeRelease(plan); err != nil {
		return err
	}
	files, err := nodeFiles(plan)
	if err != nil {
		return nodecommand.ErrVerification
	}
	for _, file := range files {
		actual, err := readManagedFile(plan.Root, filepath.FromSlash(file.name), int64(len(file.content)))
		equal := err == nil && bytes.Equal(actual, file.content)
		clear(actual)
		if !equal {
			return nodecommand.ErrVerification
		}
	}
	return verifyMaterializedCollector(plan)
}

type nativeState string

const (
	nativeMissing  nativeState = "MISSING"
	nativeRunning  nativeState = "RUNNING"
	nativeStopped  nativeState = "STOPPED"
	nativeChanging nativeState = "CHANGING"
)

type nativeCredential struct {
	Name string
	Path string
}
type nativeBind struct {
	Source        string
	Destination   string
	IgnoreMissing bool
	Flags         uint64
}
type nativeService struct {
	name               string
	description        string
	executable         string
	arguments          []string
	environment        []string
	credentials        []nativeCredential
	binds              []nativeBind
	writePaths         []string
	runtimeDirectories []string
	listenAddress      string
	collector          bool
	user               string
	policy             nodeconfig.ServicePolicy
}

type nodeSupervisor interface {
	Preflight(context.Context, uint64) error
	Inspect(context.Context, nativeService) (nativeState, error)
	Start(context.Context, nativeService) error
	Stop(context.Context, nativeService) error
	InspectStartup(context.Context, nativeStartup) (bool, error)
	RegisterStartup(context.Context, nativeStartup) error
	ReplaceStartup(context.Context, nativeStartup, nativeStartup) error
	UnregisterStartup(context.Context, nativeStartup) error
}

type nativeStartup struct {
	root, unitFile string
	service        nativeService
}

func nativeNodeStartup(plan nodecommand.Plan) nativeStartup {
	name, _ := nodeconfig.StartupServiceName(plan.Configuration.Identity)
	node := nativeNodeServices(plan)[1]
	return nativeStartup{root: plan.Root,
		unitFile: filepath.Join(plan.Root, filepath.FromSlash(layout.NodeStartupDirectory), name),
		service: nativeService{
			name: name, description: strings.Replace(node.description, "Matrix node ", "Matrix node startup ", 1),
			executable:  filepath.Join(filepath.Dir(node.executable), "mx"),
			arguments:   []string{"--format", "json", "node", "start", "--root", plan.Root},
			environment: node.environment, user: "root", policy: nodeconfig.StartupPolicy(),
			// Registration changes are limited by the adapter to its two exact
			// links. This also permits rollback of an interrupted initial install.
			writePaths: []string{plan.Root, "/etc/systemd/system"},
		},
	}
}

// This closed boot unit invokes the signed installer, never an unchecked node
// executable. Percent specifiers are escaped and dollar expansion is disabled;
// neither a shell nor operator-supplied unit directives are accepted.
func nativeStartupUnit(startup nativeStartup) []byte {
	service, policy := startup.service, startup.service.policy
	quote := func(value string) string { return strconv.Quote(strings.ReplaceAll(value, "%", "%%")) }
	var unit strings.Builder
	fmt.Fprintf(&unit, "[Unit]\nDescription=%s\nAfter=network-online.target docker.service\nWants=network-online.target\nRequiresMountsFor=%s\n\n[Service]\nType=%s\nRemainAfterExit=%t\n",
		service.description, quote(startup.root), policy.Type, policy.RemainAfterExit)
	unit.WriteString("ExecStart=:")
	for index, value := range append([]string{service.executable}, service.arguments...) {
		if index != 0 {
			unit.WriteByte(' ')
		}
		unit.WriteString(quote(value))
	}
	unit.WriteByte('\n')
	for _, value := range service.environment {
		fmt.Fprintf(&unit, "Environment=%s\n", quote(value))
	}
	for _, path := range service.writePaths {
		fmt.Fprintf(&unit, "ReadWritePaths=%s\n", quote(path))
	}
	fmt.Fprintf(&unit, "User=root\nGroup=root\nDynamicUser=false\nSlice=system.slice\nWorkingDirectory=/\nRestart=%s\nRestartSec=%dus\nTimeoutStartSec=%dus\nTimeoutStopSec=%dus\nMemoryMax=%d\nTasksMax=%d\nCPUQuota=%d%%\nNoNewPrivileges=%t\nProtectSystem=%s\nProtectHome=%s\nPrivateDevices=%t\nRuntimeDirectoryMode=%04o\nRuntimeDirectoryPreserve=%s\n",
		policy.Restart, policy.RestartMicros, policy.TimeoutStartMicros, policy.TimeoutStopMicros,
		policy.MemoryMax, policy.TasksMax, policy.CPUQuotaPerSecond/10000,
		policy.NoNewPrivileges, policy.ProtectSystem, policy.ProtectHome, policy.PrivateDevices,
		policy.RuntimeDirectoryMode, policy.RuntimeDirectoryPreserve)
	unit.WriteString("PrivateTmp=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictRealtime=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nUMask=0077\nStandardOutput=null\nStandardError=null\nKillMode=control-group\n\n[Install]\nWantedBy=multi-user.target\n")
	return []byte(unit.String())
}

func nativeNodeServices(plan nodecommand.Plan) []nativeService {
	// The journal authenticates credential bytes at every lifecycle boundary.
	// Native ownership binds the immutable enrollment and signed release, so a
	// credential change retains the same boot unit and exact service owners.
	configuration, _ := json.Marshal(plan.Configuration)
	ownership := sha256Hex(append(configuration, []byte("\x00"+plan.Bundle.ManifestSHA256)...))
	collectorName, _ := nodeconfig.ServiceName(plan.Configuration.Identity, true)
	nodeName, _ := nodeconfig.ServiceName(plan.Configuration.Identity, false)
	identity := strings.TrimSuffix(strings.TrimPrefix(collectorName, "matrix-collector-"), ".service")
	collectorRuntimeDirectory := "matrix-" + identity
	collectorExecutable := "/run/" + collectorRuntimeDirectory + "/node-exporter"
	collectorAddress, _ := nodeconfig.CollectorListenAddress(plan.Configuration)
	parents := []string{}
	for path := plan.Configuration.StoragePath; ; path = filepath.Dir(path) {
		parents = append(parents, regexp.QuoteMeta(filepath.ToSlash(path)))
		if filepath.Dir(path) == path {
			break
		}
	}
	collector := nativeService{
		name: collectorName, description: "Matrix collector " + ownership, executable: collectorExecutable,
		collector: true, user: "mxn-" + identity[:16], policy: nodeconfig.Policy(true), listenAddress: collectorAddress,
		runtimeDirectories: []string{collectorRuntimeDirectory},
		arguments: []string{"--web.listen-address=" + collectorAddress,
			"--web.config.file=/run/credentials/" + collectorName + "/collector.yaml",
			"--web.disable-exporter-metrics", "--web.max-requests=2", "--collector.disable-defaults",
			"--collector.cpu", "--collector.loadavg", "--collector.meminfo", "--collector.filesystem",
			// Go's end-of-text anchor avoids a dollar that systemd would
			// serialize as environment syntax during a manager reload.
			"--collector.filesystem.mount-points-include=^(" + strings.Join(parents, "|") + ")\\z",
			"--collector.filesystem.fs-types-exclude=^\\z", "--collector.filesystem.mount-timeout=1s"},
		credentials: []nativeCredential{
			{"collector.yaml", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorConfiguration))},
			{"collector.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorCertificate))},
			{"collector-key.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorPrivateKey))},
			{"trust.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.NodeTrust))},
		},
		binds: []nativeBind{{Source: filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorExecutable)), Destination: collectorExecutable}},
	}
	node := nativeService{
		name: nodeName, description: "Matrix node " + ownership,
		executable: filepath.Join(plan.Root, filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)), "bin", "matrix-node-agent"),
		policy:     nodeconfig.Policy(false), user: "root", listenAddress: plan.Configuration.ListenAddress,
		environment: []string{"MATRIX_NODE_CONFIGURATION_FILE=" + filepath.Join(plan.Root, filepath.FromSlash(layout.NodeConfiguration)),
			"DOCKER_CONFIG=" + filepath.Join(plan.Root, filepath.Dir(filepath.FromSlash(layout.NodeDockerConfiguration))),
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		writePaths: []string{plan.Configuration.StoragePath},
	}
	return []nativeService{collector, node}
}

var _ nodecommand.Effects = (*NodeEffects)(nil)
