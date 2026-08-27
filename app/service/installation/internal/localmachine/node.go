package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
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
	return effects.verifier.Validate(plan.Configuration, plan.Credentials)
}

func (effects *NodeEffects) ReadInstallation(root string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	source, err := readManagedFile(root, filepath.FromSlash(layout.NodeConfiguration), nodeconfig.MaximumBytes)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
	}
	defer clear(source)
	config, err := nodeconfig.DecodeConfiguration(source)
	if err != nil {
		return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
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
		// Inspect both before any start. A foreign collector must not permit a
		// partially started node, or vice versa.
		for _, service := range services {
			if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
				return err
			}
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

func (effects *NodeEffects) preflightNode(ctx context.Context, plan nodecommand.Plan) error {
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
	available, err := availableFilesystemBytes(plan.Root)
	if err != nil {
		return errors.Join(nodecommand.ErrUnavailable, err)
	}
	if available < plan.Bundle.Manifest.MinimumFreeBytes {
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
	if effects == nil || effects.supervisor == nil || ctx == nil {
		return nodecommand.ErrUnavailable
	}
	services := nativeNodeServices(plan)
	for _, service := range services {
		if _, err := effects.supervisor.Inspect(ctx, service); err != nil {
			if errors.Is(err, nodecommand.ErrConflict) {
				return err
			}
			return errors.Join(nodecommand.ErrOutcomeUnknown, err)
		}
	}
	for index := len(services) - 1; index >= 0; index-- {
		if err := effects.supervisor.Stop(ctx, services[index]); err != nil {
			return err
		}
	}
	return nil
}

func configureNode(plan nodecommand.Plan) error {
	if _, err := authenticateNodeRelease(plan); err != nil {
		return err
	}
	if _, err := ensureManagedDirectory(plan.Root, filepath.FromSlash(layout.ExecutorRoot)); err != nil {
		return errors.Join(nodecommand.ErrConflict, err)
	}
	if err := materializeCollector(plan); err != nil {
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
	credentialRoot := "/run/credentials/" + collector.name
	uri, err := nodev1.NodeURI(plan.Configuration.Identity)
	if err != nil {
		return nil, err
	}
	collectorConfiguration := []byte(fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\n  client_ca_file: %q\n  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans:\n    - %q\n  min_version: TLS13\nhttp_server_config:\n  http2: false\n",
		credentialRoot+"/collector.pem", credentialRoot+"/collector-key.pem", credentialRoot+"/trust.pem", uri))
	return []nodeFile{
		{layout.ReleaseTrust, plan.TrustBytes}, {layout.NodeConfiguration, configuration},
		{layout.NodeDockerConfiguration, []byte("{}\n")},
		{layout.CollectorConfiguration, collectorConfiguration},
		{layout.NodeCertificate, plan.Credentials.Certificate}, {layout.NodePrivateKey, plan.Credentials.PrivateKey},
		{layout.NodeTrust, plan.Credentials.Trust}, {layout.CollectorCertificate, plan.Credentials.CollectorCertificate},
		{layout.CollectorPrivateKey, plan.Credentials.CollectorPrivateKey},
	}, nil
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
}

func nativeNodeServices(plan nodecommand.Plan) []nativeService {
	commitment := sha256Hex([]byte(plan.Binding.ConfigurationDigest + "\x00" + plan.Bundle.ManifestSHA256))
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
		name: collectorName, description: "Matrix collector " + commitment, executable: collectorExecutable,
		collector: true, user: "mxn-" + identity[:16], policy: nodeconfig.Policy(true), listenAddress: collectorAddress,
		runtimeDirectories: []string{collectorRuntimeDirectory},
		arguments: []string{"--web.listen-address=" + collectorAddress,
			"--web.config.file=/run/credentials/" + collectorName + "/collector.yaml",
			"--web.disable-exporter-metrics", "--web.max-requests=2", "--collector.disable-defaults",
			"--collector.cpu", "--collector.loadavg", "--collector.meminfo", "--collector.filesystem",
			"--collector.filesystem.mount-points-include=^(" + strings.Join(parents, "|") + ")$",
			"--collector.filesystem.fs-types-exclude=^$", "--collector.filesystem.mount-timeout=1s"},
		credentials: []nativeCredential{
			{"collector.yaml", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorConfiguration))},
			{"collector.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorCertificate))},
			{"collector-key.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorPrivateKey))},
			{"trust.pem", filepath.Join(plan.Root, filepath.FromSlash(layout.NodeTrust))},
		},
		binds: []nativeBind{{Source: filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorExecutable)), Destination: collectorExecutable}},
	}
	node := nativeService{
		name: nodeName, description: "Matrix node " + commitment,
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
