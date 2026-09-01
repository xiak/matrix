package phase1e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

// This is the native companion of the existing signed platform gate, not a
// second platform workflow. SSH reaches only two explicitly prepared loopback
// forwards with pinned host keys. Product observations still use real mTLS.
const nativeFixtureRootEnvironment = "MATRIX_PHASE1_NATIVE_FIXTURE_ROOT"
const nativeFixtureRootPrefix = "/data/xiak/"
const nativePool paasv1.ResourceID = "offline-native-pool"
const nativeRuntimePool paasv1.ResourceID = "execution-pool-local"
const nativeAfterRemovalDeploymentID paasv1.ResourceID = "phase3-runtime-after-removal"
const nativeRuntimeProfileLabel = "matrix-profile"
const nativeRuntimeProfile = "local-compose"
const nativeCompleteRuntimeSnapshotTimeout = 3 * time.Minute

type nativeNodeInput struct {
	Port          int    `json:"port"`
	Endpoint      string `json:"endpoint"`
	ListenAddress string `json:"listenAddress,omitempty"`
	CollectorPort int    `json:"collectorPort,omitempty"`
}

type nativeFixtureInput struct {
	ReleaseA       string            `json:"releaseA"`
	ReleaseB       string            `json:"releaseB"`
	IdentityFile   string            `json:"identityFile"`
	KnownHostsFile string            `json:"knownHostsFile"`
	FixtureRoot    string            `json:"fixtureRoot"`
	Nodes          []nativeNodeInput `json:"nodes"`
}

type nativeHostFacts struct {
	Fingerprint  string `json:"fingerprint"`
	BootID       string `json:"bootId"`
	EngineID     string `json:"engineId"`
	CPUs         int64  `json:"cpus"`
	MemoryBytes  int64  `json:"memoryBytes"`
	StorageBytes int64  `json:"storageBytes"`
}

type nativeNodeState struct {
	input         nativeNodeInput
	facts         nativeHostFacts
	identity      nodev1.Identity
	binding       string
	configuration nodeconfig.Configuration
	digest        string
	operation     paasv1.Operation
	auditHash     string
	workload      nativeWorkload
}

type nativeWorkload struct {
	ID           string `json:"id"`
	StartedAt    string `json:"startedAt"`
	RestartCount uint64 `json:"restartCount"`
	Running      bool   `json:"running"`
}

type nativeRuntimeIdentity struct {
	BootID               string
	EngineID             string
	DockerActiveSince    string
	NodeActiveSince      string
	CollectorActiveSince string
}

type nativeLifecycleEvidence struct {
	Operations int64 `json:"operations"`
	Outbox     int64 `json:"outbox"`
}

type nativeTargetLifecycleState struct {
	RuntimeIdentities [2]nativeRuntimeIdentity
	Operations        []paasv1.Operation
	RemoveEvidence    nativeLifecycleEvidence
}

type nativeNodes struct {
	input             nativeFixtureInput
	directory         string
	releases          releasePair
	controller        nodeconfig.ControllerConfiguration
	nodes             []nativeNodeState
	deploymentRuntime bool
}

func validateNativeFixture(input nativeFixtureInput) error {
	for _, path := range []string{input.ReleaseA, input.ReleaseB, input.IdentityFile, input.KnownHostsFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return fail("native-fixture-path")
		}
	}
	if validateNativeFixtureRoot(input.FixtureRoot) != nil {
		return fail("native-fixture-root")
	}
	if len(input.Nodes) != 2 || input.Nodes[0].Port == input.Nodes[1].Port || input.Nodes[0].Endpoint == input.Nodes[1].Endpoint {
		return fail("native-fixture-two-distinct-hosts")
	}
	for _, node := range input.Nodes {
		endpoint, err := url.Parse(node.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
			return fail("native-fixture-private-endpoint")
		}
		host, port, err := net.SplitHostPort(endpoint.Host)
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		address := net.ParseIP(host)
		listenAddress := node.ListenAddress
		if listenAddress == "" {
			listenAddress = endpoint.Host
		}
		listenHost, listenPort, listenErr := net.SplitHostPort(listenAddress)
		parsedListenPort, listenPortErr := strconv.ParseUint(listenPort, 10, 16)
		parsedListenAddress := net.ParseIP(listenHost)
		if err != nil || portErr != nil || parsedPort == 0 || address == nil || !address.IsPrivate() || node.Port < 1024 || node.Port > 65535 ||
			listenErr != nil || listenPortErr != nil || parsedListenPort == 0 || parsedListenAddress == nil || !parsedListenAddress.IsPrivate() ||
			node.CollectorPort != 0 && (node.CollectorPort < 1024 || node.CollectorPort > 65535 || node.CollectorPort == int(parsedListenPort)) {
			return fail("native-fixture-private-endpoint")
		}
	}
	return nil
}

func validateNativeFixtureRoot(root string) error {
	if !path.IsAbs(root) || path.Clean(root) != root || !strings.HasPrefix(root, nativeFixtureRootPrefix) ||
		len(root) <= len(nativeFixtureRootPrefix) || strings.ContainsAny(root, "\x00\r\n") {
		return fail("native-fixture-root")
	}
	return nil
}

func (fixture *nativeNodes) root() string {
	return fixture.input.FixtureRoot
}

func (fixture *nativeNodes) installationRoot() string {
	return path.Join(fixture.root(), "installation")
}

func isNativeDeploymentRuntimePredecessor(bundle release.VerifiedBundle) bool {
	return nodecommand.ValidateInstalledRelease(bundle) == nil &&
		bundle.Manifest.Node.RuntimeRevision == nodeconfig.DeploymentRuntimePredecessorRevision &&
		bundle.Manifest.TopologyDigest == nodeconfig.DeploymentRuntimePredecessorContractDigest()
}

func validateNativeReleasePair(a, b release.VerifiedBundle) error {
	if !isNativeDeploymentRuntimePredecessor(a) || nodecommand.ValidateRelease(b) != nil ||
		b.Manifest.Node.RuntimeRevision != nodeconfig.RuntimeRevision ||
		b.Manifest.TopologyDigest != nodeconfig.ContractDigest() ||
		a.Manifest.Release.PreviousID != "" || a.Manifest.Release.PreviousVersion != "" ||
		b.Manifest.Release.PreviousID != a.Manifest.Release.ID ||
		b.Manifest.Release.PreviousVersion != a.Manifest.Release.Version ||
		a.Manifest.Release.ID == b.Manifest.Release.ID ||
		a.Manifest.Release.Version == b.Manifest.Release.Version ||
		a.Manifest.Release.SourceCommit == b.Manifest.Release.SourceCommit {
		return fail("native-real-predecessor-pair")
	}
	return nil
}

func (value *gate) prepareNativeNodes(ctx context.Context, installationID string) error {
	if value.config.nativeNodes == "" {
		return nil
	}
	content, err := os.ReadFile(value.config.nativeNodes)
	if err != nil || len(content) > 16*1024 {
		return fail("native-fixture-input")
	}
	var input nativeFixtureInput
	if decodeOne(content, &input) != nil || validateNativeFixture(input) != nil {
		return fail("native-fixture-input")
	}
	trust, err := os.ReadFile(value.config.trustKey)
	if err != nil {
		return fail("native-release-trust")
	}
	defer clear(trust)
	a, err := release.VerifyDirectory(input.ReleaseA, trust)
	if err != nil {
		return fail("native-release-a")
	}
	b, err := release.VerifyDirectory(input.ReleaseB, trust)
	if err != nil || validateNativeReleasePair(a, b) != nil {
		return fail("native-real-predecessor-pair")
	}
	directory, err := os.MkdirTemp(filepath.Dir(value.config.nativeNodes), ".combined-enrollment-")
	if err != nil {
		return fail("native-private-fixture")
	}
	fixture := &nativeNodes{input: input, directory: directory, releases: releasePair{a: a, b: b}, controller: nodeconfig.EmptyController(installationID), deploymentRuntime: value.config.nativeDeploymentRuntime}
	value.nodes = fixture
	driver, err := os.Executable()
	if err != nil {
		return fail("native-probe-driver")
	}
	for index, inputNode := range input.Nodes {
		targetID := paasv1.ResourceID(fmt.Sprintf("offline-native-%d", index+1))
		if fixture.deploymentRuntime {
			targetID = paasv1.ResourceID(fmt.Sprintf("a-runtime-native-%d", index+1))
		}
		node := nativeNodeState{input: inputNode, identity: nodev1.Identity{InstallationID: installationID, ExecutionTargetID: targetID}, binding: string(targetID) + "-connection"}
		fixture.nodes = append(fixture.nodes, node)
		if err := fixture.waitPrepared(ctx, index); err != nil {
			return err
		}
		if err := fixture.copy(ctx, index, driver, fixture.root()+"/probe.test", true, false); err != nil {
			return err
		}
		probeMode := "1"
		if fixture.deploymentRuntime {
			probeMode = "runtime"
		}
		if _, err := fixture.command(ctx, index, "env", "MATRIX_PHASE1_NATIVE_HOST_PROBE="+probeMode, nativeFixtureRootEnvironment+"="+fixture.root(), fixture.root()+"/probe.test", "-test.run=^TestOfflineNativeHostProbe$", "-test.count=1"); err != nil {
			return err
		}
		factsPath := filepath.Join(directory, fmt.Sprintf("facts-%d.json", index))
		if err := fixture.copy(ctx, index, factsPath, fixture.root()+"/facts.json", false, false); err != nil {
			return err
		}
		facts, err := os.ReadFile(factsPath)
		if err != nil || len(facts) > 4096 || decodeOne(facts, &fixture.nodes[index].facts) != nil || !validNativeFacts(fixture.nodes[index].facts) {
			return fail("native-real-host-facts")
		}
		for _, media := range []struct {
			source, target string
			directory      bool
		}{{a.Root, "node-a", true}, {b.Root, "node-b", true}, {value.config.trustKey, "trust.json", false}} {
			if err := fixture.copy(ctx, index, media.source, fixture.root()+"/"+media.target, true, media.directory); err != nil {
				return err
			}
		}
	}
	left, right := fixture.nodes[0].facts, fixture.nodes[1].facts
	if left.Fingerprint == right.Fingerprint || left.BootID == right.BootID || left.EngineID == right.EngineID {
		return fail("native-independent-kernels-and-engines")
	}
	if err := fixture.credentials(ctx, value, false); err != nil {
		return err
	}
	if fixture.deploymentRuntime {
		return value.prepareNativeRuntimeImages(ctx)
	}
	return value.prepareNativeWorkloads(ctx)
}

func validNativeFacts(facts nativeHostFacts) bool {
	return paasv1.ValidateDigest("fingerprint", facts.Fingerprint) == nil && len(facts.BootID) == 36 && facts.EngineID != "" && facts.CPUs > 0 && facts.MemoryBytes > 0 && facts.StorageBytes > 0
}

func (fixture *nativeNodes) sshArguments(index int) []string {
	return []string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UserKnownHostsFile=" + fixture.input.KnownHostsFile, "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "-o", "LogLevel=ERROR", "-i", fixture.input.IdentityFile}
}

func (fixture *nativeNodes) waitPrepared(ctx context.Context, index int) error {
	// A booted sshd may precede cloud-init's offline Docker preparation. Wait
	// before the first file write; never treat a half-prepared VM as installed.
	poll, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		_, directoryErr := fixture.command(poll, index, "test", "-d", fixture.root())
		if directoryErr == nil {
			if content, err := fixture.command(poll, index, "docker", "info", "--format", "{{.ID}}"); err == nil && strings.TrimSpace(string(content)) != "" {
				return nil
			}
		}
		if !waitPoll(poll, time.Second) {
			return fail("native-prepared-guest-timeout")
		}
	}
}

func (fixture *nativeNodes) command(ctx context.Context, index int, arguments ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	args := append(fixture.sshArguments(index), "-p", strconv.Itoa(fixture.nodes[index].input.Port), "root@127.0.0.1")
	var words []string
	for _, argument := range arguments {
		words = append(words, "'"+strings.ReplaceAll(argument, "'", "'\\''")+"'")
	}
	args = append(args, strings.Join(words, " "))
	output, err := runProcess(bounded, "ssh", args...)
	if err != nil || output.exit != 0 || len(output.stderr) != 0 {
		clear(output.stdout)
		clear(output.stderr)
		return nil, fail("native-loopback-command")
	}
	return output.stdout, nil
}

func (fixture *nativeNodes) copy(ctx context.Context, index int, local, remote string, toRemote, recursive bool) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := append(fixture.sshArguments(index), "-q", "-p", "-P", strconv.Itoa(fixture.nodes[index].input.Port))
	if recursive {
		args = append(args, "-r")
	}
	if toRemote {
		args = append(args, local, "root@127.0.0.1:"+remote)
	} else {
		args = append(args, "root@127.0.0.1:"+remote, local)
	}
	output, err := runProcess(bounded, "scp", args...)
	defer clear(output.stdout)
	defer clear(output.stderr)
	if err != nil || output.exit != 0 || len(output.stderr) != 0 {
		return fail("native-private-media-transfer-" + strconv.Itoa(index+1) + "-" + filepath.Base(remote))
	}
	return nil
}

func (fixture *nativeNodes) mx(ctx context.Context, index int, successor bool, action string, args ...string) (cli.Result, error) {
	result, err := fixture.mxResult(ctx, index, successor, action, args...)
	if err != nil || result.State != "READY" {
		return cli.Result{}, fail("native-mx-" + action)
	}
	return result, nil
}

func (fixture *nativeNodes) mxResult(ctx context.Context, index int, successor bool, action string, args ...string) (cli.Result, error) {
	media := "node-a"
	if successor {
		media = "node-b"
	}
	arguments := append([]string{fixture.root() + "/" + media + "/bin/mx", "--format", "json", "node", action}, args...)
	content, err := fixture.command(ctx, index, arguments...)
	defer clear(content)
	var result struct {
		APIVersion string     `json:"apiVersion"`
		Kind       string     `json:"kind"`
		Action     string     `json:"action"`
		Status     string     `json:"status"`
		Result     cli.Result `json:"result"`
	}
	if err != nil || decodeOne(content, &result) != nil || result.APIVersion != "cli.matrix.xiak.com/v1" || result.Kind != "NodeCommandResult" || result.Action != strings.ToUpper(strings.ReplaceAll(action, "-", "_")) || result.Status != "SUCCEEDED" || result.Result.ExecutionTargetID != string(fixture.nodes[index].identity.ExecutionTargetID) {
		return cli.Result{}, fail("native-mx-" + action)
	}
	return result.Result, nil
}

func privateFixtureFile(directory, name string, content []byte) (string, error) {
	path := filepath.Join(directory, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", fail("native-private-file")
	}
	_, writeErr := f.Write(content)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return "", fail("native-private-file")
	}
	return path, nil
}

func (fixture *nativeNodes) credentials(ctx context.Context, value *gate, rotate bool) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail("native-fixture-ca")
	}
	now := time.Now().UTC().Truncate(time.Second)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-native-gate"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fail("native-fixture-ca")
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fail("native-fixture-ca")
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, uri string, addresses []net.IP, usages ...x509.ExtKeyUsage) ([]byte, []byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		identity, err := url.Parse(uri)
		if err != nil {
			return nil, nil, err
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "isolated-native-peer"}, URIs: []*url.URL{identity}, IPAddresses: addresses, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		defer clear(private)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
	}
	controllerURI, _ := nodev1.ControllerURI(fixture.controller.InstallationID, fixture.controller.ControllerID)
	certificate, key, err := issue(2, controllerURI, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return fail("native-fixture-controller")
	}
	defer clear(key)
	controller := fixture.controller
	controller.Certificate, controller.PrivateKey, controller.Trust = certificate, key, trust
	controller.Nodes = nil
	for index := range fixture.nodes {
		node := &fixture.nodes[index]
		directory, err := os.MkdirTemp(fixture.directory, "node-input-")
		if err != nil {
			return fail("native-fixture-enrollment")
		}
		remote := fixture.root() + "/" + filepath.Base(directory)
		nodeURI, _ := nodev1.NodeURI(node.identity)
		collectorURI, _ := nodev1.CollectorURI(node.identity)
		endpoint, _ := url.Parse(node.input.Endpoint)
		listenAddress := node.input.ListenAddress
		if listenAddress == "" {
			listenAddress = endpoint.Host
		}
		listenHost, _, _ := net.SplitHostPort(listenAddress)
		addresses := []net.IP{net.ParseIP(endpoint.Hostname())}
		if listenIP := net.ParseIP(listenHost); listenIP != nil && !listenIP.Equal(addresses[0]) {
			addresses = append(addresses, listenIP)
		}
		nodeCertificate, nodeKey, err := issue(int64(10+index*2), nodeURI, addresses, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return fail("native-fixture-node")
		}
		collectorCertificate, collectorKey, err := issue(int64(11+index*2), collectorURI, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
		if err != nil {
			clear(nodeKey)
			return fail("native-fixture-collector")
		}
		for _, item := range []struct {
			name    string
			content []byte
		}{{"node.pem", nodeCertificate}, {"node-key.pem", nodeKey}, {"collector.pem", collectorCertificate}, {"collector-key.pem", collectorKey}, {"trust.pem", trust}} {
			_, err = privateFixtureFile(directory, item.name, item.content)
			if err != nil {
				clear(nodeKey)
				clear(collectorKey)
				return err
			}
		}
		clear(nodeKey)
		clear(collectorKey)
		reservedSlots := node.facts.CPUs
		if fixture.deploymentRuntime {
			reservedSlots--
		}
		collectorPort := node.input.CollectorPort
		if collectorPort == 0 {
			collectorPort = 19100
		}
		configuration := nodeconfig.Configuration{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind, Identity: node.identity, ControllerID: controller.ControllerID, BindingRef: node.binding, ExpectedFingerprint: node.facts.Fingerprint, ListenAddress: listenAddress, CollectorEndpoint: fmt.Sprintf("https://127.0.0.1:%d", collectorPort), StoragePath: fixture.installationRoot() + "/runtime/executor", CertificateFile: remote + "/node.pem", PrivateKeyFile: remote + "/node-key.pem", TrustFile: remote + "/trust.pem", SystemReserve: paasv1.Capacity{MemoryBytes: 256 << 20, WorkloadSlots: reservedSlots}}
		enrollment := nodeconfig.Enrollment{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.EnrollmentKind, Node: configuration, CollectorCertificateFile: remote + "/collector.pem", CollectorPrivateKeyFile: remote + "/collector-key.pem"}
		encoded, err := json.Marshal(enrollment)
		if err != nil {
			return fail("native-fixture-enrollment")
		}
		if _, err = privateFixtureFile(directory, "enrollment.json", encoded); err != nil {
			return err
		}
		if err = fixture.copy(ctx, index, directory, remote, true, true); err != nil {
			return err
		}
		action := "install"
		arguments := []string{"--root", fixture.installationRoot(), "--configuration", remote + "/enrollment.json"}
		if rotate {
			action = "rotate-credentials"
			arguments = append(arguments, "--expected-configuration-digest", node.digest)
		} else {
			arguments = append(arguments, "--bundle", fixture.root()+"/node-a", "--trust-key", fixture.root()+"/trust.json")
		}
		result, err := fixture.mx(ctx, index, false, action, arguments...)
		if err != nil || !result.Changed || paasv1.ValidateDigest("configurationDigest", result.ConfigurationDigest) != nil || result.ConfigurationDigest == node.digest {
			return fail("native-signed-" + action)
		}
		node.configuration, node.digest = configuration, result.ConfigurationDigest
		controller.Nodes = append(controller.Nodes, nodeconfig.Connection{BindingRef: node.binding, TargetID: node.identity.ExecutionTargetID, Endpoint: node.input.Endpoint, IdentityFingerprint: node.facts.Fingerprint})
		if rotate {
			if err := assertRetiredControllerTLS(ctx, node.input.Endpoint, node.identity, fixture.controller, controller); err != nil {
				return err
			}
		}
	}
	encoded, err := nodeconfig.EncodeController(controller)
	if err != nil {
		return fail("native-controller-encoding")
	}
	defer clear(encoded)
	input, err := privateFixtureFile(fixture.directory, fmt.Sprintf("controller-%t.json", rotate), encoded)
	if err != nil {
		return err
	}
	result, err := runMX(ctx, value.releases.a, "configure-nodes", []string{"--root", value.config.root, "--configuration", input, "--expected-configuration-digest", value.controllerConfigDigest}, value.forbidden(key))
	digest, digestErr := nodeconfig.ControllerDigest(controller)
	if err != nil || digestErr != nil || !result.Changed || result.ConfigurationDigest != digest {
		return fail("native-controller-configuration")
	}
	value.controllerConfigDigest = digest
	fixture.controller.Clear()
	controller.PrivateKey = bytes.Clone(key)
	fixture.controller = controller
	return nil
}

func assertRetiredControllerTLS(ctx context.Context, endpoint string, identity nodev1.Identity, previous, current nodeconfig.ControllerConfiguration) error {
	// Trust the NEW server for both attempts: a failed old client must not be
	// mistaken for merely refusing the new server's CA. The positive control
	// reaches HTTP using the new controller, which is denied self-readiness.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(current.Trust) {
		return fail("native-controller-revocation-fixture")
	}
	peer, _ := nodev1.NodeURI(identity)
	for index, credential := range []nodeconfig.ControllerConfiguration{previous, current} {
		pair, err := tls.X509KeyPair(credential.Certificate, credential.PrivateKey)
		if err != nil {
			return fail("native-controller-revocation-fixture")
		}
		security := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !nodev1.MatchesIdentity(state.PeerCertificates[0].URIs, peer) {
				return fail("native-controller-revocation-peer")
			}
			return nil
		}}
		transport := &http.Transport{Proxy: nil, TLSClientConfig: security, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+nodev1.ReadinessPath, nil)
		if err != nil {
			return fail("native-controller-revocation-fixture")
		}
		response, err := client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		transport.CloseIdleConnections()
		if index == 0 && (err == nil || response != nil) {
			return fail("native-retired-controller-accepted")
		}
		if index == 1 && (err != nil || response == nil || response.StatusCode != http.StatusForbidden) {
			return fail("native-current-controller-tls-control")
		}
	}
	return nil
}

func (value *gate) admitNativeNodes(ctx context.Context, bearer []byte) error {
	if value.nodes == nil {
		return nil
	}
	fixture := value.nodes
	poolID, labels := fixture.registration()
	if !fixture.deploymentRuntime {
		if _, err := value.edge.createResource(ctx, "/api/paas/v1/execution-pools", "offline-native-pool", bearer, paasv1.CreateExecutionPoolRequest{ID: nativePool, Name: string(nativePool), Spec: paasv1.ExecutionPoolSpec{AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload}}}, paasv1.OperationCreateExecutionPool, paasv1.ResourceRef{Kind: "ExecutionPool", ID: nativePool}); err != nil {
			return fail("native-platform-pool")
		}
	}
	for index := range fixture.nodes {
		node := &fixture.nodes[index]
		operation, err := value.edge.createResource(ctx, "/api/paas/v1/execution-targets", string(node.identity.ExecutionTargetID), bearer, paasv1.RegisterExecutionTargetRequest{ID: node.identity.ExecutionTargetID, Name: string(node.identity.ExecutionTargetID), ExecutionPoolID: poolID, BindingRef: node.binding, Labels: labels}, paasv1.OperationRegisterExecutionTarget, paasv1.ResourceRef{Kind: "ExecutionTarget", ID: node.identity.ExecutionTargetID})
		if err != nil || operation.InstallationID != fixture.controller.InstallationID || operation.Scope.TenantID != "" {
			return fail("native-platform-admission")
		}
		node.operation = operation
	}
	if err := value.assertNativeNodes(ctx, bearer, false); err != nil {
		return err
	}
	if err := value.nativeBackgroundAndOutage(ctx, bearer); err != nil {
		return err
	}
	emit("two-signed-native-hosts-through-platform-admission")
	return nil
}

func (fixture *nativeNodes) registration() (paasv1.ResourceID, map[string]string) {
	if fixture.deploymentRuntime {
		return nativeRuntimePool, map[string]string{nativeRuntimeProfileLabel: nativeRuntimeProfile}
	}
	return nativePool, nil
}

func (value *gate) assertNativeNodes(ctx context.Context, bearer []byte, successor bool) error {
	if value.nodes == nil {
		return nil
	}
	fixture := value.nodes
	for index := range fixture.nodes {
		node := &fixture.nodes[index]
		poll, cancel := context.WithTimeout(ctx, 45*time.Second)
		var result cli.Result
		var err error
		for {
			result, err = fixture.mxResult(poll, index, successor, "status", "--root", fixture.installationRoot())
			if err == nil && result.State == "READY" {
				break
			}
			if err == nil && result.State != "NOT_READY" {
				cancel()
				return fail("native-retained-node-release-and-credentials")
			}
			if !waitPoll(poll, time.Second) {
				cancel()
				return fail("native-retained-node-release-and-credentials")
			}
		}
		cancel()
		want := fixture.releases.a.Manifest.Release.ID
		if successor {
			want = fixture.releases.b.Manifest.Release.ID
		}
		if err != nil || result.Changed || result.ReleaseID != want || result.ConfigurationDigest != node.digest {
			return fail("native-retained-node-release-and-credentials")
		}
		poll, cancel = context.WithTimeout(ctx, 45*time.Second)
		var target paasv1.ExecutionTarget
		for {
			_, err = value.edge.get(poll, "/api/paas/v1/execution-targets/"+string(node.identity.ExecutionTargetID), bearer, &target)
			if err == nil && target.Status.Health == paasv1.ExecutionTargetHealthReady && target.Status.Usage != nil && target.Status.Usage.CPU.State == paasv1.MeasurementAvailable && target.Status.Usage.Memory.State == paasv1.MeasurementAvailable {
				break
			}
			if !waitPoll(poll, 250*time.Millisecond) {
				cancel()
				return fail("native-connected-observation")
			}
		}
		cancel()
		if !matchesNativeObservation(target, *node, fixture.deploymentRuntime, fixture.installationRoot()) {
			return fail("native-physical-observation-and-binding")
		}
		if _, err := value.nativeStoredTarget(ctx, index); err != nil {
			return err
		}
		if !fixture.deploymentRuntime {
			if err := fixture.assertWorkload(ctx, index); err != nil {
				return err
			}
		}
		var operation paasv1.Operation
		if _, err = value.edge.get(ctx, "/api/paas/v1/platform/operations/"+string(node.operation.ID), bearer, &operation); err != nil || !reflect.DeepEqual(operation, node.operation) {
			return fail("native-retained-admission-operation")
		}
		if _, err = value.edge.json(ctx, http.MethodGet, "/api/paas/v1/operations/"+string(node.operation.ID), bearer, nil, nil, http.StatusNotFound); err != nil {
			return fail("native-platform-operation-tenant-route")
		}
	}
	return value.assertNativeAudit(ctx, bearer)
}

func matchesNativeObservation(target paasv1.ExecutionTarget, node nativeNodeState, deploymentRuntime bool, installationRoot string) bool {
	usage := target.Status.Usage
	poolID, workloadSlots := nativePool, int64(0)
	if deploymentRuntime {
		poolID, workloadSlots = nativeRuntimePool, 1
	}
	profileMatches := !deploymentRuntime || target.Metadata.Labels[nativeRuntimeProfileLabel] == nativeRuntimeProfile
	if paasv1.ValidateExecutionTarget(target) != nil || target.Metadata.ID != node.identity.ExecutionTargetID || target.Metadata.Labels["matrix-machine-fingerprint"] != node.facts.Fingerprint || !profileMatches ||
		target.Spec.ExecutionPoolID != poolID || target.Spec.InfrastructureAdapter.Name != "nodehttps" || target.Status.Capacity.CPUMillis != node.facts.CPUs*1000 || target.Status.Capacity.MemoryBytes != node.facts.MemoryBytes ||
		target.Status.Allocatable.MemoryBytes != node.facts.MemoryBytes-(256<<20) || target.Status.Allocatable.WorkloadSlots != workloadSlots || usage == nil || usage.CPU.Value == nil || usage.Memory.Value == nil ||
		usage.CPU.Value.LogicalCPUs != node.facts.CPUs || usage.Memory.Value.TotalBytes != node.facts.MemoryBytes || !time.Now().Before(usage.ValidUntil) {
		return false
	}
	for _, filesystem := range usage.Filesystems {
		if filesystem.State == paasv1.MeasurementAvailable && filesystem.Value != nil && filesystem.Value.TotalBytes == node.facts.StorageBytes && strings.HasPrefix(installationRoot, strings.TrimSuffix(filesystem.MountPoint, "/")+"/") {
			return true
		}
	}
	return false
}

func (value *gate) assertNativeAudit(ctx context.Context, bearer []byte) error {
	poll, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		response, err := value.edge.json(poll, http.MethodPost, "/api/audit/v1/platform/records:query", bearer, auditv1.QueryRecordsRequest{PageSize: 10, Action: auditv1.ActionPaaSExecutionTargetRegistered}, nil, http.StatusOK)
		var page auditv1.RecordPage
		valid := err == nil && decodeOne(response.body, &page) == nil && auditv1.ValidateRecordPage(page) == nil && page.InstallationID == value.nodes.controller.InstallationID && page.NextCursor == ""
		clear(response.body)
		if valid && len(page.Records) == len(value.nodes.nodes) {
			for index := range value.nodes.nodes {
				node := &value.nodes.nodes[index]
				found := false
				for _, record := range page.Records {
					if record.Event.OperationID != auditv1.OperationID(node.operation.ID) {
						continue
					}
					if found || record.Source != auditv1.SourcePaaS || record.Event.Action != auditv1.ActionPaaSExecutionTargetRegistered || record.Event.InstallationID != value.nodes.controller.InstallationID || record.Event.Target.ID != string(node.identity.ExecutionTargetID) || record.Event.Actor.Type != auditv1.ActorUser || record.Event.Actor.ID != auditv1.ActorID(node.operation.RequestedBy.ID) || record.Event.IAMDecisionID == "" || record.Event.TenantID != "" || (node.auditHash != "" && node.auditHash != record.RecordHash) {
						return fail("native-original-admission-audit")
					}
					node.auditHash = record.RecordHash
					found = true
				}
				if !found {
					return fail("native-missing-admission-audit")
				}
			}
			return nil
		}
		if !waitPoll(poll, 250*time.Millisecond) {
			return fail("native-admission-audit-delivery")
		}
	}
}

func (value *gate) nativeStoredTarget(ctx context.Context, index int) (paasv1.ExecutionTarget, error) {
	node := value.nodes.nodes[index]
	ids, err := dockerLines(ctx, "container", "ls", "--quiet", "--filter", "label=com.xiak.matrix.installation="+node.identity.InstallationID, "--filter", "label=com.xiak.matrix.role=postgres")
	if err != nil || len(ids) != 1 {
		return paasv1.ExecutionTarget{}, fail("native-authority-database")
	}
	// The ID comes only from this gate's closed fixture, never a caller string.
	query := fmt.Sprintf("SELECT json_build_object('installationId',installation_id,'binding',binding_ref,'fingerprint',identity_fingerprint,'target',document)::text FROM paas.execution_targets WHERE id='%s'", node.identity.ExecutionTargetID)
	content, err := docker(ctx, "container", "exec", "--user", "postgres", ids[0], "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--username", "matrix", "--dbname", "matrix", "--command", query)
	var stored struct {
		InstallationID string                 `json:"installationId"`
		Binding        string                 `json:"binding"`
		Fingerprint    string                 `json:"fingerprint"`
		Target         paasv1.ExecutionTarget `json:"target"`
	}
	if err != nil || decodeOne(content, &stored) != nil || stored.InstallationID != node.identity.InstallationID || stored.Binding != node.binding || stored.Fingerprint != node.facts.Fingerprint || stored.Target.Metadata.ID != node.identity.ExecutionTargetID {
		return paasv1.ExecutionTarget{}, fail("native-sealed-authority-binding")
	}
	return stored.Target, nil
}

func (value *gate) waitNativeStored(ctx context.Context, index int, health paasv1.ExecutionTargetHealth, after time.Time) (paasv1.ExecutionTarget, error) {
	poll, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		target, err := value.nativeStoredTarget(poll, index)
		if err != nil {
			return paasv1.ExecutionTarget{}, err
		}
		if target.Status.Health == health && target.Status.Usage != nil && (after.IsZero() || target.Status.Usage.ObservedAt.After(after)) &&
			(health != paasv1.ExecutionTargetHealthReady || time.Now().Before(target.Status.Usage.ValidUntil) && target.Status.Usage.CPU.State == paasv1.MeasurementAvailable && target.Status.Usage.Memory.State == paasv1.MeasurementAvailable) {
			return target, nil
		}
		if !waitPoll(poll, 500*time.Millisecond) {
			return paasv1.ExecutionTarget{}, fail("native-background-observer")
		}
	}
}

func (value *gate) nativeBackgroundAndOutage(ctx context.Context, bearer []byte) error {
	before, err := value.nativeStoredTarget(ctx, 0)
	if err != nil || before.Status.Usage == nil {
		return fail("native-background-baseline")
	}
	// These waits read only committed SQL facts. No PaaS/node GET can cause the
	// new sample whose timestamp is being asserted.
	fresh, err := value.waitNativeStored(ctx, 0, paasv1.ExecutionTargetHealthReady, before.Status.Usage.ObservedAt)
	if err != nil {
		return err
	}
	fixture := value.nodes
	unit, err := nodeconfig.ServiceName(fixture.nodes[0].identity, false)
	if err != nil {
		return fail("native-owned-unit")
	}
	if _, err = fixture.command(ctx, 0, "systemctl", "stop", unit); err != nil {
		return err
	}
	unavailable, err := value.waitNativeStored(ctx, 0, paasv1.ExecutionTargetHealthUnavailable, time.Time{})
	if err != nil || unavailable.Status.ObservedAt.Before(fresh.Status.ObservedAt) || unavailable.Status.Capacity.CPUMillis == 0 || unavailable.Status.Capacity.MemoryBytes == 0 {
		return fail("native-outage-retained-physical-facts")
	}
	other, err := value.nativeStoredTarget(ctx, 1)
	if err != nil || other.Status.Health != paasv1.ExecutionTargetHealthReady {
		return fail("native-outage-isolation")
	}
	node := fixture.nodes[0]
	poolID, labels := fixture.registration()
	replay, err := value.edge.json(ctx, http.MethodPost, "/api/paas/v1/execution-targets", bearer, paasv1.RegisterExecutionTargetRequest{ID: node.identity.ExecutionTargetID, Name: string(node.identity.ExecutionTargetID), ExecutionPoolID: poolID, BindingRef: node.binding, Labels: labels}, map[string]string{"Idempotency-Key": string(node.identity.ExecutionTargetID)}, http.StatusOK)
	var operation paasv1.Operation
	if err != nil || decodeOne(replay.body, &operation) != nil || !reflect.DeepEqual(operation, node.operation) {
		clear(replay.body)
		return fail("native-outage-admission-replay")
	}
	clear(replay.body)
	if result, err := fixture.mx(ctx, 0, false, "start", "--root", fixture.installationRoot()); err != nil || result.ConfigurationDigest != node.digest {
		return fail("native-reconnect-original-binding")
	}
	if _, err = value.waitNativeStored(ctx, 0, paasv1.ExecutionTargetHealthReady, fresh.Status.Usage.ObservedAt); err != nil {
		return err
	}
	emit("native-background-without-readers-and-isolated-outage")
	return nil
}

func (value *gate) rotateNativeCredentials(ctx context.Context, bearer []byte) error {
	if value.nodes == nil {
		return nil
	}
	ids, err := dockerLines(ctx, "container", "ls", "--quiet", "--no-trunc")
	if err != nil {
		return fail("native-rotation-platform-baseline")
	}
	before, err := inspectContainers(ctx, ids)
	if err != nil {
		return err
	}
	if err = value.nodes.credentials(ctx, value, true); err != nil {
		return err
	}
	afterIDs, err := dockerLines(ctx, "container", "ls", "--quiet", "--no-trunc")
	if err != nil {
		return fail("native-rotation-platform-preservation")
	}
	after, err := inspectContainers(ctx, afterIDs)
	if err != nil || !preservesNativeRotationRuntime(before, after, value.nodes.controller.InstallationID) {
		return fail("native-rotation-platform-preservation")
	}
	if _, err := assertPlatform(
		ctx, value.config.root, value.releases.a.Manifest, value.releaseAPreviousID,
	); err != nil {
		return err
	}
	if err = value.assertNativeNodes(ctx, bearer, false); err != nil {
		return err
	}
	emit("native-complete-trust-replacement-with-exact-api-only-platform-effect")
	return nil
}

func preservesNativeRotationRuntime(before, after []containerInspection, installationID string) bool {
	if installationID == "" || len(before) != len(after) {
		return false
	}
	beforeAPIs, afterAPIs := 0, 0
	for _, current := range after {
		if current.Config.Labels["com.xiak.matrix.role"] == "paas-api" && current.Config.Labels["com.xiak.matrix.installation"] == installationID {
			afterAPIs++
		}
	}
	for _, original := range before {
		ownedAPI := original.Config.Labels["com.xiak.matrix.role"] == "paas-api" && original.Config.Labels["com.xiak.matrix.installation"] == installationID
		if ownedAPI {
			beforeAPIs++
		}
		found := false
		for _, current := range after {
			if !current.State.Running {
				continue
			}
			if ownedAPI {
				// configure-nodes owns exactly this API replacement. Its full
				// signed topology is also checked through assertPlatform.
				if current.Config.Labels["com.xiak.matrix.role"] == "paas-api" && current.Config.Labels["com.xiak.matrix.installation"] == installationID && current.Config.Image == original.Config.Image {
					found = true
				}
			} else if original.ID != "" && current.ID == original.ID && original.State.StartedAt != "" && current.State.StartedAt == original.State.StartedAt && current.RestartCount == original.RestartCount {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return beforeAPIs == 1 && afterAPIs == 1
}

func (value *gate) nativeReleasePair(ctx context.Context, bearer []byte) error {
	if value.nodes == nil {
		return nil
	}
	fixture := value.nodes
	for index, node := range fixture.nodes {
		result, err := fixture.mx(ctx, index, true, "upgrade", "--root", fixture.installationRoot(), "--bundle", fixture.root()+"/node-b")
		if err != nil || !result.Changed || result.ReleaseID != fixture.releases.b.Manifest.Release.ID || result.PreviousID != fixture.releases.a.Manifest.Release.ID || result.ConfigurationDigest != node.digest {
			return fail("native-real-successor-upgrade")
		}
	}
	if err := value.assertNativeNodes(ctx, bearer, true); err != nil {
		return err
	}
	if err := value.assertNativeDeploymentRuntime(ctx, bearer); err != nil {
		return err
	}
	if value.config.multiHostLifecycle {
		emit("native-successor-retained-for-multi-host-lifecycle")
		return nil
	}
	for index, node := range fixture.nodes {
		result, err := fixture.mx(ctx, index, true, "rollback", "--root", fixture.installationRoot())
		if err != nil || !result.Changed || result.ReleaseID != fixture.releases.a.Manifest.Release.ID || result.PreviousID != "" || result.ConfigurationDigest != node.digest {
			return fail("native-real-predecessor-rollback")
		}
	}
	if err := value.assertNativeNodes(ctx, bearer, false); err != nil {
		return err
	}
	emit("native-real-predecessor-successor-with-platform-and-latest-credentials")
	return nil
}

func nativeRuntimeDeploymentID(index int) paasv1.ResourceID {
	return paasv1.ResourceID(fmt.Sprintf("phase3-runtime-deployment-%d", index+1))
}

func (value *gate) assertNativeDeploymentRuntime(ctx context.Context, bearer []byte) error {
	if !value.config.nativeDeploymentRuntime {
		return nil
	}
	if value.nodes == nil || len(value.nodes.nodes) != 2 {
		return fail("native-runtime-fixture")
	}
	terminalRevisionID, err := value.createNativeTerminalApplicationRevision(ctx, bearer)
	if err != nil {
		return err
	}
	deployments := make([]paasv1.Deployment, 0, len(value.nodes.nodes))
	snapshots := make([]paasv1.DeploymentRuntimeSnapshot, 0, len(value.nodes.nodes))
	terminalSessions := make([]paasv1.ResourceID, 0, len(value.nodes.nodes))
	for index, node := range value.nodes.nodes {
		id := nativeRuntimeDeploymentID(index)
		operation, err := value.edge.mutateDeployment(
			ctx, http.MethodPost, "/api/paas/v1/deployments", string(id), "", bearer,
			paasv1.CreateDeploymentRequest{ID: id, Name: string(id), Spec: deploymentSpec(terminalRevisionID, configurationRevisionOne, paasv1.DeploymentDesiredRunning)},
			paasv1.OperationDeploy, id,
		)
		if err != nil {
			return fail("native-runtime-deployment-create")
		}
		if _, err = value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
			return fail("native-runtime-deployment-operation")
		}
		deployment, err := value.edge.waitDeployment(ctx, bearer, id, 1, paasv1.DeploymentReady)
		if err != nil {
			return fail("native-runtime-deployment-convergence")
		}
		first, err := value.waitNativeDeploymentRuntime(ctx, bearer, deployment, node.identity.ExecutionTargetID, time.Time{})
		if err != nil {
			return err
		}
		second, err := value.waitNativeDeploymentRuntime(ctx, bearer, deployment, node.identity.ExecutionTargetID, first.Value.Observation.ObservedAt)
		if err != nil || first.Value.Observation.Instances[0].ID != second.Value.Observation.Instances[0].ID ||
			first.Resources.Value == nil || second.Resources.Value == nil ||
			first.Resources.Value.Observation.Instances[0].ID != second.Resources.Value.Observation.Instances[0].ID ||
			second.Resources.Value.Observation.ObservedAt.Before(first.Resources.Value.Observation.ObservedAt) {
			return fail("native-runtime-background-snapshot")
		}
		if err := value.assertNativeProviderInstance(ctx, index, deployment, second); err != nil {
			return err
		}
		terminalSessionID, err := value.assertNativeTerminal(ctx, bearer, deployment, second, index)
		if err != nil {
			return err
		}
		response, err := value.edge.json(ctx, http.MethodGet, "/api/paas/v1/deployments/"+string(id)+"/runtime?executionTargetId="+string(node.identity.ExecutionTargetID), bearer, nil, nil, http.StatusBadRequest)
		clear(response.body)
		if err != nil {
			return fail("native-runtime-selector-rejected")
		}
		deployments = append(deployments, deployment)
		snapshots = append(snapshots, second)
		terminalSessions = append(terminalSessions, terminalSessionID)
	}
	if snapshots[0].Value.Observation.ExecutionTargetID == snapshots[1].Value.Observation.ExecutionTargetID {
		return fail("native-runtime-distinct-targets")
	}
	var inventory paasv1.DeploymentList
	if _, err := value.edge.get(ctx, "/api/paas/v1/deployments", bearer, &inventory); err != nil || paasv1.ValidateDeploymentList(inventory) != nil || inventory.NextAfter != "" {
		return fail("native-runtime-deployment-inventory")
	}
	for _, deployment := range deployments {
		found := false
		for _, item := range inventory.Items {
			found = found || item.Metadata.ID == deployment.Metadata.ID && reflect.DeepEqual(item, deployment)
		}
		if !found {
			return fail("native-runtime-deployment-inventory")
		}
	}
	deploymentIDs := make([]paasv1.ResourceID, 0, len(deployments))
	for _, deployment := range deployments {
		deploymentIDs = append(deploymentIDs, deployment.Metadata.ID)
	}
	if active, err := value.activeCapacityClaims(ctx, value.nodes.controller.InstallationID, deploymentIDs...); err != nil || active != len(deployments) {
		return fail("native-runtime-capacity-claims")
	}
	if err := value.assertNativeTerminalAudit(ctx, bearer, terminalSessions); err != nil {
		return err
	}
	var lifecycle *nativeTargetLifecycleState
	if value.config.multiHostLifecycle {
		lifecycle, err = value.beginNativeTargetLifecycle(ctx, bearer, deployments, snapshots)
		if err != nil {
			return err
		}
	}
	for index, deployment := range deployments {
		spec := deployment.Spec
		spec.DesiredState = paasv1.DeploymentDesiredStopped
		operation, err := value.edge.mutateDeployment(
			ctx,
			http.MethodPut,
			"/api/paas/v1/deployments/"+string(deployment.Metadata.ID),
			fmt.Sprintf("phase3-stop-runtime-deployment-%d", index+1),
			formatResourceVersion(deployment.Metadata.ResourceVersion),
			bearer,
			spec,
			paasv1.OperationStop,
			deployment.Metadata.ID,
		)
		if err != nil {
			return fail("native-runtime-deployment-stop")
		}
		if _, err = value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
			return fail("native-runtime-deployment-stop-operation")
		}
		if _, err = value.edge.waitDeployment(
			ctx,
			bearer,
			deployment.Metadata.ID,
			deployment.Generation+1,
			paasv1.DeploymentStopped,
		); err != nil {
			return fail("native-runtime-deployment-stop-convergence")
		}
		containers, commandErr := value.nodes.command(
			ctx,
			index,
			"docker",
			"container",
			"ls",
			"--all",
			"--quiet",
			"--filter",
			"label=com.xiak.matrix.deployment-id="+string(deployment.Metadata.ID),
		)
		if commandErr != nil || len(strings.Fields(string(containers))) != 0 {
			return fail("native-runtime-provider-stop")
		}
	}
	if active, err := value.activeCapacityClaims(
		ctx,
		value.nodes.controller.InstallationID,
		deploymentIDs...,
	); err != nil || active != 0 {
		return fail("native-runtime-released-capacity-claims")
	}
	if lifecycle != nil {
		if err := value.completeNativeTargetLifecycle(ctx, bearer, terminalRevisionID, *lifecycle); err != nil {
			return err
		}
	}
	if _, err := value.edge.verifyAuditChain(ctx, bearer); err != nil {
		return fail("native-runtime-audit-integrity")
	}
	emit("two-native-deployments-with-background-runtime-and-resource-snapshots")
	return nil
}

func (fixture *nativeNodes) runtimeIdentity(ctx context.Context, index int) (nativeRuntimeIdentity, error) {
	if fixture == nil || index < 0 || index >= len(fixture.nodes) {
		return nativeRuntimeIdentity{}, fail("native-lifecycle-runtime-identity-input")
	}
	nodeUnit, err := nodeconfig.ServiceName(fixture.nodes[index].identity, false)
	if err != nil {
		return nativeRuntimeIdentity{}, fail("native-lifecycle-node-unit")
	}
	collectorUnit, err := nodeconfig.ServiceName(fixture.nodes[index].identity, true)
	if err != nil {
		return nativeRuntimeIdentity{}, fail("native-lifecycle-collector-unit")
	}
	read := func(arguments ...string) (string, error) {
		content, commandErr := fixture.command(ctx, index, arguments...)
		if commandErr != nil {
			return "", commandErr
		}
		value := strings.TrimSpace(string(content))
		if value == "" {
			return "", fail("native-lifecycle-runtime-identity")
		}
		return value, nil
	}
	serviceStart := func(unit string) (string, error) {
		active, commandErr := read("systemctl", "is-active", unit)
		if commandErr != nil || active != "active" {
			return "", fail("native-lifecycle-service-active")
		}
		return read("systemctl", "show", "--property=ActiveEnterTimestampMonotonic", "--value", unit)
	}
	bootID, err := read("cat", "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nativeRuntimeIdentity{}, err
	}
	engineID, err := read("docker", "info", "--format", "{{.ID}}")
	if err != nil {
		return nativeRuntimeIdentity{}, err
	}
	dockerStart, err := serviceStart("docker.service")
	if err != nil {
		return nativeRuntimeIdentity{}, err
	}
	nodeStart, err := serviceStart(nodeUnit)
	if err != nil {
		return nativeRuntimeIdentity{}, err
	}
	collectorStart, err := serviceStart(collectorUnit)
	if err != nil {
		return nativeRuntimeIdentity{}, err
	}
	identity := nativeRuntimeIdentity{
		BootID: bootID, EngineID: engineID, DockerActiveSince: dockerStart,
		NodeActiveSince: nodeStart, CollectorActiveSince: collectorStart,
	}
	if identity.BootID != fixture.nodes[index].facts.BootID ||
		identity.EngineID != fixture.nodes[index].facts.EngineID {
		return nativeRuntimeIdentity{}, fail("native-lifecycle-host-replaced")
	}
	return identity, nil
}

func (value *gate) nativeLifecycleEvidence(
	ctx context.Context,
	targetID paasv1.ResourceID,
	action paasv1.OperationAction,
) (nativeLifecycleEvidence, error) {
	if value.nodes == nil {
		return nativeLifecycleEvidence{}, fail("native-lifecycle-evidence-input")
	}
	_, _, _, ok := executionTargetLifecycleContract(action)
	auditAction := map[paasv1.OperationAction]auditv1.Action{
		paasv1.OperationDrainExecutionTarget:    auditv1.ActionPaaSExecutionTargetDrained,
		paasv1.OperationActivateExecutionTarget: auditv1.ActionPaaSExecutionTargetActivated,
		paasv1.OperationRemoveExecutionTarget:   auditv1.ActionPaaSExecutionTargetRemoved,
	}[action]
	if !ok || auditAction == "" {
		return nativeLifecycleEvidence{}, fail("native-lifecycle-evidence-action")
	}
	installationID := value.nodes.controller.InstallationID
	ids, err := dockerLines(
		ctx, "container", "ls", "--quiet",
		"--filter", "label=com.xiak.matrix.installation="+installationID,
		"--filter", "label=com.xiak.matrix.role=postgres",
	)
	if err != nil || len(ids) != 1 {
		return nativeLifecycleEvidence{}, fail("native-lifecycle-authority-database")
	}
	query := fmt.Sprintf(`SELECT json_build_object(
        'operations', (SELECT count(*) FROM paas.operations WHERE installation_id='%s' AND action='%s' AND target_id='%s'),
        'outbox', (SELECT count(*) FROM paas.audit_outbox WHERE installation_id='%s' AND document->>'action'='%s' AND document#>>'{target,id}'='%s')
    )::text`, installationID, action, targetID, installationID, auditAction, targetID)
	content, err := docker(
		ctx, "container", "exec", "--user", "postgres", ids[0],
		"psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
		"--username", "matrix", "--dbname", "matrix", "--command", query,
	)
	var evidence nativeLifecycleEvidence
	if err != nil || decodeOne(content, &evidence) != nil || evidence.Operations < 0 || evidence.Outbox < 0 {
		return nativeLifecycleEvidence{}, fail("native-lifecycle-evidence")
	}
	return evidence, nil
}

func (value *gate) beginNativeTargetLifecycle(
	ctx context.Context,
	bearer []byte,
	deployments []paasv1.Deployment,
	snapshots []paasv1.DeploymentRuntimeSnapshot,
) (*nativeTargetLifecycleState, error) {
	if value.nodes == nil || len(value.nodes.nodes) != 2 || len(deployments) != 2 || len(snapshots) != 2 {
		return nil, fail("native-lifecycle-fixture")
	}
	state := &nativeTargetLifecycleState{Operations: make([]paasv1.Operation, 0, 4)}
	for index := range value.nodes.nodes {
		identity, err := value.nodes.runtimeIdentity(ctx, index)
		if err != nil {
			return nil, err
		}
		state.RuntimeIdentities[index] = identity
	}
	firstTarget := value.nodes.nodes[0].identity.ExecutionTargetID
	firstDrain, err := value.edge.transitionExecutionTarget(
		ctx, bearer, firstTarget, paasv1.OperationDrainExecutionTarget, "phase3-drain-live-target-1",
	)
	if err != nil || value.edge.replayExecutionTargetTransition(ctx, bearer, firstDrain) != nil {
		return nil, fail("native-lifecycle-drain-and-replay")
	}
	state.Operations = append(state.Operations, firstDrain.Operation)
	current, etag, err := value.edge.executionTarget(ctx, bearer, firstTarget)
	if err != nil || current.Spec.DesiredState != paasv1.ExecutionTargetDraining {
		return nil, fail("native-lifecycle-drained-target")
	}
	if _, err = value.edge.rejectExecutionTargetTransition(
		ctx, bearer, firstTarget, paasv1.OperationActivateExecutionTarget,
		firstDrain.Key, etag, paasv1.ErrorIdempotencyConflict,
	); err != nil {
		return nil, fail("native-lifecycle-changed-action-replay")
	}
	state.RemoveEvidence, err = value.nativeLifecycleEvidence(
		ctx, firstTarget, paasv1.OperationRemoveExecutionTarget,
	)
	if err != nil {
		return nil, err
	}
	blocked, err := value.edge.rejectExecutionTargetTransition(
		ctx, bearer, firstTarget, paasv1.OperationRemoveExecutionTarget,
		"phase3-remove-live-target-1", etag, paasv1.ErrorConflict,
	)
	if err != nil || !blocked.Retryable {
		return nil, fail("native-lifecycle-live-removal-blocked")
	}
	afterBlocked, err := value.nativeLifecycleEvidence(
		ctx, firstTarget, paasv1.OperationRemoveExecutionTarget,
	)
	if err != nil || afterBlocked != state.RemoveEvidence {
		return nil, fail("native-lifecycle-blocked-removal-atomic")
	}
	afterRuntime, err := value.waitNativeDeploymentRuntime(
		ctx, bearer, deployments[0], firstTarget,
		snapshots[0].Value.Observation.ObservedAt,
	)
	if err != nil || afterRuntime.Value.Observation.Instances[0].ID != snapshots[0].Value.Observation.Instances[0].ID {
		return nil, fail("native-lifecycle-drain-retained-runtime")
	}
	if err := value.assertNativeProviderInstance(ctx, 0, deployments[0], afterRuntime); err != nil {
		return nil, err
	}
	if active, err := value.activeCapacityClaims(
		ctx, value.nodes.controller.InstallationID,
		nativeRuntimeDeploymentID(0), nativeRuntimeDeploymentID(1),
	); err != nil || active != 2 {
		return nil, fail("native-lifecycle-drain-retained-capacity")
	}
	secondTarget := value.nodes.nodes[1].identity.ExecutionTargetID
	secondDrain, err := value.edge.transitionExecutionTarget(
		ctx, bearer, secondTarget, paasv1.OperationDrainExecutionTarget, "phase3-drain-live-target-2",
	)
	if err != nil {
		return nil, fail("native-lifecycle-second-drain")
	}
	secondActivate, err := value.edge.transitionExecutionTarget(
		ctx, bearer, secondTarget, paasv1.OperationActivateExecutionTarget, "phase3-activate-live-target-2",
	)
	if err != nil {
		return nil, fail("native-lifecycle-reactivate")
	}
	state.Operations = append(state.Operations, secondDrain.Operation, secondActivate.Operation)
	for index := range value.nodes.nodes {
		identity, err := value.nodes.runtimeIdentity(ctx, index)
		if err != nil || identity != state.RuntimeIdentities[index] {
			return nil, fail("native-lifecycle-command-restarted-host-or-service")
		}
	}
	emit("two-host-live-drain-removal-block-and-reactivation")
	return state, nil
}

func (value *gate) completeNativeTargetLifecycle(
	ctx context.Context,
	bearer []byte,
	applicationRevisionID paasv1.ResourceID,
	state nativeTargetLifecycleState,
) error {
	firstNode, secondNode := value.nodes.nodes[0], value.nodes.nodes[1]
	removed, err := value.edge.transitionExecutionTarget(
		ctx, bearer, firstNode.identity.ExecutionTargetID,
		paasv1.OperationRemoveExecutionTarget, "phase3-remove-stopped-target-1",
	)
	if err != nil || value.edge.replayExecutionTargetTransition(ctx, bearer, removed) != nil {
		return fail("native-lifecycle-safe-remove-and-replay")
	}
	state.Operations = append(state.Operations, removed.Operation)
	afterEvidence, err := value.nativeLifecycleEvidence(
		ctx, firstNode.identity.ExecutionTargetID, paasv1.OperationRemoveExecutionTarget,
	)
	if err != nil || afterEvidence.Operations != state.RemoveEvidence.Operations+1 ||
		afterEvidence.Outbox != state.RemoveEvidence.Outbox+1 {
		return fail("native-lifecycle-remove-operation-outbox")
	}
	tombstone, _, err := value.edge.executionTarget(ctx, bearer, firstNode.identity.ExecutionTargetID)
	if err != nil || tombstone.Spec.DesiredState != paasv1.ExecutionTargetRemoved ||
		tombstone.Metadata.ResourceVersion < removed.Before.Metadata.ResourceVersion+1 {
		return fail("native-lifecycle-retained-tombstone")
	}
	var inventory paasv1.ExecutionTargetList
	if _, err = value.edge.get(ctx, "/api/paas/v1/execution-targets", bearer, &inventory); err != nil ||
		paasv1.ValidateExecutionTargetList(inventory) != nil {
		return fail("native-lifecycle-default-inventory")
	}
	foundSecond := false
	for _, target := range inventory.Items {
		if target.Metadata.ID == firstNode.identity.ExecutionTargetID || target.Spec.DesiredState == paasv1.ExecutionTargetRemoved {
			return fail("native-lifecycle-tombstone-leaked-into-inventory")
		}
		foundSecond = foundSecond || target.Metadata.ID == secondNode.identity.ExecutionTargetID
	}
	if !foundSecond {
		return fail("native-lifecycle-active-target-missing")
	}
	poolID, labels := value.nodes.registration()
	response, err := value.edge.json(
		ctx, http.MethodPost, "/api/paas/v1/execution-targets", bearer,
		paasv1.RegisterExecutionTargetRequest{
			ID: firstNode.identity.ExecutionTargetID, Name: string(firstNode.identity.ExecutionTargetID),
			ExecutionPoolID: poolID, BindingRef: firstNode.binding, Labels: labels,
		}, map[string]string{"Idempotency-Key": "phase3-reregister-removed-target-1"},
		http.StatusConflict,
	)
	if err != nil {
		return fail("native-lifecycle-tombstone-reregistration")
	}
	var conflict paasv1.Problem
	if decodeOne(response.body, &conflict) != nil || paasv1.ValidateProblem(conflict) != nil ||
		conflict.Code != paasv1.ErrorConflict {
		clear(response.body)
		return fail("native-lifecycle-tombstone-reregistration")
	}
	clear(response.body)

	operation, err := value.edge.mutateDeployment(
		ctx, http.MethodPost, "/api/paas/v1/deployments", string(nativeAfterRemovalDeploymentID), "", bearer,
		paasv1.CreateDeploymentRequest{
			ID: nativeAfterRemovalDeploymentID, Name: string(nativeAfterRemovalDeploymentID),
			Spec: deploymentSpec(applicationRevisionID, configurationRevisionOne, paasv1.DeploymentDesiredRunning),
		}, paasv1.OperationDeploy, nativeAfterRemovalDeploymentID,
	)
	if err != nil {
		return fail("native-lifecycle-post-removal-deployment")
	}
	if _, err = value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return fail("native-lifecycle-post-removal-operation")
	}
	deployment, err := value.edge.waitDeployment(
		ctx, bearer, nativeAfterRemovalDeploymentID, 1, paasv1.DeploymentReady,
	)
	if err != nil {
		return fail("native-lifecycle-post-removal-convergence")
	}
	snapshot, err := value.waitNativeDeploymentRuntime(
		ctx, bearer, deployment, secondNode.identity.ExecutionTargetID, time.Time{},
	)
	if err != nil {
		return err
	}
	if err := value.assertNativeProviderInstance(ctx, 1, deployment, snapshot); err != nil {
		return err
	}
	spec := deployment.Spec
	spec.DesiredState = paasv1.DeploymentDesiredStopped
	operation, err = value.edge.mutateDeployment(
		ctx, http.MethodPut, "/api/paas/v1/deployments/"+string(deployment.Metadata.ID),
		"phase3-stop-runtime-after-removal", formatResourceVersion(deployment.Metadata.ResourceVersion),
		bearer, spec, paasv1.OperationStop, deployment.Metadata.ID,
	)
	if err != nil {
		return fail("native-lifecycle-post-removal-stop")
	}
	if _, err = value.edge.waitOperation(ctx, bearer, operation.ID); err != nil {
		return fail("native-lifecycle-post-removal-stop-operation")
	}
	if _, err = value.edge.waitDeployment(
		ctx, bearer, deployment.Metadata.ID, deployment.Generation+1, paasv1.DeploymentStopped,
	); err != nil {
		return fail("native-lifecycle-post-removal-stop-convergence")
	}
	if active, err := value.activeCapacityClaims(
		ctx, value.nodes.controller.InstallationID,
		nativeRuntimeDeploymentID(0), nativeRuntimeDeploymentID(1), nativeAfterRemovalDeploymentID,
	); err != nil || active != 0 {
		return fail("native-lifecycle-final-capacity-release")
	}
	for index := range value.nodes.nodes {
		identity, err := value.nodes.runtimeIdentity(ctx, index)
		if err != nil || identity != state.RuntimeIdentities[index] {
			return fail("native-lifecycle-remove-restarted-host-or-service")
		}
		result, statusErr := value.nodes.mx(ctx, index, true, "status", "--root", value.nodes.installationRoot())
		if statusErr != nil || result.Changed || result.ReleaseID != value.nodes.releases.b.Manifest.Release.ID ||
			result.ConfigurationDigest != value.nodes.nodes[index].digest {
			return fail("native-lifecycle-node-release-retained")
		}
	}
	if err := value.assertNativeLifecycleAudit(ctx, bearer, state.Operations); err != nil {
		return err
	}
	emit("safe-tombstone-removal-and-remaining-host-placement")
	return nil
}

func (value *gate) assertNativeLifecycleAudit(
	ctx context.Context,
	bearer []byte,
	operations []paasv1.Operation,
) error {
	expected := map[auditv1.Action][]paasv1.Operation{}
	for _, operation := range operations {
		action := map[paasv1.OperationAction]auditv1.Action{
			paasv1.OperationDrainExecutionTarget:    auditv1.ActionPaaSExecutionTargetDrained,
			paasv1.OperationActivateExecutionTarget: auditv1.ActionPaaSExecutionTargetActivated,
			paasv1.OperationRemoveExecutionTarget:   auditv1.ActionPaaSExecutionTargetRemoved,
		}[operation.Action]
		if action == "" {
			return fail("native-lifecycle-audit-input")
		}
		expected[action] = append(expected[action], operation)
	}
	poll, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for poll.Err() == nil {
		complete := true
		for action, wanted := range expected {
			response, err := value.edge.json(
				poll, http.MethodPost, "/api/audit/v1/platform/records:query", bearer,
				auditv1.QueryRecordsRequest{PageSize: 100, Action: action}, nil, http.StatusOK,
			)
			var page auditv1.RecordPage
			valid := err == nil && decodeOne(response.body, &page) == nil &&
				auditv1.ValidateRecordPage(page) == nil && page.InstallationID == value.nodes.controller.InstallationID &&
				page.NextCursor == ""
			clear(response.body)
			if !valid || len(page.Records) < len(wanted) {
				complete = false
				continue
			}
			if len(page.Records) != len(wanted) {
				return fail("native-lifecycle-audit-duplicate")
			}
			for _, operation := range wanted {
				matches := 0
				for _, record := range page.Records {
					if record.Event.OperationID != auditv1.OperationID(operation.ID) {
						continue
					}
					matches++
					if record.Source != auditv1.SourcePaaS || record.Event.Action != action ||
						record.Event.InstallationID != value.nodes.controller.InstallationID ||
						record.Event.TenantID != "" || record.Event.Target.ID != string(operation.Target.ID) ||
						record.Event.Actor.Type != auditv1.ActorUser ||
						record.Event.Actor.ID != auditv1.ActorID(operation.RequestedBy.ID) ||
						record.Event.IAMDecisionID == "" || record.Event.Result != auditv1.ResultSucceeded {
						return fail("native-lifecycle-audit-association")
					}
				}
				if matches != 1 {
					return fail("native-lifecycle-audit-association")
				}
			}
		}
		if complete {
			if _, err := value.edge.verifyAuditChain(ctx, bearer); err != nil {
				return fail("native-lifecycle-audit-integrity")
			}
			return nil
		}
		if !waitPoll(poll, 250*time.Millisecond) {
			break
		}
	}
	return fail("native-lifecycle-audit-delivery")
}

func (value *gate) waitNativeDeploymentRuntime(
	ctx context.Context,
	bearer []byte,
	deployment paasv1.Deployment,
	targetID paasv1.ResourceID,
	after time.Time,
) (paasv1.DeploymentRuntimeSnapshot, error) {
	// CPU, memory and network are sampled immediately, while the first complete
	// storage view may need several bounded retries when Docker's disk inventory
	// is busy. Keep the gate finite without confusing that provider warm-up with
	// a missing background observation.
	poll, cancel := context.WithTimeout(ctx, nativeCompleteRuntimeSnapshotTimeout)
	defer cancel()
	for poll.Err() == nil {
		var snapshot paasv1.DeploymentRuntimeSnapshot
		_, err := value.edge.get(poll, "/api/paas/v1/deployments/"+string(deployment.Metadata.ID)+"/runtime", bearer, &snapshot)
		if err == nil && validNativeDeploymentRuntime(snapshot, deployment, targetID, after, time.Now()) {
			return snapshot, nil
		}
		if !waitPoll(poll, 250*time.Millisecond) {
			break
		}
	}
	return paasv1.DeploymentRuntimeSnapshot{}, fail("native-runtime-background-snapshot")
}

func validNativeDeploymentRuntime(
	snapshot paasv1.DeploymentRuntimeSnapshot,
	deployment paasv1.Deployment,
	targetID paasv1.ResourceID,
	after, now time.Time,
) bool {
	if paasv1.ValidateDeploymentRuntimeSnapshot(snapshot) != nil || snapshot.Scope != deployment.Metadata.Scope || snapshot.State != paasv1.MeasurementAvailable || snapshot.Value == nil {
		return false
	}
	observation := snapshot.Value.Observation
	if observation.DeploymentID != deployment.Metadata.ID || observation.Generation != deployment.Generation || observation.ApplicationRevisionID != deployment.Spec.ApplicationRevisionID || observation.ExecutionTargetID != targetID || !observation.ObservedAt.After(after) || !snapshot.Value.ValidUntil.After(observation.ObservedAt) || !now.Before(snapshot.Value.ValidUntil) || len(observation.Instances) != 1 {
		return false
	}
	instance := observation.Instances[0]
	observedHealth := instance.Health == paasv1.DeploymentInstanceHealthNone || instance.Health == paasv1.DeploymentInstanceHealthHealthy
	if instance.ID == "" || instance.ComponentName != "web" || instance.State != paasv1.DeploymentInstanceRunning ||
		!observedHealth || instance.ExitCode != nil {
		return false
	}
	resources := snapshot.Resources
	if resources.State != paasv1.MeasurementAvailable || resources.Value == nil ||
		!resources.Value.Observation.ObservedAt.After(after) ||
		!resources.Value.ValidUntil.After(resources.Value.Observation.ObservedAt) ||
		!now.Before(resources.Value.ValidUntil) {
		return false
	}
	resourceObservation := resources.Value.Observation
	if resourceObservation.DeploymentID != observation.DeploymentID ||
		resourceObservation.Generation != observation.Generation ||
		resourceObservation.ApplicationRevisionID != observation.ApplicationRevisionID ||
		resourceObservation.ExecutionTargetID != observation.ExecutionTargetID ||
		len(resourceObservation.Instances) != 1 ||
		resourceObservation.Instances[0].ID != instance.ID {
		return false
	}
	resource := resourceObservation.Instances[0]
	if resource.CPU.State != paasv1.MeasurementAvailable || resource.CPU.Value == nil ||
		resource.CPU.Value.LimitCPUMillis != 100 || resource.CPU.Value.WindowMillis < 1 ||
		resource.Memory.State != paasv1.MeasurementAvailable || resource.Memory.Value == nil ||
		resource.Memory.Value.LimitBytes != 32*1024*1024 ||
		resource.Memory.Value.UsedBytes > resource.Memory.Value.LimitBytes ||
		resource.Network.State != paasv1.MeasurementAvailable || resource.Network.Value == nil ||
		(resource.BlockIO.State != paasv1.MeasurementAvailable &&
			resource.BlockIO.State != paasv1.MeasurementUnsupported) ||
		resource.Storage.Value == nil ||
		(resource.Storage.State != paasv1.MeasurementAvailable && resource.Storage.State != paasv1.MeasurementStale) {
		return false
	}
	storage := resource.Storage.Value
	return !storage.ObservedAt.After(resourceObservation.ObservedAt) &&
		storage.ValidUntil.After(storage.ObservedAt) &&
		storage.ImageSharedBytes <= storage.ImageTotalBytes &&
		storage.ImageUniqueBytes == storage.ImageTotalBytes-storage.ImageSharedBytes &&
		storage.VolumesState == paasv1.MeasurementAvailable && storage.Volumes != nil
}

type nativeProviderInstance struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Running bool              `json:"running"`
	Labels  map[string]string `json:"labels"`
}

func (value *gate) assertNativeProviderInstance(
	ctx context.Context,
	wantNode int,
	deployment paasv1.Deployment,
	snapshot paasv1.DeploymentRuntimeSnapshot,
) error {
	for index := range value.nodes.nodes {
		ids, err := value.nodes.command(ctx, index, "docker", "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", "label=com.xiak.matrix.deployment-id="+string(deployment.Metadata.ID))
		lines := strings.Fields(string(ids))
		if err != nil || index != wantNode && len(lines) != 0 || index == wantNode && len(lines) != 1 {
			return fail("native-runtime-provider-placement")
		}
		if index != wantNode {
			continue
		}
		content, err := value.nodes.command(ctx, index, "docker", "container", "inspect", "--format", `{"id":"{{.Id}}","name":"{{.Name}}","running":{{.State.Running}},"labels":{{json .Config.Labels}}}`, lines[0])
		var provider nativeProviderInstance
		if err != nil || decodeOne(content, &provider) != nil || !provider.Running || provider.ID == "" || provider.Name == "" {
			return fail("native-runtime-provider-placement")
		}
		instance := snapshot.Value.Observation.Instances[0]
		encoded, encodeErr := json.Marshal(snapshot)
		if string(instance.ID) == provider.ID || string(instance.ID) == strings.TrimPrefix(provider.Name, "/") ||
			encodeErr != nil || bytes.Contains(encoded, []byte(provider.ID)) ||
			bytes.Contains(encoded, []byte(strings.TrimPrefix(provider.Name, "/"))) ||
			provider.Labels["com.xiak.matrix.tenant-id"] != string(deployment.Metadata.Scope.TenantID) ||
			provider.Labels["com.xiak.matrix.deployment-id"] != string(deployment.Metadata.ID) ||
			provider.Labels["com.xiak.matrix.generation"] != strconv.FormatUint(deployment.Generation, 10) ||
			provider.Labels["com.xiak.matrix.application-revision-id"] != string(deployment.Spec.ApplicationRevisionID) ||
			provider.Labels["com.xiak.matrix.component"] != instance.ComponentName {
			return fail("native-runtime-provider-neutral-identity")
		}
	}
	return nil
}

func (value *gate) prepareNativeRuntimeImages(ctx context.Context) error {
	bundles := []release.VerifiedBundle{value.releases.a, value.releases.b}
	workloads := make([]release.Image, 0, len(bundles))
	for _, bundle := range bundles {
		workload, ok := workloadImage(bundle.Manifest)
		if !ok || workload.ImageID == "" || workload.ArchivePath == "" {
			return fail("native-runtime-workload-image")
		}
		workloads = append(workloads, workload)
	}
	fixture := value.nodes
	for index := range fixture.nodes {
		for bundleIndex, workload := range workloads {
			remote := fmt.Sprintf("%s/runtime-workload-%d.tar", fixture.root(), bundleIndex+1)
			if err := fixture.copy(ctx, index, filepath.Join(bundles[bundleIndex].Root, filepath.FromSlash(workload.ArchivePath)), remote, true, false); err != nil {
				return err
			}
			if _, err := fixture.command(ctx, index, "docker", "load", "--input", remote); err != nil {
				return err
			}
			identity, err := fixture.command(ctx, index, "docker", "image", "inspect", "--format", "{{.Id}}", workload.ImageID)
			if err != nil || strings.TrimSpace(string(identity)) != workload.ImageID {
				return fail("native-runtime-workload-image")
			}
		}
	}
	return nil
}

func (value *gate) prepareNativeWorkloads(ctx context.Context) error {
	var postgres release.Image
	for _, image := range value.releases.a.Manifest.Images {
		if image.Component == "postgres" {
			postgres = image
		}
	}
	if postgres.ImageID == "" || postgres.ArchivePath == "" {
		return fail("native-signed-postgres-fixture")
	}
	fixture := value.nodes
	for index := range fixture.nodes {
		password, err := randomPassword(rand.Reader)
		if err != nil {
			return fail("native-workload-password")
		}
		path, err := privateFixtureFile(fixture.directory, fmt.Sprintf("workload-password-%d", index), password)
		clear(password)
		if err != nil {
			return err
		}
		if err = fixture.copy(ctx, index, path, fixture.root()+"/workload-password", true, false); err != nil {
			return err
		}
		if err = fixture.copy(ctx, index, filepath.Join(value.releases.a.Root, filepath.FromSlash(postgres.ArchivePath)), fixture.root()+"/postgres.tar", true, false); err != nil {
			return err
		}
		if _, err = fixture.command(ctx, index, "docker", "load", "--input", fixture.root()+"/postgres.tar"); err != nil {
			return err
		}
		if _, err = fixture.command(ctx, index, "docker", "volume", "create", "--label", "com.xiak.matrix.task=offline-native-gate", "matrix-offline-retained-data"); err != nil {
			return err
		}
		if _, err = fixture.command(ctx, index, "docker", "run", "--detach", "--pull", "never", "--name", "matrix-offline-retained", "--label", "com.xiak.matrix.task=offline-native-gate", "--network", "none", "--cpus", "0.5", "--memory", "384m", "--memory-swap", "384m", "--pids-limit", "64", "--restart", "unless-stopped", "--mount", "type=volume,source=matrix-offline-retained-data,target=/var/lib/postgresql", "--mount", "type=bind,source="+fixture.root()+"/workload-password,target=/run/secrets/fixture-password,readonly", "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/fixture-password", postgres.ImageID); err != nil {
			return err
		}
		poll, cancel := context.WithTimeout(ctx, 90*time.Second)
		for {
			if _, err = fixture.command(poll, index, "docker", "exec", "--user", "postgres", "matrix-offline-retained", "pg_isready", "--username", "postgres"); err == nil {
				break
			}
			if !waitPoll(poll, 500*time.Millisecond) {
				cancel()
				return fail("native-workload-ready")
			}
		}
		cancel()
		statement := fmt.Sprintf("CREATE TABLE matrix_retained (id integer PRIMARY KEY, marker text NOT NULL); INSERT INTO matrix_retained VALUES (1,'offline-native-%d')", index+1)
		if _, err = fixture.command(ctx, index, "docker", "exec", "--user", "postgres", "matrix-offline-retained", "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-c", statement); err != nil {
			return err
		}
		workload, err := fixture.readWorkload(ctx, index)
		if err != nil || !workload.Running || len(workload.ID) != 64 || workload.StartedAt == "" || workload.RestartCount != 0 {
			return fail("native-workload-baseline")
		}
		fixture.nodes[index].workload = workload
		if err = fixture.assertWorkload(ctx, index); err != nil {
			return err
		}
	}
	if fixture.nodes[0].workload.ID == fixture.nodes[1].workload.ID {
		return fail("native-independent-workload-engines")
	}
	emit("two-isolated-native-postgres-retention-fixtures")
	return nil
}

func (fixture *nativeNodes) readWorkload(ctx context.Context, index int) (nativeWorkload, error) {
	format := `{"id":"{{.Id}}","startedAt":"{{.State.StartedAt}}","restartCount":{{.RestartCount}},"running":{{.State.Running}}}`
	content, err := fixture.command(ctx, index, "docker", "container", "inspect", "--format", format, "matrix-offline-retained")
	var workload nativeWorkload
	if err != nil || decodeOne(content, &workload) != nil {
		return nativeWorkload{}, fail("native-workload-observation")
	}
	return workload, nil
}

func sameNativeWorkload(before, after nativeWorkload) bool {
	return before.Running && after.Running && before.ID != "" && before.ID == after.ID && before.StartedAt != "" && before.StartedAt == after.StartedAt && before.RestartCount == after.RestartCount
}

func (fixture *nativeNodes) assertWorkload(ctx context.Context, index int) error {
	workload, err := fixture.readWorkload(ctx, index)
	if err != nil || !sameNativeWorkload(fixture.nodes[index].workload, workload) {
		return fail("native-workload-identity-and-uptime")
	}
	content, err := fixture.command(ctx, index, "docker", "exec", "--user", "postgres", "matrix-offline-retained", "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-c", "SELECT marker FROM matrix_retained WHERE id=1")
	if err != nil || strings.TrimSpace(string(content)) != fmt.Sprintf("offline-native-%d", index+1) {
		return fail("native-workload-marker-retention")
	}
	return nil
}

// A private, sanitized experiment receipt links the two existing gate phases.
// It is never presented to IAM, the node, or an installer as authority.
type nativeRetainedNode struct {
	Facts      nativeHostFacts  `json:"facts"`
	Digest     string           `json:"digest"`
	Operation  paasv1.Operation `json:"operation"`
	AuditHash  string           `json:"auditHash"`
	Workload   nativeWorkload   `json:"workload"`
	ObservedAt time.Time        `json:"observedAt"`
}

type nativeRetention struct {
	InstallationID   string               `json:"installationId"`
	ControllerDigest string               `json:"controllerDigest"`
	ReleaseID        string               `json:"releaseId"`
	ReleaseDigest    string               `json:"releaseDigest"`
	Nodes            []nativeRetainedNode `json:"nodes"`
}

func (value *gate) saveNativeRetention(ctx context.Context) error {
	if value.nodes == nil {
		return nil
	}
	fixture := value.nodes
	retained := nativeRetention{InstallationID: fixture.controller.InstallationID, ControllerDigest: value.controllerConfigDigest, ReleaseID: fixture.releases.a.Manifest.Release.ID, ReleaseDigest: fixture.releases.a.ManifestSHA256}
	for index, node := range fixture.nodes {
		target, err := value.nativeStoredTarget(ctx, index)
		if err != nil || target.Status.Usage == nil {
			return fail("native-retained-observation")
		}
		if _, err := fixture.mx(ctx, index, false, "verify", "--root", fixture.installationRoot()); err != nil {
			return err
		}
		retained.Nodes = append(retained.Nodes, nativeRetainedNode{Facts: node.facts, Digest: node.digest, Operation: node.operation, AuditHash: node.auditHash, Workload: node.workload, ObservedAt: target.Status.Usage.ObservedAt})
	}
	content, err := json.Marshal(retained)
	if err != nil {
		return fail("native-retention-encoding")
	}
	_, err = privateFixtureFile(filepath.Dir(value.config.nativeNodes), "retained.json", content)
	return err
}

func (value *gate) afterNativeRestart(ctx context.Context, installationID string) error {
	if value.config.nativeNodes == "" {
		return nil
	}
	inputBytes, err := os.ReadFile(value.config.nativeNodes)
	var input nativeFixtureInput
	if err != nil || len(inputBytes) > 16*1024 || decodeOne(inputBytes, &input) != nil || validateNativeFixture(input) != nil {
		return fail("native-restart-input")
	}
	content, err := os.ReadFile(filepath.Join(filepath.Dir(value.config.nativeNodes), "retained.json"))
	var retained nativeRetention
	if err != nil || len(content) > 64*1024 || decodeOne(content, &retained) != nil || len(retained.Nodes) != 2 || retained.InstallationID != installationID || retained.ControllerDigest != value.controllerConfigDigest {
		return fail("native-restart-retention")
	}
	trust, err := os.ReadFile(value.config.trustKey)
	if err != nil {
		return fail("native-restart-release-trust")
	}
	defer clear(trust)
	a, err := release.VerifyDirectory(input.ReleaseA, trust)
	if err != nil || !isNativeDeploymentRuntimePredecessor(a) ||
		a.Manifest.Release.ID != retained.ReleaseID || a.ManifestSHA256 != retained.ReleaseDigest {
		return fail("native-restart-predecessor-release")
	}
	controllerBytes, err := os.ReadFile(filepath.Join(value.config.root, filepath.FromSlash(layout.NodeControllerConfiguration)))
	if err != nil {
		return fail("native-restart-controller")
	}
	defer clear(controllerBytes)
	controller, err := nodeconfig.DecodeController(controllerBytes)
	if err != nil {
		return fail("native-restart-controller")
	}
	defer controller.Clear()
	digest, err := nodeconfig.ControllerDigest(controller)
	if err != nil || digest != retained.ControllerDigest || controller.InstallationID != installationID || len(controller.Nodes) != 2 {
		return fail("native-restart-latest-controller")
	}
	fixture := &nativeNodes{input: input, directory: filepath.Dir(value.config.nativeNodes), releases: releasePair{a: a}, controller: controller}
	value.nodes = fixture
	driver, err := os.Executable()
	if err != nil {
		return fail("native-restart-probe-driver")
	}
	for index, saved := range retained.Nodes {
		targetID := paasv1.ResourceID(fmt.Sprintf("offline-native-%d", index+1))
		if !validNativeFacts(saved.Facts) || paasv1.ValidateOperation(saved.Operation) != nil || saved.Operation.InstallationID != installationID || saved.Operation.Target.ID != targetID || paasv1.ValidateDigest("digest", saved.Digest) != nil || paasv1.ValidateDigest("auditHash", saved.AuditHash) != nil || saved.ObservedAt.IsZero() {
			return fail("native-restart-node-receipt")
		}
		node := nativeNodeState{input: input.Nodes[index], facts: saved.Facts, identity: nodev1.Identity{InstallationID: installationID, ExecutionTargetID: targetID}, binding: fmt.Sprintf("offline-native-%d-connection", index+1), digest: saved.Digest, operation: saved.Operation, auditHash: saved.AuditHash, workload: saved.Workload}
		fixture.nodes = append(fixture.nodes, node)
		if err := fixture.waitPrepared(ctx, index); err != nil {
			return err
		}
		if err = fixture.copy(ctx, index, driver, fixture.root()+"/probe.test", true, false); err != nil {
			return err
		}
		if _, err = fixture.command(ctx, index, "env", "MATRIX_PHASE1_NATIVE_HOST_PROBE=after-restart", nativeFixtureRootEnvironment+"="+fixture.root(), fixture.root()+"/probe.test", "-test.run=^TestOfflineNativeHostProbe$", "-test.count=1"); err != nil {
			return err
		}
		factsPath := filepath.Join(fixture.directory, fmt.Sprintf("facts-after-restart-%d.json", index))
		if err = fixture.copy(ctx, index, factsPath, fixture.root()+"/facts-after-restart.json", false, false); err != nil {
			return err
		}
		factsBytes, err := os.ReadFile(factsPath)
		var facts nativeHostFacts
		if err != nil || decodeOne(factsBytes, &facts) != nil || !sameNativeHostAfterBoot(saved.Facts, facts) {
			return fail("native-actual-kernel-boot-and-identity-" + strconv.Itoa(index+1))
		}
		fixture.nodes[index].facts = facts
		poll, cancel := context.WithTimeout(ctx, 3*time.Minute)
		for {
			status, err := fixture.mx(poll, index, false, "status", "--root", fixture.installationRoot())
			if err == nil && !status.Changed && status.ReleaseID == retained.ReleaseID && status.ConfigurationDigest == saved.Digest {
				break
			}
			if !waitPoll(poll, time.Second) {
				cancel()
				return fail("native-automatic-sealed-boot-startup")
			}
		}
		cancel()
		// Read-only status was the first node command: no test start/reconcile
		// can make a broken persistent boot entry appear to have succeeded.
		workload, err := fixture.readWorkload(ctx, index)
		oldStart, oldErr := time.Parse(time.RFC3339Nano, saved.Workload.StartedAt)
		newStart, newErr := time.Parse(time.RFC3339Nano, workload.StartedAt)
		if err != nil || !workload.Running || workload.ID != saved.Workload.ID || oldErr != nil || newErr != nil || !newStart.After(oldStart) {
			return fail("native-post-boot-workload-identity")
		}
		fixture.nodes[index].workload = workload
		if err = fixture.assertWorkload(ctx, index); err != nil {
			return err
		}
		observed, err := value.waitNativeStored(ctx, index, paasv1.ExecutionTargetHealthReady, saved.ObservedAt)
		if err != nil || !matchesNativeObservation(observed, fixture.nodes[index], false, fixture.installationRoot()) {
			return fail("native-post-boot-background-reconnection")
		}
		if err = value.nativeStoredHistory(ctx, index); err != nil {
			return err
		}
	}
	emit("two-real-native-kernel-boots-auto-reconnected-with-retained-data")
	return nil
}

func sameNativeHostAfterBoot(before, after nativeHostFacts) bool {
	// Capacity is an observation, not an immutable identity: usable kernel
	// memory can change across boots. The caller checks the fresh PaaS sample
	// against the newly probed CPU, memory and filesystem quantities instead.
	return validNativeFacts(before) && validNativeFacts(after) && before.BootID != after.BootID && before.Fingerprint == after.Fingerprint && before.EngineID == after.EngineID
}

func (value *gate) nativeStoredHistory(ctx context.Context, index int) error {
	node := value.nodes.nodes[index]
	ids, err := dockerLines(ctx, "container", "ls", "--quiet", "--filter", "label=com.xiak.matrix.installation="+node.identity.InstallationID, "--filter", "label=com.xiak.matrix.role=postgres")
	if err != nil || len(ids) != 1 || paasv1.ValidateID("operationId", string(node.operation.ID)) != nil || paasv1.ValidateDigest("recordHash", node.auditHash) != nil {
		return fail("native-post-boot-history-input")
	}
	query := fmt.Sprintf("SELECT document FROM paas.operations WHERE id='%s'; SELECT record_hash FROM audit.records WHERE record_hash='%s'", node.operation.ID, node.auditHash)
	content, err := docker(ctx, "container", "exec", "--user", "postgres", ids[0], "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--username", "matrix", "--dbname", "matrix", "--command", query)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var operation paasv1.Operation
	if err != nil || len(lines) != 2 || decodeOne([]byte(lines[0]), &operation) != nil || !reflect.DeepEqual(operation, node.operation) || lines[1] != node.auditHash {
		return fail("native-post-boot-original-operation-and-audit")
	}
	return nil
}
